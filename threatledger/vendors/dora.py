"""DORA register of information (Regulation (EU) 2022/2554, Art. 28(3); ITS 2024/2956) export.

Produces an Excel workbook with one sheet per main template, columns named after the template
fields. It is *indicative*: competent authorities collect the register in the EBA xBRL-CSV
format, so validate and convert with your regulator's tooling before submission.
"""

from __future__ import annotations

import io
from collections.abc import Iterable
from decimal import Decimal
from typing import Any

from threatledger.risks.exports import neutralise

from .models import Contract, Entity

SUBSTITUTABILITY = {
    "easy": "Easily substitutable",
    "medium": "Medium complexity in terms of substitutability",
    "hard": "Highly complex substitutability",
    "not": "Not substitutable",
}


def _contract_rows(contracts: Iterable[Contract]) -> list[list[Any]]:
    return [
        [
            c.ref,
            c.reference,
            c.entity.lei,
            c.entity.legal_name or c.entity.name,
            c.start_date,
            c.end_date,
            c.notice_days,
            "Yes" if c.auto_renew else "No",
            c.governing_law,
            c.annual_value,
            c.currency,
            c.terminated_on,
        ]
        for c in contracts
    ]


def build_register(
    org: Any, entities: list[Entity]
) -> dict[str, tuple[list[str], list[list[Any]]]]:
    ict = [e for e in entities if e.ict_provider]
    contracts = list(
        Contract.objects.filter(entity__in=ict)
        .select_related("entity")
        .prefetch_related("solutions")
        .order_by("ref")
    )
    sheets: dict[str, tuple[list[str], list[list[Any]]]] = {}
    sheets["B_01.01 Entity"] = (
        ["Name of the entity maintaining the register", "LEI", "Date of the register"],
        [[org.name, (org.settings or {}).get("lei", ""), None]],
    )
    sheets["B_02.01 Arrangements"] = (
        [
            "Contractual arrangement reference",
            "Contract number",
            "Provider LEI",
            "Provider legal name",
            "Start date",
            "End date",
            "Notice period (days)",
            "Automatic renewal",
            "Governing law (country)",
            "Annual expense",
            "Currency",
            "Termination date",
        ],
        _contract_rows(contracts),
    )
    rows = []
    for c in contracts:
        for s in c.solutions.all():
            rows.append(
                [
                    c.ref,
                    s.name,
                    s.ict_service_type,
                    s.supported_function,
                    "Yes" if s.function_is_critical else "No",
                    s.data_locations,
                    "Yes" if c.data_processing_agreement else "No",
                    "Yes" if c.audit_rights else "No",
                    "Yes" if c.exit_assistance else "No",
                    "Yes" if c.subcontracting_allowed else "No",
                ]
            )
    sheets["B_02.02 Services"] = (
        [
            "Contractual arrangement reference",
            "ICT service",
            "Type of ICT service",
            "Function supported",
            "Critical or important function",
            "Data storage/processing locations",
            "Data processing agreement",
            "Audit and access rights",
            "Exit assistance",
            "Sub-contracting permitted",
        ],
        rows,
    )
    sheets["B_05.01 Providers"] = (
        [
            "Provider LEI",
            "Provider name",
            "Legal name",
            "Country of headquarters",
            "Tier",
            "Status",
            "Substitutability",
            "Exit plan",
            "Supports a critical or important function",
        ],
        [
            [
                e.lei,
                e.name,
                e.legal_name,
                e.country,
                e.get_tier_display(),
                e.get_status_display(),
                SUBSTITUTABILITY.get(e.substitutability, ""),
                "Yes" if e.exit_plan else "No",
                "Yes" if any(s.function_is_critical for s in e.solutions.all()) else "No",
            ]
            for e in ict
        ],
    )
    functions: dict[str, set[str]] = {}
    critical: dict[str, bool] = {}
    for e in ict:
        for s in e.solutions.all():
            if s.supported_function:
                functions.setdefault(s.supported_function, set()).add(e.name)
                critical[s.supported_function] = (
                    critical.get(s.supported_function, False) or s.function_is_critical
                )
    sheets["B_06.01 Functions"] = (
        ["Function", "Critical or important", "ICT providers supporting it"],
        [
            [name, "Yes" if critical[name] else "No", ", ".join(sorted(providers))]
            for name, providers in sorted(functions.items())
        ],
    )
    return sheets


def to_xlsx(sheets: dict[str, tuple[list[str], list[list[Any]]]]) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Font

    wb = Workbook()
    wb.remove(wb.active)
    for title, (header, rows) in sheets.items():
        ws = wb.create_sheet(title[:31])
        ws.append(header)
        for cell in ws[1]:
            cell.font = Font(bold=True)
        for row in rows:
            ws.append([float(v) if isinstance(v, Decimal) else neutralise(v) for v in row])
    notes = wb.create_sheet("Read me")
    notes.append(["Indicative DORA register of information generated by ThreatLedger."])
    notes.append(
        ["Validate against the EBA taxonomy and your competent authority's format before filing."]
    )
    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()
