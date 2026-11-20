"""CSV / Excel export of the risk register, safe against formula (CSV) injection.

Spreadsheet apps execute cells beginning with = + - @ (and tab/CR) as formulas. Every text
cell is neutralised by prefixing an apostrophe, and in Excel files text is also written
with an explicit string type so openpyxl never stores it as a formula.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Iterator
from datetime import date, datetime
from typing import Any

from django.db.models import QuerySet

from .models import Risk, RiskMatrix

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n", "|", "%")

COLUMNS = [
    ("ref", "Ref"),
    ("title", "Title"),
    ("category", "Category"),
    ("status", "Status"),
    ("business_unit", "Business unit"),
    ("owner", "Owner"),
    ("assets", "Assets"),
    ("inherent_l", "Inherent L"),
    ("inherent_i", "Inherent I"),
    ("inherent_score", "Inherent score"),
    ("inherent_band", "Inherent band"),
    ("residual_l", "Residual L"),
    ("residual_i", "Residual I"),
    ("residual_score", "Residual score"),
    ("residual_band", "Residual band"),
    ("treatment", "Treatment"),
    ("target_date", "Target date"),
    ("next_review_date", "Next review"),
    ("techniques", "ATT&CK techniques"),
    ("controls", "Controls"),
    ("scenario", "Scenario"),
]


def neutralise(value: Any) -> Any:
    """Make a cell value safe for spreadsheets. Numbers and dates pass through."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, int | float | date | datetime):
        return value
    text = str(value)
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def rows(risks: QuerySet[Risk], matrix: RiskMatrix) -> Iterator[list[Any]]:
    qs = risks.select_related("owner", "business_unit").prefetch_related(
        "assets", "techniques", "controls"
    )
    for r in qs:
        record = {
            "ref": r.ref,
            "title": r.title,
            "category": r.get_category_display(),
            "status": r.get_status_display(),
            "business_unit": r.business_unit.name if r.business_unit else "",
            "owner": str(r.owner) if r.owner else "",
            "assets": "; ".join(a.name for a in r.assets.all()),
            "inherent_l": r.inherent_likelihood,
            "inherent_i": r.inherent_impact,
            "inherent_score": r.inherent.value,
            "inherent_band": matrix.band(r.inherent.value).label,
            "residual_l": r.residual_likelihood,
            "residual_i": r.residual_impact,
            "residual_score": r.residual.value,
            "residual_band": matrix.band(r.residual.value).label,
            "treatment": r.get_treatment_display(),
            "target_date": r.target_date,
            "next_review_date": r.next_review_date,
            "techniques": "; ".join(t.attack_id for t in r.techniques.all()),
            "controls": "; ".join(c.ref for c in r.controls.all()),
            "scenario": r.scenario,
        }
        yield [neutralise(record[key]) for key, _ in COLUMNS]


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, date | datetime) else value


def to_csv(data: Iterable[list[Any]]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL)
    writer.writerow([label for _, label in COLUMNS])
    for row in data:
        writer.writerow([_iso(v) for v in row])
    # UTF-8 BOM so Excel opens non-ASCII text correctly.
    return ("﻿" + buffer.getvalue()).encode("utf-8")


def to_xlsx(data: Iterable[list[Any]]) -> bytes:
    from openpyxl import Workbook
    from openpyxl.cell.cell import TYPE_STRING
    from openpyxl.styles import Font

    wb = Workbook()
    ws = wb.active
    ws.title = "Risk register"
    ws.append([label for _, label in COLUMNS])
    for cell in ws[1]:
        cell.font = Font(bold=True)
    for row in data:
        ws.append(row)
        for cell in ws[ws.max_row]:
            if isinstance(cell.value, str):
                cell.data_type = TYPE_STRING  # never a formula
    ws.freeze_panes = "A2"
    for col, width in zip("ABCDEFGHIJKLMNOPQRSTU", (9, 40, 22, 14, 18, 18, 30), strict=False):
        ws.column_dimensions[col].width = width
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()
