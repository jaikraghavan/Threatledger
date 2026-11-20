"""Build data/frameworks/nist-800-53-r5.json from NIST's official OSCAL catalog.

NIST SP 800-53 is a US Government work (public domain). Source files:
  https://github.com/usnistgov/oscal-content/tree/main/nist.gov/SP800-53/rev5/json
    NIST_SP-800-53_rev5_catalog.json
    NIST_SP-800-53_rev5_{LOW,MODERATE,HIGH}-baseline_profile.json

Usage:
  python scripts/build_nist_80053.py <dir-with-oscal-files> data/frameworks/nist-800-53-r5.json

Output uses the ThreatLedger framework JSON schema (see threatledger/frameworks/importer.py).
Withdrawn controls are omitted. Parameters are rendered NIST-style, e.g.
"[Assignment: organization-defined frequency]".
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

INSERT = re.compile(r"\{\{\s*insert:\s*param,\s*([\w.\-]+)\s*\}\}")


def label(obj: dict[str, Any]) -> str:
    labels = [p for p in obj.get("props", []) if p["name"] == "label"]
    plain = [p["value"] for p in labels if "class" not in p]
    return (plain or [p["value"] for p in labels] or [obj["id"].upper()])[0]


def withdrawn(obj: dict[str, Any]) -> bool:
    return any(p["name"] == "status" and p["value"] == "withdrawn" for p in obj.get("props", []))


def param_text(param: dict[str, Any], params: dict[str, dict[str, Any]]) -> str:
    if "select" in param:
        sel = param["select"]
        choices = [render(c, params) for c in sel.get("choice", [])]
        how = "one or more" if sel.get("how-many") == "one-or-more" else ""
        return f"[Selection{' (' + how + ')' if how else ''}: {'; '.join(choices)}]"
    lbl = param.get("label") or param["id"]
    return f"[Assignment: organization-defined {lbl}]"


def render(text: str, params: dict[str, dict[str, Any]]) -> str:
    return INSERT.sub(
        lambda m: (
            param_text(params[m.group(1)], params) if m.group(1) in params else "[Assignment]"
        ),
        text,
    )


def statement(obj: dict[str, Any], params: dict[str, dict[str, Any]]) -> str:
    lines: list[str] = []

    def walk(part: dict[str, Any], depth: int) -> None:
        prose = render(part.get("prose", ""), params).strip()
        lbl = next((p["value"] for p in part.get("props", []) if p["name"] == "label"), "")
        if prose or lbl:
            lines.append(("  " * depth) + (f"{lbl} " if lbl else "") + prose)
        for child in part.get("parts", []):
            walk(child, depth + (1 if lbl else 0))

    for part in obj.get("parts", []):
        if part["name"] == "statement":
            walk(part, 0)
    return "\n".join(line.rstrip() for line in lines if line.strip())


def baseline_ids(directory: Path) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for name in ("LOW", "MODERATE", "HIGH"):
        prof = json.loads(
            (directory / f"NIST_SP-800-53_rev5_{name}-baseline_profile.json").read_text()
        )
        ids: set[str] = set()
        for imp in prof["profile"]["imports"]:
            for inc in imp.get("include-controls", []):
                ids.update(inc.get("with-ids", []))
        out[name.lower()] = ids
    return out


def main(src: str, dest: str) -> None:
    directory = Path(src)
    catalog = json.loads((directory / "NIST_SP-800-53_rev5_catalog.json").read_text())["catalog"]
    baselines = baseline_ids(directory)
    requirements: list[dict[str, Any]] = []
    order = 0

    def add(obj: dict[str, Any], parent: str | None, family_params: dict[str, Any]) -> None:
        nonlocal order
        if withdrawn(obj):
            return
        params = {**family_params, **{p["id"]: p for p in obj.get("params", [])}}
        ref = label(obj)
        order += 1
        requirements.append(
            {
                "ref": ref,
                "title": obj["title"],
                "text": statement(obj, params),
                "parent": parent,
                "order": order,
                "baselines": [b for b in ("low", "moderate", "high") if obj["id"] in baselines[b]],
            }
        )
        for child in obj.get("controls", []):
            add(child, ref, params)

    for group in catalog["groups"]:
        fam = group["id"].upper()
        order += 1
        requirements.append(
            {"ref": fam, "title": group["title"], "is_domain": True, "order": order}
        )
        for control in group.get("controls", []):
            add(control, fam, {})

    out = {
        "schema": "threatledger-framework/1",
        "framework": {
            "code": "NIST-800-53-R5",
            "name": "NIST SP 800-53 Rev. 5",
            "version": catalog["metadata"].get("version", "5"),
            "publisher": "National Institute of Standards and Technology",
            "source_url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
            "licence_note": "US Government work, public domain. "
            "Text from NIST's official OSCAL catalog.",
            "content_level": "full",
            "description": "Security and privacy controls for information systems and "
            "organizations. "
            "Use a baseline (Low / Moderate / High) to scope what you track.",
            "baselines": ["low", "moderate", "high"],
        },
        "requirements": requirements,
    }
    Path(dest).write_text(
        json.dumps(out, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    n = sum(1 for r in requirements if not r.get("is_domain"))
    print(f"wrote {dest}: {n} controls/enhancements, {len(requirements) - n} families")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
