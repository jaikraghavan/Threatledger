"""Helpers for the framework seed builders in scripts/seeds/ (run with the project venv)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]


def write(
    name: str, header: str, framework: dict[str, Any], requirements: list[dict[str, Any]]
) -> None:
    doc = {
        "schema": "threatledger-framework/1",
        "framework": framework,
        "requirements": requirements,
    }
    path = ROOT / "data" / "frameworks" / name
    body = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=110)
    path.write_text(header + body, encoding="utf-8")
    n = sum(1 for r in requirements if not r.get("is_domain"))
    print(f"wrote {path.relative_to(ROOT)}: {n} requirements")
