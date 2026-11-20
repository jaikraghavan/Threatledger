"""Fetch CTID Mappings Explorer ATT&CK <-> NIST SP 800-53 r5 mapping files."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from threatledger.core.fetch import FetchError, fetch

REPO = "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/nist_800_53/"
ALLOWED_PREFIXES = (REPO,)
DEFAULT_ATTACK_VERSION = "16.1"  # newest NIST r5 mapping published by CTID (checked 2026-11)
VERSION_RE = re.compile(r"^\d{1,2}\.\d{1,2}$")
MAX_BYTES = 50 * 1024 * 1024


def ctid_url(attack_version: str) -> str:
    if not VERSION_RE.match(attack_version):
        raise FetchError(f"invalid ATT&CK version {attack_version!r}")
    v = attack_version
    return (
        f"{REPO}attack-{v}/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-{v}-enterprise.json"
    )


def load(
    attack_version: str | None = None, file_path: str | None = None
) -> tuple[dict[str, Any], str]:
    if file_path:
        path = Path(file_path)
        if not path.is_file():
            raise FetchError(f"no such file: {path}")
        if path.stat().st_size > MAX_BYTES:
            raise FetchError("file too large")
        data, source = path.read_bytes(), f"file:{path.name}"
    else:
        got = fetch(
            ctid_url(attack_version or DEFAULT_ATTACK_VERSION),
            allowed_prefixes=ALLOWED_PREFIXES,
            max_bytes=MAX_BYTES,
        )
        data, source = got.data, got.source
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FetchError(f"not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise FetchError("unexpected file structure")
    return payload, source
