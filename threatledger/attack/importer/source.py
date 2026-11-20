"""Fetch ATT&CK bundles. Downloads are restricted to the official MITRE repository.

SSRF / integrity controls:
- the URL is built here from a validated domain and version, never taken from user input;
- HTTPS only, to a single allowlisted host, and the final URL after redirects is re-checked;
- the body is size-capped and its SHA-256 is returned (and optionally verified).
"""

from __future__ import annotations

import re
import urllib.request  # noqa: F401 - patched in tests
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings

from threatledger.core.fetch import FetchError, fetch, verify

ALLOWED_HOST = "raw.githubusercontent.com"
REPO_PATH = "/mitre-attack/attack-stix-data/master/"
DOMAINS = frozenset({"enterprise-attack"})
VERSION_RE = re.compile(r"^\d{1,3}\.\d{1,3}$")


class SourceError(ValueError):
    """The bundle could not be obtained or failed an integrity check."""


@dataclass(frozen=True)
class FetchedBundle:
    data: bytes
    sha256: str
    source: str


def max_bytes() -> int:
    return int(getattr(settings, "ATTACK_MAX_BUNDLE_BYTES", 200 * 1024 * 1024))


def bundle_url(domain: str, version: str | None = None) -> str:
    if domain not in DOMAINS:
        raise SourceError(f"unsupported ATT&CK domain: {domain!r}")
    if version:
        if not VERSION_RE.match(version):
            raise SourceError(f"invalid ATT&CK version: {version!r} (expected e.g. 18.1)")
        name = f"{domain}-{version}.json"
    else:
        name = f"{domain}.json"
    return f"https://{ALLOWED_HOST}{REPO_PATH}{domain}/{name}"


ALLOWED_PREFIXES = (f"https://{ALLOWED_HOST}{REPO_PATH}",)


def download(
    domain: str, version: str | None = None, expected_sha256: str | None = None
) -> FetchedBundle:
    url = bundle_url(domain, version)
    try:
        got = fetch(
            url,
            allowed_prefixes=ALLOWED_PREFIXES,
            max_bytes=max_bytes(),
            expected_sha256=expected_sha256,
        )
    except FetchError as exc:
        raise SourceError(str(exc).replace("too large", "bundle too large")) from exc
    return FetchedBundle(data=got.data, sha256=got.sha256, source=got.source)


def read_file(path: str | Path, expected_sha256: str | None = None) -> FetchedBundle:
    p = Path(path)
    if not p.is_file():
        raise SourceError(f"no such file: {p}")
    limit = max_bytes()
    if p.stat().st_size > limit:
        raise SourceError(f"bundle exceeds size limit of {limit} bytes")
    data = p.read_bytes()
    try:
        digest = verify(data, expected_sha256)
    except FetchError as exc:
        raise SourceError(str(exc)) from exc
    return FetchedBundle(data=data, sha256=digest, source=f"file:{p.name}")
