"""Fetch ATT&CK bundles. Downloads are restricted to the official MITRE repository.

SSRF / integrity controls:
- the URL is built here from a validated domain and version, never taken from user input;
- HTTPS only, to a single allowlisted host, and the final URL after redirects is re-checked;
- the body is size-capped and its SHA-256 is returned (and optionally verified).
"""

from __future__ import annotations

import hashlib
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from django.conf import settings

ALLOWED_HOST = "raw.githubusercontent.com"
REPO_PATH = "/mitre-attack/attack-stix-data/master/"
DOMAINS = frozenset({"enterprise-attack"})
VERSION_RE = re.compile(r"^\d{1,3}\.\d{1,3}$")
CHUNK = 1 << 20


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


def _check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != ALLOWED_HOST:
        raise SourceError(f"refusing to fetch from {parts.scheme}://{parts.hostname}")
    if not parts.path.startswith(REPO_PATH):
        raise SourceError("refusing to fetch outside the MITRE attack-stix-data repository")


def _verify(data: bytes, expected_sha256: str | None) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 and digest.lower() != expected_sha256.strip().lower():
        raise SourceError(f"SHA-256 mismatch: expected {expected_sha256}, got {digest}")
    return digest


def download(
    domain: str, version: str | None = None, expected_sha256: str | None = None
) -> FetchedBundle:
    url = bundle_url(domain, version)
    _check_url(url)
    limit = max_bytes()
    request = urllib.request.Request(  # noqa: S310 - URL is fixed-scheme, allowlisted above
        url, headers={"User-Agent": "ThreatLedger-ATTACK-importer", "Accept": "application/json"}
    )
    try:
        # B310 suppressed: scheme and host are validated by _check_url before and after redirects
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310  # nosec B310
            _check_url(response.geturl())
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > limit:
                raise SourceError(f"bundle too large ({declared} bytes > {limit})")
            chunks: list[bytes] = []
            total = 0
            while chunk := response.read(CHUNK):
                total += len(chunk)
                if total > limit:
                    raise SourceError(f"bundle exceeds size limit of {limit} bytes")
                chunks.append(chunk)
    except SourceError:
        raise
    except Exception as exc:  # network, HTTP 404 for unknown versions, TLS errors
        raise SourceError(f"download failed: {type(exc).__name__}: {exc}") from exc
    data = b"".join(chunks)
    return FetchedBundle(data=data, sha256=_verify(data, expected_sha256), source=url)


def read_file(path: str | Path, expected_sha256: str | None = None) -> FetchedBundle:
    p = Path(path)
    if not p.is_file():
        raise SourceError(f"no such file: {p}")
    limit = max_bytes()
    if p.stat().st_size > limit:
        raise SourceError(f"bundle exceeds size limit of {limit} bytes")
    data = p.read_bytes()
    return FetchedBundle(data=data, sha256=_verify(data, expected_sha256), source=f"file:{p.name}")
