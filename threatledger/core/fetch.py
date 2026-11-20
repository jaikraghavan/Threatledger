"""Guarded HTTPS downloads for data imports (ATT&CK, CTID).

- Only URLs under an explicit allowlisted prefix are fetched (SSRF protection); the final
  URL after redirects is checked again.
- HTTPS only, size-capped while streaming, SHA-256 returned and optionally verified.
"""

from __future__ import annotations

import hashlib
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

CHUNK = 1 << 20
USER_AGENT = "ThreatLedger-data-importer"


class FetchError(ValueError):
    """The resource could not be obtained or failed an integrity check."""


@dataclass(frozen=True)
class Fetched:
    data: bytes
    sha256: str
    source: str


def check_url(url: str, allowed_prefixes: tuple[str, ...]) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise FetchError(f"refusing to fetch non-HTTPS URL {url!r}")
    normalised = f"https://{parts.hostname}{parts.path}"
    if not any(normalised.startswith(p) for p in allowed_prefixes):
        raise FetchError(
            f"refusing to fetch from {parts.scheme}://{parts.hostname} (not allowlisted)"
        )


def verify(data: bytes, expected_sha256: str | None) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 and digest.lower() != expected_sha256.strip().lower():
        raise FetchError(f"SHA-256 mismatch: expected {expected_sha256}, got {digest}")
    return digest


def fetch(
    url: str,
    *,
    allowed_prefixes: tuple[str, ...],
    max_bytes: int,
    expected_sha256: str | None = None,
    timeout: int = 120,
) -> Fetched:
    check_url(url, allowed_prefixes)
    request = urllib.request.Request(  # noqa: S310 - allowlisted HTTPS URL, checked above
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    try:
        # B310 suppressed: scheme and host are validated by check_url before and after redirects
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310  # nosec B310
            check_url(response.geturl(), allowed_prefixes)
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise FetchError(f"too large ({declared} bytes > {max_bytes})")
            chunks: list[bytes] = []
            total = 0
            while chunk := response.read(CHUNK):
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError(f"exceeds size limit of {max_bytes} bytes")
                chunks.append(chunk)
    except FetchError:
        raise
    except Exception as exc:  # network, HTTP errors (404 for unknown versions), TLS
        raise FetchError(f"download failed: {type(exc).__name__}: {exc}") from exc
    data = b"".join(chunks)
    return Fetched(data=data, sha256=verify(data, expected_sha256), source=url)
