"""Per-request context (request id, client IP, user) shared with services and logging.

Stored in ``contextvars`` so it is safe under threads and async, and so service functions
can write audit events without every caller threading the request through.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.conf import settings

if TYPE_CHECKING:
    from django.http import HttpRequest


@dataclass(frozen=True)
class RequestContext:
    request_id: str = ""
    ip: str | None = None
    user: Any = None


_current: ContextVar[RequestContext] = ContextVar("threatledger_request", default=RequestContext())  # noqa: B039

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


def get_context() -> RequestContext:
    return _current.get()


def set_context(ctx: RequestContext) -> Token[RequestContext]:
    return _current.set(ctx)


def reset_context(token: Token[RequestContext]) -> None:
    _current.reset(token)


def new_request_id(incoming: str | None = None) -> str:
    """Accept a well-formed upstream id (from Caddy/load balancer) or mint one."""
    if incoming and _REQUEST_ID_RE.match(incoming):
        return incoming
    return uuid.uuid4().hex


def client_ip(request: HttpRequest) -> str | None:
    raw: str | None = None
    if settings.TRUST_X_FORWARDED_FOR:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            # The proxy appends the real peer address last; earlier entries are client-supplied.
            raw = forwarded.split(",")[-1].strip()
    if not raw:
        raw = request.META.get("REMOTE_ADDR")
    return normalise_ip(raw)


def normalise_ip(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if settings.AUDIT_IP_MODE == "truncated":
        prefix = 24 if ip.version == 4 else 48
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False).network_address)
    return str(ip)
