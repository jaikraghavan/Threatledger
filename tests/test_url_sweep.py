"""Deny-by-default guard: every routed view must declare its access rule.

Fails the build if someone adds a URL whose view has no ``tl_access`` declaration.
Only the Django admin (superuser-only, see core/admin_site.py) is exempt.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from django.urls import URLPattern, URLResolver, get_resolver

from threatledger.accounts.permissions import AUTHENTICATED, PUBLIC
from threatledger.accounts.roles import Cap

EXEMPT_NAMESPACES = {"admin"}
# Public endpoints are reviewed explicitly: adding one should be a conscious decision.
ALLOWED_PUBLIC = {
    "accounts:login",
    "accounts:logout",
    "core:healthz",
    "core:readyz",
    # Phase 10: external questionnaire respondents (secret, expiring, hashed link tokens).
    "respond:start",
    "respond:form",
}


def _walk(patterns: list[Any], namespace: str = "") -> Iterator[tuple[str, Any]]:
    for p in patterns:
        if isinstance(p, URLResolver):
            ns = p.namespace or ""
            if ns in EXEMPT_NAMESPACES:
                continue
            child_ns = f"{namespace}:{ns}".strip(":") if ns else namespace
            yield from _walk(p.url_patterns, child_ns)
        elif isinstance(p, URLPattern):
            name = f"{namespace}:{p.name}".strip(":") if p.name else str(p.pattern)
            yield name, p.callback


def _rule(callback: Any) -> Any:
    for holder in (callback, getattr(callback, "view_class", None), getattr(callback, "cls", None)):
        rule = getattr(holder, "tl_access", None)
        if rule is not None:
            return rule
    return None


def test_every_view_declares_access():
    undeclared = [name for name, cb in _walk(get_resolver().url_patterns) if _rule(cb) is None]
    assert undeclared == [], f"Views without tl_access: {undeclared}"


def test_access_rules_are_valid():
    for name, cb in _walk(get_resolver().url_patterns):
        rule = _rule(cb)
        assert rule in (PUBLIC, AUTHENTICATED) or isinstance(rule, Cap), name


def test_public_views_are_reviewed():
    public = {name for name, cb in _walk(get_resolver().url_patterns) if _rule(cb) == PUBLIC}
    assert public == ALLOWED_PUBLIC
