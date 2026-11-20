from __future__ import annotations

from typing import Any

from django import template

from threatledger.accounts.permissions import can as _can
from threatledger.accounts.roles import Cap

register = template.Library()


@register.filter
def can(user: Any, capability: str) -> bool:
    """``{% if request.user|can:"edit_risks" %}``. Unknown capability names are False."""
    try:
        cap = Cap(capability)
    except ValueError:
        return False
    return _can(user, cap)


@register.filter
def get_item(mapping: Any, key: Any) -> Any:
    """``{{ counts|get_item:status }}`` dictionary lookup."""
    try:
        return mapping.get(key)
    except AttributeError:
        return None


@register.filter
def expires_soon(evidence: Any, days: int = 30) -> bool:
    return bool(evidence.expires_within(int(days)))


@register.filter
def chart_rows(data: dict[str, Any]) -> list[list[Any]]:
    """Chart series -> table rows: [[label, value1, value2, ...], ...] for accessible fallbacks."""
    datasets = data.get("datasets", [])
    return [
        [label, *[(ds["data"][i] if i < len(ds["data"]) else None) for ds in datasets]]
        for i, label in enumerate(data.get("labels", []))
    ]
