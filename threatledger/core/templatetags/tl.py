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


# Badge colours for workflow states across apps (Tailwind scans this file for class names).
_TONES = {
    "green": "bg-green-100 text-green-800",
    "amber": "bg-amber-100 text-amber-800",
    "red": "bg-red-100 text-red-800",
    "blue": "bg-brand-100 text-brand-700",
    "slate": "bg-slate-100 text-slate-700",
    "purple": "bg-purple-100 text-purple-800",
}
_TONE_OF = {
    # audits
    "planned": "slate",
    "in_progress": "blue",
    "in_review": "purple",
    "closed": "green",
    "compliant": "green",
    "partial": "amber",
    "non_compliant": "red",
    "not_applicable": "slate",
    "not_assessed": "slate",
    # findings
    "open": "red",
    "resolved": "purple",
    "low": "slate",
    "medium": "amber",
    "high": "red",
    "critical": "red",
    # exceptions / policies
    "requested": "amber",
    "approved": "green",
    "rejected": "slate",
    "revoked": "slate",
    "expired": "red",
    "draft": "slate",
    "superseded": "slate",
    "published": "green",
    "retired": "slate",
    "review_overdue": "red",
}


@register.filter
def tone(value: Any) -> str:
    """CSS classes for a status/severity badge, e.g. ``<span class="badge {{ s|tone }}">``."""
    return _TONES[_TONE_OF.get(str(value), "slate")]
