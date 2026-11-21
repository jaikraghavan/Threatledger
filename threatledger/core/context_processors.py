from __future__ import annotations

from typing import Any

from django.conf import settings
from django.http import HttpRequest
from django.urls import reverse

from threatledger.accounts.permissions import capabilities, get_role
from threatledger.accounts.roles import Cap

# (label, url name, capability, icon). Later phases append entries here.
NAV_ITEMS: list[tuple[str, str, Cap, str]] = [
    ("Dashboard", "core:home", Cap.VIEW_DASHBOARD, "home"),
    ("Risk register", "risks:list", Cap.VIEW_RISKS, "list"),
    ("Controls", "controls:list", Cap.VIEW_CONTROLS, "shield"),
    ("Compliance", "frameworks:list", Cap.VIEW_FRAMEWORKS, "check"),
    ("Audits", "audits:list", Cap.VIEW_AUDITS, "clipboard"),
    ("Findings", "findings:list", Cap.VIEW_FINDINGS, "flag"),
    ("Policies", "policies:list", Cap.VIEW_POLICIES, "book"),
    ("ATT&CK coverage", "coverage:matrix", Cap.VIEW_ATTACK, "grid"),
    ("Techniques", "attack:technique_list", Cap.VIEW_ATTACK, "grid"),
    ("Threat groups", "attack:group_list", Cap.VIEW_ATTACK, "users"),
    ("Audit log", "audit:list", Cap.VIEW_AUDIT_LOG, "log"),
    ("Risk matrix", "risks:matrix", Cap.MANAGE_SETTINGS, "settings"),
    ("Business units", "org:units", Cap.MANAGE_SETTINGS, "settings"),
    ("ATT&CK data", "attack:data", Cap.RUN_IMPORTS, "database"),
]


def navigation(request: HttpRequest) -> dict[str, Any]:
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        return {
            "tl_version": settings.THREATLEDGER_VERSION,
            "tl_source_url": settings.SOURCE_CODE_URL,
        }
    caps = capabilities(user)
    items = []
    for label, url_name, cap, icon in NAV_ITEMS:
        if cap in caps:
            url = reverse(url_name)
            items.append({"label": label, "url": url, "icon": icon, "active": request.path == url})
    role = get_role(user)
    return {
        "nav_items": items,
        "tl_role": role.label if role else "No role",
        "tl_version": settings.THREATLEDGER_VERSION,
        "tl_source_url": settings.SOURCE_CODE_URL,
    }
