from __future__ import annotations

from django.contrib.admin import AdminSite
from django.http import HttpRequest


def restrict_admin_to_superusers(site: AdminSite) -> None:
    """The Django admin is a break-glass tool for superusers only.

    Everyday administration happens in the app, where ``can()`` applies. Keeping the admin
    superuser-only means there is no second permission system to keep in sync.
    """

    def has_permission(request: HttpRequest) -> bool:
        user = request.user
        return bool(user.is_active and user.is_superuser)

    site.has_permission = has_permission  # type: ignore[method-assign]
    site.site_header = "ThreatLedger administration"
    site.site_title = "ThreatLedger admin"
