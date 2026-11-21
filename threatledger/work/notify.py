"""In-app notifications. Other apps call ``notify()`` from their services (lazy import)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from threatledger.accounts.roles import ROLE_CAPABILITIES, Cap

from .models import Notification


def notify(recipients: Iterable[Any], message: str, url: str = "", *, actor: Any = None) -> int:
    """Notify each distinct active recipient except the actor. Returns how many were created."""
    seen: set[int] = set()
    rows = []
    actor_id = getattr(actor, "pk", None)
    for user in recipients:
        if user is None or not getattr(user, "is_active", False):
            continue
        if user.pk in seen or user.pk == actor_id:
            continue
        seen.add(user.pk)
        rows.append(
            Notification(
                recipient=user,
                actor=actor if actor_id else None,
                message=message[:300],
                url=url[:500],
            )
        )
    Notification.objects.bulk_create(rows)
    return len(rows)


def users_with(org: Any, cap: Cap, business_unit_id: int | None = None) -> list[Any]:
    """Active members whose role grants ``cap`` (and whose BU scope covers the unit, if given)."""
    from threatledger.accounts.models import Membership
    from threatledger.accounts.permissions import business_unit_scope

    roles = [role for role, caps in ROLE_CAPABILITIES.items() if cap in caps]
    members = Membership.objects.filter(
        organisation=org, role__in=roles, user__is_active=True
    ).select_related("user")
    out = []
    for m in members:
        if business_unit_id is not None:
            scope = business_unit_scope(m.user)
            if scope is not None and business_unit_id not in scope:
                continue
        out.append(m.user)
    return out


def unread_count(user: Any) -> int:
    return Notification.objects.filter(recipient=user, read_at__isnull=True).count()
