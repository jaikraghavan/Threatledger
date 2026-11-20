"""Immutable, hash-chained audit log.

Defence in depth:
1. ``save()`` refuses updates and ``delete()`` always raises.
2. The queryset refuses ``update()`` / ``delete()`` / ``bulk_update()``.
3. On PostgreSQL a trigger rejects UPDATE, DELETE and TRUNCATE (migration 0002).
4. Each row stores ``hash = sha256(prev_hash || canonical row)``; ``manage.py audit_verify``
   detects edits made by anyone who bypasses 1-3 (e.g. a DBA dropping the trigger).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from django.conf import settings
from django.db import models


class AuditImmutableError(Exception):
    """Raised on any attempt to modify or remove an audit event."""


class Action(models.TextChoices):
    CREATE = "create", "Create"
    UPDATE = "update", "Update"
    DELETE = "delete", "Delete"
    LOGIN = "login", "Login"
    LOGOUT = "logout", "Logout"
    LOGIN_FAILED = "login_failed", "Login failed"
    PERMISSION_DENIED = "permission_denied", "Permission denied"
    EXPORT = "export", "Export"
    IMPORT = "import", "Import"
    SYSTEM = "system", "System"


class AuditEventQuerySet(models.QuerySet["AuditEvent"]):
    def update(self, **kwargs: Any) -> int:
        raise AuditImmutableError("Audit events cannot be updated")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise AuditImmutableError("Audit events cannot be deleted")

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise AuditImmutableError("Audit events cannot be updated")


GENESIS_HASH = "0" * 64


class AuditEvent(models.Model):
    at = models.DateTimeField(db_index=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,  # users with history are deactivated, never deleted
        related_name="audit_events",
    )
    actor_label = models.CharField(max_length=200, blank=True)
    action = models.CharField(max_length=32, choices=Action.choices, db_index=True)
    object_type = models.CharField(max_length=100, blank=True, db_index=True)
    object_id = models.CharField(max_length=64, blank=True, db_index=True)
    object_repr = models.CharField(max_length=300, blank=True)
    changes = models.JSONField(default=dict, blank=True)
    request_id = models.CharField(max_length=64, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    prev_hash = models.CharField(max_length=64)
    hash = models.CharField(max_length=64, unique=True)

    objects = AuditEventQuerySet.as_manager()

    class Meta:
        ordering = ["-id"]
        default_permissions = ("view",)

    def __str__(self) -> str:
        who = self.actor_label or "system"
        return f"{self.at:%Y-%m-%d %H:%M:%S} {who} {self.action} {self.object_repr}"

    # -- immutability -------------------------------------------------------------
    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise AuditImmutableError("Audit events cannot be updated")
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise AuditImmutableError("Audit events cannot be deleted")

    # -- hash chain ---------------------------------------------------------------
    def canonical(self) -> str:
        return json.dumps(
            {
                "at": self.at.isoformat(),
                "actor_id": self.actor_id,
                "actor_label": self.actor_label,
                "action": self.action,
                "object_type": self.object_type,
                "object_id": self.object_id,
                "object_repr": self.object_repr,
                "changes": self.changes,
                "request_id": self.request_id,
                "ip": self.ip,
                "prev_hash": self.prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def compute_hash(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()
