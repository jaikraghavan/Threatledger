"""Write and verify audit events. All audit writes go through :func:`record`."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from django.db import connection, models, transaction
from django.http import HttpRequest
from django.utils import timezone

from threatledger.core.context import get_context

from .models import GENESIS_HASH, Action, AuditEvent

# Field names whose values never enter the audit log, on any model.
SENSITIVE_FIELD_NAMES = frozenset(
    {"password", "secret", "token", "key", "otp_secret", "totp_secret", "recovery_codes"}
)
# Arbitrary constant identifying the audit-chain advisory lock on PostgreSQL.
_CHAIN_LOCK_ID = 7_310_442_001


def _jsonable(value: Any) -> Any:
    """Normalise to plain JSON types so the stored value hashes identically after reload."""
    return json.loads(json.dumps(value, default=str))


def snapshot(instance: models.Model, fields: Iterable[str] | None = None) -> dict[str, Any]:
    """Concrete field values of ``instance`` minus sensitive ones (FKs as ids)."""
    exclude = set(getattr(instance, "AUDIT_EXCLUDE", ())) | SENSITIVE_FIELD_NAMES
    wanted = set(fields) if fields is not None else None
    data: dict[str, Any] = {}
    for field in instance._meta.concrete_fields:
        if field.name in exclude or (wanted is not None and field.name not in wanted):
            continue
        data[field.name] = field.value_from_object(instance)
    return _jsonable(data)


def diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, list[Any]]:
    """``{field: [before, after]}`` for fields whose value changed."""
    keys = before.keys() | after.keys()
    return {k: [before.get(k), after.get(k)] for k in sorted(keys) if before.get(k) != after.get(k)}


def _actor_label(user: Any) -> str:
    if user is None or not getattr(user, "is_authenticated", False):
        return ""
    return str(user.get_username())[:200]


@transaction.atomic
def record(
    action: Action | str,
    obj: models.Model | None = None,
    *,
    actor: Any = None,
    changes: dict[str, Any] | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    object_repr: str | None = None,
) -> AuditEvent:
    ctx = get_context()
    if actor is None:
        actor = ctx.user
    authenticated = actor is not None and getattr(actor, "is_authenticated", False)

    if obj is not None:
        object_type = object_type or obj._meta.label_lower
        object_id = object_id or str(obj.pk)
        object_repr = object_repr if object_repr is not None else str(obj)

    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s)", [_CHAIN_LOCK_ID])

    last = AuditEvent.objects.order_by("-id").values_list("hash", flat=True).first()
    event = AuditEvent(
        at=timezone.now(),
        actor=actor if authenticated else None,
        actor_label=_actor_label(actor),
        action=str(action),
        object_type=(object_type or "")[:100],
        object_id=(object_id or "")[:64],
        object_repr=(object_repr or "")[:300],
        changes=_jsonable(changes or {}),
        request_id=ctx.request_id,
        ip=ctx.ip,
        prev_hash=last or GENESIS_HASH,
    )
    event.hash = event.compute_hash()
    event.save()
    return event


def record_permission_denied(request: HttpRequest, rule: str) -> AuditEvent:
    return record(
        Action.PERMISSION_DENIED,
        actor=request.user,
        object_type="url",
        object_id="",
        object_repr=request.path[:300],
        changes={"required": rule, "method": request.method},
    )


@dataclass(frozen=True)
class ChainProblem:
    event_id: int
    reason: str


def verify_chain(events: Iterable[AuditEvent]) -> list[ChainProblem]:
    """Check each event's hash and its link to the previous one. Events in id order."""
    problems: list[ChainProblem] = []
    expected_prev = GENESIS_HASH
    for event in events:
        if event.prev_hash != expected_prev:
            problems.append(ChainProblem(event.pk, "broken link (event missing or reordered)"))
        if event.compute_hash() != event.hash:
            problems.append(ChainProblem(event.pk, "content does not match hash (modified)"))
        expected_prev = event.hash
    return problems
