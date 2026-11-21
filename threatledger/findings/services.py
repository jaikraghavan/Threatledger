"""Finding and exception business rules. All writes go through here (permissions + audit)."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q, QuerySet
from django.utils import timezone

from threatledger.accounts.permissions import business_unit_scope, can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.audit.models import Action
from threatledger.audit.services import diff, record, snapshot
from threatledger.audits.models import Audit
from threatledger.controls.models import Control
from threatledger.core.refs import next_ref
from threatledger.frameworks.models import Requirement

from .models import (
    DEFAULT_DUE_DAYS,
    MAX_EXCEPTION_DAYS,
    ExceptionStatus,
    Finding,
    FindingStatus,
    SecurityException,
)


class FindingError(ValueError):
    """A business rule was violated (shown to the user)."""


FINDING_FIELDS = (
    "title",
    "description",
    "severity",
    "owner",
    "due_on",
    "business_unit",
    "audit",
    "requirement",
    "control",
    "risk",
    "remediation",
)
# What the owner of a finding may change (remediation progress, not the finding itself).
OWNER_FIELDS = frozenset({"remediation"})
NOISE = ("updated_at", "created_at", "updated_by", "created_by")


def _changes(before: dict[str, Any], obj: Any) -> dict[str, Any]:
    changes = diff(before, snapshot(obj))
    for noise in NOISE:
        changes.pop(noise, None)
    return changes


def _scoped(qs: QuerySet[Any], user: Any) -> QuerySet[Any]:
    scope = business_unit_scope(user)
    if scope is not None:
        qs = qs.filter(Q(business_unit__isnull=True) | Q(business_unit_id__in=scope))
    return qs


def _check_scope(user: Any, business_unit_id: int | None) -> None:
    scope = business_unit_scope(user)
    if scope is not None and business_unit_id is not None and business_unit_id not in scope:
        raise FindingError("This business unit is outside your scope.")


# ----------------------------------------------------------------------------- findings
def visible_findings(user: Any) -> QuerySet[Finding]:
    org = current_organisation(user)
    if org is None or not can(user, Cap.VIEW_FINDINGS):
        return Finding.objects.none()
    return _scoped(Finding.objects.filter(organisation=org), user)


def can_raise(user: Any) -> bool:
    return can(user, Cap.RAISE_FINDINGS)


def can_edit(user: Any, finding: Finding) -> bool:
    return finding.is_open and can(user, Cap.EDIT_FINDINGS)


def can_update(user: Any, finding: Finding) -> bool:
    """Owner remediation updates (or any editor)."""
    return finding.is_open and can(user, Cap.UPDATE_OWN_FINDING, finding)


def _validate_links(user: Any, data: dict[str, Any]) -> None:
    org = current_organisation(user)
    audit: Audit | None = data.get("audit")
    requirement: Requirement | None = data.get("requirement")
    control: Control | None = data.get("control")
    if audit is not None:
        if audit.organisation_id != org.pk:
            raise FindingError("Unknown audit.")
        if requirement is not None and requirement.framework_id != audit.framework_id:
            raise ValidationError({"requirement": "Requirement is not part of the audit."})
    if control is not None and control.organisation_id != org.pk:
        raise FindingError("Unknown control.")
    risk = data.get("risk")
    if risk is not None and risk.organisation_id != org.pk:
        raise FindingError("Unknown risk.")
    bu = data.get("business_unit")
    _check_scope(user, bu.pk if bu else None)


@transaction.atomic
def create_finding(*, user: Any, data: dict[str, Any]) -> Finding:
    if not can_raise(user):
        raise FindingError("You cannot raise findings.")
    data = {k: v for k, v in data.items() if k in FINDING_FIELDS}
    audit: Audit | None = data.get("audit")
    if audit is not None and audit.is_closed:
        raise FindingError("This audit is closed.")
    if data.get("business_unit") is None:
        source = audit or data.get("risk")
        data["business_unit"] = getattr(source, "business_unit", None)
    _validate_links(user, data)
    if not data.get("due_on"):
        days = DEFAULT_DUE_DAYS.get(data.get("severity") or "medium", 90)
        data["due_on"] = timezone.localdate() + timedelta(days=days)
    org = current_organisation(user)
    finding = Finding(organisation=org, created_by=user, updated_by=user, **data)
    finding.ref = next_ref(Finding, org, "F")
    finding.full_clean(exclude=["organisation", "created_by", "updated_by"])
    finding.save()
    record(Action.CREATE, finding, actor=user, changes=_changes({}, finding))
    return finding


@transaction.atomic
def update_finding(finding: Finding, *, user: Any, data: dict[str, Any]) -> Finding:
    if not can_update(user, finding):
        raise FindingError("You cannot update this finding.")
    data = {k: v for k, v in data.items() if k in FINDING_FIELDS}
    if not can_edit(user, finding) and set(data) - OWNER_FIELDS:
        raise FindingError("Finding owners may only update the remediation plan and status.")
    if set(data) - OWNER_FIELDS:
        merged = {f: getattr(finding, f) for f in FINDING_FIELDS} | data
        _validate_links(user, merged)
    before = snapshot(finding)
    for key, value in data.items():
        setattr(finding, key, value)
    finding.updated_by = user
    finding.full_clean(exclude=["organisation", "created_by", "updated_by"])
    finding.save()
    changes = _changes(before, finding)
    if changes:
        record(Action.UPDATE, finding, actor=user, changes=changes)
    return finding


def finding_transitions(user: Any, finding: Finding) -> list[str]:
    """Statuses ``user`` may move ``finding`` to."""
    s = finding.status
    out: list[str] = []
    if s in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS) and can_update(user, finding):
        out += [x for x in (FindingStatus.IN_PROGRESS, FindingStatus.RESOLVED) if x != s]
        if s == FindingStatus.IN_PROGRESS:
            out.insert(0, FindingStatus.OPEN)
    verifier = can(user, Cap.RAISE_FINDINGS) or can(user, Cap.EDIT_FINDINGS)
    if s == FindingStatus.RESOLVED and verifier and finding.owner_id != user.pk:
        out += [FindingStatus.CLOSED, FindingStatus.IN_PROGRESS]
    if s == FindingStatus.CLOSED and can(user, Cap.EDIT_FINDINGS):
        out.append(FindingStatus.OPEN)
    return out


@transaction.atomic
def set_finding_status(finding: Finding, *, user: Any, status: str, note: str = "") -> Finding:
    if status not in finding_transitions(user, finding):
        if (
            status == FindingStatus.CLOSED
            and finding.status == FindingStatus.RESOLVED
            and finding.owner_id == user.pk
        ):
            raise FindingError(
                "Segregation of duties: someone other than the owner must verify and close it."
            )
        raise FindingError("That status change is not allowed.")
    before = snapshot(finding)
    now = timezone.now()
    if status == FindingStatus.RESOLVED:
        finding.resolved_at = now
    if status == FindingStatus.CLOSED:
        finding.closed_at, finding.closed_by = now, user
    if status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS):
        finding.resolved_at = None
        finding.closed_at, finding.closed_by = None, None
    finding.status = status
    finding.updated_by = user
    finding.save()
    changes = _changes(before, finding)
    if note.strip():
        changes["note"] = [None, note.strip()[:500]]
    record(Action.UPDATE, finding, actor=user, changes=changes)
    return finding


# ----------------------------------------------------------------------------- exceptions
def visible_exceptions(user: Any) -> QuerySet[SecurityException]:
    org = current_organisation(user)
    if org is None or not can(user, Cap.VIEW_FINDINGS):
        return SecurityException.objects.none()
    return _scoped(SecurityException.objects.filter(organisation=org), user)


def active_exceptions(org: Any) -> QuerySet[SecurityException]:
    return SecurityException.objects.filter(
        organisation=org, status=ExceptionStatus.APPROVED, expires_on__gte=timezone.localdate()
    )


EXCEPTION_FIELDS = (
    "title",
    "justification",
    "compensating_measures",
    "business_unit",
    "risk",
    "finding",
    "owner",
    "expires_on",
)


@transaction.atomic
def request_exception(
    *,
    user: Any,
    data: dict[str, Any],
    requirements: Iterable[Requirement] = (),
    controls: Iterable[Control] = (),
) -> SecurityException:
    if not can(user, Cap.REQUEST_EXCEPTION):
        raise FindingError("You cannot request exceptions.")
    org = current_organisation(user)
    data = {k: v for k, v in data.items() if k in EXCEPTION_FIELDS}
    requirements, controls = list(requirements), list(controls)
    if not requirements and not controls:
        raise FindingError("Name at least one requirement or control the exception applies to.")
    if any(c.organisation_id != org.pk for c in controls):
        raise FindingError("Unknown control.")
    for key in ("risk", "finding"):
        obj = data.get(key)
        if obj is not None and obj.organisation_id != org.pk:
            raise FindingError(f"Unknown {key}.")
    bu = data.get("business_unit")
    _check_scope(user, bu.pk if bu else None)
    today = timezone.localdate()
    expires = data.get("expires_on")
    if expires is None or expires <= today or expires > today + timedelta(days=MAX_EXCEPTION_DAYS):
        raise ValidationError({"expires_on": "Expiry must be in the future and within a year."})
    if not (data.get("justification") or "").strip():
        raise ValidationError({"justification": "A justification is required."})
    exc = SecurityException(organisation=org, created_by=user, updated_by=user, **data)
    exc.owner = exc.owner or user
    exc.ref = next_ref(SecurityException, org, "EX")
    exc.full_clean(exclude=["organisation", "created_by", "updated_by"])
    exc.save()
    exc.requirements.set(requirements)
    exc.controls.set(controls)
    changes = _changes({}, exc)
    changes["requirements"] = [None, sorted(r.ref for r in requirements)]
    changes["controls"] = [None, sorted(c.ref for c in controls)]
    record(Action.CREATE, exc, actor=user, changes=changes)
    return exc


@transaction.atomic
def decide_exception(
    exc: SecurityException, *, user: Any, approve: bool, note: str = ""
) -> SecurityException:
    if not can(user, Cap.APPROVE_EXCEPTION):
        raise FindingError("You cannot approve exceptions.")
    if exc.status != ExceptionStatus.REQUESTED:
        raise FindingError("This request has already been decided.")
    if exc.created_by_id == user.pk:
        raise FindingError("Segregation of duties: you cannot decide your own request.")
    _check_scope(user, exc.business_unit_id)
    if approve and exc.expires_on < timezone.localdate():
        raise FindingError("The requested expiry date has passed; ask for a new request.")
    before = snapshot(exc)
    exc.status = ExceptionStatus.APPROVED if approve else ExceptionStatus.REJECTED
    exc.decided_by, exc.decided_at = user, timezone.now()
    exc.decision_note = note.strip()[:500]
    exc.updated_by = user
    exc.save()
    record(Action.UPDATE, exc, actor=user, changes=_changes(before, exc))
    return exc


@transaction.atomic
def revoke_exception(exc: SecurityException, *, user: Any, note: str) -> SecurityException:
    if not can(user, Cap.APPROVE_EXCEPTION):
        raise FindingError("You cannot revoke exceptions.")
    if exc.status != ExceptionStatus.APPROVED:
        raise FindingError("Only approved exceptions can be revoked.")
    if not note.strip():
        raise FindingError("Give a reason for revoking.")
    before = snapshot(exc)
    exc.status = ExceptionStatus.REVOKED
    exc.decision_note = note.strip()[:500]
    exc.updated_by = user
    exc.save()
    record(Action.UPDATE, exc, actor=user, changes=_changes(before, exc))
    return exc
