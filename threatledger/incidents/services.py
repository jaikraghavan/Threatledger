"""Incident handling rules, regulatory deadlines (derived) and alerts. Writes are audited."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q, QuerySet
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.permissions import business_unit_scope, can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.audit.models import Action
from threatledger.audit.services import diff, record, snapshot
from threatledger.core.refs import next_ref

from .models import (
    OPEN_STATUSES,
    DeadlineAlert,
    EntryKind,
    Incident,
    IncidentStatus,
    Notification,
    TimelineEntry,
)
from .regimes import REGIMES, Regime, Step


class IncidentError(ValueError):
    """A business rule was violated (shown to the user)."""


NOISE = ("updated_at", "created_at", "updated_by", "created_by")
FIELDS = (
    "title",
    "description",
    "severity",
    "occurred_at",
    "aware_at",
    "business_unit",
    "owner",
    "personal_data_breach",
    "data_subjects_affected",
    "regimes",
    "root_cause",
    "lessons_learned",
)
LINKS = ("assets", "techniques", "risks", "controls", "vendors")
SOON = timedelta(hours=2)


def _changes(before: dict[str, Any], obj: Any) -> dict[str, Any]:
    changes = diff(before, snapshot(obj))
    for noise in NOISE:
        changes.pop(noise, None)
    return changes


def _url(incident: Incident) -> str:
    return reverse("incidents:detail", args=[incident.ref])


def visible_incidents(user: Any) -> QuerySet[Incident]:
    org = current_organisation(user)
    if org is None:
        return Incident.objects.none()
    qs = Incident.objects.filter(organisation=org)
    if not can(user, Cap.VIEW_INCIDENTS):
        return qs.filter(created_by_id=user.pk)  # reporters see what they reported
    scope = business_unit_scope(user)
    if scope is not None:
        qs = qs.filter(
            Q(business_unit__isnull=True) | Q(business_unit_id__in=scope) | Q(owner_id=user.pk)
        )
    return qs


def can_manage(user: Any, incident: Incident | None = None) -> bool:
    if can(user, Cap.MANAGE_INCIDENTS):
        return True
    return incident is not None and incident.owner_id == user.pk and can(user, Cap.VIEW_INCIDENTS)


def _entry(
    incident: Incident, user: Any, kind: str, text: str, url: str = "", at: Any = None
) -> TimelineEntry:
    return TimelineEntry.objects.create(
        incident=incident, author=user, kind=kind, text=text, url=url, at=at or timezone.now()
    )


def _managers(incident: Incident) -> list[Any]:
    from threatledger.work.notify import users_with

    return users_with(incident.organisation, Cap.MANAGE_INCIDENTS, incident.business_unit_id)


def _check_regimes(regimes: Any) -> list[str]:
    regimes = list(regimes or [])
    unknown = set(regimes) - set(REGIMES)
    if unknown:
        raise ValidationError({"regimes": f"Unknown regime: {', '.join(sorted(unknown))}."})
    return sorted(set(regimes))


# ----------------------------------------------------------------------------- reporting
@transaction.atomic
def report_incident(*, user: Any, data: dict[str, Any]) -> Incident:
    if not can(user, Cap.REPORT_INCIDENT):
        raise IncidentError("You cannot report incidents.")
    org = current_organisation(user)
    allowed = {"title", "description", "severity", "occurred_at", "business_unit"}
    if can(user, Cap.MANAGE_INCIDENTS):
        allowed |= set(FIELDS)
    incident = Incident(
        organisation=org,
        created_by=user,
        updated_by=user,
        **{k: v for k, v in data.items() if k in allowed},
    )
    incident.regimes = _check_regimes(incident.regimes)
    incident.ref = next_ref(Incident, org, "INC")
    incident.full_clean(exclude=["organisation", "created_by", "updated_by"])
    incident.save()
    record(Action.CREATE, incident, actor=user, changes=_changes({}, incident))
    _entry(incident, user, EntryKind.STATUS, f"Reported by {user}.")
    from threatledger.work.notify import notify

    notify(
        _managers(incident),
        f"{incident.get_severity_display()} incident reported: {incident.ref} {incident.title}",
        _url(incident),
        actor=user,
    )
    return incident


@transaction.atomic
def update_incident(
    incident: Incident, *, user: Any, data: dict[str, Any], links: dict[str, Any] | None = None
) -> Incident:
    if not can_manage(user, incident):
        raise IncidentError("You cannot edit this incident.")
    before = snapshot(incident)
    for key, value in data.items():
        if key in FIELDS:
            setattr(incident, key, value)
    incident.regimes = _check_regimes(incident.regimes)
    if incident.occurred_at and incident.occurred_at > incident.aware_at:
        raise ValidationError({"occurred_at": "It cannot start after you became aware of it."})
    incident.updated_by = user
    incident.full_clean(exclude=["organisation", "created_by", "updated_by"])
    incident.save()
    changes = _changes(before, incident)
    for name in LINKS:
        if links is None or name not in links:
            continue
        objs = list(links[name])
        if name != "techniques" and any(
            o.organisation_id != incident.organisation_id for o in objs
        ):
            raise IncidentError(f"Unknown {name}.")
        manager = getattr(incident, name)
        old = sorted(str(o) for o in manager.all())
        manager.set(objs)
        new = sorted(str(o) for o in objs)
        if old != new:
            changes[name] = [old, new]
    if changes:
        record(Action.UPDATE, incident, actor=user, changes=changes)
        if "aware_at" in changes:
            _entry(incident, user, EntryKind.NOTE, "Awareness time corrected; deadlines moved.")
    return incident


TRANSITIONS = {
    "reported": ("triage", "false_positive"),
    "triage": ("contained", "false_positive"),
    "contained": ("eradicated", "triage"),
    "eradicated": ("recovered", "contained"),
    "recovered": ("closed", "eradicated"),
    "closed": ("triage",),
    "false_positive": ("triage",),
}


@transaction.atomic
def set_status(incident: Incident, *, user: Any, status: str, note: str = "") -> Incident:
    if not can_manage(user, incident):
        raise IncidentError("You cannot change this incident.")
    if status not in TRANSITIONS.get(incident.status, ()):
        raise IncidentError("That status change is not allowed.")
    if status == IncidentStatus.CLOSED and not (
        incident.root_cause.strip() and incident.lessons_learned.strip()
    ):
        raise IncidentError("Record the root cause and lessons learned before closing.")
    if status == IncidentStatus.CLOSED and pending_obligations(incident):
        raise IncidentError(
            "Some regulatory notifications are still open: file them or mark them not required."
        )
    before = incident.status
    incident.status = status
    incident.closed_at = timezone.now() if status in ("closed", "false_positive") else None
    incident.updated_by = user
    incident.save(update_fields=["status", "closed_at", "updated_by", "updated_at"])
    record(Action.UPDATE, incident, actor=user, changes={"status": [before, status]})
    text = f"Status: {IncidentStatus(before).label} → {incident.get_status_display()}."
    _entry(incident, user, EntryKind.STATUS, f"{text} {note}".strip())
    return incident


@transaction.atomic
def add_entry(
    incident: Incident, *, user: Any, kind: str, text: str, url: str = "", at: Any = None
) -> TimelineEntry:
    if not can_manage(user, incident):
        raise IncidentError("You cannot update this incident.")
    if kind not in (EntryKind.NOTE, EntryKind.ACTION, EntryKind.EVIDENCE):
        raise IncidentError("Unknown entry type.")
    if not text.strip():
        raise IncidentError("Write what happened.")
    if url and not url.lower().startswith(("https://", "http://")):
        raise IncidentError("Only http(s) links are allowed.")
    if at is not None and at > timezone.now() + timedelta(minutes=5):
        raise IncidentError("Timeline entries cannot be in the future.")
    entry = _entry(incident, user, kind, text.strip()[:5000], url.strip()[:1000], at)
    record(Action.UPDATE, incident, actor=user, changes={"timeline": [None, kind]})
    return entry


# ----------------------------------------------------------------------------- regulatory clocks
@dataclass
class Obligation:
    regime: Regime
    step: Step
    due_at: datetime
    filing: Notification | None

    @property
    def state(self) -> str:
        if self.filing is not None:
            return "not_required" if self.filing.not_required else "filed"
        now = timezone.now()
        if self.due_at < now:
            return "overdue"
        if self.due_at - now <= SOON:
            return "due_soon"
        return "pending"

    @property
    def is_open(self) -> bool:
        return self.filing is None

    @property
    def late(self) -> bool:
        f = self.filing
        return f is not None and f.submitted_at is not None and f.submitted_at > self.due_at


def obligations(incident: Incident) -> list[Obligation]:
    filings = {(f.regime, f.step): f for f in incident.filings.all()}
    out = []
    for key in incident.regimes or []:
        regime = REGIMES.get(key)
        if regime is None:
            continue
        for step in regime.steps:
            out.append(
                Obligation(
                    regime, step, incident.aware_at + step.after, filings.get((key, step.key))
                )
            )
    return sorted(out, key=lambda o: o.due_at)


def pending_obligations(incident: Incident) -> list[Obligation]:
    return [o for o in obligations(incident) if o.is_open]


def suggested_regimes(incident: Incident) -> list[str]:
    return [r.key for r in REGIMES.values() if r.personal_data and incident.personal_data_breach]


@transaction.atomic
def record_filing(
    incident: Incident,
    *,
    user: Any,
    regime: str,
    step: str,
    submitted_at: datetime | None = None,
    reference: str = "",
    note: str = "",
    not_required: bool = False,
) -> Notification:
    if not can_manage(user, incident):
        raise IncidentError("You cannot record notifications.")
    reg = REGIMES.get(regime)
    if (
        reg is None
        or regime not in (incident.regimes or [])
        or step not in {s.key for s in reg.steps}
    ):
        raise IncidentError("That notification step does not apply to this incident.")
    if not_required and not note.strip():
        raise IncidentError("Justify why the notification is not required.")
    if not not_required and submitted_at is None:
        submitted_at = timezone.now()
    try:
        filing = Notification.objects.create(
            incident=incident,
            regime=regime,
            step=step,
            submitted_at=None if not_required else submitted_at,
            not_required=not_required,
            reference=reference.strip()[:200],
            note=note.strip(),
            recorded_by=user,
        )
    except IntegrityError as exc:
        raise IncidentError("That step is already recorded.") from exc
    label = next(s.label for s in reg.steps if s.key == step)
    text = (
        f"{reg.label}: {label} recorded as not required ({note.strip()})"
        if not_required
        else f"{reg.label}: {label} submitted{f' (ref {reference})' if reference else ''}."
    )
    _entry(incident, user, EntryKind.NOTIFICATION, text, at=submitted_at)
    record(
        Action.UPDATE,
        incident,
        actor=user,
        changes={"filing": [None, f"{regime}/{step}"], "not_required": [None, not_required]},
    )
    return filing


def send_deadline_alerts() -> int:
    """Notify incident owners and managers when a deadline is near (≤ 2 h) or missed. Each
    step alerts once per stage. Runs every 15 minutes."""
    from threatledger.work.notify import notify

    sent = 0
    for incident in Incident.objects.filter(status__in=OPEN_STATUSES).exclude(regimes=[]):
        for o in pending_obligations(incident):
            stage = {"due_soon": "soon", "overdue": "overdue"}.get(o.state)
            if stage is None:
                continue
            try:
                with transaction.atomic():
                    DeadlineAlert.objects.create(
                        incident=incident, regime=o.regime.key, step=o.step.key, stage=stage
                    )
            except IntegrityError:
                continue
            when = timezone.localtime(o.due_at).strftime("%Y-%m-%d %H:%M")
            verb = "OVERDUE since" if stage == "overdue" else "due by"
            notify(
                [incident.owner, *_managers(incident)],
                f"{incident.ref}: {o.regime.label} – {o.step.label} {verb} {when}",
                _url(incident),
            )
            sent += 1
    return sent
