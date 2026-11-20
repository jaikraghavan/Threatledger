"""Risk register business rules. All writes go through here (audit + history in one place)."""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.db.models import QuerySet
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.permissions import business_unit_scope, can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.attack.models import Mitigation, MitigationTechnique, Technique
from threatledger.audit.models import Action
from threatledger.audit.services import diff, record, snapshot
from threatledger.controls.models import Control, ControlMitigation
from threatledger.coverage.selectors import controls_by_technique
from threatledger.org.models import Organisation

from .models import (
    SCORE_FIELDS,
    Asset,
    Risk,
    RiskAcceptance,
    RiskControl,
    RiskMatrix,
    RiskQuerySet,
    RiskScoreHistory,
    RiskStatus,
    RiskTechnique,
    Treatment,
)

logger = logging.getLogger(__name__)
_REF_RE = re.compile(r"^R-(\d+)$")
REMINDER_WINDOW_DAYS = 14
REMINDER_REPEAT_DAYS = 7


class RiskError(ValueError):
    """A business rule was violated (shown to the user)."""


# ----------------------------------------------------------------------------- scoping
def visible_risks(user: Any) -> RiskQuerySet:
    org = current_organisation(user)
    if org is None or not can(user, Cap.VIEW_RISKS):
        return Risk.objects.none()
    qs = Risk.objects.filter(organisation=org)
    scope = business_unit_scope(user)
    if scope is not None:
        qs = qs.filter(business_unit_id__in=scope)
    return qs


def visible_assets(user: Any) -> QuerySet[Asset]:
    org = current_organisation(user)
    if org is None or not can(user, Cap.VIEW_RISKS):
        return Asset.objects.none()
    qs = Asset.objects.filter(organisation=org)
    scope = business_unit_scope(user)
    if scope is not None:
        qs = qs.filter(business_unit_id__in=scope)
    return qs


def can_edit_risk(user: Any, risk: Risk) -> bool:
    if not can(user, Cap.EDIT_RISKS) or risk.archived_at is not None:
        return False
    scope = business_unit_scope(user)
    return scope is None or risk.business_unit_id in scope


def check_business_unit(user: Any, business_unit_id: int | None) -> None:
    scope = business_unit_scope(user)
    if scope is not None and business_unit_id not in scope:
        raise RiskError("You can only assign business units you are scoped to.")


# ----------------------------------------------------------------------------- validation
def validate_scores(matrix: RiskMatrix, values: dict[str, Any]) -> None:
    errors: dict[str, str] = {}
    for field in SCORE_FIELDS:
        v = values.get(field)
        if not isinstance(v, int) or not (1 <= v <= matrix.size):
            errors[field] = f"Choose a value from 1 to {matrix.size}."
    if not errors:
        inherent = values["inherent_likelihood"] * values["inherent_impact"]
        residual = values["residual_likelihood"] * values["residual_impact"]
        if residual > inherent:
            errors["residual_impact"] = (
                f"Residual score ({residual}) cannot exceed inherent score ({inherent}): "
                "controls reduce risk, they don't increase it."
            )
    if errors:
        raise ValidationError(errors)


def next_ref(org: Organisation) -> str:
    """Next R-nnnn reference. Locks the organisation row so concurrent creates don't clash."""
    Organisation.objects.select_for_update().filter(pk=org.pk).first()
    highest = 0
    for ref in Risk.objects.filter(organisation=org).values_list("ref", flat=True):
        m = _REF_RE.match(ref)
        if m:
            highest = max(highest, int(m.group(1)))
    return f"R-{highest + 1:04d}"


def _audit_snapshot(risk: Risk) -> dict[str, Any]:
    data = snapshot(risk, _audited_fields())
    data["assets"] = sorted(risk.assets.values_list("name", flat=True)) if risk.pk else []
    return data


def _audited_fields() -> list[str]:
    return [
        f.name
        for f in Risk._meta.concrete_fields
        if f.name not in {"created_at", "updated_at", "last_reminder_on", "id"}
    ]


def _history(risk: Risk, user: Any, reason: str) -> None:
    RiskScoreHistory.objects.create(
        risk=risk, reason=reason[:500], changed_by=user if user else None, **risk.scores()
    )


# ----------------------------------------------------------------------------- CRUD
@transaction.atomic
def create_risk(
    *, user: Any, data: dict[str, Any], assets: Iterable[Asset] = (), reason: str = ""
) -> Risk:
    org = current_organisation(user)
    if org is None:
        raise RiskError("No organisation configured.")
    check_business_unit(user, getattr(data.get("business_unit"), "pk", None))
    validate_scores(RiskMatrix.for_org(org), data)
    risk = Risk(organisation=org, created_by=user, updated_by=user, **data)
    risk.ref = next_ref(org)
    risk.save()
    risk.assets.set(list(assets))
    _history(risk, user, reason or "Initial assessment")
    record(Action.CREATE, risk, actor=user, changes=diff({}, _audit_snapshot(risk)))
    return risk


@transaction.atomic
def update_risk(
    risk: Risk,
    *,
    user: Any,
    data: dict[str, Any],
    assets: Iterable[Asset] | None = None,
    reason: str = "",
) -> Risk:
    if not can_edit_risk(user, risk):
        raise RiskError("You cannot edit this risk.")
    if "business_unit" in data:
        check_business_unit(user, getattr(data["business_unit"], "pk", None))
    before = _audit_snapshot(risk)
    old_scores = risk.scores()
    for key, value in data.items():
        setattr(risk, key, value)
    validate_scores(RiskMatrix.for_org(risk.organisation), risk.scores())
    risk.updated_by = user
    risk.save()
    if assets is not None:
        risk.assets.set(list(assets))
    if risk.scores() != old_scores:
        _history(risk, user, reason)
    changes = diff(before, _audit_snapshot(risk))
    changes.pop("updated_by", None)
    if changes:
        if reason:
            changes["reason"] = [None, reason[:500]]
        record(Action.UPDATE, risk, actor=user, changes=changes)
    return risk


@transaction.atomic
def archive_risk(risk: Risk, *, user: Any) -> Risk:
    if not can_edit_risk(user, risk):
        raise RiskError("You cannot archive this risk.")
    risk.archived_at = timezone.now()
    risk.updated_by = user
    risk.save(update_fields=["archived_at", "updated_by", "updated_at"])
    record(Action.UPDATE, risk, actor=user, changes={"archived": [False, True]})
    return risk


@transaction.atomic
def restore_risk(risk: Risk, *, user: Any) -> Risk:
    if not can(user, Cap.EDIT_RISKS) or risk.archived_at is None:
        raise RiskError("You cannot restore this risk.")
    check_business_unit(user, risk.business_unit_id)
    risk.archived_at = None
    risk.updated_by = user
    risk.save(update_fields=["archived_at", "updated_by", "updated_at"])
    record(Action.UPDATE, risk, actor=user, changes={"archived": [True, False]})
    return risk


# ----------------------------------------------------------------------------- assets
@transaction.atomic
def save_asset(asset: Asset, *, user: Any) -> Asset:
    if not can(user, Cap.EDIT_RISKS):
        raise RiskError("You cannot edit assets.")
    check_business_unit(user, asset.business_unit_id)
    creating = asset.pk is None
    before = {} if creating else snapshot(Asset.objects.get(pk=asset.pk))
    if creating:
        asset.organisation = current_organisation(user)
        asset.created_by = user
    asset.updated_by = user
    asset.full_clean(exclude=["organisation", "created_by", "updated_by"])
    asset.save()
    changes = diff(before, snapshot(asset))
    for noise in ("updated_at", "created_at", "updated_by"):
        changes.pop(noise, None)
    if changes:
        record(Action.CREATE if creating else Action.UPDATE, asset, actor=user, changes=changes)
    return asset


# ----------------------------------------------------------------------------- techniques
def _require_edit(user: Any, risk: Risk) -> None:
    if not can_edit_risk(user, risk):
        raise RiskError("You cannot edit this risk.")


@transaction.atomic
def link_technique(risk: Risk, technique: Technique, *, user: Any, rationale: str = "") -> bool:
    _require_edit(user, risk)
    if not technique.is_active:
        raise RiskError(f"{technique.attack_id} is revoked or deprecated; link its replacement.")
    _, created = RiskTechnique.objects.get_or_create(
        risk=risk, technique=technique, defaults={"rationale": rationale[:500]}
    )
    if created:
        record(Action.UPDATE, risk, actor=user, changes={"technique_added": [None, str(technique)]})
    return created


@transaction.atomic
def unlink_technique(risk: Risk, link: RiskTechnique, *, user: Any) -> None:
    _require_edit(user, risk)
    if link.risk_id != risk.pk:
        raise RiskError("That technique is not linked to this risk.")
    label = str(link.technique)
    link.delete()
    record(Action.UPDATE, risk, actor=user, changes={"technique_removed": [label, None]})


@transaction.atomic
def remap_revoked_technique(risk: Risk, link: RiskTechnique, *, user: Any) -> Technique:
    """Move a mapping from a revoked technique to MITRE's replacement (one click)."""
    _require_edit(user, risk)
    old = link.technique
    replacement = old.replacement() if old.is_revoked else None
    if link.risk_id != risk.pk or replacement is None or not replacement.is_active:
        raise RiskError("No active replacement is available for this technique.")
    if RiskTechnique.objects.filter(risk=risk, technique=replacement).exists():
        link.delete()
    else:
        link.technique = replacement
        link.save(update_fields=["technique"])
    record(
        Action.UPDATE,
        risk,
        actor=user,
        changes={"technique_remapped": [str(old), str(replacement)]},
    )
    return replacement


# ----------------------------------------------------------------------------- controls
@transaction.atomic
def link_control(risk: Risk, control: Control, *, user: Any, note: str = "") -> bool:
    _require_edit(user, risk)
    if control.organisation_id != risk.organisation_id or control.archived_at is not None:
        raise RiskError("That control is not available.")
    _, created = RiskControl.objects.get_or_create(
        risk=risk, control=control, defaults={"note": note[:500]}
    )
    if created:
        record(Action.UPDATE, risk, actor=user, changes={"control_added": [None, str(control)]})
    return created


@transaction.atomic
def unlink_control(risk: Risk, link: RiskControl, *, user: Any) -> None:
    _require_edit(user, risk)
    if link.risk_id != risk.pk:
        raise RiskError("That control is not linked to this risk.")
    label = str(link.control)
    link.delete()
    record(Action.UPDATE, risk, actor=user, changes={"control_removed": [label, None]})


@dataclass(frozen=True)
class Suggestion:
    control: Control
    techniques: tuple[Technique, ...]  # risk techniques this control addresses


def suggested_controls(risk: Risk) -> list[Suggestion]:
    """Controls mapped (directly or via mitigation) to the risk's techniques but not yet
    linked, ranked by how many of the risk's techniques they address, then by status."""
    techniques = {t.pk: t for t in risk.techniques.all()}
    if not techniques:
        return []
    graph = controls_by_technique(set(techniques), risk.organisation_id)
    linked = set(risk.controls.values_list("pk", flat=True))
    hits: dict[int, list[Technique]] = defaultdict(list)
    for tid, control_ids in graph.items():
        for cid in control_ids - linked:
            hits[cid].append(techniques[tid])
    controls = Control.objects.live().in_bulk(hits.keys())
    rank = {"implemented": 0, "partial": 1, "planned": 2, "not_implemented": 3}
    suggestions = [
        Suggestion(controls[cid], tuple(sorted(ts, key=lambda t: t.attack_id)))
        for cid, ts in hits.items()
        if cid in controls
    ]
    suggestions.sort(
        key=lambda s: (-len(s.techniques), rank.get(s.control.status, 9), s.control.ref)
    )
    return suggestions


def uncovered_mitigations(risk: Risk) -> list[tuple[Mitigation, list[Technique]]]:
    """ATT&CK mitigations for the risk's techniques that no control implements yet."""
    techniques = {t.pk: t for t in risk.techniques.all()}
    if not techniques:
        return []
    implemented = set(
        ControlMitigation.objects.filter(
            control__organisation_id=risk.organisation_id, control__archived_at__isnull=True
        ).values_list("mitigation_id", flat=True)
    )
    found: dict[int, list[Technique]] = defaultdict(list)
    for mid, tid in MitigationTechnique.objects.filter(
        technique_id__in=techniques, mitigation__is_deprecated=False, mitigation__is_revoked=False
    ).values_list("mitigation_id", "technique_id"):
        if mid not in implemented:
            found[mid].append(techniques[tid])
    mitigations = Mitigation.objects.in_bulk(found.keys())
    out = [(mitigations[m], sorted(ts, key=lambda t: t.attack_id)) for m, ts in found.items()]
    out.sort(key=lambda pair: (-len(pair[1]), pair[0].attack_id))
    return out


# ----------------------------------------------------------------------------- acceptance
@transaction.atomic
def request_acceptance(
    risk: Risk, *, user: Any, justification: str, expires_on: date
) -> RiskAcceptance:
    _require_edit(user, risk)
    if not justification.strip():
        raise RiskError("A justification is required.")
    today = timezone.localdate()
    if expires_on <= today or expires_on > today + timedelta(days=3 * 366):
        raise RiskError("Expiry must be in the future and within 3 years.")
    if risk.acceptances.filter(status=RiskAcceptance.Status.PENDING).exists():
        raise RiskError("An acceptance request is already pending for this risk.")
    acc = RiskAcceptance.objects.create(
        risk=risk, justification=justification.strip(), expires_on=expires_on, requested_by=user
    )
    record(
        Action.CREATE,
        acc,
        actor=user,
        changes={"expires_on": [None, expires_on.isoformat()], "risk": [None, risk.ref]},
    )
    return acc


@transaction.atomic
def decide_acceptance(acc: RiskAcceptance, *, user: Any, approve: bool, note: str = "") -> None:
    if not can(user, Cap.APPROVE_ACCEPTANCE):
        raise RiskError("You cannot approve risk acceptances.")
    if acc.status != RiskAcceptance.Status.PENDING:
        raise RiskError("This request has already been decided.")
    if acc.requested_by_id == user.pk:
        raise RiskError("Segregation of duties: you cannot decide your own acceptance request.")
    risk = acc.risk
    scope = business_unit_scope(user)
    if scope is not None and risk.business_unit_id not in scope:
        raise RiskError("This risk is outside your business units.")
    acc.status = RiskAcceptance.Status.APPROVED if approve else RiskAcceptance.Status.REJECTED
    acc.decided_by = user
    acc.decided_at = timezone.now()
    acc.decision_note = note[:500]
    acc.save()
    record(Action.UPDATE, acc, actor=user, changes={"status": ["pending", acc.status]})
    if approve:
        before = {"status": risk.status, "treatment": risk.treatment}
        risk.status = RiskStatus.ACCEPTED
        risk.treatment = Treatment.ACCEPT
        risk.updated_by = user
        risk.save(update_fields=["status", "treatment", "updated_by", "updated_at"])
        record(
            Action.UPDATE,
            risk,
            actor=user,
            changes=diff(before, {"status": risk.status, "treatment": risk.treatment}),
        )


@transaction.atomic
def expire_acceptances(today: date | None = None) -> int:
    """Daily job: approved acceptances past expiry lapse and the risk re-opens."""
    today = today or timezone.localdate()
    expired = 0
    for acc in RiskAcceptance.objects.select_related("risk").filter(
        status=RiskAcceptance.Status.APPROVED, expires_on__lt=today
    ):
        acc.status = RiskAcceptance.Status.EXPIRED
        acc.save(update_fields=["status"])
        record(Action.SYSTEM, acc, changes={"status": ["approved", "expired"]})
        risk = acc.risk
        if risk.status == RiskStatus.ACCEPTED:
            risk.status = RiskStatus.OPEN
            risk.save(update_fields=["status", "updated_at"])
            record(
                Action.SYSTEM,
                risk,
                changes={"status": ["accepted", "open"], "reason": [None, "acceptance expired"]},
            )
        expired += 1
    return expired


# ----------------------------------------------------------------------------- reminders
def _absolute(path: str) -> str:
    return f"{settings.SITE_URL.rstrip('/')}{path}"


def send_review_reminders(today: date | None = None) -> int:
    """Daily job: one digest email per owner for risks due for review within 14 days or
    overdue. Each risk is included at most once a week."""
    today = today or timezone.localdate()
    window = today + timedelta(days=REMINDER_WINDOW_DAYS)
    repeat_before = today - timedelta(days=REMINDER_REPEAT_DAYS)
    due = (
        Risk.objects.live()
        .exclude(status=RiskStatus.CLOSED)
        .filter(next_review_date__isnull=False, next_review_date__lte=window, owner__isnull=False)
        .filter(owner__is_active=True)
        .exclude(owner__email="")
        .exclude(last_reminder_on__gt=repeat_before)
        .select_related("owner")
        .order_by("owner_id", "next_review_date")
    )
    by_owner: dict[int, list[Risk]] = defaultdict(list)
    for risk in due:
        by_owner[risk.owner_id].append(risk)  # type: ignore[index]
    sent = 0
    for risks in by_owner.values():
        owner = risks[0].owner
        if owner is None:  # pragma: no cover - excluded by the query
            continue
        lines = [
            f"{'OVERDUE' if r.next_review_date < today else 'Due'} {r.next_review_date:%Y-%m-%d}  "  # type: ignore[operator]
            f"{r.ref} {r.title}\n    {_absolute(reverse('risks:detail', args=[r.ref]))}"
            for r in risks
        ]
        body = (
            f"Hello {owner.get_short_name() or owner.get_username()},\n\n"
            f"These risks you own are due for review:\n\n" + "\n".join(lines) + "\n\n"
            "Reviewing a risk means confirming (or updating) its scores, treatment and next "
            "review date.\n\n— ThreatLedger"
        )
        try:
            send_mail(
                f"[ThreatLedger] {len(risks)} risk review(s) due",
                body,
                settings.DEFAULT_FROM_EMAIL,
                [owner.email],
            )
        except Exception:
            logger.exception("review reminder email failed for user %s", owner.pk)
            continue
        Risk.objects.filter(pk__in=[r.pk for r in risks]).update(last_reminder_on=today)
        sent += 1
    return sent


# ----------------------------------------------------------------------------- matrix
@transaction.atomic
def update_matrix(matrix: RiskMatrix, *, user: Any, data: dict[str, Any]) -> RiskMatrix:
    if not can(user, Cap.MANAGE_SETTINGS):
        raise RiskError("You cannot change the risk matrix.")
    before = snapshot(matrix)
    for key, value in data.items():
        setattr(matrix, key, value)
    matrix.full_clean(exclude=["organisation"])
    highest = 0
    for values in Risk.objects.filter(organisation=matrix.organisation).values_list(*SCORE_FIELDS):
        highest = max(highest, *values)
    if highest > matrix.size:
        raise ValidationError(
            {"size": f"Existing risks use scores up to {highest}; the matrix can't be smaller."}
        )
    matrix.save()
    changes = diff(before, snapshot(matrix))
    changes.pop("updated_at", None)
    if changes:
        record(Action.UPDATE, matrix, actor=user, changes=changes)
    return matrix
