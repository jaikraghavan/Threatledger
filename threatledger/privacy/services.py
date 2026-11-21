"""Privacy rules: records of processing and DPIAs. All writes are audited."""

from __future__ import annotations

from typing import Any

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q, QuerySet
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.permissions import business_unit_scope, can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.audit.models import Action
from threatledger.audit.services import diff, record, snapshot
from threatledger.core.dates import add_months
from threatledger.core.refs import next_ref

from .models import DATA_CATEGORIES, DATA_SUBJECTS, Dpia, DpiaStatus, Processing


class PrivacyError(ValueError):
    """A business rule was violated (shown to the user)."""


NOISE = ("updated_at", "created_at", "updated_by", "created_by")
PROCESSING_FIELDS = (
    "name",
    "purpose",
    "role",
    "legal_basis",
    "legal_basis_note",
    "status",
    "owner",
    "business_unit",
    "data_categories",
    "data_subjects",
    "recipients",
    "transfer_countries",
    "transfer_safeguard",
    "retention",
    "security_measures",
    "large_scale",
    "systematic_monitoring",
    "automated_decisions",
    "new_technology",
)
DPIA_FIELDS = (
    "description",
    "necessity",
    "risks_to_individuals",
    "measures",
    "residual_risk",
    "dpo_advice",
)
LINKS = ("processors", "assets", "controls")


def _changes(before: dict[str, Any], obj: Any) -> dict[str, Any]:
    changes = diff(before, snapshot(obj))
    for noise in NOISE:
        changes.pop(noise, None)
    return changes


def visible_processing(user: Any) -> QuerySet[Processing]:
    org = current_organisation(user)
    if org is None or not can(user, Cap.VIEW_PRIVACY):
        return Processing.objects.none()
    qs = Processing.objects.filter(organisation=org)
    scope = business_unit_scope(user)
    if scope is not None:
        qs = qs.filter(Q(business_unit__isnull=True) | Q(business_unit_id__in=scope))
    return qs


def visible_dpias(user: Any) -> QuerySet[Dpia]:
    return Dpia.objects.filter(processing__in=visible_processing(user))


def _require(user: Any) -> None:
    if not can(user, Cap.MANAGE_PRIVACY):
        raise PrivacyError("You cannot change privacy records.")


def _clean(p: Processing, user: Any) -> None:
    allowed_cats = {k for k, _ in DATA_CATEGORIES}
    allowed_subjects = {k for k, _ in DATA_SUBJECTS}
    if set(p.data_categories or []) - allowed_cats or set(p.data_subjects or []) - allowed_subjects:
        raise ValidationError({"data_categories": "Unknown category or data subject."})
    if not p.data_categories:
        raise ValidationError({"data_categories": "Choose at least one category of personal data."})
    if p.transfer_countries.strip() and not p.transfer_safeguard:
        raise ValidationError(
            {"transfer_safeguard": "Record the safeguard for the international transfer."}
        )
    bu = p.business_unit
    scope = business_unit_scope(user)
    if bu is not None and scope is not None and bu.pk not in scope:
        raise PrivacyError("This business unit is outside your scope.")


def _set_links(p: Processing, links: dict[str, Any]) -> dict[str, Any]:
    changes = {}
    for name in LINKS:
        if name not in links:
            continue
        objs = list(links[name])
        if any(o.organisation_id != p.organisation_id for o in objs):
            raise PrivacyError(f"Unknown {name}.")
        manager = getattr(p, name)
        before = sorted(str(o) for o in manager.all())
        manager.set(objs)
        after = sorted(str(o) for o in objs)
        if before != after:
            changes[name] = [before, after]
    return changes


@transaction.atomic
def create_processing(
    *, user: Any, data: dict[str, Any], links: dict[str, Any] | None = None
) -> Processing:
    _require(user)
    org = current_organisation(user)
    p = Processing(
        organisation=org,
        created_by=user,
        updated_by=user,
        **{k: v for k, v in data.items() if k in PROCESSING_FIELDS},
    )
    _clean(p, user)
    p.ref = next_ref(Processing, org, "PA")
    p.full_clean(exclude=["organisation", "created_by", "updated_by"])
    p.save()
    changes = _changes({}, p)
    changes.update(_set_links(p, links or {}))
    record(Action.CREATE, p, actor=user, changes=changes)
    return p


@transaction.atomic
def update_processing(
    p: Processing, *, user: Any, data: dict[str, Any], links: dict[str, Any] | None = None
) -> Processing:
    _require(user)
    before = snapshot(p)
    for key, value in data.items():
        if key in PROCESSING_FIELDS:
            setattr(p, key, value)
    _clean(p, user)
    p.updated_by = user
    p.full_clean(exclude=["organisation", "created_by", "updated_by"])
    p.save()
    changes = _changes(before, p)
    changes.update(_set_links(p, links or {}))
    if changes:
        record(Action.UPDATE, p, actor=user, changes=changes)
    return p


# ----------------------------------------------------------------------------- DPIA
def current_dpia(p: Processing) -> Dpia | None:
    return p.dpias.order_by("-created_at").first()


def dpia_state(p: Processing, dpia: Dpia | None = None) -> str:
    """not_needed | missing | in_progress | approved | review_due (derived)."""
    dpia = dpia if dpia is not None else current_dpia(p)
    if dpia is None:
        return "missing" if p.dpia_required else "not_needed"
    if dpia.status == DpiaStatus.APPROVED:
        if dpia.review_due and dpia.review_due < timezone.localdate():
            return "review_due"
        return "approved"
    return "in_progress"


@transaction.atomic
def create_dpia(p: Processing, *, user: Any, data: dict[str, Any], risks: Any = ()) -> Dpia:
    _require(user)
    open_dpia = p.dpias.exclude(status=DpiaStatus.APPROVED).first()
    if open_dpia is not None:
        raise PrivacyError(f"{open_dpia.ref} is still open for this processing.")
    dpia = Dpia(
        organisation=p.organisation,
        processing=p,
        created_by=user,
        updated_by=user,
        **{k: v for k, v in data.items() if k in DPIA_FIELDS},
    )
    dpia.ref = next_ref(Dpia, p.organisation, "DPIA")
    dpia.full_clean(exclude=["organisation", "created_by", "updated_by", "processing"])
    dpia.save()
    risks = list(risks)
    if any(r.organisation_id != p.organisation_id for r in risks):
        raise PrivacyError("Unknown risk.")
    dpia.risks.set(risks)
    record(Action.CREATE, dpia, actor=user, changes={"processing": [None, p.ref]})
    return dpia


@transaction.atomic
def update_dpia(dpia: Dpia, *, user: Any, data: dict[str, Any], risks: Any = None) -> Dpia:
    _require(user)
    if dpia.status not in (DpiaStatus.DRAFT, DpiaStatus.REJECTED):
        raise PrivacyError("Only drafts can be edited.")
    before = snapshot(dpia)
    for key, value in data.items():
        if key in DPIA_FIELDS:
            setattr(dpia, key, value)
    dpia.updated_by = user
    dpia.full_clean(exclude=["organisation", "created_by", "updated_by", "processing"])
    dpia.save()
    if risks is not None:
        risks = list(risks)
        if any(r.organisation_id != dpia.organisation_id for r in risks):
            raise PrivacyError("Unknown risk.")
        dpia.risks.set(risks)
    changes = _changes(before, dpia)
    if changes:
        record(Action.UPDATE, dpia, actor=user, changes=changes)
    return dpia


@transaction.atomic
def submit_dpia(dpia: Dpia, *, user: Any) -> Dpia:
    _require(user)
    if dpia.status not in (DpiaStatus.DRAFT, DpiaStatus.REJECTED):
        raise PrivacyError("Only drafts can be submitted.")
    before = dpia.status
    dpia.status = DpiaStatus.IN_REVIEW
    dpia.updated_by = user
    dpia.save(update_fields=["status", "updated_by", "updated_at"])
    record(Action.UPDATE, dpia, actor=user, changes={"status": [before, dpia.status]})
    from threatledger.work.notify import notify, users_with

    notify(
        users_with(dpia.organisation, Cap.APPROVE_DPIA),
        f"{dpia.ref} awaits approval: {dpia.processing.name}",
        reverse("privacy:dpia", args=[dpia.ref]),
        actor=user,
    )
    return dpia


@transaction.atomic
def decide_dpia(dpia: Dpia, *, user: Any, approve: bool, note: str = "") -> Dpia:
    if not can(user, Cap.APPROVE_DPIA):
        raise PrivacyError("You cannot approve DPIAs.")
    if dpia.status != DpiaStatus.IN_REVIEW:
        raise PrivacyError("Only DPIAs in review can be decided.")
    authors = {dpia.created_by_id, dpia.updated_by_id}
    if user.pk in authors:
        raise PrivacyError("Segregation of duties: someone who did not write it must decide.")
    if not approve and not note.strip():
        raise PrivacyError("Explain what needs rework.")
    dpia.status = DpiaStatus.APPROVED if approve else DpiaStatus.REJECTED
    dpia.decided_by, dpia.decided_at = user, timezone.now()
    dpia.decision_note = note.strip()[:500]
    if approve:
        dpia.review_due = add_months(timezone.localdate(), 12)
    dpia.save()
    record(Action.UPDATE, dpia, actor=user, changes={"status": ["in_review", dpia.status]})
    from threatledger.work.notify import notify

    notify(
        [dpia.created_by, dpia.processing.owner],
        f"{dpia.ref} {dpia.get_status_display().lower()}",
        reverse("privacy:dpia", args=[dpia.ref]),
        actor=user,
    )
    return dpia
