"""Audit and campaign business rules. All writes go through here (permissions + audit log)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q, QuerySet
from django.utils import timezone

from threatledger.accounts.permissions import business_unit_scope, can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.audit.models import Action
from threatledger.audit.services import diff, record, snapshot
from threatledger.controls.models import Evidence
from threatledger.core.dates import add_months
from threatledger.core.refs import next_ref
from threatledger.frameworks.compliance import ReqStatus, requirement_status
from threatledger.frameworks.models import Framework, Requirement
from threatledger.frameworks.services import framework_result
from threatledger.org.models import BusinessUnit

from .models import (
    RECURRENCE_MONTHS,
    Audit,
    AuditResult,
    AuditStatus,
    Campaign,
    Judgement,
    Recurrence,
)
from .scoring import AuditScore, is_divergent, suggest


class AuditError(ValueError):
    """A business rule was violated (shown to the user)."""


AUDIT_FIELDS = ("name", "business_unit", "baseline", "scope_note", "lead_auditor", "due_on")
NOISE = ("updated_at", "created_at", "updated_by", "created_by")


def _changes(before: dict[str, Any], obj: Any) -> dict[str, Any]:
    changes = diff(before, snapshot(obj))
    for noise in NOISE:
        changes.pop(noise, None)
    return changes


# ----------------------------------------------------------------------------- access
def visible_audits(user: Any) -> QuerySet[Audit]:
    org = current_organisation(user)
    if org is None or not can(user, Cap.VIEW_AUDITS):
        return Audit.objects.none()
    qs = Audit.objects.filter(organisation=org)
    scope = business_unit_scope(user)
    if scope is not None:
        qs = qs.filter(Q(business_unit__isnull=True) | Q(business_unit_id__in=scope))
    return qs


def visible_campaigns(user: Any) -> QuerySet[Campaign]:
    org = current_organisation(user)
    if org is None or not can(user, Cap.VIEW_AUDITS):
        return Campaign.objects.none()
    return Campaign.objects.filter(organisation=org)


def can_manage(user: Any, audit: Audit | None = None) -> bool:
    return can(user, Cap.MANAGE_AUDITS) and (audit is None or not audit.is_closed)


def can_perform(user: Any, audit: Audit) -> bool:
    return can(user, Cap.PERFORM_AUDITS) and audit.status in (
        AuditStatus.PLANNED,
        AuditStatus.IN_PROGRESS,
    )


def _check_perimeter(user: Any, bu: BusinessUnit | None) -> None:
    scope = business_unit_scope(user)
    if bu is None:
        if scope is not None:
            raise AuditError("You can only plan audits for your own business units.")
        return
    if bu.organisation_id != current_organisation(user).pk:
        raise AuditError("Unknown business unit.")
    if scope is not None and bu.pk not in scope:
        raise AuditError("This business unit is outside your scope.")


def _check_baseline(framework: Framework, baseline: str) -> None:
    if baseline and baseline not in (framework.baselines or []):
        raise ValidationError({"baseline": f"{framework.name} has no '{baseline}' baseline."})


# ----------------------------------------------------------------------------- audits
@transaction.atomic
def create_audit(*, user: Any, data: dict[str, Any], campaign: Campaign | None = None) -> Audit:
    if not can_manage(user):
        raise AuditError("You cannot plan audits.")
    org = current_organisation(user)
    data = dict(data)
    framework = data.pop("framework")
    _check_perimeter(user, data.get("business_unit"))
    _check_baseline(framework, data.get("baseline", ""))
    audit = Audit(
        organisation=org,
        framework=framework,
        campaign=campaign,
        created_by=user,
        updated_by=user,
        **{k: v for k, v in data.items() if k in AUDIT_FIELDS},
    )
    audit.ref = next_ref(Audit, org, "A")
    audit.full_clean(exclude=["organisation", "created_by", "updated_by"])
    audit.save()
    record(Action.CREATE, audit, actor=user, changes=_changes({}, audit))
    return audit


@transaction.atomic
def update_audit(audit: Audit, *, user: Any, data: dict[str, Any]) -> Audit:
    if not can_manage(user, audit):
        raise AuditError("You cannot edit this audit.")
    if "business_unit" in data:
        _check_perimeter(user, data["business_unit"])
    _check_baseline(audit.framework, data.get("baseline", audit.baseline))
    before = snapshot(audit)
    for key, value in data.items():
        if key in AUDIT_FIELDS:
            setattr(audit, key, value)
    audit.updated_by = user
    audit.full_clean(exclude=["organisation", "created_by", "updated_by"])
    audit.save()
    changes = _changes(before, audit)
    if changes:
        record(Action.UPDATE, audit, actor=user, changes=changes)
    return audit


# (from, to) -> capability needed
_TRANSITIONS: dict[tuple[str, str], tuple[Cap, ...]] = {
    (AuditStatus.PLANNED, AuditStatus.IN_PROGRESS): (Cap.MANAGE_AUDITS, Cap.PERFORM_AUDITS),
    (AuditStatus.IN_PROGRESS, AuditStatus.IN_REVIEW): (Cap.MANAGE_AUDITS, Cap.PERFORM_AUDITS),
    (AuditStatus.IN_REVIEW, AuditStatus.IN_PROGRESS): (Cap.MANAGE_AUDITS, Cap.PERFORM_AUDITS),
    (AuditStatus.IN_REVIEW, AuditStatus.CLOSED): (Cap.MANAGE_AUDITS,),
}


def allowed_transitions(user: Any, audit: Audit) -> list[str]:
    return [
        to
        for (frm, to), caps in _TRANSITIONS.items()
        if frm == audit.status and any(can(user, c) for c in caps)
    ]


@transaction.atomic
def set_status(audit: Audit, *, user: Any, status: str, conclusion: str = "") -> Audit:
    if status not in allowed_transitions(user, audit):
        raise AuditError(
            f"Cannot move this audit from {audit.get_status_display()} to "
            f"{AuditStatus(status).label if status in AuditStatus.values else status}."
        )
    before = snapshot(audit)
    if status == AuditStatus.CLOSED:
        if not conclusion.strip():
            raise AuditError("Write a conclusion before closing the audit.")
        audit.conclusion = conclusion.strip()
        audit.closed_at = timezone.now()
        audit.closed_by = user
    audit.status = status
    audit.updated_by = user
    audit.save()
    record(Action.UPDATE, audit, actor=user, changes=_changes(before, audit))
    return audit


# ----------------------------------------------------------------------------- results
@dataclass
class Row:
    requirement: Requirement
    result: AuditResult | None
    derived: ReqStatus | None
    controls: list[Any]

    @property
    def judgement(self) -> str:
        return self.result.judgement if self.result else Judgement.NOT_ASSESSED

    @property
    def suggestion(self) -> Judgement:
        return suggest(self.derived)

    @property
    def divergent(self) -> bool:
        return is_divergent(self.judgement, self.derived)


def scoped_requirements(audit: Audit) -> QuerySet[Requirement]:
    """Assessable requirements of the framework (baseline filtering happens in Python, because
    JSON ``contains`` lookups are not portable to SQLite)."""
    return Requirement.objects.filter(framework=audit.framework, is_domain=False).order_by(
        "order", "id"
    )


def _in_baseline(audit: Audit, req: Requirement) -> bool:
    return not audit.baseline or audit.baseline in (req.baselines or [])


def audit_rows(audit: Audit) -> tuple[list[Row], AuditScore]:
    """Every requirement in scope with its judgement and live derived status (fixed queries)."""
    fr = framework_result(audit.framework, audit.organisation)
    results = {
        r.requirement_id: r
        for r in audit.results.select_related("assessed_by").prefetch_related("evidence")
    }
    rows: list[Row] = []
    score = AuditScore()
    for req in scoped_requirements(audit):
        if not _in_baseline(audit, req):
            continue
        controls = fr.controls_by_requirement.get(req.pk, [])
        derived = (
            None if req.pk in fr.not_applicable else requirement_status(c.status for c in controls)
        )
        row = Row(req, results.get(req.pk), derived, controls)
        rows.append(row)
        result = row.result
        score.add(row.judgement, result.maturity if result else None, row.divergent)
    return rows, score


def audit_score(audit: Audit) -> AuditScore:
    return audit_rows(audit)[1]


def list_scores(audits: list[Audit]) -> dict[int, AuditScore]:
    """Progress/score/maturity for many audits in a fixed number of queries.

    Divergence needs the live derived status per requirement, so it is left at 0 here and only
    shown on the audit page.
    """
    if not audits:
        return {}
    totals: dict[tuple[int, str], int] = {}
    for fw_id in {a.framework_id for a in audits}:
        baselines = [
            bl or []
            for bl in Requirement.objects.filter(framework_id=fw_id, is_domain=False).values_list(
                "baselines", flat=True
            )
        ]
        for a in audits:
            if a.framework_id == fw_id and (fw_id, a.baseline) not in totals:
                totals[(fw_id, a.baseline)] = sum(
                    1 for bl in baselines if not a.baseline or a.baseline in bl
                )
    scores = {a.pk: AuditScore() for a in audits}
    for audit_id, judgement, maturity in AuditResult.objects.filter(audit__in=audits).values_list(
        "audit_id", "judgement", "maturity"
    ):
        scores[audit_id].add(judgement, maturity, False)
    for a in audits:
        score = scores[a.pk]
        score.total = max(totals[(a.framework_id, a.baseline)], score.total)
    return scores


def _derived_for(audit: Audit, requirement: Requirement) -> ReqStatus | None:
    from threatledger.frameworks.services import requirement_state

    _, controls, scope, _ = requirement_state(requirement, audit.organisation)
    if scope is not None and not scope.applicable:
        return None
    return requirement_status(c.status for c in controls)


def _evidence_for(audit: Audit, evidence_ids: Iterable[int]) -> list[Evidence]:
    ids = {int(i) for i in evidence_ids}
    if not ids:
        return []
    found = list(
        Evidence.objects.filter(
            pk__in=ids, control__organisation=audit.organisation, archived_at__isnull=True
        )
    )
    if len(found) != len(ids):
        raise AuditError("Unknown evidence selected.")
    return found


@transaction.atomic
def record_judgement(
    audit: Audit,
    requirement: Requirement,
    *,
    user: Any,
    judgement: str,
    maturity: int | None = None,
    observation: str = "",
    evidence_ids: Iterable[int] = (),
) -> AuditResult:
    if not can_perform(user, audit):
        raise AuditError("You cannot record judgements in this audit.")
    if requirement.framework_id != audit.framework_id or requirement.is_domain:
        raise AuditError("This requirement is not part of the audit.")
    if not _in_baseline(audit, requirement):
        raise AuditError("This requirement is outside the audit baseline.")
    if judgement not in Judgement.values or judgement == Judgement.NOT_ASSESSED:
        raise AuditError("Choose a judgement.")
    if maturity is not None and not 0 <= maturity <= 5:
        raise AuditError("Maturity must be between 0 and 5.")
    if judgement in (Judgement.PARTIAL, Judgement.NON_COMPLIANT, Judgement.NOT_APPLICABLE) and (
        not observation.strip()
    ):
        raise AuditError("Explain the judgement in an observation.")
    evidence = _evidence_for(audit, evidence_ids)
    result, created = AuditResult.objects.get_or_create(audit=audit, requirement=requirement)
    before = {} if created else snapshot(result)
    before_evidence = [] if created else sorted(result.evidence.values_list("pk", flat=True))
    result.judgement = judgement
    result.maturity = maturity
    result.observation = observation.strip()
    result.derived_at_judgement = str(_derived_for(audit, requirement) or "not_applicable")
    result.assessed_by = user
    result.assessed_at = timezone.now()
    result.save()
    result.evidence.set(evidence)
    changes = _changes(before, result)
    changes.pop("assessed_at", None)
    after_evidence = sorted(e.pk for e in evidence)
    if after_evidence != before_evidence:
        changes["evidence"] = [before_evidence, after_evidence]
    if changes:
        changes["requirement"] = [None, requirement.ref]
        record(Action.UPDATE, audit, actor=user, changes={"result": changes})
    if audit.status == AuditStatus.PLANNED:
        audit.status = AuditStatus.IN_PROGRESS
        audit.save(update_fields=["status", "updated_at"])
        record(Action.UPDATE, audit, actor=user, changes={"status": ["planned", "in_progress"]})
    return result


@transaction.atomic
def accept_suggestions(audit: Audit, *, user: Any) -> int:
    """Record the derived suggestion for every requirement not yet judged."""
    if not can_perform(user, audit):
        raise AuditError("You cannot record judgements in this audit.")
    rows, _ = audit_rows(audit)
    now = timezone.now()
    accepted: dict[str, str] = {}
    for row in rows:
        if row.result is not None and row.result.judgement != Judgement.NOT_ASSESSED:
            continue
        result = row.result or AuditResult(audit=audit, requirement=row.requirement)
        result.judgement = row.suggestion
        result.observation = "Accepted the status derived from mapped controls."
        result.derived_at_judgement = str(row.derived or "not_applicable")
        result.assessed_by = user
        result.assessed_at = now
        result.save()
        accepted[row.requirement.ref] = row.suggestion
    if accepted:
        record(Action.UPDATE, audit, actor=user, changes={"accepted_suggestions": accepted})
        if audit.status == AuditStatus.PLANNED:
            audit.status = AuditStatus.IN_PROGRESS
            audit.save(update_fields=["status", "updated_at"])
    return len(accepted)


# ----------------------------------------------------------------------------- campaigns
@transaction.atomic
def create_campaign(
    *,
    user: Any,
    data: dict[str, Any],
    perimeters: list[BusinessUnit | None],
    previous: Campaign | None = None,
) -> Campaign:
    if not can_manage(user):
        raise AuditError("You cannot plan campaigns.")
    if not perimeters:
        raise AuditError("Choose at least one perimeter.")
    for bu in perimeters:
        _check_perimeter(user, bu)
    org = current_organisation(user)
    campaign = Campaign(
        organisation=org,
        previous=previous,
        created_by=user,
        updated_by=user,
        **{
            k: data[k]
            for k in ("name", "description", "framework", "starts_on", "due_on", "recurrence")
            if k in data
        },
    )
    campaign.ref = next_ref(Campaign, org, "C")
    campaign.full_clean(exclude=["organisation", "created_by", "updated_by", "previous"])
    campaign.save()
    record(Action.CREATE, campaign, actor=user, changes=_changes({}, campaign))
    for bu in perimeters:
        create_audit(
            user=user,
            campaign=campaign,
            data={
                "framework": campaign.framework,
                "name": f"{campaign.name} · {bu.name if bu else 'Organisation-wide'}",
                "business_unit": bu,
                "due_on": campaign.due_on,
                "baseline": data.get("baseline", ""),
            },
        )
    return campaign


def campaign_status(audits: Iterable[Any]) -> str:
    statuses = {a.status for a in audits}
    if not statuses or statuses == {AuditStatus.PLANNED}:
        return AuditStatus.PLANNED
    if statuses == {AuditStatus.CLOSED}:
        return AuditStatus.CLOSED
    return AuditStatus.IN_PROGRESS


@transaction.atomic
def launch_next_cycle(campaign: Campaign, *, user: Any) -> Campaign:
    if campaign.recurrence == Recurrence.NONE:
        raise AuditError("This campaign does not recur.")
    if Campaign.objects.filter(previous=campaign).exists():
        raise AuditError("The next cycle has already been launched.")
    months = RECURRENCE_MONTHS[campaign.recurrence]
    audits = list(campaign.audits.select_related("business_unit"))
    baseline = audits[0].baseline if audits else ""
    return create_campaign(
        user=user,
        previous=campaign,
        perimeters=[a.business_unit for a in audits] or [None],
        data={
            "name": campaign.name,
            "description": campaign.description,
            "framework": campaign.framework,
            "starts_on": add_months(campaign.starts_on, months),
            "due_on": add_months(campaign.due_on, months),
            "recurrence": campaign.recurrence,
            "baseline": baseline,
        },
    )
