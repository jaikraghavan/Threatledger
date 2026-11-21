"""Third-party risk rules. All writes go through here (permissions + audit log)."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from django.db import transaction
from django.db.models import Q, QuerySet
from django.utils import timezone

from threatledger.accounts.permissions import business_unit_scope, can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.audit.models import Action
from threatledger.audit.services import diff, record, snapshot
from threatledger.core.dates import add_months
from threatledger.core.refs import next_ref

from .models import REASSESS_MONTHS, TIER_ORDER, Contract, Entity, EntityStatus, Solution


class VendorError(ValueError):
    """A business rule was violated (shown to the user)."""


NOISE = ("updated_at", "created_at", "updated_by", "created_by")
ENTITY_FIELDS = (
    "name",
    "legal_name",
    "lei",
    "country",
    "website",
    "description",
    "owner",
    "business_unit",
    "tier",
    "status",
    "data_access",
    "ict_provider",
    "substitutability",
    "exit_plan",
    "security_contact",
    "external_rating",
    "external_rating_source",
    "external_rating_date",
)
SOLUTION_FIELDS = (
    "name",
    "description",
    "ict_service_type",
    "supported_function",
    "function_is_critical",
    "data_locations",
)
CONTRACT_FIELDS = (
    "title",
    "reference",
    "start_date",
    "end_date",
    "notice_days",
    "auto_renew",
    "annual_value",
    "currency",
    "governing_law",
    "security_clauses",
    "audit_rights",
    "breach_notification_hours",
    "data_processing_agreement",
    "exit_assistance",
    "subcontracting_allowed",
    "document_url",
    "terminated_on",
)


def _changes(before: dict[str, Any], obj: Any) -> dict[str, Any]:
    changes = diff(before, snapshot(obj))
    for noise in NOISE:
        changes.pop(noise, None)
    return changes


def _require(user: Any) -> None:
    if not can(user, Cap.MANAGE_VENDORS):
        raise VendorError("You cannot change third-party records.")


# ----------------------------------------------------------------------------- access
def visible_entities(user: Any) -> QuerySet[Entity]:
    org = current_organisation(user)
    if org is None or not can(user, Cap.VIEW_VENDORS):
        return Entity.objects.none()
    qs = Entity.objects.filter(organisation=org)
    scope = business_unit_scope(user)
    if scope is not None:
        qs = qs.filter(Q(business_unit__isnull=True) | Q(business_unit_id__in=scope))
    return qs


def visible_contracts(user: Any) -> QuerySet[Contract]:
    return Contract.objects.filter(entity__in=visible_entities(user))


def _clean_entity(entity: Entity, user: Any) -> None:
    entity.lei = entity.lei.strip().upper()
    entity.country = entity.country.strip().upper()
    if entity.lei and (len(entity.lei) != 20 or not entity.lei.isalnum()):
        from django.core.exceptions import ValidationError

        raise ValidationError({"lei": "An LEI has 20 letters and digits."})
    bu = entity.business_unit
    scope = business_unit_scope(user)
    if bu is not None and scope is not None and bu.pk not in scope:
        raise VendorError("This business unit is outside your scope.")


# ----------------------------------------------------------------------------- entities
@transaction.atomic
def create_entity(*, user: Any, data: dict[str, Any], risks: Any = ()) -> Entity:
    _require(user)
    org = current_organisation(user)
    entity = Entity(
        organisation=org,
        created_by=user,
        updated_by=user,
        **{k: v for k, v in data.items() if k in ENTITY_FIELDS},
    )
    _clean_entity(entity, user)
    entity.ref = next_ref(Entity, org, "V")
    entity.full_clean(exclude=["organisation", "created_by", "updated_by"])
    entity.save()
    set_risks(entity, list(risks), user=user, audit=False)
    record(Action.CREATE, entity, actor=user, changes=_changes({}, entity))
    return entity


@transaction.atomic
def update_entity(entity: Entity, *, user: Any, data: dict[str, Any], risks: Any = None) -> Entity:
    _require(user)
    before = snapshot(entity)
    for key, value in data.items():
        if key in ENTITY_FIELDS:
            setattr(entity, key, value)
    _clean_entity(entity, user)
    entity.updated_by = user
    entity.full_clean(exclude=["organisation", "created_by", "updated_by"])
    entity.save()
    changes = _changes(before, entity)
    if risks is not None:
        changes.update(set_risks(entity, list(risks), user=user, audit=False))
    if changes:
        record(Action.UPDATE, entity, actor=user, changes=changes)
    return entity


def set_risks(entity: Entity, risks: list[Any], *, user: Any, audit: bool = True) -> dict[str, Any]:
    if any(r.organisation_id != entity.organisation_id for r in risks):
        raise VendorError("Unknown risk.")
    before = sorted(entity.risks.values_list("ref", flat=True))
    entity.risks.set(risks)
    after = sorted(r.ref for r in risks)
    changes = {"risks": [before, after]} if before != after else {}
    if audit and changes:
        record(Action.UPDATE, entity, actor=user, changes=changes)
    return changes


# ----------------------------------------------------------------------------- solutions
@transaction.atomic
def add_solution(entity: Entity, *, user: Any, data: dict[str, Any], assets: Any = ()) -> Solution:
    _require(user)
    solution = Solution(entity=entity, **{k: v for k, v in data.items() if k in SOLUTION_FIELDS})
    solution.full_clean(exclude=["entity"])
    solution.save()
    assets = list(assets)
    if any(a.organisation_id != entity.organisation_id for a in assets):
        raise VendorError("Unknown asset.")
    solution.assets.set(assets)
    record(
        Action.UPDATE,
        entity,
        actor=user,
        changes={"solution_added": [None, solution.name], "assets": [None, len(assets)]},
    )
    return solution


@transaction.atomic
def remove_solution(solution: Solution, *, user: Any) -> None:
    _require(user)
    if solution.contracts.exists():
        raise VendorError("Remove it from its contracts first.")
    entity, name = solution.entity, solution.name
    solution.delete()
    record(Action.UPDATE, entity, actor=user, changes={"solution_removed": [name, None]})


# ----------------------------------------------------------------------------- contracts
@transaction.atomic
def create_contract(
    entity: Entity, *, user: Any, data: dict[str, Any], solutions: Any = ()
) -> Contract:
    _require(user)
    org = current_organisation(user)
    contract = Contract(
        organisation=org,
        entity=entity,
        created_by=user,
        updated_by=user,
        **{k: v for k, v in data.items() if k in CONTRACT_FIELDS},
    )
    contract.ref = next_ref(Contract, org, "CT")
    contract.full_clean(exclude=["organisation", "created_by", "updated_by"])
    contract.save()
    _set_solutions(contract, solutions)
    record(Action.CREATE, contract, actor=user, changes=_changes({}, contract))
    return contract


def _set_solutions(contract: Contract, solutions: Any) -> None:
    solutions = list(solutions)
    if any(s.entity_id != contract.entity_id for s in solutions):
        raise VendorError("Services must belong to the contract's vendor.")
    contract.solutions.set(solutions)


@transaction.atomic
def update_contract(
    contract: Contract, *, user: Any, data: dict[str, Any], solutions: Any = None
) -> Contract:
    _require(user)
    before = snapshot(contract)
    for key, value in data.items():
        if key in CONTRACT_FIELDS:
            setattr(contract, key, value)
    contract.updated_by = user
    contract.full_clean(exclude=["organisation", "created_by", "updated_by"])
    contract.save()
    if solutions is not None:
        _set_solutions(contract, solutions)
    changes = _changes(before, contract)
    if changes:
        record(Action.UPDATE, contract, actor=user, changes=changes)
    return contract


# ----------------------------------------------------------------------------- posture (derived)
@dataclass
class Posture:
    entity: Entity
    last_assessment: Any = None  # latest accepted (or submitted) assessment
    score: float | None = None
    pending: int = 0  # assessments out for answers
    reassess_due: date | None = None
    open_findings: int = 0
    contracts: list[Contract] = field(default_factory=list)
    risk_count: int = 0

    @property
    def reassess_overdue(self) -> bool:
        return self.reassess_due is not None and self.reassess_due < timezone.localdate()

    @property
    def never_assessed(self) -> bool:
        return self.last_assessment is None

    @property
    def contract_alert(self) -> str:
        states = {c.state for c in self.contracts}
        if "notice_due" in states:
            return "notice_due"
        if self.contracts and states <= {"expired", "terminated"}:
            return "expired"
        return ""

    @property
    def flags(self) -> list[str]:
        out = []
        e = self.entity
        if e.status in (EntityStatus.ACTIVE, EntityStatus.OFFBOARDING):
            if self.never_assessed:
                out.append("never assessed")
            elif self.reassess_overdue:
                out.append("reassessment overdue")
            if e.tier in ("critical", "high") and not e.exit_plan:
                out.append("no exit plan")
            if not self.contracts:
                out.append("no contract")
        if self.contract_alert == "notice_due":
            out.append("contract notice window")
        if self.open_findings:
            out.append(f"{self.open_findings} open finding{'s' if self.open_findings > 1 else ''}")
        return out


def postures(entities: list[Entity]) -> list[Posture]:
    """Assessment, contract and finding state per vendor in a fixed number of queries."""
    from threatledger.findings.models import Finding, FindingStatus
    from threatledger.work.models import Assignment, AssignmentStatus
    from threatledger.work.services import assessment_score

    ids = [e.pk for e in entities]
    by_entity: dict[int, list[Any]] = defaultdict(list)
    for a in (
        Assignment.objects.filter(entity_id__in=ids)
        .select_related("questionnaire")
        .prefetch_related("answers__question")
        .order_by("-submitted_at", "-created_at")
    ):
        if a.entity_id is not None:
            by_entity[a.entity_id].append(a)
    contracts: dict[int, list[Contract]] = defaultdict(list)
    for c in Contract.objects.filter(entity_id__in=ids):
        contracts[c.entity_id].append(c)
    findings: dict[int, int] = defaultdict(int)
    for eid in (
        Finding.objects.filter(entity_id__in=ids)
        .exclude(status=FindingStatus.CLOSED)
        .values_list("entity_id", flat=True)
    ):
        findings[eid] += 1
    risks: dict[int, int] = defaultdict(int)
    for eid in Entity.risks.through.objects.filter(entity_id__in=ids).values_list(
        "entity_id", flat=True
    ):
        risks[eid] += 1
    out = []
    for e in entities:
        assessments = by_entity.get(e.pk, [])
        done = [
            a
            for a in assessments
            if a.status in (AssignmentStatus.ACCEPTED, AssignmentStatus.SUBMITTED)
        ]
        last = done[0] if done else None
        p = Posture(
            entity=e,
            last_assessment=last,
            score=assessment_score(last) if last else None,
            pending=sum(a.editable_by_respondent for a in assessments),
            open_findings=findings.get(e.pk, 0),
            contracts=contracts.get(e.pk, []),
            risk_count=risks.get(e.pk, 0),
        )
        if last is not None and last.submitted_at:
            base = timezone.localtime(last.submitted_at).date()
            p.reassess_due = add_months(base, REASSESS_MONTHS[e.tier])
        out.append(p)
    return sorted(out, key=lambda p: (TIER_ORDER[p.entity.tier], p.entity.name.lower()))
