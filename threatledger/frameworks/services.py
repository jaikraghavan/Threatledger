"""Frameworks & compliance business rules. All writes go through here (audited)."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from django.conf import settings
from django.db import transaction
from django.db.models import QuerySet

from threatledger.accounts.permissions import can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.attack.models import Technique
from threatledger.audit.models import Action
from threatledger.audit.services import record
from threatledger.controls.models import Control, MappingSource
from threatledger.org.models import Organisation

from . import importer
from .compliance import ReqStatus, Summary, requirement_status
from .models import (
    ControlRequirement,
    Framework,
    OrgFramework,
    Requirement,
    RequirementMapping,
    RequirementScope,
    TechniqueRequirement,
)

DATA_DIR = Path(settings.BASE_DIR) / "data" / "frameworks"
STARTER_CONTROLS = Path(settings.BASE_DIR) / "data" / "controls" / "starter.yaml"
SEED_FILES = [
    "nist-800-53-r5.json",
    "iso-27001-2022.yaml",
    "soc2-tsc-2017.yaml",
    "cis-controls-v8.yaml",
    "hipaa-security-rule.yaml",
    "india-dpdp-2023.yaml",
]


class FrameworkError(ValueError):
    """A business rule was violated (shown to the user)."""


# ----------------------------------------------------------------------------- org settings
def org_framework(org: Organisation, framework: Framework) -> OrgFramework:
    of, _ = OrgFramework.objects.get_or_create(
        organisation=org,
        framework=framework,
        defaults={"baseline": "moderate" if "moderate" in framework.baselines else ""},
    )
    return of


def adopted_frameworks(org: Organisation) -> list[Framework]:
    frameworks = list(Framework.objects.all())
    settings_by_fw = {of.framework_id: of for of in OrgFramework.objects.filter(organisation=org)}
    return [
        f for f in frameworks if settings_by_fw.get(f.pk) is None or settings_by_fw[f.pk].adopted
    ]


@transaction.atomic
def set_adoption(
    framework: Framework, *, user: Any, adopted: bool, baseline: str | None = None
) -> OrgFramework:
    if not can(user, Cap.EDIT_FRAMEWORKS):
        raise FrameworkError("You cannot change framework settings.")
    org = current_organisation(user)
    of = org_framework(org, framework)
    before = {"adopted": of.adopted, "baseline": of.baseline}
    of.adopted = adopted
    if baseline is not None:
        if baseline and baseline not in framework.baselines:
            raise FrameworkError(f"Unknown baseline {baseline!r}.")
        of.baseline = baseline
    of.save()
    after = {"adopted": of.adopted, "baseline": of.baseline}
    changes = {k: [before[k], after[k]] for k in before if before[k] != after[k]}
    if changes:
        record(Action.UPDATE, framework, actor=user, changes=changes)
    return of


@transaction.atomic
def set_applicability(
    requirement: Requirement, *, user: Any, applicable: bool, justification: str = ""
) -> RequirementScope:
    if not can(user, Cap.EDIT_FRAMEWORKS):
        raise FrameworkError("You cannot change requirement scope.")
    if not applicable and not justification.strip():
        raise FrameworkError("A justification is required to mark a requirement not applicable.")
    org = current_organisation(user)
    scope, _ = RequirementScope.objects.get_or_create(organisation=org, requirement=requirement)
    before = scope.applicable
    scope.applicable = applicable
    scope.justification = justification.strip()[:500] if not applicable else ""
    scope.updated_by = user
    scope.save()
    record(
        Action.UPDATE,
        requirement,
        actor=user,
        changes={"applicable": [before, applicable], "justification": [None, scope.justification]},
    )
    return scope


# ----------------------------------------------------------------------------- status
@dataclass
class FrameworkResult:
    framework: Framework
    settings: OrgFramework
    summary: Summary
    controls_by_requirement: dict[int, list[Control]] = field(default_factory=dict)
    not_applicable: set[int] = field(default_factory=set)
    out_of_baseline: set[int] = field(default_factory=set)


def _org_control_links(
    org: Organisation, requirement_ids: Any = None, framework: Framework | None = None
) -> QuerySet[ControlRequirement]:
    qs = ControlRequirement.objects.filter(
        control__organisation=org, control__archived_at__isnull=True
    ).select_related("control")
    if framework is not None:
        qs = qs.filter(requirement__framework=framework)
    if requirement_ids is not None:
        qs = qs.filter(requirement_id__in=requirement_ids)
    return qs


def framework_result(framework: Framework, org: Organisation) -> FrameworkResult:
    """Derived status for every tracked requirement (fixed number of queries)."""
    of = org_framework(org, framework)
    rows = list(
        Requirement.objects.filter(framework=framework, is_domain=False).values_list(
            "pk", "baselines"
        )
    )
    na = set(
        RequirementScope.objects.filter(
            organisation=org, requirement__framework=framework, applicable=False
        ).values_list("requirement_id", flat=True)
    )
    out_of_baseline = {pk for pk, bl in rows if of.baseline and of.baseline not in (bl or [])}
    tracked = [pk for pk, _ in rows if pk not in na and pk not in out_of_baseline]
    controls: dict[int, list[Control]] = defaultdict(list)
    for link in _org_control_links(org, framework=framework):
        controls[link.requirement_id].append(link.control)
    summary = Summary()
    for pk in tracked:
        summary.add(pk, requirement_status(c.status for c in controls.get(pk, [])))
    return FrameworkResult(framework, of, summary, dict(controls), na, out_of_baseline)


def requirement_state(
    requirement: Requirement, org: Organisation
) -> tuple[ReqStatus | None, list[Control], RequirementScope | None, bool]:
    """(status or None if not tracked, mapped controls, scope row, in baseline)."""
    controls = [link.control for link in _org_control_links(org, requirement_ids=[requirement.pk])]
    scope = RequirementScope.objects.filter(organisation=org, requirement=requirement).first()
    of = org_framework(org, requirement.framework)
    in_baseline = not of.baseline or of.baseline in (requirement.baselines or [])
    tracked = not requirement.is_domain and in_baseline and (scope is None or scope.applicable)
    status = requirement_status(c.status for c in controls) if tracked else None
    return status, sorted(controls, key=lambda c: c.ref), scope, in_baseline


# ----------------------------------------------------------------------------- mappings
@transaction.atomic
def map_control(requirement: Requirement, control: Control, *, user: Any) -> bool:
    if not can(user, Cap.EDIT_MAPPINGS):
        raise FrameworkError("You cannot change mappings.")
    if requirement.is_domain:
        raise FrameworkError("Map controls to requirements, not to domains.")
    if control.organisation_id != current_organisation(user).pk or control.archived_at:
        raise FrameworkError("That control is not available.")
    _, created = ControlRequirement.objects.get_or_create(control=control, requirement=requirement)
    if created:
        record(
            Action.UPDATE,
            control,
            actor=user,
            changes={
                "requirement_added": [None, f"{requirement.framework.code} {requirement.ref}"]
            },
        )
    return created


@transaction.atomic
def unmap_control(link: ControlRequirement, *, user: Any) -> None:
    if not can(user, Cap.EDIT_MAPPINGS):
        raise FrameworkError("You cannot change mappings.")
    label = f"{link.requirement.framework.code} {link.requirement.ref}"
    control = link.control
    link.delete()
    record(Action.UPDATE, control, actor=user, changes={"requirement_removed": [label, None]})


def related_requirements(
    requirement: Requirement, org: Organisation
) -> dict[str, list[Requirement]]:
    """Crosswalk links (both directions) and requirements sharing a mapped control."""
    crosswalk = {
        m.to_requirement
        for m in requirement.mappings_from.select_related("to_requirement__framework")
    } | {
        m.from_requirement
        for m in requirement.mappings_to.select_related("from_requirement__framework")
    }
    control_ids = _org_control_links(org, requirement_ids=[requirement.pk]).values_list(
        "control_id", flat=True
    )
    shared = set(
        Requirement.objects.filter(control_links__control_id__in=list(control_ids))
        .exclude(pk=requirement.pk)
        .select_related("framework")
    )
    key = lambda r: (r.framework.name, r.order)  # noqa: E731
    return {"crosswalk": sorted(crosswalk, key=key), "shared": sorted(shared - crosswalk, key=key)}


@dataclass
class CrossRow:
    control: Control
    by_framework: dict[Framework, list[Requirement]]

    @property
    def requirement_count(self) -> int:
        return sum(len(v) for v in self.by_framework.values())

    @property
    def framework_count(self) -> int:
        return len(self.by_framework)


def cross_framework(org: Organisation) -> list[CrossRow]:
    rows: dict[int, CrossRow] = {}
    for link in (
        _org_control_links(org)
        .select_related("requirement__framework")
        .order_by("requirement__framework__name", "requirement__order")
    ):
        row = rows.setdefault(link.control_id, CrossRow(link.control, {}))
        row.by_framework.setdefault(link.requirement.framework, []).append(link.requirement)
    return sorted(rows.values(), key=lambda r: (-r.requirement_count, r.control.ref))


# ----------------------------------------------------------------------------- import / seed
def import_framework_bytes(
    data: bytes,
    filename: str,
    *,
    user: Any = None,
    meta: dict[str, Any] | None = None,
    dry_run: bool = False,
    indicative: bool | None = None,
) -> importer.LoadResult:
    doc = importer.parse(data, filename, meta)
    result = importer.load(doc, dry_run=dry_run, indicative=indicative)
    if not dry_run:
        record(
            Action.IMPORT,
            result.framework,
            actor=user,
            changes={k: [None, v] for k, v in result.as_dict().items()},
        )
    return result


def load_crosswalk(path: Path | None = None) -> int:
    data = yaml.safe_load((path or DATA_DIR / "crosswalk.yaml").read_text(encoding="utf-8"))
    index = {(r.framework.code, r.ref): r for r in Requirement.objects.select_related("framework")}
    created = 0
    for m in data.get("mappings", []):
        a, b = index.get(tuple(m["from"])), index.get(tuple(m["to"]))
        if a and b:
            _, new = RequirementMapping.objects.get_or_create(
                from_requirement=a,
                to_requirement=b,
                defaults={
                    "relationship": m.get("relationship", "related"),
                    "source": MappingSource.SEED,
                    "indicative": True,
                },
            )
            created += int(new)
    return created


def apply_starter_requirement_mappings(org: Organisation) -> int:
    """Indicative control→requirement links for starter controls present in the org."""
    data = yaml.safe_load(STARTER_CONTROLS.read_text(encoding="utf-8"))
    controls = {c.ref: c for c in Control.objects.filter(organisation=org)}
    index = {(r.framework.code, r.ref): r for r in Requirement.objects.select_related("framework")}
    created = 0
    for item in data["controls"]:
        control = controls.get(str(item["ref"]).upper())
        if control is None:
            continue
        for code, refs in (item.get("requirements") or {}).items():
            for ref in refs:
                req = index.get((code, str(ref)))
                if req is None:
                    continue
                _, new = ControlRequirement.objects.get_or_create(
                    control=control,
                    requirement=req,
                    defaults={"source": MappingSource.SEED, "indicative": True},
                )
                created += int(new)
    return created


@dataclass
class SeedReport:
    frameworks: list[dict[str, Any]]
    crosswalk_created: int
    control_mappings_created: int


@transaction.atomic
def seed_frameworks(org: Organisation | None = None) -> SeedReport:
    results = []
    for name in SEED_FILES:
        path = DATA_DIR / name
        results.append(import_framework_bytes(path.read_bytes(), name, indicative=True).as_dict())
    crosswalk = load_crosswalk()
    mapped = apply_starter_requirement_mappings(org) if org else 0
    return SeedReport(results, crosswalk, mapped)


# ----------------------------------------------------------------------------- CTID
_CAPABILITY = re.compile(r"^([A-Z]{2})-0*(\d+)(?:\(0*(\d+)\))?$")


def normalise_nist_id(capability_id: str) -> str | None:
    """CTID 'AC-02' / 'AC-02(01)' -> NIST label 'AC-2' / 'AC-2(1)'."""
    m = _CAPABILITY.match(capability_id.strip().upper())
    if not m:
        return None
    return f"{m.group(1)}-{int(m.group(2))}" + (f"({int(m.group(3))})" if m.group(3) else "")


@dataclass
class CtidReport:
    attack_version: str
    created: int = 0
    existing: int = 0
    skipped_unknown_technique: int = 0
    skipped_revoked_technique: int = 0
    skipped_unknown_control: int = 0
    non_mappable: int = 0
    warnings: list[str] = field(default_factory=list)


@transaction.atomic
def import_ctid(
    payload: dict[str, Any], *, framework_code: str = "NIST-800-53-R5", user: Any = None
) -> CtidReport:
    meta = payload.get("metadata") or {}
    if (
        meta.get("mapping_framework") != "nist_800_53"
        or meta.get("mapping_framework_version") != "rev5"
    ):
        raise FrameworkError("Not a CTID NIST SP 800-53 rev5 mapping file.")
    framework = Framework.objects.filter(code=framework_code).first()
    if framework is None:
        raise FrameworkError("Load NIST SP 800-53 r5 first (seed_frameworks).")
    report = CtidReport(attack_version=str(meta.get("attack_version", "")))
    from threatledger.attack.services import current_release

    release = current_release()
    if release and report.attack_version and release.version != report.attack_version:
        report.warnings.append(
            f"Mappings target ATT&CK v{report.attack_version}; "
            f"loaded ATT&CK is v{release.version}. "
            "Techniques changed since then are skipped or kept as revoked."
        )
    reqs = {r.ref: r for r in Requirement.objects.filter(framework=framework)}
    techniques = {t.attack_id: t for t in Technique.objects.all()}
    existing = set(TechniqueRequirement.objects.values_list("technique_id", "requirement_id"))
    to_create = []
    for obj in payload.get("mapping_objects") or []:
        if obj.get("status") == "non_mappable" or not obj.get("capability_id"):
            report.non_mappable += 1
            continue
        technique = techniques.get(str(obj.get("attack_object_id", "")))
        if technique is None:
            report.skipped_unknown_technique += 1
            continue
        if technique.is_revoked:
            report.skipped_revoked_technique += 1
            continue
        ref = normalise_nist_id(str(obj["capability_id"]))
        req = reqs.get(ref or "")
        if req is None:
            report.skipped_unknown_control += 1
            continue
        key = (technique.pk, req.pk)
        if key in existing:
            report.existing += 1
            continue
        existing.add(key)
        to_create.append(
            TechniqueRequirement(
                technique=technique,
                requirement=req,
                mapping_type=str(obj.get("mapping_type") or "mitigates")[:32],
                source="ctid",
                attack_version=report.attack_version[:16],
                comments=str(obj.get("comments") or "")[:2000],
            )
        )
    TechniqueRequirement.objects.bulk_create(to_create, batch_size=1000)
    report.created = len(to_create)
    record(
        Action.IMPORT,
        framework,
        actor=user,
        changes={
            "ctid_attack_version": [None, report.attack_version],
            "created": [None, report.created],
            "skipped": [
                None,
                report.skipped_unknown_technique
                + report.skipped_revoked_technique
                + report.skipped_unknown_control,
            ],
        },
    )
    return report


def visible_frameworks(user: Any) -> QuerySet[Framework]:
    return Framework.objects.all() if can(user, Cap.VIEW_FRAMEWORKS) else Framework.objects.none()
