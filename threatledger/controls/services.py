"""Control library business rules. All writes go through here (audit in one place)."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import yaml
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import UploadedFile
from django.core.mail import send_mail
from django.db import transaction
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.permissions import can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.attack.models import Mitigation, MitigationTechnique, Technique
from threatledger.audit.models import Action
from threatledger.audit.services import diff, record, snapshot
from threatledger.org.models import Organisation

from .models import (
    Control,
    ControlMitigation,
    ControlQuerySet,
    ControlStatus,
    ControlTechnique,
    ControlTest,
    ControlType,
    Evidence,
    MappingSource,
)
from .uploads import validate_upload

logger = logging.getLogger(__name__)

STARTER_FILE = Path(settings.BASE_DIR) / "data" / "controls" / "starter.yaml"
# Fields a control owner may change on their own controls (operational, not design).
OWNER_FIELDS = frozenset({"status", "effectiveness", "description"})
EXPIRY_STAGES = ((3, 0), (2, 7), (1, 30))  # (stage, days before expiry) highest first


class ControlError(ValueError):
    """A business rule was violated (shown to the user)."""


# ----------------------------------------------------------------------------- access
def visible_controls(user: Any) -> ControlQuerySet:
    org = current_organisation(user)
    if org is None or not can(user, Cap.VIEW_CONTROLS):
        return Control.objects.none()
    return Control.objects.filter(organisation=org)


def can_edit_fully(user: Any) -> bool:
    return can(user, Cap.EDIT_ANY_CONTROL)


def can_edit(user: Any, control: Control) -> bool:
    return control.archived_at is None and can(user, Cap.EDIT_OWN_CONTROL, control)


def can_upload(user: Any, control: Control) -> bool:
    return control.archived_at is None and can(user, Cap.UPLOAD_EVIDENCE, control)


def can_map(user: Any, control: Control) -> bool:
    return control.archived_at is None and can(user, Cap.EDIT_MAPPINGS)


def _audit(action: Action, obj: Any, user: Any, before: dict[str, Any]) -> None:
    changes = diff(before, snapshot(obj))
    for noise in ("updated_at", "created_at", "updated_by", "created_by"):
        changes.pop(noise, None)
    if changes:
        record(action, obj, actor=user, changes=changes)


# ----------------------------------------------------------------------------- CRUD
@transaction.atomic
def create_control(*, user: Any, data: dict[str, Any]) -> Control:
    if not can_edit_fully(user):
        raise ControlError("You cannot create controls.")
    org = current_organisation(user)
    control = Control(organisation=org, created_by=user, updated_by=user, **data)
    control.ref = control.ref.strip().upper()
    if Control.objects.filter(organisation=org, ref__iexact=control.ref).exists():
        raise ValidationError({"ref": "A control with this reference already exists."})
    control.full_clean(exclude=["organisation", "created_by", "updated_by"])
    control.save()
    _audit(Action.CREATE, control, user, {})
    return control


@transaction.atomic
def update_control(control: Control, *, user: Any, data: dict[str, Any]) -> Control:
    if not can_edit(user, control):
        raise ControlError("You cannot edit this control.")
    if not can_edit_fully(user) and set(data) - OWNER_FIELDS:
        raise ControlError("Control owners may only change status, effectiveness and description.")
    before = snapshot(control)
    for key, value in data.items():
        setattr(control, key, value)
    if "ref" in data:
        control.ref = control.ref.strip().upper()
        clash = Control.objects.filter(organisation=control.organisation, ref__iexact=control.ref)
        if clash.exclude(pk=control.pk).exists():
            raise ValidationError({"ref": "A control with this reference already exists."})
    control.updated_by = user
    control.full_clean(exclude=["organisation", "created_by", "updated_by"])
    control.save()
    _audit(Action.UPDATE, control, user, before)
    return control


@transaction.atomic
def set_archived(control: Control, *, user: Any, archived: bool) -> Control:
    if not can_edit_fully(user):
        raise ControlError("You cannot archive controls.")
    if archived == (control.archived_at is not None):
        return control
    control.archived_at = timezone.now() if archived else None
    control.updated_by = user
    control.save(update_fields=["archived_at", "updated_by", "updated_at"])
    record(Action.UPDATE, control, actor=user, changes={"archived": [not archived, archived]})
    return control


# ----------------------------------------------------------------------------- mappings
@transaction.atomic
def add_mitigation(control: Control, mitigation: Mitigation, *, user: Any) -> bool:
    if not can_map(user, control):
        raise ControlError("You cannot change this control's mappings.")
    if not mitigation.is_active:
        raise ControlError(f"{mitigation.attack_id} is deprecated or revoked.")
    _, created = ControlMitigation.objects.get_or_create(control=control, mitigation=mitigation)
    if created:
        record(
            Action.UPDATE,
            control,
            actor=user,
            changes={"mitigation_added": [None, str(mitigation)]},
        )
    return created


@transaction.atomic
def remove_mitigation(control: Control, link: ControlMitigation, *, user: Any) -> None:
    if not can_map(user, control) or link.control_id != control.pk:
        raise ControlError("You cannot change this control's mappings.")
    label = str(link.mitigation)
    link.delete()
    record(Action.UPDATE, control, actor=user, changes={"mitigation_removed": [label, None]})


@transaction.atomic
def add_technique(control: Control, technique: Technique, *, user: Any) -> bool:
    if not can_map(user, control):
        raise ControlError("You cannot change this control's mappings.")
    if not technique.is_active:
        raise ControlError(f"{technique.attack_id} is revoked or deprecated; map its replacement.")
    _, created = ControlTechnique.objects.get_or_create(control=control, technique=technique)
    if created:
        record(
            Action.UPDATE, control, actor=user, changes={"technique_added": [None, str(technique)]}
        )
    return created


@transaction.atomic
def remove_technique(control: Control, link: ControlTechnique, *, user: Any) -> None:
    if not can_map(user, control) or link.control_id != control.pk:
        raise ControlError("You cannot change this control's mappings.")
    label = str(link.technique)
    link.delete()
    record(Action.UPDATE, control, actor=user, changes={"technique_removed": [label, None]})


@dataclass(frozen=True)
class CoveredTechnique:
    technique: Technique
    direct: bool
    via: tuple[Mitigation, ...]  # mitigations through which the control reaches it


def covered_techniques(control: Control) -> list[CoveredTechnique]:
    """Active techniques this control addresses, directly or via mitigations it implements."""
    direct = set(control.technique_links.values_list("technique_id", flat=True))
    via: dict[int, list[Mitigation]] = defaultdict(list)
    mitigations = {m.pk: m for m in control.mitigations.all()}
    for mid, tid in MitigationTechnique.objects.filter(mitigation_id__in=mitigations).values_list(
        "mitigation_id", "technique_id"
    ):
        via[tid].append(mitigations[mid])
    techniques = Technique.objects.active().in_bulk(direct | set(via))
    out = [
        CoveredTechnique(
            t, t.pk in direct, tuple(sorted(via.get(t.pk, []), key=lambda m: m.attack_id))
        )
        for t in techniques.values()
    ]
    return sorted(out, key=lambda c: c.technique.attack_id)


# ----------------------------------------------------------------------------- evidence
@transaction.atomic
def add_file_evidence(
    control: Control,
    *,
    user: Any,
    upload: UploadedFile,
    title: str,
    description: str = "",
    valid_until: date | None = None,
) -> Evidence:
    if not can_upload(user, control):
        raise ControlError("You cannot add evidence to this control.")
    checked = validate_upload(upload)
    evidence = Evidence(
        control=control,
        kind=Evidence.Kind.FILE,
        title=(title or checked.original_filename)[:200],
        description=description,
        original_filename=checked.original_filename,
        content_type=checked.content_type,
        size=checked.size,
        sha256=checked.sha256,
        uploaded_by=user,
        valid_until=valid_until,
    )
    evidence.file.save(checked.original_filename, upload, save=False)
    evidence.save()
    record(
        Action.CREATE,
        evidence,
        actor=user,
        changes={
            "control": [None, control.ref],
            "file": [None, checked.original_filename],
            "sha256": [None, checked.sha256],
            "size": [None, checked.size],
        },
    )
    return evidence


@transaction.atomic
def add_link_evidence(
    control: Control,
    *,
    user: Any,
    url: str,
    title: str,
    description: str = "",
    valid_until: date | None = None,
) -> Evidence:
    if not can_upload(user, control):
        raise ControlError("You cannot add evidence to this control.")
    if not url.lower().startswith(("https://", "http://")):
        raise ValidationError({"url": "Only http(s) links are allowed."})
    evidence = Evidence(
        control=control,
        kind=Evidence.Kind.LINK,
        title=title[:200] or url[:200],
        description=description,
        url=url,
        uploaded_by=user,
        valid_until=valid_until,
    )
    evidence.full_clean(exclude=["file", "control", "uploaded_by"])
    evidence.save()
    record(
        Action.CREATE,
        evidence,
        actor=user,
        changes={"control": [None, control.ref], "url": [None, url]},
    )
    return evidence


@transaction.atomic
def archive_evidence(evidence: Evidence, *, user: Any) -> None:
    """Evidence is retained for audit; archiving hides it without deleting the file."""
    if not (can_edit_fully(user) or evidence.uploaded_by_id == user.pk):
        raise ControlError("Only the uploader or a risk manager can archive evidence.")
    evidence.archived_at = timezone.now()
    evidence.save(update_fields=["archived_at"])
    record(Action.UPDATE, evidence, actor=user, changes={"archived": [False, True]})


def record_download(evidence: Evidence, user: Any) -> None:
    record(
        Action.EXPORT,
        evidence,
        actor=user,
        changes={
            "download": [None, evidence.original_filename],
            "control": [None, evidence.control.ref],
        },
    )


# ----------------------------------------------------------------------------- testing
@transaction.atomic
def record_test(
    control: Control,
    *,
    user: Any,
    tested_on: date,
    method: str,
    result: str,
    notes: str = "",
    evidence: list[Evidence] | None = None,
) -> ControlTest:
    if not can_edit(user, control):
        raise ControlError("You cannot record tests for this control.")
    if tested_on > timezone.localdate():
        raise ValidationError({"tested_on": "Test date cannot be in the future."})
    evidence = evidence or []
    if any(e.control_id != control.pk for e in evidence):
        raise ControlError("Evidence must belong to this control.")
    test = ControlTest.objects.create(
        control=control, tested_on=tested_on, tester=user, method=method, result=result, notes=notes
    )
    test.evidence.set(evidence)
    before = snapshot(control)
    if control.last_tested_at is None or tested_on >= control.last_tested_at:
        control.last_tested_at = tested_on
        control.last_test_result = result
        control.save(update_fields=["last_tested_at", "last_test_result", "updated_at"])
    record(
        Action.CREATE,
        test,
        actor=user,
        changes={
            "control": [None, control.ref],
            "result": [None, result],
            "tested_on": [None, tested_on.isoformat()],
        },
    )
    _audit(Action.UPDATE, control, user, before)
    return test


# ----------------------------------------------------------------------------- starter set
@dataclass
class SeedResult:
    created: list[str]
    skipped: list[str]
    missing_attack_ids: list[str]
    requirement_mappings: int = 0


@transaction.atomic
def seed_starter_controls(
    org: Organisation, *, user: Any = None, path: Path = STARTER_FILE
) -> SeedResult:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    result = SeedResult([], [], [])
    existing = set(Control.objects.filter(organisation=org).values_list("ref", flat=True))
    mitigations = {m.attack_id: m for m in Mitigation.objects.active()}
    techniques = {t.attack_id: t for t in Technique.objects.active()}
    for item in data["controls"]:
        ref = str(item["ref"]).upper()
        if ref in existing:
            result.skipped.append(ref)
            continue
        control = Control.objects.create(
            organisation=org,
            ref=ref,
            name=item["name"],
            description=item.get("description", ""),
            control_type=ControlType(item.get("type", "preventive")),
            status=ControlStatus.NOT_IMPLEMENTED,  # honest starting point: assess, then update
            created_by=user,
            updated_by=user,
        )
        for mid in item.get("mitigations") or []:
            if mid in mitigations:
                ControlMitigation.objects.create(
                    control=control, mitigation=mitigations[mid], source=MappingSource.SEED
                )
            else:
                result.missing_attack_ids.append(mid)
        for tid in item.get("techniques") or []:
            if tid in techniques:
                ControlTechnique.objects.create(
                    control=control, technique=techniques[tid], source=MappingSource.SEED
                )
            else:
                result.missing_attack_ids.append(tid)
        record(
            Action.CREATE,
            control,
            actor=user,
            changes={"ref": [None, ref], "source": [None, "starter set"]},
        )
        result.created.append(ref)
    # Framework requirement mappings, if frameworks are loaded (seeding order doesn't matter).
    from threatledger.frameworks.services import apply_starter_requirement_mappings

    result.requirement_mappings = apply_starter_requirement_mappings(org)
    return result


# ----------------------------------------------------------------------------- expiry alerts
def _stage_for(valid_until: date, today: date) -> int:
    days = (valid_until - today).days
    for stage, threshold in EXPIRY_STAGES:
        if days <= threshold:
            return stage
    return 0


def send_evidence_expiry_alerts(today: date | None = None) -> int:
    """Daily job: notify control owners when evidence is 30 / 7 days from expiry and when
    it has expired. Each stage is notified once per evidence item."""
    today = today or timezone.localdate()
    candidates = (
        Evidence.objects.filter(
            archived_at__isnull=True,
            valid_until__isnull=False,
            valid_until__lte=today + timedelta(days=30),
            control__archived_at__isnull=True,
        )
        .select_related("control", "control__owner", "uploaded_by")
        .order_by("valid_until")
    )
    by_recipient: dict[int, list[tuple[Evidence, int]]] = defaultdict(list)
    recipients: dict[int, Any] = {}
    for ev in candidates:
        stage = _stage_for(ev.valid_until, today)  # type: ignore[arg-type]
        if stage <= ev.expiry_notice_stage:
            continue
        person = ev.control.owner or ev.uploaded_by
        if not person.is_active or not person.email:
            continue
        recipients[person.pk] = person
        by_recipient[person.pk].append((ev, stage))
    sent = 0
    for pk, items in by_recipient.items():
        person = recipients[pk]
        lines = []
        for ev, _stage in items:
            state = "EXPIRED" if ev.valid_until <= today else "expires"  # type: ignore[operator]
            path = reverse("controls:detail", args=[ev.control.ref])
            url = f"{settings.SITE_URL.rstrip('/')}{path}"
            lines.append(
                f"{state} {ev.valid_until:%Y-%m-%d}  {ev.control.ref} — {ev.title}\n    {url}"
            )
        try:
            send_mail(
                f"[ThreatLedger] {len(items)} evidence item(s) expiring",
                f"Hello {person.get_short_name() or person.get_username()},\n\n"
                "Evidence for controls you own needs refreshing:\n\n"
                + "\n".join(lines)
                + "\n\nUpload current evidence so the control keeps counting as tested."
                + "\n\n— ThreatLedger",
                settings.DEFAULT_FROM_EMAIL,
                [person.email],
            )
        except Exception:
            logger.exception("evidence expiry email failed for user %s", pk)
            continue
        for ev, stage in items:
            Evidence.objects.filter(pk=ev.pk).update(expiry_notice_stage=stage)
        sent += 1
    return sent
