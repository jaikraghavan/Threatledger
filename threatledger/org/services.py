"""Business-unit hierarchy (perimeters). All writes go through here and are audited."""

from __future__ import annotations

from typing import Any

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import ProtectedError

from threatledger.accounts.permissions import can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.audit.models import Action
from threatledger.audit.services import diff, record, snapshot

from .models import BusinessUnit, descendant_ids


class OrgError(ValueError):
    """A business rule was violated (shown to the user)."""


def _require(user: Any) -> None:
    if not can(user, Cap.MANAGE_SETTINGS):
        raise OrgError("Only administrators can change business units.")


def _check_parent(bu: BusinessUnit, parent: BusinessUnit | None) -> None:
    if parent is None:
        return
    if parent.organisation_id != bu.organisation_id:
        raise ValidationError({"parent": "Parent must belong to the same organisation."})
    if bu.pk and parent.pk in descendant_ids(bu.organisation_id, {bu.pk}):
        raise ValidationError({"parent": "A unit cannot sit inside itself or its own sub-units."})


@transaction.atomic
def create_business_unit(*, user: Any, data: dict[str, Any]) -> BusinessUnit:
    _require(user)
    bu = BusinessUnit(organisation=current_organisation(user), **data)
    _check_parent(bu, bu.parent)
    bu.full_clean()
    bu.save()
    record(Action.CREATE, bu, actor=user, changes=diff({}, snapshot(bu)))
    return bu


@transaction.atomic
def update_business_unit(bu: BusinessUnit, *, user: Any, data: dict[str, Any]) -> BusinessUnit:
    _require(user)
    before = snapshot(bu)
    for key, value in data.items():
        setattr(bu, key, value)
    _check_parent(bu, bu.parent)
    bu.full_clean()
    bu.save()
    changes = diff(before, snapshot(bu))
    if changes:
        record(Action.UPDATE, bu, actor=user, changes=changes)
    return bu


@transaction.atomic
def delete_business_unit(bu: BusinessUnit, *, user: Any) -> None:
    _require(user)
    if bu.children.exists():
        raise OrgError("Move or delete its sub-units first.")
    if bu.members.exists():
        raise OrgError("Remove it from user memberships first.")
    before = snapshot(bu)
    try:
        bu.delete()
    except ProtectedError as exc:
        raise OrgError("It is still used by risks, assets or other records.") from exc
    record(
        Action.DELETE,
        actor=user,
        object_type="org.businessunit",
        object_id=str(before.get("id", "")),
        object_repr=str(before.get("name", "")),
        changes=diff(before, {}),
    )


WORKFLOW_LABELS = {
    "require_evidence_review": "Four-eyes evidence review: new evidence waits for someone other "
    "than the uploader to accept it.",
    "control_status_approval": "Control owners' status changes need approval from a risk manager "
    "before coverage and compliance change.",
}


@transaction.atomic
def set_workflow(org: Any, *, user: Any, values: dict[str, bool]) -> None:
    _require(user)
    from .models import Organisation

    org = Organisation.objects.select_for_update().get(pk=org.pk)
    settings = dict(org.settings or {})
    changes = {}
    for key in Organisation.WORKFLOW_DEFAULTS:
        if key in values:
            before = org.workflow(key)
            settings[key] = bool(values[key])
            if before != settings[key]:
                changes[key] = [before, settings[key]]
    org.settings = settings
    org.save(update_fields=["settings"])
    if changes:
        record(Action.UPDATE, org, actor=user, changes=changes)
