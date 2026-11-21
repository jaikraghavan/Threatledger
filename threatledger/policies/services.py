"""Policy business rules: versions, approval with segregation of duties, periodic review."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from django.db import transaction
from django.db.models import Max, QuerySet
from django.utils import timezone

from threatledger.accounts.permissions import can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.audit.models import Action
from threatledger.audit.services import diff, record, snapshot
from threatledger.core.dates import add_months
from threatledger.core.refs import next_ref

from .models import Policy, PolicyVersion, VersionStatus


class PolicyError(ValueError):
    """A business rule was violated (shown to the user)."""


POLICY_FIELDS = ("title", "kind", "summary", "owner", "review_interval_months")
VERSION_FIELDS = ("body", "document_url", "change_summary")
NOISE = ("updated_at", "created_at", "updated_by", "created_by")


def _changes(before: dict[str, Any], obj: Any) -> dict[str, Any]:
    changes = diff(before, snapshot(obj))
    for noise in NOISE:
        changes.pop(noise, None)
    return changes


def visible_policies(user: Any) -> QuerySet[Policy]:
    org = current_organisation(user)
    if org is None or not can(user, Cap.VIEW_POLICIES):
        return Policy.objects.none()
    return Policy.objects.filter(organisation=org)


def can_edit(user: Any, policy: Policy | None = None) -> bool:
    return can(user, Cap.EDIT_POLICIES) and (policy is None or policy.retired_at is None)


# ----------------------------------------------------------------------------- derived state
@dataclass
class PolicyState:
    published: PolicyVersion | None
    open_version: PolicyVersion | None  # draft or in review
    status: str  # draft | in_review | published | review_overdue | retired
    next_review_on: date | None

    @property
    def label(self) -> str:
        return {
            "draft": "Draft",
            "in_review": "In review",
            "published": "Published",
            "review_overdue": "Review overdue",
            "retired": "Retired",
        }[self.status]


def policy_state(policy: Policy, versions: list[PolicyVersion] | None = None) -> PolicyState:
    versions = list(policy.versions.all()) if versions is None else versions
    published = next((v for v in versions if v.status == VersionStatus.APPROVED), None)
    open_version = next(
        (v for v in versions if v.status in (VersionStatus.DRAFT, VersionStatus.IN_REVIEW)), None
    )
    next_review = None
    if published and published.decided_at:
        next_review = add_months(
            timezone.localtime(published.decided_at).date(), policy.review_interval_months
        )
    if policy.retired_at:
        status = "retired"
    elif published:
        status = (
            "review_overdue" if next_review and next_review < timezone.localdate() else "published"
        )
    elif open_version and open_version.status == VersionStatus.IN_REVIEW:
        status = "in_review"
    else:
        status = "draft"
    return PolicyState(published, open_version, status, next_review)


# ----------------------------------------------------------------------------- writes
@transaction.atomic
def create_policy(
    *, user: Any, data: dict[str, Any], body: str, controls: Any = (), requirements: Any = ()
) -> Policy:
    if not can_edit(user):
        raise PolicyError("You cannot create policies.")
    org = current_organisation(user)
    policy = Policy(
        organisation=org,
        created_by=user,
        updated_by=user,
        **{k: v for k, v in data.items() if k in POLICY_FIELDS},
    )
    policy.ref = next_ref(Policy, org, "POL", width=3)
    policy.full_clean(exclude=["organisation", "created_by", "updated_by"])
    policy.save()
    _set_links(policy, controls, requirements)
    record(Action.CREATE, policy, actor=user, changes=_changes({}, policy))
    PolicyVersion.objects.create(
        policy=policy, number=1, body=body, author=user, change_summary="First draft"
    )
    return policy


def _set_links(policy: Policy, controls: Any, requirements: Any) -> None:
    controls = list(controls)
    if any(c.organisation_id != policy.organisation_id for c in controls):
        raise PolicyError("Unknown control.")
    policy.controls.set(controls)
    policy.requirements.set(list(requirements))


@transaction.atomic
def update_policy(
    policy: Policy,
    *,
    user: Any,
    data: dict[str, Any],
    controls: Any = None,
    requirements: Any = None,
) -> Policy:
    if not can_edit(user, policy):
        raise PolicyError("You cannot edit this policy.")
    before = snapshot(policy)
    before_links = (
        sorted(policy.controls.values_list("ref", flat=True)),
        sorted(policy.requirements.values_list("pk", flat=True)),
    )
    for key, value in data.items():
        if key in POLICY_FIELDS:
            setattr(policy, key, value)
    policy.updated_by = user
    policy.full_clean(exclude=["organisation", "created_by", "updated_by"])
    policy.save()
    if controls is not None or requirements is not None:
        _set_links(
            policy,
            policy.controls.all() if controls is None else controls,
            policy.requirements.all() if requirements is None else requirements,
        )
    changes = _changes(before, policy)
    after_links = (
        sorted(policy.controls.values_list("ref", flat=True)),
        sorted(policy.requirements.values_list("pk", flat=True)),
    )
    if after_links[0] != before_links[0]:
        changes["controls"] = [before_links[0], after_links[0]]
    if after_links[1] != before_links[1]:
        changes["requirements"] = [before_links[1], after_links[1]]
    if changes:
        record(Action.UPDATE, policy, actor=user, changes=changes)
    return policy


@transaction.atomic
def start_revision(policy: Policy, *, user: Any) -> PolicyVersion:
    if not can_edit(user, policy):
        raise PolicyError("You cannot revise this policy.")
    state = policy_state(policy)
    if state.open_version:
        raise PolicyError(f"{state.open_version.label} is already open; finish it first.")
    number = (policy.versions.aggregate(n=Max("number"))["n"] or 0) + 1
    base = state.published
    version = PolicyVersion.objects.create(
        policy=policy,
        number=number,
        body=base.body if base else "",
        document_url=base.document_url if base else "",
        author=user,
    )
    record(Action.CREATE, version, actor=user, changes={"number": [None, number]})
    return version


@transaction.atomic
def edit_version(version: PolicyVersion, *, user: Any, data: dict[str, Any]) -> PolicyVersion:
    if not can_edit(user, version.policy):
        raise PolicyError("You cannot edit this policy.")
    if version.status != VersionStatus.DRAFT:
        raise PolicyError("Only drafts can be edited.")
    before = snapshot(version)
    for key, value in data.items():
        if key in VERSION_FIELDS:
            setattr(version, key, value)
    version.full_clean()
    version.save()
    changes = _changes(before, version)
    if changes:
        changes.pop("body", None)
        changes["body_changed"] = [None, before.get("body") != version.body]
        record(Action.UPDATE, version, actor=user, changes=changes)
    return version


@transaction.atomic
def submit_version(version: PolicyVersion, *, user: Any) -> PolicyVersion:
    if not can_edit(user, version.policy):
        raise PolicyError("You cannot submit this policy.")
    if version.status != VersionStatus.DRAFT:
        raise PolicyError("Only drafts can be submitted.")
    if not version.body.strip() and not version.document_url:
        raise PolicyError("Write the policy text or link the document first.")
    version.status = VersionStatus.IN_REVIEW
    version.submitted_at = timezone.now()
    version.save()
    record(Action.UPDATE, version, actor=user, changes={"status": ["draft", "in_review"]})
    return version


@transaction.atomic
def decide_version(
    version: PolicyVersion, *, user: Any, approve: bool, note: str = ""
) -> PolicyVersion:
    if not can(user, Cap.APPROVE_POLICIES):
        raise PolicyError("You cannot approve policies.")
    if version.status != VersionStatus.IN_REVIEW:
        raise PolicyError("Only versions in review can be decided.")
    if version.author_id == user.pk:
        raise PolicyError("Segregation of duties: you cannot approve a version you wrote.")
    if not approve and not note.strip():
        raise PolicyError("Explain what needs to change.")
    now = timezone.now()
    if approve:
        for old in version.policy.versions.filter(status=VersionStatus.APPROVED):
            old.status = VersionStatus.SUPERSEDED
            old.save(update_fields=["status"])
            record(Action.UPDATE, old, actor=user, changes={"status": ["approved", "superseded"]})
        version.status = VersionStatus.APPROVED
        version.effective_on = timezone.localdate()
    else:
        version.status = VersionStatus.DRAFT  # back to the author for changes
    version.decided_by, version.decided_at = user, now
    version.decision_note = note.strip()[:500]
    version.save()
    record(
        Action.UPDATE,
        version,
        actor=user,
        changes={
            "status": ["in_review", version.status],
            "decision": [None, "approved" if approve else "changes requested"],
            "note": [None, version.decision_note],
        },
    )
    return version


@transaction.atomic
def confirm_review(policy: Policy, *, user: Any, note: str = "") -> PolicyVersion:
    """Periodic review with no changes: re-approve the published text as a new version."""
    if not can(user, Cap.APPROVE_POLICIES) or not can_edit(user, policy):
        raise PolicyError("You cannot review this policy.")
    state = policy_state(policy)
    if state.published is None:
        raise PolicyError("There is no published version to review.")
    if state.open_version:
        raise PolicyError("Finish the open revision instead.")
    published = state.published
    if published.author_id == user.pk:
        raise PolicyError("Segregation of duties: someone other than the author must review it.")
    number = (policy.versions.aggregate(n=Max("number"))["n"] or 0) + 1
    published.status = VersionStatus.SUPERSEDED
    published.save(update_fields=["status"])
    now = timezone.now()
    version = PolicyVersion.objects.create(
        policy=policy,
        number=number,
        body=published.body,
        document_url=published.document_url,
        change_summary=f"Periodic review, no changes. {note.strip()}"[:500].strip(),
        status=VersionStatus.APPROVED,
        author=published.author,
        submitted_at=now,
        decided_by=user,
        decided_at=now,
        effective_on=timezone.localdate(),
    )
    record(Action.CREATE, version, actor=user, changes={"review": [None, "no changes"]})
    return version


@transaction.atomic
def set_retired(policy: Policy, *, user: Any, retired: bool) -> Policy:
    if not can(user, Cap.EDIT_POLICIES):
        raise PolicyError("You cannot retire policies.")
    before = snapshot(policy)
    policy.retired_at = timezone.now() if retired else None
    policy.updated_by = user
    policy.save()
    record(Action.UPDATE, policy, actor=user, changes=_changes(before, policy))
    return policy
