from __future__ import annotations

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.roles import Role
from threatledger.audit.models import AuditEvent
from threatledger.policies import services
from threatledger.policies.models import Policy, VersionStatus
from threatledger.risks.tests.helpers import make_control

pytestmark = pytest.mark.django_db


@pytest.fixture
def rm(users):
    return users[Role.RISK_MANAGER]


@pytest.fixture
def admin(users):
    return users[Role.ADMIN]


def _policy(user, org=None, **data):
    controls = [make_control(org, "CTL-MFA")] if org else []
    return services.create_policy(
        user=user,
        data={"title": "Access control policy", "kind": "policy", **data},
        body="All remote access uses MFA.",
        controls=controls,
    )


def test_new_policy_starts_as_draft_v1(rm, org):
    p = _policy(rm, org)
    state = services.policy_state(p)
    assert p.ref == "POL-001" and state.status == "draft" and state.published is None
    assert state.open_version is not None and state.open_version.number == 1
    assert state.label == "Draft"
    assert [c.ref for c in p.controls.all()] == ["CTL-MFA"]


def test_only_editors_create(users):
    for role in (Role.AUDITOR, Role.CONTROL_OWNER, Role.VIEWER):
        with pytest.raises(services.PolicyError):
            _policy(users[role])


def test_approval_needs_another_person_and_supersedes(rm, admin):
    p = _policy(rm)
    v1 = p.versions.get()
    with pytest.raises(services.PolicyError, match="Write the policy"):
        services.submit_version(services.edit_version(v1, user=rm, data={"body": " "}), user=rm)
    services.edit_version(v1, user=rm, data={"body": "Text v1"})
    services.submit_version(v1, user=rm)
    assert services.policy_state(p).status == "in_review"
    with pytest.raises(services.PolicyError, match="Segregation"):
        services.decide_version(v1, user=rm, approve=True)
    with pytest.raises(services.PolicyError, match="Explain"):
        services.decide_version(v1, user=admin, approve=False)
    services.decide_version(v1, user=admin, approve=False, note="Add scope")
    assert v1.status == VersionStatus.DRAFT  # back to the author
    services.submit_version(v1, user=rm)
    services.decide_version(v1, user=admin, approve=True)
    state = services.policy_state(p)
    assert state.status == "published" and state.published == v1
    assert state.next_review_on is not None

    v2 = services.start_revision(p, user=rm)
    assert v2.number == 2 and v2.body == "Text v1"
    with pytest.raises(services.PolicyError, match="already open"):
        services.start_revision(p, user=rm)
    services.edit_version(v2, user=rm, data={"body": "Text v2", "change_summary": "Scope"})
    services.submit_version(v2, user=rm)
    with pytest.raises(services.PolicyError, match="Only drafts"):
        services.edit_version(v2, user=rm, data={"body": "sneaky"})
    services.decide_version(v2, user=admin, approve=True)
    v1.refresh_from_db()
    assert v1.status == VersionStatus.SUPERSEDED
    assert services.policy_state(p).published == v2
    assert AuditEvent.objects.filter(object_type="policies.policyversion").count() >= 5


def test_review_overdue_and_confirm_review(rm, admin):
    p = _policy(rm, review_interval_months=6)
    v1 = p.versions.get()
    services.submit_version(v1, user=rm)
    services.decide_version(v1, user=admin, approve=True)
    v1.decided_at = timezone.now() - timedelta(days=200)
    v1.save()
    assert services.policy_state(p).status == "review_overdue"
    with pytest.raises(services.PolicyError, match="Segregation"):
        services.confirm_review(p, user=rm)  # rm wrote the text
    v3 = services.confirm_review(p, user=admin, note="Still accurate")
    state = services.policy_state(p)
    assert state.status == "published" and state.published == v3
    assert v3.body == v1.body and v3.author == rm


def test_retire_and_restore(rm):
    p = _policy(rm)
    services.set_retired(p, user=rm, retired=True)
    assert services.policy_state(p).status == "retired"
    with pytest.raises(services.PolicyError):
        services.update_policy(p, user=rm, data={"title": "x"})
    services.set_retired(p, user=rm, retired=False)
    services.update_policy(p, user=rm, data={"title": "Renamed"}, controls=[])
    assert Policy.objects.get(pk=p.pk).title == "Renamed"


def test_policy_views(client_for, rm, admin, org):
    c = client_for(Role.RISK_MANAGER)
    r = c.post(
        reverse("policies:create"),
        {
            "title": "Backup standard",
            "kind": "standard",
            "review_interval_months": 12,
            "body": "Daily backups.",
        },
    )
    p = Policy.objects.get(title="Backup standard")
    assert r.status_code == 302
    v1 = p.versions.get()
    c.post(
        reverse("policies:version_edit", args=[p.ref, v1.number]),
        {"body": "Daily, tested quarterly.", "submit": "1"},
    )
    v1.refresh_from_db()
    assert v1.status == "in_review"
    a = client_for(Role.ADMIN)
    page = a.get(reverse("policies:detail", args=[p.ref]))
    assert b"Approve and publish" in page.content
    a.post(reverse("policies:version_decide", args=[p.ref, 1]), {"decision": "approve"})
    assert services.policy_state(p).status == "published"
    c.post(reverse("policies:revise", args=[p.ref]))
    assert p.versions.count() == 2
    viewer = client_for(Role.VIEWER)
    assert viewer.get(reverse("policies:list")).status_code == 200
    assert viewer.get(reverse("policies:detail", args=[p.ref])).status_code == 200
    assert viewer.get(reverse("policies:create")).status_code == 403
    assert (
        c.get(reverse("policies:list"), {"status": "published", "kind": "standard"}).status_code
        == 200
    )
