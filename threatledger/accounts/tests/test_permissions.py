from __future__ import annotations

from types import SimpleNamespace

import pytest

from threatledger.accounts.permissions import can, capabilities, clear_role_cache, get_role
from threatledger.accounts.roles import ROLE_CAPABILITIES, Cap, Role

pytestmark = pytest.mark.django_db


def test_every_role_has_an_entry_in_the_matrix():
    assert set(ROLE_CAPABILITIES) == set(Role)


def test_admin_has_every_capability():
    assert ROLE_CAPABILITIES[Role.ADMIN] == frozenset(Cap)


# Expected matrix from PLAN.md §3.1 — a change here must be a deliberate design decision.
EXPECTED = {
    Cap.MANAGE_USERS: {Role.ADMIN},
    Cap.MANAGE_SETTINGS: {Role.ADMIN},
    Cap.RUN_IMPORTS: {Role.ADMIN},
    Cap.EDIT_RISKS: {Role.ADMIN, Role.RISK_MANAGER},
    Cap.APPROVE_ACCEPTANCE: {Role.ADMIN, Role.RISK_MANAGER},
    Cap.EDIT_ANY_CONTROL: {Role.ADMIN, Role.RISK_MANAGER},
    Cap.EDIT_FRAMEWORKS: {Role.ADMIN, Role.RISK_MANAGER},
    Cap.EDIT_MAPPINGS: {Role.ADMIN, Role.RISK_MANAGER},
    Cap.EDIT_OWN_CONTROL: {Role.ADMIN, Role.RISK_MANAGER, Role.CONTROL_OWNER},
    Cap.UPLOAD_EVIDENCE: {Role.ADMIN, Role.RISK_MANAGER, Role.CONTROL_OWNER},
    Cap.VIEW_EVIDENCE: {Role.ADMIN, Role.RISK_MANAGER, Role.CONTROL_OWNER, Role.AUDITOR},
    Cap.VIEW_AUDIT_LOG: {Role.ADMIN, Role.RISK_MANAGER, Role.CONTROL_OWNER, Role.AUDITOR},
    Cap.EXPORT_DATA: {Role.ADMIN, Role.RISK_MANAGER, Role.CONTROL_OWNER, Role.AUDITOR},
    Cap.VIEW_DASHBOARD: set(Role),
    Cap.VIEW_RISKS: set(Role),
    Cap.VIEW_CONTROLS: set(Role),
    Cap.VIEW_FRAMEWORKS: set(Role),
    Cap.VIEW_ATTACK: set(Role),
    # Phase 8 governance
    Cap.VIEW_POLICIES: set(Role),
    Cap.VIEW_AUDITS: {Role.ADMIN, Role.RISK_MANAGER, Role.CONTROL_OWNER, Role.AUDITOR},
    Cap.VIEW_FINDINGS: {Role.ADMIN, Role.RISK_MANAGER, Role.CONTROL_OWNER, Role.AUDITOR},
    Cap.MANAGE_AUDITS: {Role.ADMIN, Role.RISK_MANAGER},
    Cap.PERFORM_AUDITS: {Role.ADMIN, Role.RISK_MANAGER, Role.AUDITOR},
    Cap.RAISE_FINDINGS: {Role.ADMIN, Role.RISK_MANAGER, Role.AUDITOR},
    Cap.EDIT_FINDINGS: {Role.ADMIN, Role.RISK_MANAGER},
    Cap.UPDATE_OWN_FINDING: {Role.ADMIN, Role.RISK_MANAGER, Role.CONTROL_OWNER},
    Cap.REQUEST_EXCEPTION: {Role.ADMIN, Role.RISK_MANAGER, Role.CONTROL_OWNER},
    Cap.APPROVE_EXCEPTION: {Role.ADMIN, Role.RISK_MANAGER},
    Cap.EDIT_POLICIES: {Role.ADMIN, Role.RISK_MANAGER},
    Cap.APPROVE_POLICIES: {Role.ADMIN, Role.RISK_MANAGER},
}


def test_expected_matrix_covers_every_capability():
    assert set(EXPECTED) == set(Cap)


@pytest.mark.parametrize("cap", list(Cap))
def test_role_matrix(users, cap):
    for role, user in users.items():
        assert can(user, cap) is (role in EXPECTED[cap]), f"{role} / {cap}"


def test_auditor_and_viewer_have_no_write_capabilities():
    writes = {
        c for c in Cap if c.value.startswith(("edit_", "manage_", "approve_", "upload_", "run_"))
    }
    assert not writes & ROLE_CAPABILITIES[Role.AUDITOR]
    assert not writes & ROLE_CAPABILITIES[Role.VIEWER]


def test_auditor_only_writes_audit_judgements_and_findings():
    """Auditor independence: they record judgements and raise findings, nothing else."""
    reads = {c for c in Cap if c.value.startswith(("view_", "export_"))}
    assert ROLE_CAPABILITIES[Role.AUDITOR] - reads == {Cap.PERFORM_AUDITS, Cap.RAISE_FINDINGS}
    assert not (ROLE_CAPABILITIES[Role.VIEWER] - reads)


def test_anonymous_user_has_nothing():
    from django.contrib.auth.models import AnonymousUser

    assert capabilities(AnonymousUser()) == frozenset()
    assert not can(AnonymousUser(), Cap.VIEW_DASHBOARD)
    assert not can(None, Cap.VIEW_DASHBOARD)


def test_user_without_membership_has_nothing(make_user):
    user = make_user(role=None)
    assert get_role(user) is None
    assert not can(user, Cap.VIEW_DASHBOARD)


def test_inactive_user_has_nothing(users):
    user = users[Role.ADMIN]
    user.is_active = False
    assert not can(user, Cap.VIEW_DASHBOARD)


def test_superuser_is_admin(make_user):
    user = make_user(role=None, username="root", is_superuser=True)
    assert get_role(user) is Role.ADMIN


def test_control_owner_may_edit_only_own_objects(users):
    owner = users[Role.CONTROL_OWNER]
    mine = SimpleNamespace(owner_id=owner.pk)
    theirs = SimpleNamespace(owner_id=users[Role.RISK_MANAGER].pk)
    unowned = SimpleNamespace()
    assert can(owner, Cap.EDIT_OWN_CONTROL, mine)
    assert not can(owner, Cap.EDIT_OWN_CONTROL, theirs)
    assert not can(owner, Cap.EDIT_OWN_CONTROL, unowned)
    assert can(owner, Cap.UPLOAD_EVIDENCE, mine)
    assert not can(owner, Cap.UPLOAD_EVIDENCE, theirs)


def test_risk_manager_may_edit_any_control(users):
    rm = users[Role.RISK_MANAGER]
    theirs = SimpleNamespace(owner_id=users[Role.CONTROL_OWNER].pk)
    assert can(rm, Cap.EDIT_OWN_CONTROL, theirs)


def test_role_change_takes_effect_after_cache_clear(users):
    viewer = users[Role.VIEWER]
    assert not can(viewer, Cap.EDIT_RISKS)
    viewer.memberships.update(role=Role.RISK_MANAGER)
    clear_role_cache(viewer)
    assert can(viewer, Cap.EDIT_RISKS)
