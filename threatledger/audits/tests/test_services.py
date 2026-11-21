from __future__ import annotations

from datetime import date

import pytest
from django.core.exceptions import ValidationError

from threatledger.accounts.models import Membership
from threatledger.accounts.permissions import clear_role_cache
from threatledger.accounts.roles import Role
from threatledger.audit.models import AuditEvent
from threatledger.audits import services
from threatledger.audits.models import AuditResult, AuditStatus, Judgement
from threatledger.audits.scoring import AuditScore, is_divergent, suggest
from threatledger.controls.models import Evidence
from threatledger.core.dates import add_months
from threatledger.frameworks import services as fw_services
from threatledger.frameworks.compliance import ReqStatus
from threatledger.org.models import BusinessUnit
from threatledger.risks.tests.helpers import make_control

from .helpers import framework, req

pytestmark = pytest.mark.django_db


@pytest.fixture
def fw():
    return framework()


@pytest.fixture
def rm(users):
    return users[Role.RISK_MANAGER]


@pytest.fixture
def auditor(users):
    return users[Role.AUDITOR]


def _audit(rm, fw, **data):
    return services.create_audit(user=rm, data={"name": "Q1", "framework": fw, **data})


# ----------------------------------------------------------------------------- scoring
def test_suggestion_mapping_and_divergence():
    assert suggest(ReqStatus.MET) == Judgement.COMPLIANT
    assert suggest(ReqStatus.PARTIAL) == Judgement.PARTIAL
    assert suggest(ReqStatus.GAP) == Judgement.NON_COMPLIANT
    assert suggest(ReqStatus.NO_CONTROL) == Judgement.NON_COMPLIANT
    assert suggest(None) == Judgement.NOT_APPLICABLE
    assert not is_divergent(Judgement.NOT_ASSESSED, ReqStatus.MET)
    assert not is_divergent(Judgement.COMPLIANT, ReqStatus.MET)
    assert is_divergent(Judgement.COMPLIANT, ReqStatus.GAP)


def test_score_maths():
    s = AuditScore()
    s.add(Judgement.COMPLIANT, 4, False)
    s.add(Judgement.PARTIAL, 2, True)
    s.add(Judgement.NON_COMPLIANT, None, False)
    s.add(Judgement.NOT_APPLICABLE, None, False)
    s.add(Judgement.NOT_ASSESSED, None, False)
    assert (s.total, s.assessed, s.not_assessed) == (5, 4, 1)
    assert s.progress == 80.0
    assert s.score == 50.0  # (1 + 0.5) / 3
    assert s.maturity == 3.0
    assert s.divergent == 1
    assert [css for _, _, css in s.bar] == [
        "fill-green-500",
        "fill-amber-400",
        "fill-red-400",
        "fill-slate-400",
    ]
    assert AuditScore().score is None and AuditScore().progress == 0.0


def test_add_months_clamps():
    assert add_months(date(2026, 1, 31), 1) == date(2026, 2, 28)
    assert add_months(date(2026, 11, 15), 3) == date(2027, 2, 15)


# ----------------------------------------------------------------------------- audits
def test_create_audit_assigns_ref_and_audits(rm, fw):
    a = _audit(rm, fw)
    b = _audit(rm, fw, name="Q2")
    assert (a.ref, b.ref) == ("A-0001", "A-0002")
    assert a.status == AuditStatus.PLANNED
    assert AuditEvent.objects.filter(object_type="audits.audit", object_id=str(a.pk)).exists()


def test_only_managers_plan_audits(users, fw):
    for role in (Role.AUDITOR, Role.CONTROL_OWNER, Role.VIEWER):
        with pytest.raises(services.AuditError):
            _audit(users[role], fw)


def test_baseline_must_exist(rm, fw):
    with pytest.raises(ValidationError):
        _audit(rm, fw, baseline="high")
    a = _audit(rm, fw, baseline="low")
    rows, score = services.audit_rows(a)
    assert [r.requirement.ref for r in rows] == ["A-1"]
    assert score.total == 1


def test_hybrid_judgement_is_kept_and_divergence_follows_live_status(org, rm, auditor, fw):
    """The core Phase 8 rule: judgements are frozen; derived status stays live."""
    ctl = make_control(org, "MFA", status="implemented")
    fw_services.map_control(req(fw, "A-1"), ctl, user=rm)
    a = _audit(rm, fw)
    rows, _ = services.audit_rows(a)
    assert rows[0].suggestion == Judgement.COMPLIANT
    services.record_judgement(a, req(fw, "A-1"), user=auditor, judgement=Judgement.COMPLIANT)
    a.refresh_from_db()
    assert a.status == AuditStatus.IN_PROGRESS  # first judgement starts the audit
    assert services.audit_score(a).divergent == 0

    ctl.status = "not_implemented"
    ctl.save()
    rows, score = services.audit_rows(a)
    row = rows[0]
    assert row.judgement == Judgement.COMPLIANT  # unchanged
    assert row.derived == ReqStatus.GAP  # live
    assert row.divergent and score.divergent == 1
    assert row.result is not None
    assert row.result.derived_at_judgement == "met"  # what the auditor saw


def test_judgement_rules(org, rm, auditor, fw):
    a = _audit(rm, fw)
    r1 = req(fw, "A-1")
    with pytest.raises(services.AuditError, match="observation"):
        services.record_judgement(a, r1, user=auditor, judgement=Judgement.NON_COMPLIANT)
    with pytest.raises(services.AuditError, match="judgement"):
        services.record_judgement(a, r1, user=auditor, judgement=Judgement.NOT_ASSESSED)
    with pytest.raises(services.AuditError, match="Maturity"):
        services.record_judgement(a, r1, user=auditor, judgement=Judgement.COMPLIANT, maturity=6)
    with pytest.raises(services.AuditError, match="not part"):
        services.record_judgement(a, req(fw, "D"), user=auditor, judgement=Judgement.COMPLIANT)
    low = _audit(rm, fw, baseline="low")
    with pytest.raises(services.AuditError, match="baseline"):
        services.record_judgement(low, req(fw, "A-2"), user=auditor, judgement="compliant")


def test_viewer_and_control_owner_cannot_judge(users, rm, fw):
    a = _audit(rm, fw)
    for role in (Role.VIEWER, Role.CONTROL_OWNER):
        with pytest.raises(services.AuditError):
            services.record_judgement(
                a, req(fw, "A-1"), user=users[role], judgement=Judgement.COMPLIANT
            )


def test_evidence_must_belong_to_the_organisation(org, rm, auditor, fw, users):
    from threatledger.org.models import Organisation

    ctl = make_control(org, "MFA")
    mine = Evidence.objects.create(
        control=ctl, kind="link", url="https://e.example", title="ok", uploaded_by=rm
    )
    other_org = Organisation.objects.create(name="Elsewhere")
    theirs = Evidence.objects.create(
        control=make_control(other_org, "X"),
        kind="link",
        url="https://x.example",
        title="no",
        uploaded_by=rm,
    )
    a = _audit(rm, fw)
    result = services.record_judgement(
        a, req(fw, "A-1"), user=auditor, judgement="compliant", evidence_ids=[mine.pk]
    )
    assert list(result.evidence.all()) == [mine]
    with pytest.raises(services.AuditError, match="evidence"):
        services.record_judgement(
            a, req(fw, "A-1"), user=auditor, judgement="compliant", evidence_ids=[theirs.pk]
        )


def test_accept_suggestions_fills_only_unjudged(org, rm, auditor, fw):
    ctl = make_control(org, "MFA", status="partial")
    fw_services.map_control(req(fw, "A-2"), ctl, user=rm)
    fw_services.set_applicability(req(fw, "A-3"), user=rm, applicable=False, justification="x")
    a = _audit(rm, fw)
    services.record_judgement(
        a, req(fw, "A-1"), user=auditor, judgement="not_applicable", observation="Out of scope"
    )
    assert services.accept_suggestions(a, user=auditor) == 2
    got = dict(AuditResult.objects.filter(audit=a).values_list("requirement__ref", "judgement"))
    assert got == {"A-1": "not_applicable", "A-2": "partial", "A-3": "not_applicable"}
    assert services.accept_suggestions(a, user=auditor) == 0


def test_status_workflow_and_closed_audit_is_frozen(rm, auditor, fw):
    a = _audit(rm, fw)
    assert services.allowed_transitions(auditor, a) == [AuditStatus.IN_PROGRESS]
    services.set_status(a, user=auditor, status=AuditStatus.IN_PROGRESS)
    services.set_status(a, user=auditor, status=AuditStatus.IN_REVIEW)
    with pytest.raises(services.AuditError):  # auditors cannot close
        services.set_status(a, user=auditor, status=AuditStatus.CLOSED, conclusion="done")
    with pytest.raises(services.AuditError, match="conclusion"):
        services.set_status(a, user=rm, status=AuditStatus.CLOSED)
    services.set_status(a, user=rm, status=AuditStatus.CLOSED, conclusion="Adequate.")
    a.refresh_from_db()
    assert a.closed_by == rm and a.closed_at is not None
    with pytest.raises(services.AuditError):
        services.record_judgement(a, req(fw, "A-1"), user=auditor, judgement="compliant")
    with pytest.raises(services.AuditError):
        services.update_audit(a, user=rm, data={"name": "x"})
    assert services.allowed_transitions(rm, a) == []


def test_in_review_blocks_judgements(rm, auditor, fw):
    a = _audit(rm, fw)
    services.set_status(a, user=rm, status=AuditStatus.IN_PROGRESS)
    services.set_status(a, user=rm, status=AuditStatus.IN_REVIEW)
    with pytest.raises(services.AuditError):
        services.record_judgement(a, req(fw, "A-1"), user=auditor, judgement="compliant")


# ----------------------------------------------------------------------------- perimeters
def test_business_unit_scope_limits_audits(org, users, make_user, fw):
    rm = users[Role.RISK_MANAGER]
    parent = BusinessUnit.objects.create(organisation=org, name="EMEA")
    child = BusinessUnit.objects.create(organisation=org, name="UK", parent=parent)
    other = BusinessUnit.objects.create(organisation=org, name="APAC")
    in_child = _audit(rm, fw, business_unit=child)
    in_other = _audit(rm, fw, business_unit=other)
    org_wide = _audit(rm, fw)
    scoped = make_user(Role.AUDITOR, username="emea-auditor")
    Membership.objects.get(user=scoped).business_units.set([parent])
    clear_role_cache(scoped)
    visible = set(services.visible_audits(scoped))
    assert visible == {in_child, org_wide}  # child of EMEA is inside the scope
    assert in_other not in visible


def test_scoped_manager_cannot_plan_org_wide_or_foreign_audits(org, make_user, fw):
    bu = BusinessUnit.objects.create(organisation=org, name="EMEA")
    other = BusinessUnit.objects.create(organisation=org, name="APAC")
    mgr = make_user(Role.RISK_MANAGER, username="emea-rm")
    Membership.objects.get(user=mgr).business_units.set([bu])
    with pytest.raises(services.AuditError):
        _audit(mgr, fw)
    with pytest.raises(services.AuditError):
        _audit(mgr, fw, business_unit=other)
    assert _audit(mgr, fw, business_unit=bu).business_unit == bu


# ----------------------------------------------------------------------------- campaigns
def test_campaign_creates_an_audit_per_perimeter_and_recurs(org, rm, fw):
    emea = BusinessUnit.objects.create(organisation=org, name="EMEA")
    c = services.create_campaign(
        user=rm,
        perimeters=[None, emea],
        data={
            "name": "SOC readiness",
            "framework": fw,
            "starts_on": date(2026, 1, 31),
            "due_on": date(2026, 3, 31),
            "recurrence": "quarterly",
            "baseline": "moderate",
        },
    )
    audits = list(c.audits.order_by("ref"))
    assert [a.business_unit for a in audits] == [None, emea]
    assert all(a.baseline == "moderate" and a.due_on == c.due_on for a in audits)
    assert services.campaign_status(audits) == AuditStatus.PLANNED
    nxt = services.launch_next_cycle(c, user=rm)
    assert (nxt.starts_on, nxt.due_on) == (date(2026, 4, 30), date(2026, 6, 30))
    assert nxt.previous == c and nxt.audits.count() == 2
    with pytest.raises(services.AuditError, match="already"):
        services.launch_next_cycle(c, user=rm)


def test_campaign_status_is_derived():
    from types import SimpleNamespace as NS

    assert services.campaign_status([NS(status="closed"), NS(status="closed")]) == "closed"
    assert services.campaign_status([NS(status="closed"), NS(status="planned")]) == "in_progress"
    assert services.campaign_status([]) == "planned"


def test_one_off_campaign_cannot_recur(rm, fw):
    c = services.create_campaign(
        user=rm,
        perimeters=[None],
        data={"name": "x", "framework": fw, "due_on": date(2099, 1, 1)},
    )
    with pytest.raises(services.AuditError, match="recur"):
        services.launch_next_cycle(c, user=rm)
    with pytest.raises(services.AuditError, match="perimeter"):
        services.create_campaign(user=rm, perimeters=[], data={"name": "y", "framework": fw})


def test_list_scores_match_full_scores(org, rm, auditor, fw):
    a = _audit(rm, fw)
    b = _audit(rm, fw, baseline="low")
    services.record_judgement(a, req(fw, "A-1"), user=auditor, judgement="compliant", maturity=3)
    scores = services.list_scores([a, b])
    full = services.audit_score(a)
    assert (scores[a.pk].total, scores[a.pk].assessed, scores[a.pk].score) == (
        full.total,
        full.assessed,
        full.score,
    )
    assert scores[b.pk].total == 1
    assert services.list_scores([]) == {}
