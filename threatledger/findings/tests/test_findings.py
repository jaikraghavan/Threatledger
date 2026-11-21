from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.models import Membership
from threatledger.accounts.roles import Role
from threatledger.audits import services as audit_services
from threatledger.audits.tests.helpers import framework, req
from threatledger.controls.models import Control
from threatledger.findings import services
from threatledger.findings.models import Finding, FindingStatus, SecurityException
from threatledger.org.models import BusinessUnit
from threatledger.risks.tests.helpers import make_control

pytestmark = pytest.mark.django_db
TODAY = timezone.localdate


@pytest.fixture
def rm(users):
    return users[Role.RISK_MANAGER]


@pytest.fixture
def owner(users):
    return users[Role.CONTROL_OWNER]


def _finding(user, **data):
    return services.create_finding(user=user, data={"title": "No MFA on VPN", **data})


# ----------------------------------------------------------------------------- findings
def test_auditor_raises_finding_with_default_due_date(users):
    f = _finding(users[Role.AUDITOR], severity="critical")
    assert f.ref == "F-0001" and f.status == FindingStatus.OPEN
    assert f.due_on == TODAY() + timedelta(days=30)
    assert _finding(users[Role.AUDITOR], severity="low").due_on == TODAY() + timedelta(days=180)


@pytest.mark.parametrize("role", [Role.CONTROL_OWNER, Role.VIEWER])
def test_others_cannot_raise(users, role):
    with pytest.raises(services.FindingError):
        _finding(users[role])


def test_finding_from_audit_inherits_perimeter_and_checks_requirement(org, rm, users):
    fw = framework()
    bu = BusinessUnit.objects.create(organisation=org, name="EMEA")
    audit = audit_services.create_audit(
        user=rm, data={"name": "a", "framework": fw, "business_unit": bu}
    )
    f = _finding(users[Role.AUDITOR], audit=audit, requirement=req(fw, "A-1"))
    assert f.business_unit == bu
    audit_services.set_status(audit, user=rm, status="in_progress")
    audit_services.set_status(audit, user=rm, status="in_review")
    audit_services.set_status(audit, user=rm, status="closed", conclusion="x")
    audit.refresh_from_db()
    with pytest.raises(services.FindingError, match="closed"):
        _finding(users[Role.AUDITOR], audit=audit)


def test_owner_can_only_update_remediation(org, rm, owner):
    f = _finding(rm, owner=owner)
    services.update_finding(f, user=owner, data={"remediation": "Rolling out"})
    with pytest.raises(services.FindingError, match="only update"):
        services.update_finding(f, user=owner, data={"severity": "low"})
    stranger = _finding(rm)
    with pytest.raises(services.FindingError):
        services.update_finding(stranger, user=owner, data={"remediation": "x"})


def test_lifecycle_with_segregation_of_duties(rm, owner, users):
    f = _finding(rm, owner=owner)
    assert services.finding_transitions(owner, f) == ["in_progress", "resolved"]
    services.set_finding_status(f, user=owner, status="in_progress")
    services.set_finding_status(f, user=owner, status="resolved")
    assert f.resolved_at is not None
    with pytest.raises(services.FindingError):  # owner cannot verify own fix
        services.set_finding_status(f, user=owner, status="closed")
    services.set_finding_status(f, user=users[Role.AUDITOR], status="closed", note="Verified")
    assert (f.status, f.closed_by) == ("closed", users[Role.AUDITOR])
    with pytest.raises(services.FindingError):  # closed findings are not editable
        services.update_finding(f, user=rm, data={"title": "x"})
    services.set_finding_status(f, user=rm, status="open")
    assert f.closed_at is None and f.resolved_at is None


def test_owner_who_is_manager_still_cannot_close_own(rm):
    f = _finding(rm, owner=rm)
    services.set_finding_status(f, user=rm, status="resolved")
    with pytest.raises(services.FindingError, match="Segregation"):
        services.set_finding_status(f, user=rm, status="closed")


def test_overdue_is_derived(rm):
    f = _finding(rm, due_on=TODAY() - timedelta(days=1))
    assert f.overdue
    f.status = FindingStatus.RESOLVED
    assert not f.overdue


def test_scope_hides_other_business_units(org, rm, make_user):
    a = BusinessUnit.objects.create(organisation=org, name="A")
    b = BusinessUnit.objects.create(organisation=org, name="B")
    fa, fb, fo = _finding(rm, business_unit=a), _finding(rm, business_unit=b), _finding(rm)
    scoped = make_user(Role.AUDITOR, username="scoped")
    Membership.objects.get(user=scoped).business_units.set([a])
    assert set(services.visible_findings(scoped)) == {fa, fo}
    assert fb not in services.visible_findings(scoped)


# ----------------------------------------------------------------------------- exceptions
def _exception(user, org, **data):
    ctl = make_control(org, f"C-{Control.objects.count()}")
    return services.request_exception(
        user=user,
        controls=[ctl],
        data={
            "title": "Legacy app without SSO",
            "justification": "Vendor upgrade due Q3",
            "expires_on": TODAY() + timedelta(days=90),
            **data,
        },
    )


def test_exception_needs_scope_justification_and_bounded_expiry(org, owner):
    with pytest.raises(services.FindingError, match="at least one"):
        services.request_exception(
            user=owner,
            data={"title": "x", "justification": "y", "expires_on": TODAY() + timedelta(days=5)},
        )
    with pytest.raises(ValidationError):
        _exception(owner, org, expires_on=TODAY() + timedelta(days=400))
    with pytest.raises(ValidationError):
        _exception(owner, org, justification=" ")
    exc = _exception(owner, org)
    assert exc.ref == "EX-0001" and exc.owner == owner and exc.status == "requested"


def test_exception_approval_segregation_expiry_and_revocation(org, rm, owner, users):
    exc = _exception(rm, org)
    with pytest.raises(services.FindingError, match="Segregation"):
        services.decide_exception(exc, user=rm, approve=True)
    with pytest.raises(services.FindingError):
        services.decide_exception(exc, user=owner, approve=True)  # owners cannot approve
    services.decide_exception(exc, user=users[Role.ADMIN], approve=True, note="ok")
    assert exc.is_active and exc.effective_status == "approved"
    assert exc in services.active_exceptions(org)
    exc.expires_on = TODAY() - timedelta(days=1)
    assert exc.effective_status == "expired" and exc.effective_status_label == "Expired"
    exc.expires_on = TODAY() + timedelta(days=10)
    assert exc.expires_soon
    with pytest.raises(services.FindingError, match="reason"):
        services.revoke_exception(exc, user=rm, note="")
    services.revoke_exception(exc, user=rm, note="Compensating control failed")
    assert exc.status == "revoked" and not exc.is_active


def test_exception_views(client_for, org, users):
    exc = _exception(users[Role.CONTROL_OWNER], org)
    c = client_for(Role.RISK_MANAGER)
    assert c.get(reverse("findings:exceptions")).status_code == 200
    page = c.get(reverse("findings:exception", args=[exc.ref]))
    assert b"Approve" in page.content
    c.post(reverse("findings:exception_decide", args=[exc.ref]), {"decision": "approve"})
    exc.refresh_from_db()
    assert exc.status == "approved"
    assert client_for(Role.VIEWER).get(reverse("findings:exceptions")).status_code == 403
    assert client_for(Role.AUDITOR).get(reverse("findings:exception_create")).status_code == 403


def test_exception_form_parses_requirement_refs(client_for, org):
    fw = framework()
    c = client_for(Role.CONTROL_OWNER)
    url = reverse("findings:exception_create")
    assert (
        c.get(url, {"requirement": req(fw, "A-1").pk}).context["form"].initial["requirement_refs"]
        == "FW-A A-1"
    )
    bad = c.post(
        url,
        {
            "title": "t",
            "justification": "j",
            "requirement_refs": "FW-A Z-9",
            "expires_on": (TODAY() + timedelta(days=30)).isoformat(),
        },
    )
    assert bad.status_code == 200 and "Unknown requirement" in bad.content.decode()
    ok = c.post(
        url,
        {
            "title": "t",
            "justification": "j",
            "requirement_refs": "fw-a a-1",
            "expires_on": (TODAY() + timedelta(days=30)).isoformat(),
        },
    )
    exc = SecurityException.objects.get()
    assert ok.status_code == 302 and list(exc.requirements.all()) == [req(fw, "A-1")]


# ----------------------------------------------------------------------------- views
def test_finding_views_end_to_end(client_for, users, org):
    fw = framework()
    audit = audit_services.create_audit(
        user=users[Role.RISK_MANAGER], data={"name": "a", "framework": fw}
    )
    aud = client_for(Role.AUDITOR)
    url = reverse("findings:create")
    form = aud.get(url, {"audit": audit.ref, "requirement": req(fw, "A-2").pk})
    assert form.context["form"].initial["title"].startswith("A-2")
    r = aud.post(
        url,
        {
            "title": "A-2 not met",
            "severity": "high",
            "audit": audit.pk,
            "requirement": req(fw, "A-2").pk,
            "owner": users[Role.CONTROL_OWNER].pk,
        },
    )
    f = Finding.objects.get()
    assert r.status_code == 302 and f.requirement == req(fw, "A-2") and f.audit == audit
    assert aud.get(reverse("findings:list")).status_code == 200
    assert (
        aud.get(reverse("findings:list"), {"overdue": "1", "severity": "high"}).status_code == 200
    )
    owner = client_for(Role.CONTROL_OWNER)
    edit = owner.get(reverse("findings:edit", args=[f.ref]))
    assert list(edit.context["form"].fields) == ["remediation"]
    owner.post(reverse("findings:edit", args=[f.ref]), {"remediation": "Patching"})
    owner.post(reverse("findings:status", args=[f.ref]), {"status": "resolved"})
    aud.post(reverse("findings:status", args=[f.ref]), {"status": "closed"})
    f.refresh_from_db()
    assert (f.remediation, f.status) == ("Patching", "closed")
    detail = aud.get(reverse("audits:detail", args=[audit.ref]))
    assert f.ref.encode() in detail.content
    assert client_for(Role.VIEWER).get(reverse("findings:list")).status_code == 403


def test_requirement_and_control_pages_show_findings_and_exceptions(client_for, users, org):
    fw = framework()
    rm = users[Role.RISK_MANAGER]
    ctl = make_control(org, "CTL-VPN")
    f = _finding(rm, requirement=None, control=ctl)
    exc = services.request_exception(
        user=rm,
        requirements=[req(fw, "A-1")],
        data={
            "title": "VPN waiver",
            "justification": "j",
            "expires_on": TODAY() + timedelta(days=9),
        },
    )
    c = client_for(Role.AUDITOR)
    page = c.get(reverse("controls:detail", args=[ctl.ref])).content.decode()
    assert f.ref in page
    rpage = c.get(reverse("frameworks:requirement", args=[fw.code, req(fw, "A-1").pk]))
    body = rpage.content.decode()
    assert exc.ref in body and "Requested" in body and "never change it" in body
    services.decide_exception(exc, user=users[Role.ADMIN], approve=True)
    body = c.get(reverse("frameworks:requirement", args=[fw.code, req(fw, "A-1").pk])).content
    assert b">Approved<" in body
    viewer = client_for(Role.VIEWER).get(reverse("controls:detail", args=[ctl.ref]))
    assert f.ref.encode() not in viewer.content  # viewers do not see findings


def test_dashboard_governance_kpis(client_for, users):
    _finding(users[Role.RISK_MANAGER], severity="critical", due_on=TODAY() - timedelta(days=1))
    ctx = client_for(Role.AUDITOR).get(reverse("core:home")).context
    assert ctx["gov"]["findings_open"] == 1 and ctx["gov"]["findings_overdue"] == 1
    assert "findings_open" not in client_for(Role.VIEWER).get(reverse("core:home")).context["gov"]


def test_list_status_filter_distinguishes_open_from_not_closed(client_for, users):
    rm = users[Role.RISK_MANAGER]
    a, b = _finding(rm, owner=rm), _finding(rm, owner=rm)
    services.set_finding_status(b, user=rm, status="in_progress")
    c = client_for(Role.AUDITOR)
    default = c.get(reverse("findings:list"))
    assert {f.ref for f in default.context["findings"]} == {a.ref, b.ref}
    assert b'<option value="active" selected>Not closed</option>' in default.content
    only_open = c.get(reverse("findings:list"), {"status": "open"})
    assert [f.ref for f in only_open.context["findings"]] == [a.ref]
