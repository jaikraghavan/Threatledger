from __future__ import annotations

from datetime import date

import pytest
from django.urls import reverse

from threatledger.accounts.roles import Role
from threatledger.audit.models import Action, AuditEvent
from threatledger.audits import services
from threatledger.audits.models import Audit, AuditResult, Campaign
from threatledger.frameworks import services as fw_services
from threatledger.risks.tests.helpers import make_control

from .helpers import framework, req

pytestmark = pytest.mark.django_db


@pytest.fixture
def fw():
    return framework()


@pytest.fixture
def audit(users, fw):
    return services.create_audit(
        user=users[Role.RISK_MANAGER], data={"name": "Annual", "framework": fw}
    )


@pytest.mark.parametrize(
    ("role", "code"), [(Role.AUDITOR, 200), (Role.CONTROL_OWNER, 200), (Role.VIEWER, 403)]
)
def test_list_and_detail_access(client_for, audit, role, code):
    c = client_for(role)
    assert c.get(reverse("audits:list")).status_code == code
    assert c.get(reverse("audits:detail", args=[audit.ref])).status_code == code
    assert c.get(reverse("audits:campaigns")).status_code == code


def test_manager_creates_audit_through_the_form(client_for, fw):
    c = client_for(Role.RISK_MANAGER)
    assert c.get(reverse("audits:create")).status_code == 200
    r = c.post(reverse("audits:create"), {"name": "ISO surveillance", "framework": fw.pk})
    audit = Audit.objects.get(name="ISO surveillance")
    assert r.status_code == 302 and r["Location"].endswith(f"/audits/{audit.ref}/")


def test_auditor_cannot_create(client_for):
    assert client_for(Role.AUDITOR).get(reverse("audits:create")).status_code == 403


def test_auditor_records_a_judgement_and_moves_to_next(client_for, audit, fw):
    c = client_for(Role.AUDITOR)
    url = reverse("audits:requirement", args=[audit.ref, req(fw, "A-1").pk])
    page = c.get(url)
    assert page.status_code == 200 and b"(suggested)" in page.content
    r = c.post(url, {"judgement": "compliant", "maturity": "3", "next": "1"})
    assert r.status_code == 302
    assert r["Location"].endswith(f"/requirements/{req(fw, 'A-2').pk}/")
    res = AuditResult.objects.get(audit=audit, requirement__ref="A-1")
    assert (res.judgement, res.maturity) == ("compliant", 3)


def test_invalid_judgement_shows_error(client_for, audit, fw):
    url = reverse("audits:requirement", args=[audit.ref, req(fw, "A-1").pk])
    r = client_for(Role.AUDITOR).post(url, {"judgement": "partial"})
    assert r.status_code == 200 and b"observation" in r.content


def test_viewer_cannot_post_judgement(client_for, audit, fw):
    url = reverse("audits:requirement", args=[audit.ref, req(fw, "A-1").pk])
    assert client_for(Role.CONTROL_OWNER).post(url, {"judgement": "compliant"}).status_code == 403


def test_domain_requirement_is_404(client_for, audit, fw):
    url = reverse("audits:requirement", args=[audit.ref, req(fw, "D").pk])
    assert client_for(Role.AUDITOR).get(url).status_code == 404


def test_accept_and_status_and_close(client_for, audit):
    aud, rm = client_for(Role.AUDITOR), client_for(Role.RISK_MANAGER)
    assert aud.get(reverse("audits:accept", args=[audit.ref])).status_code == 403  # POST only
    aud.post(reverse("audits:accept", args=[audit.ref]))
    assert audit.results.count() == 3
    aud.post(reverse("audits:status", args=[audit.ref]), {"status": "in_review"})
    rm.post(reverse("audits:status", args=[audit.ref]), {"status": "closed", "conclusion": "OK"})
    audit.refresh_from_db()
    assert audit.status == "closed"
    page = rm.get(reverse("audits:detail", args=[audit.ref]))
    assert b"Judgements are frozen" in page.content
    assert rm.get(reverse("audits:edit", args=[audit.ref])).status_code == 302


def test_detail_filters(client_for, audit, fw, users, org):
    ctl = make_control(org, "C1", status="not_implemented")
    fw_services.map_control(req(fw, "A-1"), ctl, user=users[Role.RISK_MANAGER])
    services.record_judgement(
        audit, req(fw, "A-1"), user=users[Role.AUDITOR], judgement="compliant"
    )
    c = client_for(Role.AUDITOR)
    divergent = c.get(reverse("audits:detail", args=[audit.ref]), {"show": "divergent"})
    assert [r.requirement.ref for r in divergent.context["rows"]] == ["A-1"]
    todo = c.get(reverse("audits:detail", args=[audit.ref]), {"show": "todo"})
    assert [r.requirement.ref for r in todo.context["rows"]] == ["A-2", "A-3"]


def test_detail_query_count_is_bounded(client_for, audit, fw, users, django_assert_max_num_queries):
    for ref in ("A-1", "A-2", "A-3"):
        services.record_judgement(
            audit, req(fw, ref), user=users[Role.AUDITOR], judgement="compliant"
        )
    c = client_for(Role.AUDITOR)
    with django_assert_max_num_queries(25):
        assert c.get(reverse("audits:detail", args=[audit.ref])).status_code == 200


def test_export_is_neutralised_and_audited(client_for, audit, fw, users):
    services.record_judgement(
        audit,
        req(fw, "A-1"),
        user=users[Role.AUDITOR],
        judgement="partial",
        observation="=HYPERLINK(1)",
    )
    r = client_for(Role.AUDITOR).get(reverse("audits:export", args=[audit.ref]))
    body = r.content.decode("utf-8-sig")
    assert r["Content-Type"].startswith("text/csv")
    assert "'=HYPERLINK(1)" in body and "=HYPERLINK" not in body.replace("'=HYPERLINK", "")
    assert AuditEvent.objects.filter(action=Action.EXPORT, object_id=str(audit.pk)).exists()
    assert (
        client_for(Role.VIEWER).get(reverse("audits:export", args=[audit.ref])).status_code == 403
    )


def test_campaign_pages(client_for, fw, org):
    from threatledger.org.models import BusinessUnit

    bu = BusinessUnit.objects.create(organisation=org, name="EMEA")
    c = client_for(Role.RISK_MANAGER)
    assert c.get(reverse("audits:campaign_create")).status_code == 200
    r = c.post(
        reverse("audits:campaign_create"),
        {
            "name": "Quarterly",
            "framework": fw.pk,
            "starts_on": "2026-01-01",
            "due_on": "2026-03-31",
            "recurrence": "quarterly",
            "perimeters": [bu.pk],
            "organisation_wide": "on",
        },
    )
    campaign = Campaign.objects.get()
    assert r.status_code == 302 and campaign.audits.count() == 2
    page = c.get(reverse("audits:campaign", args=[campaign.ref]))
    assert page.status_code == 200 and b"Launch next cycle" in page.content
    c.post(reverse("audits:campaign_next", args=[campaign.ref]))
    nxt = Campaign.objects.get(previous=campaign)
    assert nxt.starts_on == date(2026, 4, 1)
    assert c.get(reverse("audits:campaigns")).status_code == 200


def test_campaign_needs_a_perimeter(client_for, fw):
    r = client_for(Role.RISK_MANAGER).post(
        reverse("audits:campaign_create"),
        {
            "name": "x",
            "framework": fw.pk,
            "starts_on": "2026-01-01",
            "due_on": "2026-02-01",
            "recurrence": "none",
        },
    )
    assert r.status_code == 200 and b"at least one perimeter" in r.content
