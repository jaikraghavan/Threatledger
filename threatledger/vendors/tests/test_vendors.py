from __future__ import annotations

import io
import logging
from datetime import date, timedelta

import pytest
from django.core import mail
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.roles import Role
from threatledger.audit.models import Action, AuditEvent
from threatledger.core.dates import add_months
from threatledger.core.logging import scrub
from threatledger.findings import services as finding_services
from threatledger.risks.tests.helpers import make_risk
from threatledger.vendors import dora, services
from threatledger.vendors.models import Contract
from threatledger.work import services as work_services
from threatledger.work.models import AccessLink, Assignment, Notification

pytestmark = pytest.mark.django_db
TODAY = timezone.localdate


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()


@pytest.fixture
def rm(users):
    return users[Role.RISK_MANAGER]


def _vendor(user, **data):
    return services.create_entity(
        user=user,
        data={"name": "CloudCo", "tier": "critical", "ict_provider": True, "owner": user, **data},
    )


def _questionnaire(user):
    return work_services.create_questionnaire(
        user=user,
        title="Vendor security baseline",
        questions=[
            {"text": "SOC 2 Type II report?", "kind": "yes_no", "evidence_required": True},
            {"text": "MFA for admins?", "kind": "yes_no"},
            {"text": "Pen test in last 12 months?", "kind": "yes_no"},
        ],
    )


def _send(rm, entity, days=30):
    return work_services.send_external_assessment(
        entity,
        user=rm,
        questionnaire=_questionnaire(rm),
        name="Dana Vendor",
        email="dana@cloudco.example",
        days=days,
    )


# ----------------------------------------------------------------------------- entities & contracts
def test_entity_rules(rm, users):
    v = _vendor(rm, lei="5493001kjtiigc8y1r12", country="ie")
    assert (v.ref, v.lei, v.country) == ("V-0001", "5493001KJTIIGC8Y1R12", "IE")
    with pytest.raises(ValidationError):
        _vendor(rm, name="Bad", lei="123")
    for role in (Role.CONTROL_OWNER, Role.AUDITOR, Role.VIEWER):
        with pytest.raises(services.VendorError):
            _vendor(users[role])
    risk = make_risk(rm)
    services.update_entity(v, user=rm, data={"tier": "high"}, risks=[risk])
    assert list(v.risks.all()) == [risk]
    assert AuditEvent.objects.filter(object_type="vendors.entity", object_id=str(v.pk)).count() == 2


def test_contract_state_is_derived(rm):
    v = _vendor(rm)
    today = TODAY()

    def make(**kw):
        return services.create_contract(
            v, user=rm, data={"title": "MSA", "start_date": today - timedelta(days=400), **kw}
        )

    assert make(end_date=today + timedelta(days=400)).state == "active"
    c = make(end_date=today + timedelta(days=120), notice_days=90)
    assert c.notice_deadline == today + timedelta(days=30) and c.state == "notice_due"
    assert make(end_date=today - timedelta(days=1)).state == "expired"
    assert make(end_date=today - timedelta(days=1), auto_renew=True).state != "expired"
    assert make(terminated_on=today).state == "terminated"
    with pytest.raises(ValidationError):
        make(end_date=today - timedelta(days=800))


def test_solutions_and_contract_coverage(rm):
    v, other = _vendor(rm), _vendor(rm, name="Other")
    s = services.add_solution(v, user=rm, data={"name": "Hosting", "function_is_critical": True})
    foreign = services.add_solution(other, user=rm, data={"name": "x"})
    with pytest.raises(services.VendorError, match="belong"):
        services.create_contract(
            v, user=rm, data={"title": "t", "start_date": TODAY()}, solutions=[foreign]
        )
    services.create_contract(v, user=rm, data={"title": "t", "start_date": TODAY()}, solutions=[s])
    with pytest.raises(services.VendorError, match="contracts"):
        services.remove_solution(s, user=rm)


def test_posture_flags_and_reassessment(org, rm):
    v = _vendor(rm)
    (p,) = services.postures([v])
    assert set(p.flags) == {"never assessed", "no exit plan", "no contract"}
    a, token = _send(rm, v)
    link = work_services.resolve_link(token)
    assert link is not None
    for q in a.questionnaire.questions.all():
        work_services.save_external_answer(
            link,
            q,
            value="Yes" if "MFA" not in q.text else "No",
            evidence_url="https://cloudco.example/soc2" if "SOC" in q.text else "",
        )
    work_services.submit_external(link)
    finding_services.create_finding(user=rm, data={"title": "No admin MFA", "entity": v})
    (p,) = services.postures([v])
    a.refresh_from_db()
    assert p.score == 66.7 and p.last_assessment == a and p.open_findings == 1
    assert p.reassess_due == add_months(timezone.localtime(a.submitted_at).date(), 12)
    assert "1 open finding" in p.flags and "never assessed" not in p.flags


def test_scoping_by_business_unit(org, rm, make_user):
    from threatledger.accounts.models import Membership
    from threatledger.org.models import BusinessUnit

    a = BusinessUnit.objects.create(organisation=org, name="A")
    b = BusinessUnit.objects.create(organisation=org, name="B")
    va, vb = _vendor(rm, business_unit=a), _vendor(rm, name="B co", business_unit=b)
    scoped = make_user(Role.AUDITOR, username="aud-a")
    Membership.objects.get(user=scoped).business_units.set([a])
    assert list(services.visible_entities(scoped)) == [va]
    assert vb not in services.visible_contracts(scoped).values_list("entity", flat=True)


# ----------------------------------------------------------------------------- external links
def test_send_assessment_stores_only_a_hash(rm):
    v = _vendor(rm)
    a, token = _send(rm, v)
    link = AccessLink.objects.get()
    assert len(token) >= 40 and token not in link.token_hash and link.prefix == token[:6]
    assert a.is_external and a.respondent is None and a.entity == v
    assert work_services.resolve_link(token) is not None
    assert work_services.resolve_link(token + "x") is None
    assert work_services.resolve_link("") is None
    link.refresh_from_db()
    assert link.use_count == 1 and link.last_used_at is not None
    events = AuditEvent.objects.filter(object_type="work.accesslink")
    assert events.exists() and all(token not in str(e.changes) for e in events)


def test_link_validation_rules(rm, users):
    v = _vendor(rm)
    q = _questionnaire(rm)
    with pytest.raises(work_services.WorkError, match="email"):
        work_services.send_external_assessment(v, user=rm, questionnaire=q, name="x", email="nope")
    with pytest.raises(work_services.WorkError):
        work_services.send_external_assessment(
            v, user=users[Role.AUDITOR], questionnaire=q, name="x", email="a@b.example"
        )
    with pytest.raises(work_services.WorkError, match="between"):
        _send(rm, v, days=120)


def test_new_link_revokes_old_and_expiry(rm):
    v = _vendor(rm)
    a, first = _send(rm, v)
    second = work_services.issue_link(a, user=rm, days=7)
    assert work_services.resolve_link(first) is None
    assert work_services.resolve_link(second) is not None
    AccessLink.objects.filter(revoked_at__isnull=True).update(
        expires_at=timezone.now() - timedelta(seconds=1)
    )
    assert work_services.resolve_link(second) is None
    third = work_services.issue_link(a, user=rm, days=7)
    assert work_services.revoke_links(a, user=rm) == 1
    assert work_services.resolve_link(third) is None


def test_public_respond_flow(client, rm, users):
    v = _vendor(rm)
    a, token = _send(rm, v)
    anon = Client()
    r = anon.get(reverse("respond:start"), {"token": token})
    assert r.status_code == 302 and r["Location"] == reverse("respond:form")
    assert r["Referrer-Policy"] == "no-referrer"
    page = anon.get(reverse("respond:form"))
    assert page.status_code == 200 and b"SOC 2 Type II report?" in page.content
    assert page["X-Robots-Tag"].startswith("noindex") and page["Cache-Control"] == "no-store"
    assert token.encode() not in page.content
    q1, q2, q3 = a.questionnaire.questions.all()
    anon.post(
        reverse("respond:form"),
        {
            f"q{q1.pk}": "Yes",
            f"q{q1.pk}_file": SimpleUploadedFile("soc2.pdf", b"%PDF-1.7\n%%EOF\n"),
            f"q{q2.pk}": "Yes",
            f"q{q3.pk}": "N/A",
            "submit": "1",
        },
    )
    a.refresh_from_db()
    assert a.status == "submitted"
    assert a.answers.get(question=q1).original_filename == "soc2.pdf"
    assert Notification.objects.filter(recipient=rm, message__contains="(external)").exists()
    done = anon.get(reverse("respond:form"))
    assert b"were submitted" in done.content and b'type="file"' not in done.content
    # the risk manager reviews it like any other questionnaire
    m = Client()
    m.force_login(rm)
    m.post(reverse("work:assignment_review", args=[a.ref]), {"decision": "accept"})
    a.refresh_from_db()
    assert a.status == "accepted"
    assert work_services.assessment_score(a) == 100.0


def test_public_pages_reject_bad_tokens_and_rate_limit(rm):
    anon = Client()
    assert anon.get(reverse("respond:form")).status_code == 404  # no session
    assert anon.get(reverse("respond:start"), {"token": "guess"}).status_code == 404
    for _ in range(25):
        r = anon.get(reverse("respond:start"), {"token": "guess"})
    assert r.status_code == 429


def test_revoked_link_locks_out_existing_session(rm):
    v = _vendor(rm)
    a, token = _send(rm, v)
    anon = Client()
    anon.get(reverse("respond:start"), {"token": token})
    assert anon.get(reverse("respond:form")).status_code == 200
    work_services.revoke_links(a, user=rm)
    assert anon.get(reverse("respond:form")).status_code == 404


def test_token_is_scrubbed_from_logs():
    line = "GET /respond/start/?token=abcDEF123_-xyz987654321 HTTP/1.1"
    assert "abcDEF123" not in scrub(line)


def test_respond_pages_never_log_the_token(rm, caplog):
    v = _vendor(rm)
    _, token = _send(rm, v)
    caplog.set_level(logging.DEBUG)
    Client().get(reverse("respond:start"), {"token": token})
    assert token not in caplog.text


# ----------------------------------------------------------------------------- views
def test_vendor_pages(client_for, rm, users):
    c = client_for(Role.RISK_MANAGER)
    r = c.post(
        reverse("vendors:create"),
        {
            "name": "PayFast",
            "tier": "high",
            "status": "active",
            "data_access": "personal",
            "substitutability": "hard",
            "ict_provider": "on",
        },
    )
    v = services.visible_entities(rm).get(name="PayFast")
    assert r.status_code == 302
    c.post(
        reverse("vendors:solution_add", args=[v.ref]),
        {
            "s-name": "Card processing",
            "s-supported_function": "Payments",
            "s-function_is_critical": "on",
        },
    )
    c.post(
        reverse("vendors:contract_create", args=[v.ref]),
        {
            "title": "Processing agreement",
            "start_date": "2026-01-01",
            "end_date": "2028-12-31",
            "notice_days": 180,
            "currency": "EUR",
            "solutions": [v.solutions.get().pk],
        },
    )
    assert Contract.objects.get().solutions.count() == 1
    q = _questionnaire(rm)
    sent = c.post(
        reverse("vendors:assessment_send", args=[v.ref]),
        {
            "x-questionnaire": q.pk,
            "x-contact_email": "sec@payfast.example",
            "x-days": 14,
            "x-send_email": "on",
        },
    )
    assert sent.status_code == 200 and b"/respond/start/?token=" in sent.content
    assert sent["Cache-Control"] == "no-store"
    assert mail.outbox and "/respond/start/?token=" in mail.outbox[0].body
    assert mail.outbox[0].to == ["sec@payfast.example"]
    a = Assignment.objects.get(entity=v)
    relink = c.post(reverse("vendors:assessment_link", args=[v.ref, a.ref]), {"days": "7"})
    assert (
        relink.status_code == 200
        and AccessLink.objects.filter(revoked_at__isnull=True).count() == 1
    )
    c.post(reverse("vendors:assessment_link", args=[v.ref, a.ref]), {"action": "revoke"})
    assert not AccessLink.objects.filter(revoked_at__isnull=True).exists()
    for url in (
        reverse("vendors:list"),
        reverse("vendors:detail", args=[v.ref]),
        reverse("vendors:contracts"),
        reverse("vendors:list") + "?attention=1&status=all",
    ):
        assert client_for(Role.AUDITOR).get(url).status_code == 200
    assert client_for(Role.VIEWER).get(reverse("vendors:list")).status_code == 403
    assert client_for(Role.AUDITOR).get(reverse("vendors:create")).status_code == 403


def test_dora_register_export(client_for, rm):
    from openpyxl import load_workbook

    v = _vendor(rm, lei="5493001KJTIIGC8Y1R12", legal_name="=CloudCo Ltd", country="IE")
    s = services.add_solution(
        v,
        user=rm,
        data={
            "name": "IaaS",
            "ict_service_type": "Cloud IaaS",
            "supported_function": "Payments",
            "function_is_critical": True,
            "data_locations": "IE, DE",
        },
    )
    services.create_contract(
        v,
        user=rm,
        data={
            "title": "Cloud MSA",
            "start_date": date(2025, 1, 1),
            "annual_value": "120000.00",
            "governing_law": "IE",
            "audit_rights": True,
        },
        solutions=[s],
    )
    _vendor(rm, name="Not ICT", ict_provider=False)
    r = client_for(Role.AUDITOR).get(reverse("vendors:dora"))
    assert r.status_code == 200
    wb = load_workbook(io.BytesIO(r.content))
    providers = list(wb["B_05.01 Providers"].values)
    assert len(providers) == 2 and providers[1][0] == "5493001KJTIIGC8Y1R12"
    arrangements = list(wb["B_02.01 Arrangements"].values)
    assert arrangements[1][3] == "'=CloudCo Ltd"  # formula injection neutralised
    assert arrangements[1][9] == 120000.0
    services_rows = list(wb["B_02.02 Services"].values)
    assert services_rows[1][4] == "Yes" and services_rows[1][7] == "Yes"
    assert list(wb["B_06.01 Functions"].values)[1][0] == "Payments"
    assert AuditEvent.objects.filter(action=Action.EXPORT, object_repr__contains="DORA").exists()
    assert client_for(Role.VIEWER).get(reverse("vendors:dora")).status_code == 403
    sheets = dora.build_register(v.organisation, [v])
    assert set(sheets) >= {"B_01.01 Entity", "B_02.01 Arrangements", "B_05.01 Providers"}


def test_vendor_comments_and_finding_prefill(client_for, rm):
    v = _vendor(rm)
    work_services.add_comment(v, user=rm, body="Renewal negotiation starts in March.")
    page = client_for(Role.AUDITOR).get(reverse("vendors:detail", args=[v.ref]))
    assert b"Renewal negotiation" in page.content
    form = client_for(Role.AUDITOR).get(reverse("findings:create"), {"entity": v.ref})
    assert form.context["form"].initial["entity"] == v


def test_digest_contract_notice_and_reassessment(rm):
    from threatledger.work.digest import build_digest

    v = _vendor(rm)
    services.create_contract(
        v,
        user=rm,
        data={
            "title": "MSA",
            "start_date": TODAY() - timedelta(days=300),
            "end_date": TODAY() + timedelta(days=100),
            "notice_days": 90,
        },
    )
    lines = build_digest(rm).lines
    assert any("give notice by" in line for line in lines)
