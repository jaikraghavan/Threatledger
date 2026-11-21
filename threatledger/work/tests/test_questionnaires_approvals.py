from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.core import mail
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.roles import Role
from threatledger.audit.models import AuditEvent
from threatledger.controls import services as control_services
from threatledger.controls.models import Control
from threatledger.org import services as org_services
from threatledger.risks.tests.helpers import make_control
from threatledger.work import services
from threatledger.work.digest import build_digest, send_digests
from threatledger.work.models import Assignment, DigestLog, Notification

pytestmark = pytest.mark.django_db
QUESTIONS: list[dict[str, Any]] = [
    {"text": "Is MFA enforced for all admins?", "kind": "yes_no", "evidence_required": True},
    {"text": "Patch cadence", "kind": "choice", "choices": ["Weekly", "Monthly"]},
    {"text": "Anything else?", "kind": "text", "required": False},
]


@pytest.fixture
def rm(users):
    return users[Role.RISK_MANAGER]


@pytest.fixture
def owner(users):
    return users[Role.CONTROL_OWNER]


def _questionnaire(rm):
    return services.create_questionnaire(user=rm, title="Access review", questions=QUESTIONS)


# ----------------------------------------------------------------------------- questionnaires
def test_question_validation(rm):
    q = _questionnaire(rm)
    assert [x.kind for x in q.questions.all()] == ["yes_no", "choice", "text"]
    assert q.questions.first().options == ["Yes", "No", "N/A"]
    from django.core.exceptions import ValidationError

    with pytest.raises(ValidationError):
        services.add_question(q, user=rm, data={"text": "Pick", "kind": "choice", "choices": ["A"]})
    with pytest.raises(ValidationError):
        services.add_question(q, user=rm, data={"text": " "})


def test_answer_submit_review_cycle(org, users, rm, owner):
    q = _questionnaire(rm)
    with pytest.raises(services.WorkError):
        services.assign_questionnaire(q, user=rm, respondents=[], data={})
    (a,) = services.assign_questionnaire(
        q, user=rm, respondents=[owner], data={"control": make_control(org, "CTL-MFA")}
    )
    assert a.ref == "QA-0001" and a.status == "sent"
    assert Notification.objects.filter(recipient=owner, url=f"/work/answers/{a.ref}/").exists()
    q1, q2, _ = q.questions.all()
    with pytest.raises(services.WorkError):  # only the respondent answers
        services.save_answer(a, q1, user=rm, value="Yes")
    with pytest.raises(services.WorkError, match="options"):
        services.save_answer(a, q2, user=owner, value="Daily")
    services.save_answer(a, q1, user=owner, value="Yes")
    services.save_answer(a, q2, user=owner, value="Monthly")
    a.refresh_from_db()
    assert a.status == "in_progress"
    with pytest.raises(services.WorkError, match="1 question"):  # evidence still missing
        services.submit_assignment(a, user=owner)
    services.save_answer(
        a, q1, user=owner, value="Yes", upload=SimpleUploadedFile("mfa.csv", b"user,mfa\na,yes\n")
    )
    services.submit_assignment(a, user=owner)
    assert a.status == "submitted"
    with pytest.raises(services.WorkError, match="submitted"):
        services.save_answer(a, q2, user=owner, value="Weekly")
    with pytest.raises(services.WorkError, match="Explain"):
        services.review_assignment(a, user=rm, accept=False)
    services.review_assignment(a, user=rm, accept=False, note="Attach the export, not a sample")
    assert a.status == "returned" and a.editable_by_respondent
    services.submit_assignment(a, user=owner)
    services.review_assignment(a, user=rm, accept=True)
    assert a.status == "accepted" and a.reviewed_by == rm


def test_reviewer_cannot_review_own_answers(rm):
    q = _questionnaire(rm)
    (a,) = services.assign_questionnaire(q, user=rm, respondents=[rm], data={})
    q1, q2, _ = q.questions.all()
    services.save_answer(a, q1, user=rm, value="No", evidence_url="https://wiki.example/x")
    services.save_answer(a, q2, user=rm, value="Weekly")
    services.submit_assignment(a, user=rm)
    with pytest.raises(services.WorkError, match="Segregation"):
        services.review_assignment(a, user=rm, accept=True)


def test_questions_locked_while_out(rm, owner):
    q = _questionnaire(rm)
    services.assign_questionnaire(q, user=rm, respondents=[owner], data={})
    with pytest.raises(services.WorkError, match="cannot change"):
        services.add_question(q, user=rm, data={"text": "Late addition"})


def test_questionnaire_views_and_file_download(client_for, users, rm, owner):
    m = client_for(Role.RISK_MANAGER)
    m.post(reverse("work:questionnaire_create"), {"title": "Vendor basics"})
    q = services.visible_questionnaires(rm).get(title="Vendor basics")
    url = reverse("work:questionnaire", args=[q.ref])
    m.post(
        url,
        {
            "action": "question",
            "q-text": "SOC 2 report?",
            "q-kind": "yes_no",
            "q-required": "on",
            "q-evidence_required": "on",
        },
    )
    m.post(url, {"action": "assign", "a-respondents": [users[Role.VIEWER].pk]})
    a = Assignment.objects.get()
    viewer = client_for(Role.VIEWER)  # respondent mode: any role can answer what it is sent
    page = viewer.get(reverse("work:assignment", args=[a.ref]))
    assert page.status_code == 200 and b"SOC 2 report?" in page.content
    qn = q.questions.get()
    viewer.post(
        reverse("work:assignment", args=[a.ref]),
        {
            f"q{qn.pk}": "Yes",
            f"q{qn.pk}_file": SimpleUploadedFile("soc2.csv", b"a,b\n1,2\n"),
            "submit": "1",
        },
    )
    a.refresh_from_db()
    assert a.status == "submitted"
    answer = a.answers.get()
    dl = m.get(reverse("work:answer_file", args=[answer.pk]))
    assert dl.status_code == 200 and dl["Content-Disposition"].startswith("attachment")
    assert b"".join(dl.streaming_content) == b"a,b\n1,2\n"
    # another viewer, not the respondent, cannot fetch it
    outsider = client_for(Role.AUDITOR)  # auditors may view tasks: allowed
    assert outsider.get(reverse("work:answer_file", args=[answer.pk])).status_code == 200
    from django.test import Client

    stranger_user = users[Role.VIEWER].__class__.objects.create_user("v2", "v2@x.example", "x" * 16)
    from threatledger.accounts.models import Membership

    Membership.objects.create(user=stranger_user, organisation=a.organisation, role=Role.VIEWER)
    stranger = Client()
    stranger.force_login(stranger_user)
    assert stranger.get(reverse("work:answer_file", args=[answer.pk])).status_code == 404
    assert stranger.get(reverse("work:assignment", args=[a.ref])).status_code == 404
    m.post(reverse("work:assignment_review", args=[a.ref]), {"decision": "accept"})
    a.refresh_from_db()
    assert a.status == "accepted"
    assert m.get(reverse("work:questionnaires")).status_code == 200
    assert viewer.get(reverse("work:questionnaires")).status_code == 403


def test_disallowed_upload_is_rejected(rm, users):
    q = _questionnaire(rm)
    (a,) = services.assign_questionnaire(q, user=rm, respondents=[users[Role.VIEWER]], data={})
    from django.core.exceptions import ValidationError

    with pytest.raises(ValidationError):
        services.save_answer(
            a,
            q.questions.first(),
            user=users[Role.VIEWER],
            value="Yes",
            upload=SimpleUploadedFile("x.exe", b"MZ\x90\x00binary"),
        )


# ----------------------------------------------------------------------------- approvals
def _enable(org, admin, **values):
    org_services.set_workflow(org, user=admin, values=values)
    org.refresh_from_db()


def test_control_status_approval_flow(org, users, rm, owner):
    admin = users[Role.ADMIN]
    ctl = make_control(org, "CTL-EDR", status="planned", owner=owner)
    _enable(org, admin, control_status_approval=True)
    control_services.update_control(ctl, user=owner, data={"status": "implemented"})
    ctl.refresh_from_db()
    assert ctl.status == "planned"  # unchanged until approved: coverage stays honest
    cr = control_services.pending_change(ctl)
    assert cr is not None and cr.to_status == "implemented"
    assert Notification.objects.filter(recipient=rm).exists()
    with pytest.raises(control_services.ControlError, match="already"):
        control_services.request_status_change(ctl, user=owner, to_status="partial")
    with pytest.raises(control_services.ControlError, match="Explain"):
        control_services.decide_change(cr, user=rm, approve=False)
    control_services.decide_change(cr, user=rm, approve=True)
    ctl.refresh_from_db()
    assert ctl.status == "implemented"
    assert Notification.objects.filter(recipient=owner, message__contains="approved").exists()
    # managers' own changes apply directly
    control_services.update_control(ctl, user=rm, data={"status": "partial"})
    ctl.refresh_from_db()
    assert ctl.status == "partial"


def test_change_request_withdraw_and_segregation(org, users, rm, owner):
    ctl = make_control(org, "CTL-X", status="planned", owner=owner)
    cr = control_services.request_status_change(ctl, user=owner, to_status="implemented")
    with pytest.raises(control_services.ControlError):
        control_services.withdraw_change(cr, user=rm)
    control_services.withdraw_change(cr, user=owner)
    assert cr.status == "withdrawn"
    cr2 = control_services.request_status_change(ctl, user=rm, to_status="implemented")
    with pytest.raises(control_services.ControlError, match="Segregation"):
        control_services.decide_change(cr2, user=rm, approve=True)


def test_evidence_four_eyes_review(org, users, rm, owner):
    admin = users[Role.ADMIN]
    ctl = make_control(org, "CTL-BKP", owner=owner)
    before = control_services.add_link_evidence(
        ctl, user=owner, url="https://x.example/a", title="a"
    )
    assert before.review_status == "accepted"  # off by default
    _enable(org, admin, require_evidence_review=True)
    ctl = Control.objects.get(pk=ctl.pk)
    ev = control_services.add_link_evidence(ctl, user=rm, url="https://x.example/b", title="b")
    assert ev.review_status == "pending"
    with pytest.raises(control_services.ControlError, match="Four-eyes"):
        control_services.review_evidence(ev, user=rm, accept=True)
    with pytest.raises(control_services.ControlError):
        control_services.review_evidence(ev, user=users[Role.VIEWER], accept=True)
    control_services.review_evidence(ev, user=users[Role.AUDITOR], accept=False, note="Stale")
    assert ev.review_status == "rejected"
    assert Notification.objects.filter(recipient=rm, message__contains="rejected").exists()
    with pytest.raises(control_services.ControlError, match="already"):
        control_services.review_evidence(ev, user=users[Role.ADMIN], accept=True)


def test_approvals_page_and_actions(client_for, org, users, rm, owner):
    _enable(org, users[Role.ADMIN], require_evidence_review=True, control_status_approval=True)
    ctl = make_control(org, "CTL-Z", status="planned", owner=owner)
    ctl = Control.objects.get(pk=ctl.pk)
    ev = control_services.add_link_evidence(ctl, user=owner, url="https://x.example/z", title="z")
    cr = control_services.request_status_change(ctl, user=owner, to_status="implemented")
    page = client_for(Role.RISK_MANAGER).get(reverse("work:approvals"))
    assert b"CTL-Z" in page.content and b"Evidence to review (1)" in page.content
    own = client_for(Role.CONTROL_OWNER).get(reverse("work:approvals"))
    assert b"My pending requests" in own.content and b"Evidence to review" not in own.content
    a = client_for(Role.AUDITOR)
    a.post(reverse("work:evidence_review", args=[ev.pk]), {"decision": "accept"})
    ev.refresh_from_db()
    assert ev.review_status == "accepted"
    client_for(Role.RISK_MANAGER).post(
        reverse("work:change_decide", args=[cr.pk]), {"decision": "approve"}
    )
    cr.refresh_from_db()
    assert cr.status == "approved"
    detail = client_for(Role.AUDITOR).get(reverse("controls:detail", args=[ctl.ref]))
    assert b"asked to change the status" not in detail.content
    assert a.post(reverse("work:change_decide", args=[cr.pk]), {}).status_code == 403


def test_owner_edit_view_reports_pending_approval(client_for, org, users, owner):
    _enable(org, users[Role.ADMIN], control_status_approval=True)
    ctl = make_control(org, "CTL-Q", status="planned", owner=owner)
    r = client_for(Role.CONTROL_OWNER).post(
        reverse("controls:edit", args=[ctl.ref]), {"status": "implemented"}, follow=True
    )
    assert b"awaiting approval" in r.content
    assert b"asked to change the status" in r.content


def test_workflow_settings_view(client_for, org):
    c = client_for(Role.ADMIN)
    assert c.get(reverse("org:workflow")).status_code == 200
    c.post(reverse("org:workflow"), {"require_evidence_review": "on"})
    org.refresh_from_db()
    assert org.workflow("require_evidence_review") and not org.workflow("control_status_approval")
    assert AuditEvent.objects.filter(object_type="org.organisation").exists()
    assert client_for(Role.RISK_MANAGER).get(reverse("org:workflow")).status_code == 403


# ----------------------------------------------------------------------------- digest
def test_digest_contents_and_once_a_day(org, users, rm, owner, settings):
    settings.SITE_URL = "https://grc.example"
    services.create_task(
        user=rm,
        data={"title": "Rotate keys", "due_on": timezone.localdate() - timedelta(days=2)},
        assignees=[owner],
    )
    services.create_task(
        user=rm,
        data={"title": "Far away", "due_on": timezone.localdate() + timedelta(days=30)},
        assignees=[owner],
    )
    lines = build_digest(owner).lines
    assert (
        len(lines) == 1 and "OVERDUE" in lines[0] and "https://grc.example/work/tasks/" in lines[0]
    )
    assert send_digests() == 1
    assert mail.outbox[0].to == [owner.email] and "Rotate keys" in mail.outbox[0].body
    assert send_digests() == 0  # once per day
    assert DigestLog.objects.count() == 1


def test_digest_respects_opt_out_and_approvals(org, users, rm, owner):
    services.set_preference(owner, email_digest=False)
    services.create_task(
        user=rm, data={"title": "x", "due_on": timezone.localdate()}, assignees=[owner]
    )
    ctl = make_control(org, "CTL-D", status="planned", owner=owner)
    control_services.request_status_change(ctl, user=owner, to_status="implemented")
    assert send_digests() == 2  # risk manager and admin have an approval waiting
    assert {m.to[0] for m in mail.outbox} == {rm.email, users[Role.ADMIN].email}
    assert "approval" in mail.outbox[0].body
