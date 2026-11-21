from __future__ import annotations

from datetime import date, timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.models import Membership
from threatledger.accounts.roles import Role
from threatledger.controls import services as control_services
from threatledger.findings import services as finding_services
from threatledger.org.models import BusinessUnit
from threatledger.risks.tests.helpers import make_control, make_risk
from threatledger.work import services
from threatledger.work.models import Comment, Notification, Task
from threatledger.work.notify import notify, users_with

pytestmark = pytest.mark.django_db


@pytest.fixture
def rm(users):
    return users[Role.RISK_MANAGER]


@pytest.fixture
def owner(users):
    return users[Role.CONTROL_OWNER]


def _task(user, assignees=(), **data):
    return services.create_task(
        user=user, data={"title": "Review firewall rules", **data}, assignees=assignees
    )


def _inbox(user):
    return list(Notification.objects.filter(recipient=user).values_list("message", flat=True))


# ----------------------------------------------------------------------------- notify
def test_notify_skips_actor_inactive_and_duplicates(users, rm, owner):
    owner2 = users[Role.AUDITOR]
    owner2.is_active = False
    owner2.save()
    assert notify([owner, owner, rm, owner2, None], "hello", "/x/", actor=rm) == 1
    assert _inbox(owner) == ["hello"] and _inbox(rm) == []


def test_users_with_respects_business_unit_scope(org, users, make_user):
    a = BusinessUnit.objects.create(organisation=org, name="A")
    b = BusinessUnit.objects.create(organisation=org, name="B")
    scoped = make_user(Role.RISK_MANAGER, username="rm-a")
    Membership.objects.get(user=scoped).business_units.set([a])
    from threatledger.accounts.roles import Cap

    approvers = users_with(org, Cap.APPROVE_EXCEPTION, b.pk)
    assert scoped not in approvers and users[Role.RISK_MANAGER] in approvers
    assert scoped in users_with(org, Cap.APPROVE_EXCEPTION, a.pk)


# ----------------------------------------------------------------------------- tasks
def test_create_task_assigns_and_notifies(rm, owner):
    t = _task(rm, [owner], due_on=date(2026, 12, 1))
    assert t.ref == "T-0001" and list(t.assignees.all()) == [owner]
    assert _inbox(owner) == ["Task T-0001 assigned to you: Review firewall rules"]


@pytest.mark.parametrize("role", [Role.CONTROL_OWNER, Role.AUDITOR, Role.VIEWER])
def test_only_managers_create_tasks(users, role):
    with pytest.raises(services.WorkError):
        _task(users[role])


def test_assignee_progresses_but_others_cannot(users, rm, owner):
    t = _task(rm, [owner])
    services.set_task_status(t, user=owner, status="in_progress")
    with pytest.raises(services.WorkError):
        services.set_task_status(t, user=users[Role.AUDITOR], status="done")
    with pytest.raises(services.WorkError):  # assignees cannot cancel
        services.set_task_status(t, user=owner, status="cancelled")
    services.set_task_status(t, user=owner, status="done", note="ok")
    assert t.completed_by == owner and not t.is_open
    with pytest.raises(services.WorkError):  # only managers reopen
        services.set_task_status(t, user=owner, status="todo")
    services.set_task_status(t, user=rm, status="todo")
    assert t.completed_at is None


def test_evidence_required_tasks(org, rm, owner):
    ctl = make_control(org, "CTL-FW", owner=owner)
    t = _task(rm, [owner], control=ctl, requires_evidence=True)
    with pytest.raises(services.WorkError, match="note"):
        services.set_task_status(t, user=owner, status="done")
    with pytest.raises(services.WorkError, match="Add evidence"):
        services.set_task_status(t, user=owner, status="done", note="Checked")
    control_services.add_link_evidence(
        ctl, user=owner, url="https://wiki.example/fw-review", title="Rule review"
    )
    services.set_task_status(t, user=owner, status="done", note="Checked")
    assert t.status == "done"


def test_periodic_task_creates_next_occurrence(rm, owner):
    t = _task(rm, [owner], due_on=date(2026, 1, 31), recurrence="monthly")
    services.set_task_status(t, user=owner, status="done", note="ok")
    nxt = Task.objects.get(previous=t)
    assert nxt.due_on == date(2026, 2, 28) and list(nxt.assignees.all()) == [owner]
    assert nxt.recurrence == "monthly" and nxt.status == "todo"
    services.set_task_status(t, user=rm, status="todo")
    services.set_task_status(t, user=rm, status="done")
    assert Task.objects.filter(previous=t).count() == 1  # never duplicated
    weekly = _task(rm, [owner], due_on=date(2026, 3, 2), recurrence="weekly")
    services.set_task_status(weekly, user=rm, status="cancelled")
    assert Task.objects.get(previous=weekly).due_on == date(2026, 3, 9)


def test_overdue_and_visibility(users, rm, owner):
    t = _task(rm, [users[Role.VIEWER]], due_on=timezone.localdate() - timedelta(days=1))
    other = _task(rm, [owner])
    assert t.overdue
    viewer = users[Role.VIEWER]
    assert list(services.visible_tasks(viewer)) == [t]  # viewers see only their own
    assert set(services.visible_tasks(users[Role.AUDITOR])) == {t, other}
    services.set_task_status(t, user=viewer, status="done")  # respondents can finish
    assert not t.overdue


def test_update_task_notifies_new_assignees_only(users, rm, owner):
    t = _task(rm, [owner])
    Notification.objects.all().delete()
    services.update_task(
        t, user=rm, data={"priority": "high"}, assignees=[owner, users[Role.AUDITOR]]
    )
    assert _inbox(owner) == [] and len(_inbox(users[Role.AUDITOR])) == 1
    with pytest.raises(services.WorkError):
        services.update_task(t, user=owner, data={"title": "x"})


def test_task_links_must_be_in_the_organisation(rm):
    from threatledger.org.models import Organisation

    other = Organisation.objects.create(name="Other")
    with pytest.raises(services.WorkError, match="control"):
        _task(rm, control=make_control(other, "X"))


# ----------------------------------------------------------------------------- comments
def test_comment_mentions_notify_only_people_who_can_see(users, rm, owner):
    finding = finding_services.create_finding(user=rm, data={"title": "Weak TLS", "owner": owner})
    Notification.objects.all().delete()
    c = services.add_comment(
        finding, user=rm, body="@control_owner please fix; cc @viewer and @nobody"
    )
    assert list(c.mentions.all()) == [owner]  # viewers cannot see findings
    assert any(m.endswith("mentioned you on F-0001") for m in _inbox(owner))
    assert _inbox(users[Role.VIEWER]) == []


def test_comment_rules(users, rm):
    risk = make_risk(rm)
    with pytest.raises(services.WorkError):
        services.add_comment(risk, user=users[Role.VIEWER], body="hi")
    with pytest.raises(services.WorkError, match="Write"):
        services.add_comment(risk, user=rm, body="   ")
    with pytest.raises(services.WorkError, match="5,000"):
        services.add_comment(risk, user=rm, body="x" * 5001)
    with pytest.raises(services.WorkError):
        services.commentable(rm, "accounts.user", "1")


def test_comment_view_and_thread_rendering(client_for, users, rm):
    risk = make_risk(rm)
    c = client_for(Role.AUDITOR)
    r = c.post(
        reverse("work:comment_add"),
        {
            "target": "risks.risk",
            "object_id": risk.pk,
            "body": "Evidence for residual score?",
            "next": "https://evil.example/",
        },
    )
    assert r.status_code == 302 and r["Location"] == f"/risks/{risk.ref}/#comments"
    assert Comment.objects.get().author == users[Role.AUDITOR]
    page = c.get(reverse("risks:detail", args=[risk.ref]))
    assert b"Evidence for residual score?" in page.content and b"Discussion (1)" in page.content
    assert client_for(Role.VIEWER).post(reverse("work:comment_add"), {}).status_code == 403
    bogus = c.post(reverse("work:comment_add"), {"target": "risks.risk", "object_id": "999"})
    assert bogus.status_code == 302


# ----------------------------------------------------------------------------- views
def test_work_pages(client_for, users, rm, owner):
    t = _task(rm, [owner], recurrence="quarterly", due_on=date(2026, 1, 15))
    oc = client_for(Role.CONTROL_OWNER)
    mine = oc.get(reverse("work:mine"))
    assert mine.status_code == 200 and t.ref.encode() in mine.content
    assert oc.get(reverse("work:board")).status_code == 200
    assert oc.get(reverse("work:tasks"), {"status": "all", "mine": "1"}).status_code == 200
    detail = oc.get(reverse("work:task", args=[t.ref]))
    assert b"Mark done" in detail.content
    r = oc.post(reverse("work:task_status", args=[t.ref]), {"status": "done", "note": "ok"})
    assert r.status_code == 302
    assert Task.objects.filter(previous=t, due_on=date(2026, 4, 15)).exists()
    viewer = client_for(Role.VIEWER)
    assert viewer.get(reverse("work:mine")).status_code == 200
    assert viewer.get(reverse("work:board")).status_code == 403
    assert viewer.get(reverse("work:task", args=[t.ref])).status_code == 404
    m = client_for(Role.RISK_MANAGER)
    assert m.get(reverse("work:task_create"), {"control": "nope"}).status_code == 200
    r = m.post(
        reverse("work:task_create"),
        {
            "title": "Quarterly access review",
            "priority": "high",
            "recurrence": "quarterly",
            "assignees": [owner.pk],
        },
    )
    assert r.status_code == 302 and Task.objects.filter(title="Quarterly access review").exists()


def test_notification_views(client_for, users, rm, owner):
    notify([owner], "Look at this", "/risks/", actor=rm)
    notify([owner], "Evil", "https://evil.example/", actor=rm)
    c = client_for(Role.CONTROL_OWNER)
    page = c.get(reverse("work:notifications"))
    assert b"Look at this" in page.content
    home = c.get("/")
    assert home.context["tl_unread"] == 2
    good, evil = Notification.objects.order_by("id")
    assert c.get(reverse("work:notification_open", args=[good.pk]))["Location"] == "/risks/"
    assert c.get(reverse("work:notification_open", args=[evil.pk]))["Location"] == "/"
    c.post(reverse("work:notifications_read"))
    assert not Notification.objects.filter(read_at__isnull=True).exists()
    other = client_for(Role.AUDITOR)
    assert other.get(reverse("work:notification_open", args=[good.pk])).status_code == 404


def test_preferences(client_for, owner):
    c = client_for(Role.CONTROL_OWNER)
    assert c.get(reverse("work:preferences")).status_code == 200
    c.post(reverse("work:preferences"), {})
    assert services.preference(owner).email_digest is False
    c.post(reverse("work:preferences"), {"email_digest": "on"})
    assert services.preference(owner).email_digest is True
