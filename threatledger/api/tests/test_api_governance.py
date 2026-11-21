"""API v1: audits, findings, exceptions and policies (Phase 8)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.test import Client
from django.utils import timezone

from threatledger.accounts.roles import Role
from threatledger.api.models import ApiToken
from threatledger.audits import services as audit_services
from threatledger.audits.tests.helpers import framework, req
from threatledger.findings import services as finding_services
from threatledger.findings.models import Finding
from threatledger.frameworks import services as fw_services
from threatledger.policies import services as policy_services
from threatledger.risks.tests.helpers import make_control

pytestmark = pytest.mark.django_db
JSON = "application/json"


@pytest.fixture
def tokens(users):
    return {role: ApiToken.issue(user, f"{role} token", 30)[1] for role, user in users.items()}


def api(raw: str) -> Client:
    return Client(HTTP_AUTHORIZATION=f"Bearer {raw}")


def test_audits_with_scores_and_results(org, users, tokens):
    fw = framework()
    rm, auditor = users[Role.RISK_MANAGER], users[Role.AUDITOR]
    ctl = make_control(org, "MFA", status="not_implemented")
    fw_services.map_control(req(fw, "A-1"), ctl, user=rm)
    audit = audit_services.create_audit(user=rm, data={"name": "Annual", "framework": fw})
    audit_services.record_judgement(
        audit, req(fw, "A-1"), user=auditor, judgement="compliant", maturity=4
    )
    c = api(tokens[Role.AUDITOR])
    listing = c.get("/api/v1/audits/").json()["results"]
    assert listing[0]["ref"] == audit.ref
    assert listing[0]["score"]["assessed"] == 1 and listing[0]["score"]["requirements"] == 3
    detail = c.get(f"/api/v1/audits/{audit.ref}/").json()
    assert detail["score"]["maturity"] == 4.0
    results = c.get(f"/api/v1/audits/{audit.ref}/results/").json()
    first = results[0]
    assert (first["requirement"], first["judgement"], first["derived_now"]) == (
        "A-1",
        "compliant",
        "gap",
    )
    assert first["divergent"] is True and first["derived_at_judgement"] == "gap"
    assert api(tokens[Role.VIEWER]).get("/api/v1/audits/").status_code == 403


def test_findings_create_update_and_verify(users, tokens):
    owner = users[Role.CONTROL_OWNER]
    created = api(tokens[Role.AUDITOR]).post(
        "/api/v1/findings/",
        {"title": "Stale admin accounts", "severity": "high", "owner": owner.username},
        content_type=JSON,
    )
    assert created.status_code == 201, created.content
    ref = created.json()["ref"]
    assert created.json()["status"] == "open" and created.json()["due_on"]
    oc = api(tokens[Role.CONTROL_OWNER])
    assert oc.post("/api/v1/findings/", {"title": "x"}, content_type=JSON).status_code == 403
    r = oc.patch(
        f"/api/v1/findings/{ref}/",
        {"remediation": "Removed", "status": "resolved"},
        content_type=JSON,
    )
    assert r.status_code == 200 and r.json()["status"] == "resolved"
    # owners cannot verify their own fix, nor change the severity
    assert (
        oc.patch(f"/api/v1/findings/{ref}/", {"status": "closed"}, content_type=JSON).status_code
        == 403
    )
    assert (
        oc.patch(f"/api/v1/findings/{ref}/", {"severity": "low"}, content_type=JSON).status_code
        == 403
    )
    done = api(tokens[Role.AUDITOR]).patch(
        f"/api/v1/findings/{ref}/", {"status": "closed"}, content_type=JSON
    )
    assert done.status_code == 200 and Finding.objects.get(ref=ref).closed_by == users[Role.AUDITOR]
    assert api(tokens[Role.VIEWER]).get("/api/v1/findings/").status_code == 403


def test_exceptions_and_policies_read(org, users, tokens):
    rm, admin = users[Role.RISK_MANAGER], users[Role.ADMIN]
    exc = finding_services.request_exception(
        user=rm,
        controls=[make_control(org, "LEGACY")],
        data={
            "title": "Legacy",
            "justification": "j",
            "expires_on": timezone.localdate() + timedelta(days=30),
        },
    )
    finding_services.decide_exception(exc, user=admin, approve=True)
    data = api(tokens[Role.AUDITOR]).get("/api/v1/exceptions/").json()["results"]
    assert data[0]["status"] == "approved" and data[0]["controls"] == ["LEGACY"]

    p = policy_services.create_policy(
        user=rm, data={"title": "AUP", "kind": "policy"}, body="Be nice"
    )
    v = p.versions.get()
    policy_services.submit_version(v, user=rm)
    policy_services.decide_version(v, user=admin, approve=True)
    got = api(tokens[Role.VIEWER]).get(f"/api/v1/policies/{p.ref}/").json()
    assert got["status"] == "published" and got["published_version"] == 1
    assert got["next_review_on"]


def test_tasks_api(users, tokens):
    from threatledger.work import services as work_services
    from threatledger.work.models import Task

    rm, viewer = users[Role.RISK_MANAGER], users[Role.VIEWER]
    t = work_services.create_task(
        user=rm,
        data={"title": "Monthly backup restore test", "recurrence": "monthly"},
        assignees=[viewer],
    )
    other = work_services.create_task(user=rm, data={"title": "Not yours"})
    v = api(tokens[Role.VIEWER])
    refs = [x["ref"] for x in v.get("/api/v1/tasks/").json()["results"]]
    assert refs == [t.ref]
    assert v.get(f"/api/v1/tasks/{other.ref}/").status_code == 404
    r = v.patch(
        f"/api/v1/tasks/{t.ref}/", {"status": "done", "note": "Restored"}, content_type=JSON
    )
    assert r.status_code == 200 and r.json()["status"] == "done"
    assert Task.objects.filter(previous=t).exists()
    bad = api(tokens[Role.AUDITOR]).patch(
        f"/api/v1/tasks/{other.ref}/", {"status": "done"}, content_type=JSON
    )
    assert bad.status_code == 403
