from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.roles import Role
from threatledger.api.models import ApiToken, hash_token
from threatledger.audit.models import Action, AuditEvent
from threatledger.frameworks.importer import load, parse
from threatledger.frameworks.tests.test_services import FW_A
from threatledger.risks.models import Risk
from threatledger.risks.tests.helpers import make_control, make_risk, map_direct, technique

pytestmark = pytest.mark.django_db


@pytest.fixture
def tokens(users):
    return {role: ApiToken.issue(user, f"{role} token", 30)[1] for role, user in users.items()}


def api(raw: str | None = None) -> Client:
    return Client(HTTP_AUTHORIZATION=f"Bearer {raw}") if raw else Client()


# ----------------------------------------------------------------------------- tokens
def test_token_is_hashed_and_authenticates(users, tokens):
    raw = tokens[Role.AUDITOR]
    token = ApiToken.objects.get(user=users[Role.AUDITOR])
    assert token.token_hash == hash_token(raw) and raw not in token.token_hash
    response = api(raw).get(reverse("api:me"))
    assert response.status_code == 200
    assert response.json() == {
        **response.json(),
        "username": "auditor",
        "role": "auditor",
        "auth": "token",
    }
    token.refresh_from_db()
    assert token.last_used_at is not None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw[:-2] + "xx",  # wrong secret
        lambda raw: raw.replace("tl_", "tx_"),  # malformed
        lambda raw: "tl_00000000_" + "a" * 30,  # unknown prefix
        lambda raw: raw + " extra",  # extra part
    ],
)
def test_bad_tokens_rejected_generically(tokens, mutate):
    response = api(mutate(tokens[Role.VIEWER])).get(reverse("api:me"))
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token."


def test_revoked_expired_and_inactive_tokens_rejected(users, tokens):
    t = ApiToken.objects.get(user=users[Role.VIEWER])
    t.expires_at = timezone.now() - timedelta(seconds=1)
    t.save()
    assert api(tokens[Role.VIEWER]).get(reverse("api:me")).status_code == 401
    t2 = ApiToken.objects.get(user=users[Role.AUDITOR])
    t2.revoked_at = timezone.now()
    t2.save()
    assert api(tokens[Role.AUDITOR]).get(reverse("api:me")).status_code == 401
    users[Role.ADMIN].is_active = False
    users[Role.ADMIN].save()
    assert api(tokens[Role.ADMIN]).get(reverse("api:me")).status_code == 401


def test_token_management_ui(client_for, users):
    c = client_for(Role.VIEWER)
    created = c.post(reverse("accounts:tokens"), {"name": "CI", "days": "30"})
    raw = created.context["new_token"]
    assert raw.startswith("tl_") and raw.encode() in created.content
    assert raw.encode() not in c.get(reverse("accounts:tokens")).content  # shown once
    assert api(raw).get(reverse("api:me")).status_code == 200
    mine = ApiToken.objects.get(user=users[Role.VIEWER])
    other = ApiToken.issue(users[Role.AUDITOR], "theirs", 30)[0]
    c.post(reverse("accounts:tokens"), {"revoke": other.pk})
    other.refresh_from_db()
    assert other.revoked_at is None  # can't revoke someone else's token
    c.post(reverse("accounts:tokens"), {"revoke": mine.pk})
    assert api(raw).get(reverse("api:me")).status_code == 401
    assert AuditEvent.objects.filter(object_type="api.apitoken", action=Action.CREATE).exists()


# ----------------------------------------------------------------------------- risks
def test_risk_list_and_retrieve(users, tokens):
    risk = make_risk(users[Role.RISK_MANAGER])
    data = api(tokens[Role.VIEWER]).get("/api/v1/risks/").json()
    assert data["count"] == 1
    item = data["results"][0]
    assert item["ref"] == risk.ref
    assert item["inherent"] == {"likelihood": 4, "impact": 5, "score": 20, "band": "critical"}
    assert api(tokens[Role.VIEWER]).get(f"/api/v1/risks/{risk.ref}/").json()["title"] == risk.title


def test_risk_create_and_update_permissions(users, tokens):
    body = {
        "title": "API risk",
        "scenario": "x",
        "inherent_likelihood": 3,
        "inherent_impact": 3,
        "residual_likelihood": 2,
        "residual_impact": 2,
    }
    assert (
        api(tokens[Role.VIEWER])
        .post("/api/v1/risks/", body, content_type="application/json")
        .status_code
        == 403
    )
    created = api(tokens[Role.RISK_MANAGER]).post(
        "/api/v1/risks/", body, content_type="application/json"
    )
    assert created.status_code == 201, created.content
    ref = created.json()["ref"]
    patched = api(tokens[Role.RISK_MANAGER]).patch(
        f"/api/v1/risks/{ref}/",
        {"residual_likelihood": 1, "reason": "MFA"},
        content_type="application/json",
    )
    assert patched.status_code == 200
    assert patched.json()["residual"]["score"] == 2
    assert Risk.objects.get(ref=ref).score_history.all()[0].reason == "MFA"
    assert AuditEvent.objects.filter(action=Action.CREATE, object_type="risks.risk").exists()


def test_risk_validation_errors(users, tokens):
    body = {
        "title": "Bad",
        "scenario": "x",
        "inherent_likelihood": 2,
        "inherent_impact": 2,
        "residual_likelihood": 5,
        "residual_impact": 5,
    }
    response = api(tokens[Role.RISK_MANAGER]).post(
        "/api/v1/risks/", body, content_type="application/json"
    )
    assert response.status_code == 400
    assert "cannot exceed inherent" in str(response.json())
    accepted = api(tokens[Role.RISK_MANAGER]).post(
        "/api/v1/risks/",
        {**body, "residual_likelihood": 1, "residual_impact": 1, "status": "accepted"},
        content_type="application/json",
    )
    assert accepted.status_code == 400


def test_link_technique_action(users, tokens):
    risk = make_risk(users[Role.RISK_MANAGER])
    technique("T1566", "Phishing")
    url = f"/api/v1/risks/{risk.ref}/techniques/"
    assert (
        api(tokens[Role.VIEWER])
        .post(url, {"attack_id": "T1566"}, content_type="application/json")
        .status_code
        == 403
    )
    response = api(tokens[Role.RISK_MANAGER]).post(
        url, {"attack_id": "T1566"}, content_type="application/json"
    )
    assert response.status_code == 200 and response.json()["techniques"] == ["T1566"]
    assert (
        api(tokens[Role.RISK_MANAGER])
        .post(url, {"attack_id": "bad"}, content_type="application/json")
        .status_code
        == 400
    )


# ----------------------------------------------------------------------------- controls
def test_control_patch_by_owner(org, users, tokens):
    mine = make_control(org, "CTL-MFA", status="planned", owner=users[Role.CONTROL_OWNER])
    theirs = make_control(org, "CTL-EDR", status="planned")
    c = api(tokens[Role.CONTROL_OWNER])
    ok = c.patch(
        f"/api/v1/controls/{mine.ref}/", {"status": "implemented"}, content_type="application/json"
    )
    assert ok.status_code == 200 and ok.json()["status"] == "implemented"
    assert (
        c.patch(
            f"/api/v1/controls/{theirs.ref}/",
            {"status": "implemented"},
            content_type="application/json",
        ).status_code
        == 403
    )
    assert (
        api(tokens[Role.AUDITOR])
        .patch(
            f"/api/v1/controls/{mine.ref}/", {"status": "planned"}, content_type="application/json"
        )
        .status_code
        == 403
    )
    c.patch(f"/api/v1/controls/{mine.ref}/", {"name": "Renamed"}, content_type="application/json")
    mine.refresh_from_db()
    assert mine.name == "CTL-MFA"  # read-only field ignored
    listing = api(tokens[Role.VIEWER]).get("/api/v1/controls/?status=implemented").json()
    assert [x["ref"] for x in listing["results"]] == ["CTL-MFA"]


# ----------------------------------------------------------------------------- read endpoints
def test_techniques_with_coverage(org, users, tokens):
    t = technique("T1078", "Valid Accounts")
    technique("T1110", "Brute Force")
    map_direct(make_control(org, "CTL-MFA", status="implemented"), t)
    data = api(tokens[Role.VIEWER]).get("/api/v1/techniques/").json()["results"]
    assert {x["attack_id"]: x["coverage"] for x in data} == {"T1078": "covered", "T1110": "gap"}
    assert api(tokens[Role.VIEWER]).get("/api/v1/techniques/T1078/").json()["coverage"] == "covered"
    assert [
        x["attack_id"]
        for x in api(tokens[Role.VIEWER]).get("/api/v1/techniques/?q=brute").json()["results"]
    ] == ["T1110"]


def test_frameworks_and_requirements(org, users, tokens):
    from threatledger.frameworks import services
    from threatledger.frameworks.models import Requirement

    fw = load(parse(FW_A, "a.yaml")).framework
    services.map_control(
        Requirement.objects.get(framework=fw, ref="A-1"),
        make_control(org, "CTL-1", status="implemented"),
        user=users[Role.ADMIN],
    )
    frameworks = api(tokens[Role.VIEWER]).get("/api/v1/frameworks/").json()
    assert frameworks[0]["code"] == "FW-A" and frameworks[0]["met"] == 1
    gaps = (
        api(tokens[Role.VIEWER])
        .get("/api/v1/frameworks/FW-A/requirements/?status=no_control")
        .json()
    )
    assert [r["ref"] for r in gaps["requirements"]] == ["A-2", "A-3"]
    met = api(tokens[Role.VIEWER]).get("/api/v1/frameworks/FW-A/requirements/?status=met").json()
    assert met["requirements"] == [
        {"ref": "A-1", "title": "One", "status": "met", "controls": ["CTL-1"]}
    ]


def test_coverage_and_navigator(org, users, tokens):
    t = technique("T1078")
    risk = make_risk(users[Role.RISK_MANAGER])
    from threatledger.risks import services as rs

    rs.link_technique(risk, t, user=users[Role.RISK_MANAGER])
    summary = api(tokens[Role.VIEWER]).get("/api/v1/coverage/?scope=risks").json()
    assert (summary["total"], summary["gap"]) == (1, 1)
    assert api(tokens[Role.VIEWER]).get("/api/v1/coverage/navigator/").status_code == 403
    layer = api(tokens[Role.AUDITOR]).get("/api/v1/coverage/navigator/?scope=risks").json()
    assert layer["versions"]["layer"] == "4.5"


def test_audit_events_endpoint(users, tokens):
    make_risk(users[Role.RISK_MANAGER])
    assert api(tokens[Role.VIEWER]).get("/api/v1/audit-events/").status_code == 403
    data = (
        api(tokens[Role.AUDITOR])
        .get("/api/v1/audit-events/?action=create&object_type=risks.risk")
        .json()
    )
    assert data["count"] == 1 and len(data["results"][0]["hash"]) == 64
    assert api(tokens[Role.AUDITOR]).get("/api/v1/audit-events/?since=yesterday").status_code == 400


def test_schema_and_docs(client_for, tokens):
    assert Client().get(reverse("api:schema")).status_code == 401
    schema = api(tokens[Role.VIEWER]).get(reverse("api:schema") + "?format=json")
    assert schema.status_code == 200
    paths = schema.json()["paths"]
    assert "/api/v1/risks/" in paths and "/api/v1/controls/{ref}/" in paths
    docs = client_for(Role.VIEWER).get(reverse("api:docs"))
    assert docs.status_code == 200
    assert "/api/v1/risks/{ref}/techniques/" in [op["path"] for op in docs.context["operations"]]


def test_throttling_is_configured(settings):
    from config.settings import base

    rf: dict[str, Any] = dict(base.REST_FRAMEWORK)
    assert "rest_framework.throttling.UserRateThrottle" in rf["DEFAULT_THROTTLE_CLASSES"]
    assert rf["DEFAULT_THROTTLE_RATES"]["anon"] == "30/hour"


def test_openapi_schema_validates_without_warnings(tmp_path):
    """drf-spectacular warnings also fail `check --deploy` in CI; catch them here first."""
    from django.core.management import call_command

    out = tmp_path / "schema.yaml"
    call_command("spectacular", "--file", str(out), "--validate", "--fail-on-warn")
    text = out.read_text()
    assert "ApiToken" in text and "bearerFormat" in text
