from __future__ import annotations

import pytest
from django.test import Client
from django.urls import reverse

from conftest import TEST_PASSWORD
from threatledger.accounts.roles import Role
from threatledger.audit.models import Action, AuditEvent

pytestmark = pytest.mark.django_db


def test_login_page_is_public(client):
    assert client.get(reverse("accounts:login")).status_code == 200


def test_anonymous_is_redirected_to_login(client):
    response = client.get(reverse("core:home"))
    assert response.status_code == 302
    assert response["Location"].startswith(reverse("accounts:login"))


def test_anonymous_htmx_request_gets_hx_redirect(client):
    response = client.get(reverse("audit:list"), HTTP_HX_REQUEST="true")
    assert response.status_code == 401
    assert response["HX-Redirect"] == reverse("accounts:login")


def test_successful_login_is_audited(users):
    c = Client()
    response = c.post(reverse("accounts:login"), {"username": "viewer", "password": TEST_PASSWORD})
    assert response.status_code == 302
    event = AuditEvent.objects.filter(action=Action.LOGIN).get()
    assert event.actor == users[Role.VIEWER]


def test_failed_login_is_audited_without_password(users):
    c = Client()
    c.post(reverse("accounts:login"), {"username": "viewer", "password": "wrong-password-123"})
    event = AuditEvent.objects.filter(action=Action.LOGIN_FAILED).get()
    assert event.changes == {"username": "viewer"}
    assert "wrong-password-123" not in event.canonical()


def test_logout_requires_post_and_is_audited(client_for):
    c = client_for(Role.VIEWER)
    assert c.get(reverse("accounts:logout")).status_code == 405
    assert c.post(reverse("accounts:logout")).status_code == 302
    assert AuditEvent.objects.filter(action=Action.LOGOUT).exists()


def test_password_change_requires_login(client):
    assert client.get(reverse("accounts:password_change")).status_code == 302


def test_password_change_page_for_any_authenticated_user(make_user):
    c = Client()
    c.force_login(make_user(role=None, username="nobody"))
    assert c.get(reverse("accounts:password_change")).status_code == 200


def test_login_form_has_csrf_protection(users):
    c = Client(enforce_csrf_checks=True)
    response = c.post(reverse("accounts:login"), {"username": "viewer", "password": TEST_PASSWORD})
    assert response.status_code == 403


def test_api_me_returns_role_and_capabilities(client_for):
    response = client_for(Role.AUDITOR).get(reverse("api:me"))
    assert response.status_code == 200
    body = response.json()
    assert body["role"] == "auditor"
    assert "view_audit_log" in body["capabilities"]
    assert "edit_risks" not in body["capabilities"]


def test_api_me_rejects_anonymous(client):
    response = client.get(reverse("api:me"))
    assert response.status_code == 401
    assert response["WWW-Authenticate"].startswith("Bearer")
