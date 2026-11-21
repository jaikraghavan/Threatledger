from __future__ import annotations

import pytest
from django.test import Client
from django.urls import reverse

from threatledger.accounts.roles import Role

pytestmark = pytest.mark.django_db


def test_home_renders_role_navigation(client_for):
    response = client_for(Role.AUDITOR).get(reverse("core:home"))
    assert response.status_code == 200
    labels = [i["label"] for i in response.context["nav_items"]]
    assert labels == [
        "Dashboard",
        "Risk register",
        "Controls",
        "Compliance",
        "Audits",
        "Findings",
        "Policies",
        "ATT&CK coverage",
        "Techniques",
        "Threat groups",
        "Audit log",
    ]
    assert b"Auditor" in response.content


def test_viewer_does_not_see_audit_link(client_for):
    response = client_for(Role.VIEWER).get(reverse("core:home"))
    assert [i["label"] for i in response.context["nav_items"]] == [
        "Dashboard",
        "Risk register",
        "Controls",
        "Compliance",
        "Policies",
        "ATT&CK coverage",
        "Techniques",
        "Threat groups",
    ]


def test_user_without_role_gets_403_on_home(make_user):
    c = Client()
    c.force_login(make_user(role=None, username="nobody"))
    assert c.get(reverse("core:home")).status_code == 403


def test_htmx_requests_carry_csrf_header(client_for):
    response = client_for(Role.VIEWER).get(reverse("core:home"))
    assert b'hx-headers=\'{"X-CSRFToken": "' in response.content


def test_django_admin_is_superuser_only(users, make_user):
    staff_admin = users[Role.ADMIN]
    staff_admin.is_staff = True
    staff_admin.save()
    c = Client()
    c.force_login(staff_admin)
    assert c.get(reverse("admin:index")).status_code == 302  # bounced to admin login

    root = make_user(role=None, username="root", is_superuser=True, is_staff=True)
    c.force_login(root)
    assert c.get(reverse("admin:index")).status_code == 200


def test_custom_404(client_for):
    response = client_for(Role.VIEWER).get("/definitely-not-here/")
    assert response.status_code == 404


def test_can_template_filter(users):
    from threatledger.core.templatetags.tl import can

    assert can(users[Role.RISK_MANAGER], "edit_risks") is True
    assert can(users[Role.VIEWER], "edit_risks") is False
    assert can(users[Role.ADMIN], "no_such_capability") is False
