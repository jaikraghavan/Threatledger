from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.roles import Role
from threatledger.audit.models import Action, AuditEvent
from threatledger.privacy import services
from threatledger.privacy.models import Processing
from threatledger.risks.tests.helpers import make_control, make_risk
from threatledger.work.models import Notification

pytestmark = pytest.mark.django_db
BASE = {
    "name": "Customer orders",
    "purpose": "Fulfil and deliver orders",
    "legal_basis": "contract",
    "retention": "6 years after the order",
    "data_categories": ["identity", "contact", "financial"],
    "data_subjects": ["customers"],
}


@pytest.fixture
def rm(users):
    return users[Role.RISK_MANAGER]


def _p(user, **data):
    return services.create_processing(user=user, data={**BASE, **data})


def test_create_and_validation(org, rm, users):
    p = _p(rm, transfer_countries="US", transfer_safeguard="scc")
    assert p.ref == "PA-0001" and not p.special_category and not p.dpia_required
    with pytest.raises(ValidationError):
        _p(rm, data_categories=[])
    with pytest.raises(ValidationError):
        _p(rm, data_categories=["dna"])
    with pytest.raises(ValidationError, match="safeguard"):
        _p(rm, transfer_countries="US")
    for role in (Role.AUDITOR, Role.CONTROL_OWNER, Role.VIEWER):
        with pytest.raises(services.PrivacyError):
            _p(users[role])


def test_dpia_screening_is_derived(rm):
    p = _p(rm, data_categories=["health"], large_scale=True)
    assert p.special_category and p.dpia_triggers == ["special-category data", "large scale"]
    assert p.dpia_required and services.dpia_state(p) == "missing"
    one = _p(rm, data_subjects=["children"])
    assert not one.dpia_required
    assert _p(rm, automated_decisions=True).dpia_required


def test_links_must_be_in_the_organisation(org, rm):
    from threatledger.org.models import Organisation

    other = Organisation.objects.create(name="Other")
    with pytest.raises(services.PrivacyError):
        services.create_processing(
            user=rm, data=BASE, links={"controls": [make_control(other, "X")]}
        )
    p = services.create_processing(user=rm, data=BASE, links={"controls": [make_control(org, "C")]})
    assert [c.ref for c in p.controls.all()] == ["C"]


def test_dpia_lifecycle_with_segregation(rm, users):
    admin = users[Role.ADMIN]
    p = _p(rm, data_categories=["health"], large_scale=True)
    d = services.create_dpia(
        p,
        user=rm,
        data={"description": "d", "necessity": "n", "risks_to_individuals": "r", "measures": "m"},
        risks=[make_risk(rm)],
    )
    assert d.ref == "DPIA-0001" and services.dpia_state(p) == "in_progress"
    with pytest.raises(services.PrivacyError, match="still open"):
        services.create_dpia(p, user=rm, data={})
    with pytest.raises(services.PrivacyError, match="in review"):
        services.decide_dpia(d, user=admin, approve=True)
    services.submit_dpia(d, user=rm)
    assert Notification.objects.filter(recipient=admin, message__contains="DPIA-0001").exists()
    with pytest.raises(services.PrivacyError, match="Segregation"):
        services.decide_dpia(d, user=rm, approve=True)
    with pytest.raises(services.PrivacyError, match="rework"):
        services.decide_dpia(d, user=admin, approve=False)
    services.decide_dpia(d, user=admin, approve=False, note="Add retention analysis")
    services.update_dpia(d, user=rm, data={"necessity": "n + retention"})
    services.submit_dpia(d, user=rm)
    services.decide_dpia(d, user=admin, approve=True)
    assert services.dpia_state(p) == "approved" and d.review_due is not None
    d.review_due = timezone.localdate() - timedelta(days=1)
    d.save()
    assert services.dpia_state(p) == "review_due"
    with pytest.raises(services.PrivacyError, match="drafts"):
        services.update_dpia(d, user=rm, data={"measures": "x"})


def test_views_and_export(client_for, rm, users):
    c = client_for(Role.RISK_MANAGER)
    r = c.post(
        reverse("privacy:create"),
        {
            "name": "Payroll",
            "purpose": "Pay staff",
            "role": "controller",
            "legal_basis": "legal_obligation",
            "status": "active",
            "retention": "7 years",
            "data_categories": ["identity", "financial", "employment"],
            "data_subjects": ["employees"],
            "recipients": "=cmd|' /C calc'!A0",
        },
    )
    p = Processing.objects.get(name="Payroll")
    assert r.status_code == 302 and p.data_subjects == ["employees"]
    assert c.get(reverse("privacy:detail", args=[p.ref])).status_code == 200
    c.post(
        reverse("privacy:dpia_create", args=[p.ref]),
        {
            "description": "d",
            "necessity": "n",
            "risks_to_individuals": "r",
            "measures": "m",
            "residual_risk": "low",
        },
    )
    dpia = p.dpias.get()
    c.post(
        reverse("privacy:dpia_edit", args=[dpia.ref]),
        {
            "description": "d",
            "necessity": "n",
            "risks_to_individuals": "r",
            "measures": "m",
            "residual_risk": "low",
            "submit": "1",
        },
    )
    page = client_for(Role.ADMIN).get(reverse("privacy:dpia", args=[dpia.ref]))
    assert b"Approve" in page.content
    assert b"Approve" not in c.get(reverse("privacy:dpia", args=[dpia.ref])).content
    client_for(Role.ADMIN).post(
        reverse("privacy:dpia_decide", args=[dpia.ref]), {"decision": "approve"}
    )
    dpia.refresh_from_db()
    assert dpia.status == "approved"
    export = client_for(Role.AUDITOR).get(reverse("privacy:export"))
    body = export.content.decode("utf-8-sig")
    assert "Payroll" in body and "'=cmd" in body
    assert AuditEvent.objects.filter(
        action=Action.EXPORT, object_type="privacy.processing"
    ).exists()
    assert (
        client_for(Role.AUDITOR).get(reverse("privacy:list"), {"dpia": "missing"}).status_code
        == 200
    )
    assert client_for(Role.VIEWER).get(reverse("privacy:list")).status_code == 403
    assert client_for(Role.AUDITOR).get(reverse("privacy:create")).status_code == 403
