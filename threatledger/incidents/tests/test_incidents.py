from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.roles import Role
from threatledger.incidents import services
from threatledger.incidents.models import Incident
from threatledger.incidents.regimes import REGIMES
from threatledger.risks.tests.helpers import make_control, technique
from threatledger.work.models import Notification

pytestmark = pytest.mark.django_db


@pytest.fixture
def rm(users):
    return users[Role.RISK_MANAGER]


def _report(user, **data):
    return services.report_incident(
        user=user, data={"title": "Suspicious login", "description": "Impossible travel", **data}
    )


def test_anyone_can_report_and_sees_only_their_own(users, rm):
    viewer = users[Role.VIEWER]
    mine = _report(viewer, regimes=["gdpr"], owner=rm)
    assert (
        mine.ref == "INC-0001" and mine.regimes == [] and mine.owner is None
    )  # no managerial fields
    other = _report(rm, title="Other")
    assert list(services.visible_incidents(viewer)) == [mine]
    assert set(services.visible_incidents(users[Role.AUDITOR])) == {mine, other}
    assert Notification.objects.filter(recipient=rm, message__contains="INC-0001").exists()
    assert mine.timeline.count() == 1
    with pytest.raises(services.IncidentError):
        services.update_incident(mine, user=viewer, data={"title": "x"})


def test_regulatory_deadlines_are_derived_from_awareness(rm):
    aware = timezone.now() - timedelta(hours=5)
    i = _report(rm, aware_at=aware, regimes=["certin", "gdpr", "nis2"])
    obs = services.obligations(i)
    assert [(o.regime.key, o.step.key) for o in obs] == [
        ("certin", "report"),
        ("nis2", "early_warning"),
        ("gdpr", "authority"),
        ("nis2", "notification"),
        ("nis2", "final"),
    ]
    assert obs[0].due_at == aware + timedelta(hours=6) and obs[0].state == "due_soon"
    services.update_incident(i, user=rm, data={"aware_at": aware - timedelta(hours=2)})
    assert services.obligations(i)[0].state == "overdue"  # correcting awareness moves clocks
    assert i.timeline.filter(text__contains="deadlines moved").exists()
    with pytest.raises(ValidationError):
        services.update_incident(i, user=rm, data={"regimes": ["hipaa"]})


def test_filing_and_not_required(rm):
    i = _report(rm, regimes=["gdpr", "certin"], personal_data_breach=True)
    with pytest.raises(services.IncidentError, match="does not apply"):
        services.record_filing(i, user=rm, regime="nis2", step="early_warning")
    with pytest.raises(services.IncidentError, match="Justify"):
        services.record_filing(i, user=rm, regime="gdpr", step="authority", not_required=True)
    services.record_filing(
        i,
        user=rm,
        regime="gdpr",
        step="authority",
        not_required=True,
        note="Encrypted laptop; key not compromised (Art. 34(3)(a)).",
    )
    late = timezone.now() + timedelta(hours=7)
    services.record_filing(
        i, user=rm, regime="certin", step="report", submitted_at=late, reference="CI-1"
    )
    states = {o.regime.key: o for o in services.obligations(i)}
    assert states["gdpr"].state == "not_required"
    assert states["certin"].state == "filed" and states["certin"].late
    with pytest.raises(services.IncidentError, match="already"):
        services.record_filing(i, user=rm, regime="certin", step="report")
    assert i.timeline.filter(kind="notification").count() == 2
    assert services.suggested_regimes(i) == ["gdpr", "dpdp"]


def test_status_workflow_and_closure_rules(rm):
    i = _report(rm, regimes=["certin"])
    with pytest.raises(services.IncidentError):
        services.set_status(i, user=rm, status="closed")
    for s in ("triage", "contained", "eradicated", "recovered"):
        services.set_status(i, user=rm, status=s)
    with pytest.raises(services.IncidentError, match="root cause"):
        services.set_status(i, user=rm, status="closed")
    services.update_incident(i, user=rm, data={"root_cause": "Phish", "lessons_learned": "FIDO2"})
    with pytest.raises(services.IncidentError, match="notifications"):
        services.set_status(i, user=rm, status="closed")
    services.record_filing(i, user=rm, regime="certin", step="report")
    services.set_status(i, user=rm, status="closed")
    assert i.closed_at is not None and not i.is_open
    services.set_status(i, user=rm, status="triage")  # reopen
    assert i.closed_at is None


def test_owner_can_manage_and_links(org, users, rm):
    owner = users[Role.CONTROL_OWNER]
    i = _report(rm, owner=owner)
    t = technique("T1078")
    ctl = make_control(org, "CTL-MFA")
    services.update_incident(
        i, user=owner, data={"severity": "high"}, links={"techniques": [t], "controls": [ctl]}
    )
    assert list(i.techniques.all()) == [t] and list(i.controls.all()) == [ctl]
    services.add_entry(i, user=owner, kind="action", text="Disabled account")
    with pytest.raises(services.IncidentError):
        services.add_entry(i, user=owner, kind="status", text="x")
    with pytest.raises(services.IncidentError, match="future"):
        services.add_entry(
            i, user=owner, kind="note", text="x", at=timezone.now() + timedelta(days=1)
        )
    with pytest.raises(services.IncidentError):
        services.add_entry(i, user=users[Role.AUDITOR], kind="note", text="x")
    with pytest.raises(ValidationError, match="start after"):
        services.update_incident(
            i, user=rm, data={"occurred_at": timezone.now() + timedelta(hours=1)}
        )


def test_deadline_alerts_once_per_stage(rm, users):
    i = _report(rm, owner=rm, regimes=["certin"], aware_at=timezone.now() - timedelta(hours=5))
    Notification.objects.all().delete()
    assert services.send_deadline_alerts() == 1
    assert services.send_deadline_alerts() == 0
    msgs = list(Notification.objects.filter(recipient=rm).values_list("message", flat=True))
    assert len(msgs) == 1 and "due by" in msgs[0]
    i.aware_at = timezone.now() - timedelta(hours=7)
    i.save()
    assert services.send_deadline_alerts() == 1
    assert Notification.objects.filter(message__contains="OVERDUE").exists()
    services.set_status(i, user=rm, status="false_positive")
    i.aware_at = timezone.now() - timedelta(days=60)
    i.regimes = ["nis2"]
    i.save()
    assert services.send_deadline_alerts() == 0  # closed incidents never alert


def test_regime_catalogue_is_consistent():
    for regime in REGIMES.values():
        hours = [s.after for s in regime.steps]
        assert hours == sorted(hours) and len({s.key for s in regime.steps}) == len(hours)


def test_views(client_for, users, rm):
    v = client_for(Role.VIEWER)
    assert v.get(reverse("incidents:report")).status_code == 200
    r = v.post(
        reverse("incidents:report"),
        {"title": "Lost laptop", "severity": "high", "description": "Left on train"},
    )
    i = Incident.objects.get()
    assert r.status_code == 302 and i.created_by == users[Role.VIEWER]
    assert v.get(reverse("incidents:detail", args=[i.ref])).status_code == 200
    assert v.get(reverse("incidents:edit", args=[i.ref])).status_code == 403
    m = client_for(Role.RISK_MANAGER)
    r = m.post(
        reverse("incidents:edit", args=[i.ref]),
        {
            "title": "Lost laptop",
            "severity": "high",
            "owner": rm.pk,
            "aware_at": (timezone.localtime() - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
            "personal_data_breach": "on",
            "regimes": ["gdpr"],
            "description": "Left on train",
        },
    )
    i.refresh_from_db()
    assert r.status_code == 302 and i.regimes == ["gdpr"]
    page = m.get(reverse("incidents:detail", args=[i.ref]))
    assert b"Notify the supervisory authority" in page.content and b"due in" in page.content
    m.post(reverse("incidents:entry", args=[i.ref]), {"kind": "action", "text": "Remote wipe sent"})
    m.post(
        reverse("incidents:filing", args=[i.ref]),
        {"regime": "gdpr", "step": "authority", "reference": "DPC-123"},
    )
    assert i.filings.get().reference == "DPC-123"
    m.post(reverse("incidents:status", args=[i.ref]), {"status": "triage"})
    i.refresh_from_db()
    assert i.status == "triage"
    assert m.get(reverse("incidents:list"), {"show": "all"}).status_code == 200
    assert i.timeline.count() == 4
