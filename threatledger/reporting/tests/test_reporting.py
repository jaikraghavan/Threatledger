from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.management import call_command
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.roles import Role
from threatledger.controls.models import Control
from threatledger.frameworks import services as fw_services
from threatledger.frameworks.importer import load, parse
from threatledger.frameworks.tests.test_services import FW_A
from threatledger.reporting import services
from threatledger.reporting.models import ComplianceSnapshot, CoverageSnapshot, RiskSnapshot
from threatledger.risks import services as risk_services
from threatledger.risks.tests.helpers import make_control, make_risk, map_direct, technique

pytestmark = pytest.mark.django_db


@pytest.fixture
def world(org, users):
    rm = users[Role.RISK_MANAGER]
    fw = load(parse(FW_A, "a.yaml")).framework
    ctl = make_control(org, "CTL-MFA", status="planned", name="MFA")
    t1, t2 = technique("T1078", "Valid Accounts"), technique("T1110", "Brute Force")
    map_direct(ctl, t1)
    from threatledger.frameworks.models import Requirement

    fw_services.map_control(Requirement.objects.get(framework=fw, ref="A-1"), ctl, user=rm)
    critical = make_risk(
        rm, title="Account takeover", owner=rm
    )  # residual 2x4 = 8 medium, inherent 20 critical
    high = make_risk(
        rm, title="Ransomware", residual_likelihood=3, residual_impact=4
    )  # residual 12 high
    for r in (critical, high):
        risk_services.link_technique(r, t1, user=rm)
    risk_services.link_technique(high, t2, user=rm)
    return {"fw": fw, "ctl": ctl, "t1": t1, "t2": t2, "rm": rm}


def test_kpis(org, world):
    k = services.kpis(org)
    assert k["open_risks"] == 2
    assert k["critical_high"] == 1
    assert (k["coverage"].covered, k["coverage"].gap) == (0, 2)
    assert (k["controls_total"], k["controls_implemented"], k["controls_pct"]) == (1, 0, 0)
    assert k["tests_overdue"] == 1
    assert [r.title for r in k["top_risks"]] == ["Ransomware", "Account takeover"]
    assert k["frameworks"][0].framework.code == "FW-A"


def test_threat_gaps_and_priorities(org, world):
    gaps = services.top_threat_gaps(org)
    assert [(g.technique.attack_id, g.risk_count) for g in gaps] == [("T1078", 2), ("T1110", 1)]
    priorities = services.control_priorities(org)
    assert [(p.control.ref, p.requirements, p.risks) for p in priorities] == [("CTL-MFA", 1, 0)]
    Control.objects.filter(pk=world["ctl"].pk).update(status="implemented")
    assert [g.technique.attack_id for g in services.top_threat_gaps(org)] == ["T1110"]
    assert services.control_priorities(org) == []


def test_snapshots_idempotent_and_series(org, world):
    today = timezone.localdate()
    services.take_snapshots(org, today - timedelta(days=1))
    Control.objects.filter(pk=world["ctl"].pk).update(status="implemented")
    services.take_snapshots(org, today)
    services.take_snapshots(org, today)  # same day again: updates, no duplicate
    assert ComplianceSnapshot.objects.count() == 2
    assert CoverageSnapshot.objects.count() == 2
    assert RiskSnapshot.objects.count() == 2
    comp = services.compliance_series(org)
    assert comp["labels"] == [(today - timedelta(days=1)).isoformat(), today.isoformat()]
    assert comp["datasets"][0]["data"] == [0.0, round(100 / 3, 1)]
    cov = services.coverage_series(org)
    assert cov["datasets"][0]["data"] == [0, 50]
    risk = services.risk_series(org)
    assert {d["band"]: d["data"] for d in risk["datasets"]}["high"] == [1, 1]
    snap = RiskSnapshot.objects.get(date=today)
    assert snap.residual == {"low": 0, "medium": 1, "high": 1, "critical": 0}
    assert snap.average_residual == 10.0


def test_snapshot_command_and_daily_task(org, world):
    from io import StringIO

    from threatledger.reporting.tasks import daily

    out = StringIO()
    call_command("take_snapshots", stdout=out)
    assert "1 organisation" in out.getvalue()
    assert daily() == "snapshotted_organisations=1"


def test_risk_score_series(world):
    risk = risk_services.visible_risks(world["rm"]).get(title="Ransomware")
    risk_services.update_risk(risk, user=world["rm"], data={"residual_likelihood": 1}, reason="EDR")
    series = services.risk_score_series(risk)
    assert [d["data"] for d in series["datasets"]] == [[20, 20], [12, 4]]


@pytest.mark.parametrize("role", list(Role))
def test_dashboard_and_board_report_for_every_role(client_for, world, role):
    c = client_for(role)
    dash = c.get(reverse("core:home"))
    assert dash.status_code == 200
    assert dash.context["k"]["open_risks"] == 2
    board = c.get(reverse("reporting:board"))
    assert board.status_code == 200
    assert b'data-action="print"' in board.content
    assert b"Information security risk &amp; compliance report" in board.content


def test_dashboard_charts_render_with_snapshots(client_for, org, world):
    today = timezone.localdate()
    services.take_snapshots(org, today - timedelta(days=1))
    services.take_snapshots(org, today)
    body = client_for(Role.VIEWER).get(reverse("core:home")).content.decode()
    assert 'data-chart="compliance-series"' in body
    assert '<script id="compliance-series" type="application/json">' in body
    assert "<script>" not in body  # no inline executable script (CSP-ready)
    assert "chart-4.6.1.umd.min.js" in body


def test_dashboard_without_snapshots_shows_placeholder(client_for, world):
    body = client_for(Role.VIEWER).get(reverse("core:home")).content.decode()
    assert "Trends appear once daily snapshots accumulate" in body


def test_dashboard_respects_business_unit_scope(client_for, org, world, users):
    from threatledger.accounts.models import Membership
    from threatledger.org.models import BusinessUnit

    bu = BusinessUnit.objects.create(organisation=org, name="Payments")
    Membership.objects.get(user=users[Role.VIEWER]).business_units.set([bu])
    assert client_for(Role.VIEWER).get(reverse("core:home")).context["k"]["open_risks"] == 0


def test_dashboard_query_count(client_for, world, django_assert_max_num_queries):
    c = client_for(Role.RISK_MANAGER)
    with django_assert_max_num_queries(60):
        c.get(reverse("core:home"))
