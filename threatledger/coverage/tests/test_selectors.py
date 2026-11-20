from __future__ import annotations

import pytest
from django.utils import timezone

from threatledger.coverage.engine import Coverage
from threatledger.coverage.selectors import controls_by_technique, coverage_for
from threatledger.org.models import Organisation
from threatledger.risks.tests.helpers import (
    make_control,
    map_direct,
    map_mitigation,
    mitigation,
    technique,
)

pytestmark = pytest.mark.django_db


def test_direct_and_mitigation_paths(org):
    t1, t2 = technique("T1566"), technique("T1059")
    direct = make_control(org, "CTL-1")
    via_m = make_control(org, "CTL-2")
    map_direct(direct, t1)
    map_mitigation(via_m, mitigation("M1049", t1, t2))
    graph = controls_by_technique({t1.pk, t2.pk}, org.pk)
    assert graph[t1.pk] == {direct.pk, via_m.pk}
    assert graph[t2.pk] == {via_m.pk}


def test_other_orgs_and_archived_controls_ignored(org):
    t = technique("T1566")
    other = Organisation.objects.create(name="Other")
    map_direct(make_control(other, "X-1"), t)
    map_direct(make_control(org, "OLD", archived_at=timezone.now()), t)
    assert controls_by_technique({t.pk}, org.pk) == {}


def test_coverage_for_uses_status_and_inheritance(org):
    parent = technique("T1059")
    sub = technique("T1059.001", parent=parent)
    lone = technique("T1003")
    map_direct(make_control(org, "EDR", status="implemented"), parent)
    map_direct(make_control(org, "PAM", status="partial"), lone)
    result = coverage_for([sub.pk, lone.pk], org.pk)
    assert result[sub.pk].status is Coverage.COVERED
    assert result[sub.pk].inherited is True
    assert result[lone.pk].status is Coverage.PARTIAL


def test_changing_one_control_status_changes_coverage(org):
    """Core invariant: coverage is derived from control status on every read."""
    t = technique("T1566")
    ctl = make_control(org, "MFA", status="planned")
    map_direct(ctl, t)
    assert coverage_for([t.pk], org.pk)[t.pk].status is Coverage.GAP
    ctl.status = "implemented"
    ctl.save()
    assert coverage_for([t.pk], org.pk)[t.pk].status is Coverage.COVERED
