from __future__ import annotations

import json

import pytest
from django.urls import reverse

from threatledger.accounts.roles import Role
from threatledger.attack.models import Group, Technique
from threatledger.attack.tests import bundles
from threatledger.attack.tests.test_importer import _load
from threatledger.audit.models import Action, AuditEvent
from threatledger.coverage.matrix import build_matrix, navigator_layer, resolve_scope, sectors
from threatledger.risks import services as risk_services
from threatledger.risks.tests.helpers import make_control, make_risk, map_direct

pytestmark = pytest.mark.django_db


@pytest.fixture
def attack(org, users):
    """bundle_v1: T1566 (+T1566.001), T1059 (+T1059.001); G0001 uses T1566.001 + T1059.001."""
    _load(bundles.bundle_v1())
    rm = users[Role.RISK_MANAGER]
    t = {x.attack_id: x for x in Technique.objects.all()}
    edr = make_control(org, "CTL-EDR", status="implemented")
    map_direct(edr, t["T1059"])  # parent covered -> T1059.001 inherits
    email = make_control(org, "CTL-EMAIL", status="partial")
    map_direct(email, t["T1566.001"])
    risk = make_risk(rm, owner=rm)
    risk_services.link_technique(risk, t["T1059.001"], user=rm)
    return t


def test_scope_all(attack, org, users):
    scope = resolve_scope(users[Role.VIEWER], "all")
    assert scope.technique_ids == set(Technique.objects.active().values_list("pk", flat=True))
    m = build_matrix(scope, org)
    assert [t.shortname for t, _ in m.columns] == ["initial-access", "execution", "stealth"]
    assert (m.summary.covered, m.summary.partial, m.summary.gap) == (
        2,
        1,
        1,
    )  # T1059, T1059.001 | T1566.001 | T1566


def test_scope_risks_and_mine(attack, org, users):
    scope = resolve_scope(users[Role.VIEWER], "risks")
    assert scope.technique_ids == {attack["T1059.001"].pk}
    m = build_matrix(scope, org)
    execution = {t.shortname: cells for t, cells in m.columns}["execution"]
    parent_cell = execution[0]
    assert parent_cell.technique.attack_id == "T1059"
    assert parent_cell.in_scope is False and parent_cell.sub_in_scope == 1
    sub = [
        (s.attack_id, cov.status.label, cov.inherited, ins)
        for s, cov, ins in parent_cell.subtechniques
    ]
    assert sub == [("T1059.001", "Covered", True, True)]
    assert m.summary.total == 1 and m.summary.percent == 100
    assert resolve_scope(users[Role.VIEWER], "risks", "mine").technique_ids == set()
    assert resolve_scope(users[Role.RISK_MANAGER], "risks", "mine").technique_ids == {
        attack["T1059.001"].pk
    }


def test_scope_group_and_sector(attack, org, users, monkeypatch):
    g = resolve_scope(users[Role.VIEWER], "group", "g0001")
    assert g.label == "APT Test (G0001)"
    assert g.technique_ids == {attack["T1566.001"].pk, attack["T1059.001"].pk}
    assert resolve_scope(users[Role.VIEWER], "group", "G9999").technique_ids == set()
    monkeypatch.setattr(
        "threatledger.coverage.matrix.sectors",
        lambda: {"test": {"label": "Testing", "groups": ["G0001", "G9999"]}},
    )
    s = resolve_scope(users[Role.VIEWER], "sector", "test")
    assert s.groups == [Group.objects.get(attack_id="G0001")]
    assert s.technique_ids == g.technique_ids
    assert resolve_scope(users[Role.VIEWER], "sector", "nope").label == "Unknown sector"
    assert resolve_scope(users[Role.VIEWER], "bogus").kind == "risks"


def test_sector_file_is_valid():
    data = sectors()
    assert len(data) >= 6
    for key, s in data.items():
        assert s["label"] and s["groups"], key
        assert all(g.startswith("G") and g[1:].isdigit() for g in s["groups"]), key


def test_navigator_layer_shape(attack, org, users):
    m = build_matrix(resolve_scope(users[Role.VIEWER], "all"), org)
    layer = navigator_layer(m, "20.1", "Acme")
    assert layer["versions"] == {"attack": "20", "navigator": "5.1.0", "layer": "4.5"}
    assert layer["domain"] == "enterprise-attack"
    for key in (
        "name",
        "description",
        "filters",
        "sorting",
        "layout",
        "hideDisabled",
        "techniques",
        "gradient",
        "legendItems",
        "metadata",
        "showTacticRowBackground",
        "tacticRowBackground",
        "selectTechniquesAcrossTactics",
        "selectSubtechniquesWithParent",
    ):
        assert key in layer, key
    by_id = {(e["techniqueID"], e["tactic"]): e for e in layer["techniques"]}
    assert set(by_id) == {("T1566", "initial-access"), ("T1566.001", "initial-access"), ("T1059", "execution"),
                          ("T1059.001", "execution"), ("T1059.001", "stealth")}  # fmt: skip
    assert by_id[("T1059.001", "execution")]["score"] == 2
    assert "via parent" in by_id[("T1059.001", "execution")]["comment"]
    assert by_id[("T1566", "initial-access")]["color"] == "#ef4444"
    assert by_id[("T1566.001", "initial-access")]["metadata"] == [
        {"name": "controls", "value": "CTL-EMAIL"}
    ]
    for e in layer["techniques"]:
        assert set(e) >= {
            "techniqueID",
            "tactic",
            "score",
            "color",
            "comment",
            "enabled",
            "metadata",
            "showSubtechniques",
        }
    json.dumps(layer)  # serialisable


@pytest.mark.parametrize("role", list(Role))
def test_matrix_page_for_every_role(client_for, attack, role):
    response = client_for(role).get(reverse("coverage:matrix"), {"scope": "all"})
    assert response.status_code == 200
    assert response.context["matrix"].summary.total == 4


def test_matrix_page_empty_scope(client_for, attack):
    response = client_for(Role.VIEWER).get(
        reverse("coverage:matrix"), {"scope": "risks", "value": "mine"}
    )
    assert b"No techniques in this scope" in response.content


def test_navigator_export_permission_and_audit(client_for, attack):
    url = reverse("coverage:navigator")
    assert client_for(Role.VIEWER).get(url).status_code == 403
    response = client_for(Role.AUDITOR).get(url, {"scope": "group", "value": "G0001"})
    assert response.status_code == 200
    assert response["Content-Disposition"].startswith(
        'attachment; filename="threatledger-apt-test-g0001-'
    )
    layer = json.loads(response.content)
    assert {e["techniqueID"] for e in layer["techniques"]} == {"T1566.001", "T1059.001"}
    assert AuditEvent.objects.filter(
        action=Action.EXPORT, object_type="coverage.navigator"
    ).exists()


def test_matrix_query_count_is_bounded(client_for, attack, django_assert_max_num_queries):
    c = client_for(Role.VIEWER)
    with django_assert_max_num_queries(20):
        assert c.get(reverse("coverage:matrix"), {"scope": "all"}).status_code == 200
