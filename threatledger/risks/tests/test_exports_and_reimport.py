from __future__ import annotations

import csv
import io

import pytest
from django.db.models.deletion import ProtectedError
from django.urls import reverse
from openpyxl import load_workbook

from threatledger.accounts.roles import Role
from threatledger.attack.models import Technique
from threatledger.attack.tests import bundles
from threatledger.attack.tests.test_importer import _load
from threatledger.audit.models import Action, AuditEvent
from threatledger.risks import services
from threatledger.risks.exports import neutralise

from .helpers import make_risk

pytestmark = pytest.mark.django_db

EVIL = ['=HYPERLINK("http://evil")', "+1+2", "-cmd", "@SUM(A1)", "\tx", "\rx", "|calc", "%x"]


@pytest.mark.parametrize("value", EVIL)
def test_neutralise_prefixes_formula_starts(value):
    assert neutralise(value) == "'" + value


@pytest.mark.parametrize(
    ("value", "expected"), [("Normal text", "Normal text"), (5, 5), (None, ""), (True, "Yes")]
)
def test_neutralise_leaves_safe_values(value, expected):
    assert neutralise(value) == expected


@pytest.fixture
def evil_risk(users):
    return make_risk(
        users[Role.RISK_MANAGER], title='=HYPERLINK("http://evil","click")', scenario="@cmd"
    )


def test_csv_export_is_neutralised(client_for, evil_risk):
    response = client_for(Role.AUDITOR).get(reverse("risks:export"), {"format": "csv"})
    assert response.status_code == 200
    assert response["Content-Disposition"].startswith('attachment; filename="risk-register-')
    text = response.content.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0][0] == "Ref"
    assert rows[1][1] == '\'=HYPERLINK("http://evil","click")'
    assert rows[1][-1] == "'@cmd"
    assert rows[1][9] == "20"  # inherent score stays numeric


def test_xlsx_export_never_contains_formulas(client_for, evil_risk):
    response = client_for(Role.RISK_MANAGER).get(reverse("risks:export"), {"format": "xlsx"})
    assert response.status_code == 200
    ws = load_workbook(io.BytesIO(response.content)).active
    title = ws.cell(row=2, column=2)
    assert title.data_type == "s"
    assert title.value.startswith("'=")
    assert ws.cell(row=2, column=10).value == 20
    for row in ws.iter_rows():
        for cell in row:
            assert cell.data_type != "f"


def test_export_is_audited_and_respects_filters(client_for, users):
    rm = users[Role.RISK_MANAGER]
    make_risk(rm, title="Alpha")
    make_risk(rm, title="Beta")
    response = client_for(Role.RISK_MANAGER).get(
        reverse("risks:export"), {"format": "csv", "q": "Beta"}
    )
    assert len(list(csv.reader(io.StringIO(response.content.decode("utf-8-sig"))))) == 2
    event = AuditEvent.objects.get(action=Action.EXPORT)
    assert event.changes["rows"] == [None, 1]
    assert event.changes["filters"][1]["q"] == "Beta"


@pytest.mark.parametrize(
    ("role", "status"), [(Role.VIEWER, 403), (Role.AUDITOR, 200), (Role.CONTROL_OWNER, 200)]
)
def test_export_permission(client_for, role, status):
    assert client_for(role).get(reverse("risks:export"), {"format": "csv"}).status_code == status


def test_export_rejects_unknown_format(client_for):
    assert client_for(Role.ADMIN).get(reverse("risks:export"), {"format": "pdf"}).status_code == 404


# ----------------------------------------------------------------------------- ATT&CK re-import safety
def test_risk_mapping_survives_reimport_that_revokes_the_technique(users):
    """Phase 2 promise: a revoked technique keeps its risk links and can be remapped."""
    rm = users[Role.RISK_MANAGER]
    _load(bundles.bundle_v1())
    risk = make_risk(rm)
    services.link_technique(risk, Technique.objects.get(attack_id="T1566.001"), user=rm)

    _load(bundles.bundle_v2())  # T1566.001 revoked -> T1566.002

    link = risk.technique_links.select_related("technique").get()
    assert link.technique.attack_id == "T1566.001"
    assert link.technique.is_revoked
    services.remap_revoked_technique(risk, link, user=rm)
    assert list(risk.techniques.values_list("attack_id", flat=True)) == ["T1566.002"]


def test_mapped_technique_cannot_be_deleted(users):
    rm = users[Role.RISK_MANAGER]
    _load(bundles.bundle_v1())
    t = Technique.objects.get(attack_id="T1059")
    services.link_technique(make_risk(rm), t, user=rm)
    with pytest.raises(ProtectedError):
        t.delete()
