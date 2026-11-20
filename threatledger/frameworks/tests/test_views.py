from __future__ import annotations

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from threatledger.accounts.roles import Role
from threatledger.frameworks import services
from threatledger.frameworks.importer import load, parse
from threatledger.frameworks.models import (
    ControlRequirement,
    Framework,
    Requirement,
    TechniqueRequirement,
)
from threatledger.risks.tests.helpers import make_control, technique

from .test_services import FW_A, FW_B

pytestmark = pytest.mark.django_db
LIST = reverse("frameworks:list")


@pytest.fixture
def fws():
    return load(parse(FW_A, "a.yaml")).framework, load(parse(FW_B, "b.yaml")).framework


@pytest.fixture
def mapped(org, fws, users):
    a, b = fws
    ctl = make_control(org, "CTL-MFA", status="implemented", name="MFA")
    services.map_control(
        Requirement.objects.get(framework=a, ref="A-1"), ctl, user=users[Role.ADMIN]
    )
    services.map_control(
        Requirement.objects.get(framework=b, ref="B-1"), ctl, user=users[Role.ADMIN]
    )
    return ctl


@pytest.mark.parametrize("role", list(Role))
def test_every_role_can_view(client_for, fws, mapped, role):
    a, _ = fws
    c = client_for(role)
    r = Requirement.objects.get(framework=a, ref="A-1")
    for url in (
        LIST,
        reverse("frameworks:detail", args=[a.code]),
        reverse("frameworks:requirement", args=[a.code, r.pk]),
        reverse("frameworks:cross"),
    ):
        assert c.get(url).status_code == 200, url


def test_list_shows_percentages(client_for, fws, mapped):
    response = client_for(Role.VIEWER).get(LIST)
    pct = {r.framework.code: r.summary.percent for r in response.context["adopted"]}
    assert pct == {"FW-A": round(100 / 3, 1), "FW-B": 50.0}
    assert b"<rect" in response.content  # CSP-safe SVG bar, no inline style


def test_empty_state_and_seed_button(client_for):
    response = client_for(Role.ADMIN).get(LIST)
    assert b"Load seeded frameworks" in response.content
    assert (
        client_for(Role.RISK_MANAGER)
        .post(reverse("frameworks:import"), {"action": "seed"})
        .status_code
        == 403
    )
    assert (
        client_for(Role.ADMIN).post(reverse("frameworks:import"), {"action": "seed"}).status_code
        == 302
    )
    assert Framework.objects.count() == 6


def test_detail_gap_filter_and_search(client_for, fws, mapped):
    a, _ = fws
    url = reverse("frameworks:detail", args=[a.code])
    c = client_for(Role.VIEWER)

    def refs(params):
        return [row["req"].ref for g in c.get(url, params).context["groups"] for row in g["rows"]]

    assert refs({}) == ["A-1", "A-2", "A-3"]
    assert refs({"status": "gaps"}) == ["A-2", "A-3"]
    assert refs({"status": "met"}) == ["A-1"]
    assert refs({"q": "three"}) == ["A-3"]


def test_settings_view(client_for, fws):
    a, _ = fws
    url = reverse("frameworks:settings", args=[a.code])
    assert client_for(Role.CONTROL_OWNER).post(url, {"adopted": "1"}).status_code == 403
    client_for(Role.RISK_MANAGER).post(url, {"adopted": "1", "baseline": "low"})
    detail = client_for(Role.VIEWER).get(reverse("frameworks:detail", args=[a.code]))
    assert detail.context["summary"].tracked == 1
    client_for(Role.ADMIN).post(url, {"adopted": "", "next": "list"})
    assert [r.framework.code for r in client_for(Role.VIEWER).get(LIST).context["not_adopted"]] == [
        "FW-A"
    ]


def test_requirement_map_unmap_htmx(client_for, org, fws):
    a, _ = fws
    r = Requirement.objects.get(framework=a, ref="A-2")
    ctl = make_control(org, "CTL-EDR", name="EDR", status="partial")
    c = client_for(Role.RISK_MANAGER)
    found = c.get(
        reverse("frameworks:requirement_control_search", args=[a.code, r.pk]), {"q": "edr"}
    )
    assert [x.ref for x in found.context["results"]] == ["CTL-EDR"]
    panel = c.post(reverse("frameworks:requirement_map", args=[a.code, r.pk]), {"control": ctl.pk})
    assert panel.templates[0].name == "frameworks/_requirement_panel.html"
    assert panel.context["status"].value == "partial"
    link = ControlRequirement.objects.get()
    c.post(reverse("frameworks:requirement_map", args=[a.code, r.pk]), {"remove": link.pk})
    assert not ControlRequirement.objects.exists()
    assert (
        client_for(Role.CONTROL_OWNER)
        .post(reverse("frameworks:requirement_map", args=[a.code, r.pk]), {"control": ctl.pk})
        .status_code
        == 403
    )


def test_requirement_scope_view(client_for, fws):
    a, _ = fws
    r = Requirement.objects.get(framework=a, ref="A-3")
    url = reverse("frameworks:requirement_scope", args=[a.code, r.pk])
    client_for(Role.RISK_MANAGER).post(url, {"applicable": "0", "justification": "Out of scope"})
    assert (
        client_for(Role.VIEWER)
        .get(reverse("frameworks:detail", args=[a.code]))
        .context["summary"]
        .tracked
        == 2
    )
    assert client_for(Role.AUDITOR).post(url, {"applicable": "1"}).status_code == 403


def test_requirement_page_shows_ctid_techniques_with_coverage(client_for, org, fws, users):
    a, _ = fws
    r = Requirement.objects.get(framework=a, ref="A-1")
    t = technique("T1078", "Valid Accounts")
    TechniqueRequirement.objects.create(technique=t, requirement=r, attack_version="16.1")
    response = client_for(Role.VIEWER).get(reverse("frameworks:requirement", args=[a.code, r.pk]))
    assert [(tech.attack_id, cov.status.label) for tech, cov in response.context["techniques"]] == [
        ("T1078", "Gap")
    ]
    page = client_for(Role.VIEWER).get(reverse("attack:technique_detail", args=["T1078"]))
    assert [link.requirement.ref for link in page.context["framework_requirements"]] == ["A-1"]


def test_cross_framework_view(client_for, mapped):
    response = client_for(Role.VIEWER).get(reverse("frameworks:cross"))
    row = response.context["rows"][0]
    assert (row.control.ref, row.requirement_count, row.framework_count) == ("CTL-MFA", 2, 2)
    assert "satisfies 2 requirements across 2 frameworks" in response.content.decode()
    assert (
        client_for(Role.VIEWER).get(reverse("frameworks:cross"), {"q": "nomatch"}).context["rows"]
        == []
    )


def test_control_detail_compliance_panel(client_for, mapped):
    response = client_for(Role.VIEWER).get(reverse("controls:detail", args=["CTL-MFA"]))
    assert [fw.code for fw, _ in response.context["requirements_by_framework"]] == ["FW-A", "FW-B"]


def test_import_view(client_for):
    url = reverse("frameworks:import")
    assert client_for(Role.RISK_MANAGER).get(url).status_code == 403
    c = client_for(Role.ADMIN)
    dry = c.post(url, {"file": SimpleUploadedFile("fw.yaml", FW_B), "dry_run": "1"})
    assert dry.context["result"]["dry_run"] is True
    assert not Framework.objects.exists()
    done = c.post(url, {"file": SimpleUploadedFile("fw.yaml", FW_B)})
    assert done.context["result"]["created"] == 2
    assert Framework.objects.get(code="FW-B").is_indicative is False
    bad = c.post(
        url, {"file": SimpleUploadedFile("x.yaml", b"framework: {code: x}\nrequirements: []")}
    )
    assert bad.context["errors"]
    csv = c.post(
        url,
        {
            "file": SimpleUploadedFile("p.csv", b"ref,title\n1,One\n"),
            "code": "PCI",
            "name": "PCI DSS",
        },
    )
    assert csv.context["result"]["framework"] == "PCI"
    assert c.post(url, {}).context["errors"] == ["Choose a file to import."]
