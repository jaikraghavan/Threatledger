from __future__ import annotations

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.roles import Role
from threatledger.risks import services
from threatledger.risks.models import Asset, Risk, RiskAcceptance, RiskMatrix

from .helpers import make_control, make_risk, map_direct, technique

pytestmark = pytest.mark.django_db
LIST = reverse("risks:list")


def _form(**overrides):
    data = {
        "title": "Data breach via stolen credentials",
        "scenario": "Credential stuffing against the customer portal.",
        "category": "cyber",
        "inherent_likelihood": "4",
        "inherent_impact": "4",
        "residual_likelihood": "2",
        "residual_impact": "3",
        "treatment": "mitigate",
        "status": "open",
        "next_review_date": (timezone.localdate() + timedelta(days=90)).isoformat(),
    }
    data.update(overrides)
    return data


@pytest.fixture
def rm(users):
    return users[Role.RISK_MANAGER]


@pytest.mark.parametrize("role", list(Role))
def test_every_role_can_view_register_and_heatmap(client_for, rm, role):
    risk = make_risk(rm)
    c = client_for(role)
    for url in (LIST, reverse("risks:heatmap"), reverse("risks:detail", args=[risk.ref]),
                reverse("risks:asset_list"), reverse("risks:acceptances")):  # fmt: skip
        assert c.get(url).status_code == 200, url


@pytest.mark.parametrize(
    ("role", "status"),
    [(Role.RISK_MANAGER, 200), (Role.ADMIN, 200), (Role.CONTROL_OWNER, 403), (Role.VIEWER, 403)],
)
def test_create_page_permission(client_for, role, status):
    assert client_for(role).get(reverse("risks:create")).status_code == status


def test_create_risk_via_form(client_for, rm):
    response = client_for(Role.RISK_MANAGER).post(reverse("risks:create"), _form(owner=rm.pk))
    assert response.status_code == 302
    risk = Risk.objects.get()
    assert response["Location"] == reverse("risks:detail", args=[risk.ref])
    assert (risk.inherent.value, risk.residual.value, risk.owner) == (16, 6, rm)


def test_form_rejects_residual_above_inherent(client_for):
    response = client_for(Role.RISK_MANAGER).post(
        reverse("risks:create"), _form(residual_likelihood="5", residual_impact="5")
    )
    assert response.status_code == 200
    assert "cannot exceed inherent" in response.content.decode()
    assert not Risk.objects.exists()


def test_form_score_choices_follow_matrix(client_for, org):
    m = RiskMatrix.for_org(org)
    m.size, m.likelihood_labels, m.impact_labels = 3, ["L", "M", "H"], ["l", "m", "h"]
    m.low_max, m.medium_max, m.high_max = 2, 4, 6
    m.save()
    form = client_for(Role.RISK_MANAGER).get(reverse("risks:create")).context["form"]
    assert [c[0] for c in form.fields["inherent_likelihood"].choices] == [1, 2, 3]
    assert "accepted" not in [c[0] for c in form.fields["status"].choices]


def test_edit_with_reason_records_history(client_for, rm):
    risk = make_risk(rm)
    url = reverse("risks:edit", args=[risk.ref])
    assert client_for(Role.RISK_MANAGER).get(url).status_code == 200
    response = client_for(Role.RISK_MANAGER).post(
        url, _form(residual_likelihood="1", reason="MFA enforced")
    )
    assert response.status_code == 302
    assert risk.score_history.all()[0].reason == "MFA enforced"


def test_viewer_cannot_edit_or_archive(client_for, rm):
    risk = make_risk(rm)
    c = client_for(Role.VIEWER)
    assert c.get(reverse("risks:edit", args=[risk.ref])).status_code == 403
    assert c.post(reverse("risks:archive", args=[risk.ref])).status_code == 403
    assert (
        c.post(reverse("risks:technique_add", args=[risk.ref]), {"technique": 1}).status_code == 403
    )


def test_archive_and_restore_views(client_for, rm):
    risk = make_risk(rm)
    c = client_for(Role.RISK_MANAGER)
    c.post(reverse("risks:archive", args=[risk.ref]))
    assert list(c.get(LIST).context["risks"]) == []
    assert [r.ref for r in c.get(LIST, {"archived": "1"}).context["risks"]] == [risk.ref]
    c.post(reverse("risks:archive", args=[risk.ref]), {"restore": "1"})
    risk.refresh_from_db()
    assert risk.archived_at is None


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"q": "Alpha"}, ["R-0001"]),
        ({"q": "R-0002"}, ["R-0002"]),
        ({"status": "closed"}, ["R-0003"]),
        ({"status": "active"}, ["R-0001", "R-0002"]),
        ({"band": "critical", "band_of": "inherent"}, ["R-0001", "R-0003"]),
        ({"band": "medium", "band_of": "inherent"}, ["R-0002"]),
        ({"band": "low"}, ["R-0003"]),
        ({"cell": "residual:1:1"}, ["R-0003"]),
        ({"technique": "t1566"}, ["R-0002"]),
        ({"review": "overdue"}, ["R-0002"]),
        ({"owner": "me"}, ["R-0001"]),
        ({"sort": "ref"}, ["R-0001", "R-0002", "R-0003"]),
    ],
)
def test_list_filters(client_for, rm, users, params, expected):
    today = timezone.localdate()
    make_risk(rm, title="Alpha", owner=rm, inherent_likelihood=5, inherent_impact=4)
    beta = make_risk(rm, title="Beta", inherent_likelihood=3, inherent_impact=3,
                     next_review_date=today - timedelta(days=2))  # fmt: skip
    make_risk(rm, title="Gamma", status="closed", residual_likelihood=1, residual_impact=1,
              next_review_date=today - timedelta(days=2))  # fmt: skip
    services.link_technique(beta, technique("T1566"), user=rm)
    response = client_for(Role.RISK_MANAGER).get(LIST, params)
    assert sorted(r.ref for r in response.context["risks"]) == sorted(expected)
    if "sort" in params:
        assert [r.ref for r in response.context["risks"]] == expected


def test_list_htmx_partial(client_for, rm):
    make_risk(rm)
    response = client_for(Role.VIEWER).get(LIST, HTTP_HX_REQUEST="true")
    assert response.templates[0].name == "risks/_risk_table.html"


def test_detail_shows_coverage_and_suggestions(client_for, org, rm):
    risk = make_risk(rm)
    t = technique("T1566", "Phishing")
    services.link_technique(risk, t, user=rm)
    map_direct(make_control(org, "CTL-EMAIL", status="partial", name="Email filtering"), t)
    response = client_for(Role.VIEWER).get(reverse("risks:detail", args=[risk.ref]))
    body = response.content.decode()
    assert "Partial" in body
    assert "CTL-EMAIL" in body
    assert response.context["coverage_summary"].partial == 1
    assert [s.control.ref for s in response.context["suggestions"]] == ["CTL-EMAIL"]
    assert "Link</button>" not in body  # viewer: no edit buttons


def test_htmx_technique_search_add_remove(client_for, rm):
    risk = make_risk(rm)
    t = technique("T1566", "Phishing")
    technique("T1059", "Command and Scripting Interpreter")
    c = client_for(Role.RISK_MANAGER)
    found = c.get(reverse("risks:technique_search", args=[risk.ref]), {"q": "phish"})
    assert [x.attack_id for x in found.context["results"]] == ["T1566"]
    panel = c.post(
        reverse("risks:technique_add", args=[risk.ref]), {"technique": t.pk}, HTTP_HX_REQUEST="true"
    )
    assert panel.templates[0].name == "risks/_panels.html"
    assert list(risk.techniques.all()) == [t]
    again = c.get(reverse("risks:technique_search", args=[risk.ref]), {"q": "T15"})
    assert list(again.context["results"]) == []  # already linked
    link = risk.technique_links.get()
    c.post(reverse("risks:technique_remove", args=[risk.ref, link.pk]))
    assert not risk.techniques.exists()


def test_htmx_remap_view(client_for, rm):
    new, old = technique("T1059.001"), technique("T1086")
    risk = make_risk(rm)
    services.link_technique(risk, old, user=rm)
    old.is_revoked, old.revoked_by = True, new
    old.save()
    link = risk.technique_links.get()
    response = client_for(Role.RISK_MANAGER).post(
        reverse("risks:technique_remap", args=[risk.ref, link.pk])
    )
    assert response.status_code == 200
    assert list(risk.techniques.all()) == [new]


def test_htmx_control_search_add_remove(client_for, org, rm):
    risk = make_risk(rm)
    ctl = make_control(org, "CTL-MFA", name="Multi-factor authentication")
    c = client_for(Role.RISK_MANAGER)
    found = c.get(reverse("risks:control_search", args=[risk.ref]), {"q": "factor"})
    assert [x.ref for x in found.context["results"]] == ["CTL-MFA"]
    c.post(reverse("risks:control_add", args=[risk.ref]), {"control": ctl.pk})
    assert list(risk.controls.all()) == [ctl]
    c.post(reverse("risks:control_remove", args=[risk.ref, risk.control_links.get().pk]))
    assert not risk.controls.exists()


def test_panel_endpoints_require_post(client_for, rm):
    risk = make_risk(rm)
    assert (
        client_for(Role.RISK_MANAGER)
        .get(reverse("risks:technique_add", args=[risk.ref]))
        .status_code
        == 403
    )


def test_heatmap_counts_and_cell_links(client_for, rm):
    make_risk(rm)
    make_risk(rm)
    response = client_for(Role.VIEWER).get(reverse("risks:heatmap"))
    kinds = {kind: grid for kind, _, grid in response.context["heatmaps"]}
    top_row = kinds["inherent"][1]  # likelihood 4 (rows run 5 -> 1)
    assert top_row["likelihood"] == 4
    assert top_row["cells"][4]["count"] == 2  # impact 5
    assert top_row["cells"][4]["band"] == "critical"
    assert "cell=inherent:4:5" in response.content.decode()
    assert response.context["total"] == 2


def test_matrix_settings_admin_only_and_saves(client_for):
    url = reverse("risks:matrix")
    assert client_for(Role.RISK_MANAGER).get(url).status_code == 403
    c = client_for(Role.ADMIN)
    assert c.get(url).status_code == 200
    data = {"size": "5", "likelihood_labels": "1\n2\n3\n4\n5", "impact_labels": "a\nb\nc\nd\ne",
            "low_max": "3", "medium_max": "8", "high_max": "14"}  # fmt: skip
    assert c.post(url, data).status_code == 302
    bad = c.post(url, {**data, "likelihood_labels": "only one"})
    assert bad.status_code == 200
    assert "exactly 5" in bad.content.decode()


def test_asset_crud(client_for, org):
    c = client_for(Role.RISK_MANAGER)
    data = {"name": "Customer DB", "kind": "data_store", "criticality": "5",
            "data_classification": "restricted", "contains_personal_data": "on"}  # fmt: skip
    assert c.post(reverse("risks:asset_create"), data).status_code == 302
    asset = Asset.objects.get()
    assert asset.contains_personal_data and asset.organisation == org
    assert c.get(reverse("risks:asset_detail", args=[asset.pk])).status_code == 200
    dup = c.post(reverse("risks:asset_create"), {**data, "name": "customer db"})
    assert "already exists" in dup.content.decode()
    c.post(reverse("risks:asset_edit", args=[asset.pk]), {**data, "criticality": "4"})
    asset.refresh_from_db()
    assert asset.criticality == 4
    assert client_for(Role.VIEWER).get(reverse("risks:asset_create")).status_code == 403
    assert (
        client_for(Role.VIEWER)
        .get(reverse("risks:asset_list"), {"personal": "1"})
        .context["assets"][0]
        == asset
    )


def test_acceptance_flow_through_views(client_for, rm, make_user):
    risk = make_risk(rm)
    c = client_for(Role.RISK_MANAGER)
    c.post(reverse("risks:acceptance_request", args=[risk.ref]),
           {"justification": "Isolated legacy kiosk", "expires_on": (timezone.localdate() + timedelta(days=30)).isoformat()})  # fmt: skip
    acc = RiskAcceptance.objects.get()
    c.post(reverse("risks:acceptance_decide", args=[acc.pk]), {"decision": "approve"})
    acc.refresh_from_db()
    assert acc.status == RiskAcceptance.Status.PENDING  # own request: refused
    pending = client_for(Role.ADMIN).get(reverse("risks:acceptances"))
    assert list(pending.context["acceptances"]) == [acc]
    response = client_for(Role.ADMIN).post(reverse("risks:acceptance_decide", args=[acc.pk]),
                                           {"decision": "approve", "next_page": "queue"})  # fmt: skip
    assert response["Location"] == reverse("risks:acceptances")
    acc.refresh_from_db()
    assert acc.status == RiskAcceptance.Status.APPROVED
    assert (
        client_for(Role.AUDITOR)
        .post(reverse("risks:acceptance_decide", args=[acc.pk]), {"decision": "reject"})
        .status_code
        == 403
    )


def test_unknown_or_out_of_scope_risk_is_404(client_for):
    assert client_for(Role.VIEWER).get("/risks/R-9999/").status_code == 404


def test_detail_query_count_is_independent_of_technique_count(
    client_for, org, rm, django_assert_max_num_queries
):
    risk = make_risk(rm)
    ctl = make_control(org, "CTL-1")
    for i in range(12):
        t = technique(f"T1{i:03d}")
        map_direct(ctl, t)
        services.link_technique(risk, t, user=rm)
    c = client_for(Role.RISK_MANAGER)
    with django_assert_max_num_queries(35):
        assert c.get(reverse("risks:detail", args=[risk.ref])).status_code == 200
