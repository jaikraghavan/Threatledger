from __future__ import annotations

from unittest import mock

import pytest
from django.urls import reverse

from threatledger.accounts.roles import Role
from threatledger.attack.models import ImportRun

from . import bundles
from .test_importer import _load

pytestmark = pytest.mark.django_db


@pytest.fixture
def attack_v1():
    _load(bundles.bundle_v1())


@pytest.fixture
def attack_v2():
    _load(bundles.bundle_v1())
    _load(bundles.bundle_v2())


LIST = reverse("attack:technique_list")


def _ids(response) -> list[str]:
    return [t.attack_id for t in response.context["techniques"]]


@pytest.mark.parametrize("role", list(Role))
def test_every_role_can_browse(client_for, attack_v1, role):
    c = client_for(role)
    assert c.get(LIST).status_code == 200
    assert c.get(reverse("attack:technique_detail", args=["T1059.001"])).status_code == 200
    assert c.get(reverse("attack:group_list")).status_code == 200
    assert c.get(reverse("attack:group_detail", args=["G0001"])).status_code == 200


def test_anonymous_redirected(client, attack_v1):
    assert client.get(LIST).status_code == 302


def test_empty_state_before_import(client_for):
    response = client_for(Role.ADMIN).get(LIST)
    assert b"No ATT&amp;CK data yet" in response.content
    assert reverse("attack:data").encode() in response.content


def test_list_shows_active_techniques_in_id_order(client_for, attack_v1):
    response = client_for(Role.VIEWER).get(LIST)
    assert _ids(response) == ["T1059", "T1059.001", "T1566", "T1566.001"]
    assert response.context["techniques"][0].sub_count == 1


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"q": "T1059"}, ["T1059", "T1059.001"]),
        ({"q": "t1566.0"}, ["T1566.001"]),
        ({"q": "powershell"}, ["T1059.001"]),
        ({"q": "Spearphishing"}, ["T1566.001"]),
        ({"tactic": "initial-access"}, ["T1566", "T1566.001"]),
        ({"tactic": "stealth"}, ["T1059.001"]),
        ({"platform": "macOS"}, ["T1059"]),
        ({"platform": "Linux", "level": "top"}, ["T1059", "T1566"]),
        ({"level": "sub"}, ["T1059.001", "T1566.001"]),
        ({"q": "<script>"}, []),
    ],
)
def test_filters(client_for, attack_v1, params, expected):
    assert _ids(client_for(Role.VIEWER).get(LIST, params)) == expected


def test_revoked_hidden_unless_requested(client_for, attack_v2):
    c = client_for(Role.VIEWER)
    assert "T1566.001" not in _ids(c.get(LIST))
    assert "T1566.001" in _ids(c.get(LIST, {"revoked": "1"}))


def test_htmx_returns_table_partial(client_for, attack_v1):
    response = client_for(Role.VIEWER).get(LIST, {"q": "phish"}, HTTP_HX_REQUEST="true")
    assert response.templates[0].name == "attack/_technique_table.html"
    assert b"<html" not in response.content


def test_tactic_dropdown_in_matrix_order(client_for, attack_v1):
    response = client_for(Role.VIEWER).get(LIST)
    assert [t.shortname for t in response.context["tactics"]] == [
        "initial-access", "execution", "stealth"
    ]  # fmt: skip


def test_technique_detail_content(client_for, attack_v1):
    response = client_for(Role.VIEWER).get(reverse("attack:technique_detail", args=["T1566.001"]))
    body = response.content.decode()
    assert "Spearphishing Attachment" in body
    assert "M1049" in body
    assert "Antivirus/Antimalware" in body
    assert reverse("attack:group_detail", args=["G0001"]) in body
    assert reverse("attack:technique_detail", args=["T1566"]) in body  # breadcrumb to parent


def test_technique_detail_detection_chain(client_for, attack_v1):
    body = (
        client_for(Role.VIEWER)
        .get(reverse("attack:technique_detail", args=["T1059.001"]))
        .content.decode()
    )
    for text in ("DET0001", "AN0001", "Process Creation"):
        assert text in body
    assert "Citation" not in body
    assert "<code>powershell.exe</code>" in body


def test_revoked_technique_points_to_replacement(client_for, attack_v2):
    response = client_for(Role.VIEWER).get(reverse("attack:technique_detail", args=["T1566.001"]))
    assert response.status_code == 200
    assert response.context["replacement"].attack_id == "T1566.002"
    assert b"revoked" in response.content
    new = client_for(Role.VIEWER).get(reverse("attack:technique_detail", args=["T1566.002"]))
    assert [t.attack_id for t in new.context["replaces"]] == ["T1566.001"]


def test_unknown_technique_404(client_for, attack_v1):
    assert client_for(Role.VIEWER).get("/attack/techniques/T0000/").status_code == 404
    assert client_for(Role.VIEWER).get("/attack/techniques/not-an-id/").status_code == 404


def test_group_search_by_alias_and_id(client_for, attack_v1):
    c = client_for(Role.VIEWER)
    url = reverse("attack:group_list")
    assert [g.name for g in c.get(url, {"q": "bear"}).context["groups"]] == ["APT Test"]
    assert [g.name for g in c.get(url, {"q": "G0001"}).context["groups"]] == ["APT Test"]
    assert list(c.get(url, {"q": "nobody"}).context["groups"]) == []
    group = c.get(url).context["groups"][0]
    assert (group.technique_count, group.software_count) == (2, 1)


def test_group_detail_groups_techniques_by_tactic(client_for, attack_v1):
    response = client_for(Role.VIEWER).get(reverse("attack:group_detail", args=["G0001"]))
    grouped = [
        (t.shortname, [link.technique.attack_id for link in ls])
        for t, ls in response.context["techniques_by_tactic"]
    ]
    assert grouped == [
        ("initial-access", ["T1566.001"]),
        ("execution", ["T1059.001"]),
        ("stealth", ["T1059.001"]),
    ]
    assert response.context["technique_count"] == 2
    assert b"TestRAT" in response.content


# ------------------------------------------------------------------------------ data page
DATA = reverse("attack:data")


@pytest.mark.parametrize(
    ("role", "status"),
    [(Role.ADMIN, 200), (Role.RISK_MANAGER, 403), (Role.AUDITOR, 403), (Role.VIEWER, 403)],
)
def test_data_page_admin_only(client_for, role, status):
    assert client_for(role).get(DATA).status_code == status


def test_data_page_shows_release(client_for, attack_v1):
    response = client_for(Role.ADMIN).get(DATA)
    assert response.context["release"].version == "19.0"
    assert response.context["counts"]["techniques"] == 2


def test_post_queues_import(client_for):
    with mock.patch("threatledger.attack.views.services.enqueue") as enq:
        response = client_for(Role.ADMIN).post(DATA, {"version": "20.1"})
    assert response.status_code == 302
    run = enq.call_args.args[0]
    assert run.requested_version == "20.1"
    assert run.requested_by.username == "admin"


def test_post_rejects_bad_version(client_for):
    with mock.patch("threatledger.attack.views.services.enqueue") as enq:
        client_for(Role.ADMIN).post(DATA, {"version": "../../x"})
    enq.assert_not_called()
    assert not ImportRun.objects.exists()


def test_post_refuses_concurrent_import(client_for):
    ImportRun.objects.create(status=ImportRun.Status.RUNNING)
    with mock.patch("threatledger.attack.views.services.enqueue") as enq:
        client_for(Role.ADMIN).post(DATA, {"version": ""})
    enq.assert_not_called()


def test_post_forbidden_for_non_admin(client_for):
    with mock.patch("threatledger.attack.views.services.enqueue") as enq:
        assert client_for(Role.RISK_MANAGER).post(DATA, {"version": ""}).status_code == 403
    enq.assert_not_called()


def test_runs_partial_polls_while_active(client_for):
    ImportRun.objects.create(status=ImportRun.Status.QUEUED)
    response = client_for(Role.ADMIN).get(DATA, HTTP_HX_REQUEST="true")
    assert response.templates[0].name == "attack/_runs.html"
    assert b'hx-trigger="every 3s"' in response.content


def test_nav_shows_attack_links_by_role(client_for):
    admin_nav = [i["label"] for i in client_for(Role.ADMIN).get(LIST).context["nav_items"]]
    viewer_nav = [i["label"] for i in client_for(Role.VIEWER).get(LIST).context["nav_items"]]
    assert "ATT&CK data" in admin_nav
    assert "ATT&CK data" not in viewer_nav
    assert "Techniques" in viewer_nav
    assert "Threat groups" in viewer_nav


@pytest.mark.parametrize(
    ("url", "limit"),
    [
        # +2 over steady state: the first request after login writes the session once
        # (idle-timeout activity stamp), which happens at most once a minute.
        (LIST, 14),
        (reverse("attack:technique_detail", args=["T1059.001"]), 27),
        (reverse("attack:group_list"), 9),
        (reverse("attack:group_detail", args=["G0001"]), 12),
    ],
)
def test_pages_use_bounded_queries(
    client_for, attack_v1, django_assert_max_num_queries, url, limit
):
    """Guards against N+1 regressions (counts are constant regardless of data size)."""
    c = client_for(Role.VIEWER)
    with django_assert_max_num_queries(limit):
        assert c.get(url).status_code == 200
