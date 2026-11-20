from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.roles import Role
from threatledger.audit.models import Action, AuditEvent
from threatledger.controls import services
from threatledger.controls.models import Control, Evidence
from threatledger.org.models import Organisation
from threatledger.risks import services as risk_services
from threatledger.risks.tests.helpers import make_control, make_risk, mitigation, technique

from .test_uploads import PDF

pytestmark = pytest.mark.django_db
LIST = reverse("controls:list")


@pytest.fixture
def owner(users):
    return users[Role.CONTROL_OWNER]


@pytest.fixture
def owned(org, owner):
    return make_control(
        org, "CTL-MFA", status="planned", owner=owner, name="Multi-factor authentication"
    )


@pytest.mark.parametrize("role", list(Role))
def test_every_role_can_browse(client_for, owned, role):
    c = client_for(role)
    assert c.get(LIST).status_code == 200
    assert c.get(reverse("controls:detail", args=[owned.ref])).status_code == 200


def test_empty_library_offers_starter(client_for):
    response = client_for(Role.RISK_MANAGER).get(LIST)
    assert response.context["library_empty"]
    assert reverse("controls:seed_starter").encode() in response.content


@pytest.mark.parametrize(
    ("role", "status"), [(Role.RISK_MANAGER, 302), (Role.CONTROL_OWNER, 403), (Role.VIEWER, 403)]
)
def test_seed_starter_view_permission(client_for, role, status):
    assert client_for(role).post(reverse("controls:seed_starter")).status_code == status
    assert Control.objects.count() == (14 if status == 302 else 0)


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"q": "factor"}, ["CTL-MFA"]),
        ({"status": "implemented"}, ["CTL-EDR"]),
        ({"type": "detective"}, ["CTL-EDR"]),
        ({"owner": "me"}, ["CTL-MFA"]),
        ({"test": "overdue"}, ["CTL-MFA"]),
        ({"archived": "1"}, ["CTL-OLD"]),
    ],
)
def test_list_filters(client_for, org, owned, params, expected):
    make_control(
        org,
        "CTL-EDR",
        status="implemented",
        control_type="detective",
        last_tested_at=timezone.localdate(),
    )
    make_control(org, "CTL-OLD", archived_at=timezone.now())
    response = client_for(Role.CONTROL_OWNER).get(LIST, params)
    assert [c.ref for c in response.context["controls"]] == expected


def test_create_control_via_form(client_for):
    data = {
        "ref": "ctl-siem",
        "name": "SIEM",
        "control_type": "detective",
        "status": "partial",
        "effectiveness": "3",
        "test_frequency_days": "180",
    }
    response = client_for(Role.RISK_MANAGER).post(reverse("controls:create"), data)
    assert response.status_code == 302
    c = Control.objects.get()
    assert (c.ref, c.effectiveness) == ("CTL-SIEM", 3)
    dup = client_for(Role.RISK_MANAGER).post(reverse("controls:create"), data)
    assert "already exists" in dup.content.decode()


def test_owner_gets_limited_form_and_can_update_status(client_for, owned):
    c = client_for(Role.CONTROL_OWNER)
    url = reverse("controls:edit", args=[owned.ref])
    form = c.get(url).context["form"]
    assert set(form.fields) == {"status", "effectiveness", "description"}
    assert (
        c.post(
            url, {"status": "implemented", "effectiveness": "", "description": "Rolled out"}
        ).status_code
        == 302
    )
    owned.refresh_from_db()
    assert owned.status == "implemented"


def test_owner_cannot_edit_others_control(client_for, org):
    other = make_control(org, "CTL-OTHER")
    assert (
        client_for(Role.CONTROL_OWNER).get(reverse("controls:edit", args=[other.ref])).status_code
        == 403
    )
    assert client_for(Role.CONTROL_OWNER).get(reverse("controls:create")).status_code == 403


def test_status_change_in_ui_updates_risk_coverage(client_for, org, owned, users):
    """End-to-end core idea: control owner flips status → risk page shows new coverage."""
    rm = users[Role.RISK_MANAGER]
    t = technique("T1078", "Valid Accounts")
    services.add_mitigation(owned, mitigation("M1032", t), user=rm)
    risk = make_risk(rm)
    risk_services.link_technique(risk, t, user=rm)
    detail = reverse("risks:detail", args=[risk.ref])
    assert client_for(Role.VIEWER).get(detail).context["coverage_summary"].gap == 1
    client_for(Role.CONTROL_OWNER).post(
        reverse("controls:edit", args=[owned.ref]),
        {"status": "implemented", "effectiveness": "", "description": ""},
    )
    assert client_for(Role.VIEWER).get(detail).context["coverage_summary"].covered == 1


def test_mapping_htmx_flow(client_for, owned):
    t = technique("T1110", "Brute Force")
    m = mitigation("M1032", t)
    c = client_for(Role.RISK_MANAGER)
    found = c.get(
        reverse("controls:mapping_search", args=[owned.ref]), {"kind": "mitigation", "q": "M10"}
    )
    assert [r.attack_id for r in found.context["results"]] == ["M1032"]
    panel = c.post(
        reverse("controls:mapping_add", args=[owned.ref]), {"kind": "mitigation", "id": m.pk}
    )
    assert panel.templates[0].name == "controls/_mappings.html"
    assert [x.technique.attack_id for x in panel.context["covered"]] == ["T1110"]
    c.post(reverse("controls:mapping_add", args=[owned.ref]), {"kind": "technique", "id": t.pk})
    link = owned.technique_links.get()
    c.post(reverse("controls:mapping_remove", args=[owned.ref, "technique", link.pk]))
    assert not owned.technique_links.exists()
    assert (
        client_for(Role.CONTROL_OWNER)
        .post(reverse("controls:mapping_add", args=[owned.ref]), {"kind": "technique", "id": t.pk})
        .status_code
        == 403
    )


def test_upload_download_and_headers(client_for, owned):
    c = client_for(Role.CONTROL_OWNER)
    response = c.post(
        reverse("controls:evidence_add", args=[owned.ref]),
        {
            "file": SimpleUploadedFile("mfa-policy.pdf", PDF),
            "title": "MFA policy",
            "valid_until": (timezone.localdate() + timedelta(days=365)).isoformat(),
        },
    )
    assert response.status_code == 302
    ev = Evidence.objects.get()
    download = client_for(Role.AUDITOR).get(reverse("controls:evidence_download", args=[ev.pk]))
    assert download.status_code == 200
    assert download["Content-Disposition"].startswith("attachment")
    assert 'filename="mfa-policy.pdf"' in download["Content-Disposition"]
    assert download["Content-Type"] == "application/pdf"
    assert download["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in download["Content-Security-Policy"]
    assert b"".join(download.streaming_content) == PDF
    assert AuditEvent.objects.filter(action=Action.EXPORT, object_type="controls.evidence").exists()


def test_viewer_cannot_see_or_download_evidence(client_for, owned, owner):
    ev = services.add_file_evidence(
        owned, user=owner, upload=SimpleUploadedFile("a.pdf", PDF), title="Secret"
    )
    detail = client_for(Role.VIEWER).get(reverse("controls:detail", args=[owned.ref]))
    assert b"Secret" not in detail.content
    assert (
        client_for(Role.VIEWER).get(reverse("controls:evidence_download", args=[ev.pk])).status_code
        == 403
    )


def test_evidence_of_other_org_is_404(client_for):
    other = Organisation.objects.create(name="Other")
    from threatledger.accounts.models import User

    stranger = User.objects.create_user("stranger", "s@x.example", "x" * 16)
    ctl = make_control(other, "X-1")
    ev = Evidence.objects.create(
        control=ctl, kind="link", url="https://x.example", title="t", uploaded_by=stranger
    )
    assert (
        client_for(Role.AUDITOR)
        .get(reverse("controls:evidence_download", args=[ev.pk]))
        .status_code
        == 404
    )


def test_bad_upload_rejected_with_message(client_for, owned):
    c = client_for(Role.CONTROL_OWNER)
    response = c.post(
        reverse("controls:evidence_add", args=[owned.ref]),
        {"file": SimpleUploadedFile("x.pdf", b"<html>"), "title": "x"},
        follow=True,
    )
    assert "Evidence not added" in response.content.decode()
    assert not Evidence.objects.exists()


def test_upload_to_others_control_forbidden(client_for, org):
    other = make_control(org, "CTL-OTHER")
    response = client_for(Role.CONTROL_OWNER).post(
        reverse("controls:evidence_add", args=[other.ref]),
        {"file": SimpleUploadedFile("a.pdf", PDF)},
    )
    assert response.status_code == 403


def test_link_evidence_and_archive_views(client_for, owned):
    c = client_for(Role.CONTROL_OWNER)
    c.post(
        reverse("controls:evidence_add", args=[owned.ref]),
        {"kind": "link", "title": "Ticket", "url": "https://jira.example/SEC-1"},
    )
    ev = Evidence.objects.get()
    c.post(reverse("controls:evidence_archive", args=[ev.pk]))
    ev.refresh_from_db()
    assert ev.archived_at is not None


def test_record_test_view(client_for, owned):
    c = client_for(Role.CONTROL_OWNER)
    c.post(
        reverse("controls:test_record", args=[owned.ref]),
        {
            "tested_on": timezone.localdate().isoformat(),
            "method": "inspection",
            "result": "pass",
            "notes": "Sampled 25 users",
        },
    )
    owned.refresh_from_db()
    assert owned.last_test_result == "pass"
    assert (
        client_for(Role.AUDITOR)
        .post(reverse("controls:test_record", args=[owned.ref]), {})
        .status_code
        == 403
    )


def test_evidence_register_filters(client_for, owned, owner):
    today = timezone.localdate()
    services.add_link_evidence(
        owned,
        user=owner,
        url="https://x.example/1",
        title="Old",
        valid_until=today - timedelta(days=1),
    )
    services.add_link_evidence(
        owned,
        user=owner,
        url="https://x.example/2",
        title="Soon",
        valid_until=today + timedelta(days=10),
    )
    c = client_for(Role.AUDITOR)
    url = reverse("controls:evidence_list")
    assert [e.title for e in c.get(url, {"due": "expired"}).context["evidence_items"]] == ["Old"]
    assert [e.title for e in c.get(url, {"due": "30"}).context["evidence_items"]] == ["Soon"]
    assert client_for(Role.VIEWER).get(url).status_code == 403


def test_archive_view_rm_only(client_for, owned):
    assert (
        client_for(Role.CONTROL_OWNER)
        .post(reverse("controls:archive", args=[owned.ref]))
        .status_code
        == 403
    )
    client_for(Role.RISK_MANAGER).post(reverse("controls:archive", args=[owned.ref]))
    owned.refresh_from_db()
    assert owned.archived_at is not None


def test_technique_page_shows_org_coverage(client_for, owned, users):
    t = technique("T1110", "Brute Force")
    services.add_technique(owned, t, user=users[Role.RISK_MANAGER])
    response = client_for(Role.VIEWER).get(reverse("attack:technique_detail", args=["T1110"]))
    assert response.context["org_coverage"].status.label == "Gap"  # control is only planned
    assert [c.ref for c in response.context["org_controls"]] == ["CTL-MFA"]
