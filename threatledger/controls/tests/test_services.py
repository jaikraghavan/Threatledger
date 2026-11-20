from __future__ import annotations

from datetime import timedelta

import pytest
from django.core import mail
from django.core.exceptions import ValidationError
from django.core.files.storage import storages
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from threatledger.accounts.roles import Role
from threatledger.audit.models import Action, AuditEvent
from threatledger.controls import services
from threatledger.controls.models import Control, ControlStatus, Evidence
from threatledger.controls.models import TestResult as Result
from threatledger.coverage.engine import Coverage
from threatledger.coverage.selectors import coverage_for
from threatledger.risks.tests.helpers import make_control, mitigation, technique

from .test_uploads import PDF

pytestmark = pytest.mark.django_db


@pytest.fixture
def rm(users):
    return users[Role.RISK_MANAGER]


@pytest.fixture
def owner(users):
    return users[Role.CONTROL_OWNER]


@pytest.fixture
def owned(org, owner):
    return make_control(org, "CTL-MFA", status="planned", owner=owner, name="MFA")


# ----------------------------------------------------------------------------- CRUD & permissions
def test_create_normalises_ref_and_audits(rm):
    c = services.create_control(
        user=rm, data={"ref": " ctl-edr ", "name": "EDR", "status": "partial"}
    )
    assert c.ref == "CTL-EDR"
    assert AuditEvent.objects.get(action=Action.CREATE, object_id=str(c.pk)).changes["name"] == [
        None,
        "EDR",
    ]
    with pytest.raises(ValidationError, match="already exists"):
        services.create_control(user=rm, data={"ref": "ctl-EDR", "name": "Dup"})


def test_only_risk_managers_create(owner, users):
    for user in (owner, users[Role.AUDITOR], users[Role.VIEWER]):
        with pytest.raises(services.ControlError):
            services.create_control(user=user, data={"ref": "X", "name": "X"})


def test_owner_may_update_operational_fields_of_own_control_only(org, owned, owner):
    services.update_control(owned, user=owner, data={"status": "implemented", "effectiveness": 4})
    owned.refresh_from_db()
    assert (owned.status, owned.effectiveness) == ("implemented", 4)
    with pytest.raises(services.ControlError, match="only change status"):
        services.update_control(owned, user=owner, data={"name": "Renamed"})
    other = make_control(org, "CTL-OTHER")
    with pytest.raises(services.ControlError):
        services.update_control(other, user=owner, data={"status": "implemented"})


def test_effectiveness_range_enforced(owned, rm):
    with pytest.raises(ValidationError):
        services.update_control(owned, user=rm, data={"effectiveness": 7})


def test_status_change_is_audited_and_changes_coverage(org, owned, owner):
    """Core invariant: one control's status flows straight into threat coverage."""
    t = technique("T1078")
    services.add_technique(owned, t, user=make_rm(org))
    assert coverage_for([t.pk], org.pk)[t.pk].status is Coverage.GAP
    services.update_control(owned, user=owner, data={"status": ControlStatus.IMPLEMENTED})
    assert coverage_for([t.pk], org.pk)[t.pk].status is Coverage.COVERED
    event = AuditEvent.objects.filter(action=Action.UPDATE, object_id=str(owned.pk)).first()
    assert event is not None
    assert event.changes["status"] == ["planned", "implemented"]


def make_rm(org):
    from threatledger.accounts.models import Membership, User

    user = User.objects.create_user("rm2", "rm2@example.com", "x" * 16)
    Membership.objects.create(user=user, organisation=org, role=Role.RISK_MANAGER)
    return user


def test_archive_removes_control_from_coverage(org, rm):
    t = technique("T1566")
    c = make_control(org, "CTL-EMAIL")
    services.add_technique(c, t, user=rm)
    assert coverage_for([t.pk], org.pk)[t.pk].status is Coverage.COVERED
    services.set_archived(c, user=rm, archived=True)
    assert coverage_for([t.pk], org.pk)[t.pk].status is Coverage.GAP
    with pytest.raises(services.ControlError):
        services.set_archived(c, user=make_user_role(org, Role.CONTROL_OWNER), archived=False)


def make_user_role(org, role):
    from threatledger.accounts.models import Membership, User

    user = User.objects.create_user(f"u-{role}", f"{role}@x.example", "x" * 16)
    Membership.objects.create(user=user, organisation=org, role=role)
    return user


# ----------------------------------------------------------------------------- mappings
def test_mappings_and_covered_techniques(org, rm, owner):
    t1, t2, t3 = technique("T1566"), technique("T1204"), technique("T1059")
    m = mitigation("M1017", t1, t2)
    c = make_control(org, "CTL-AWARE")
    assert services.add_mitigation(c, m, user=rm)
    assert not services.add_mitigation(c, m, user=rm)
    services.add_technique(c, t1, user=rm)
    services.add_technique(c, t3, user=rm)
    covered = {x.technique.attack_id: x for x in services.covered_techniques(c)}
    assert set(covered) == {"T1566", "T1204", "T1059"}
    assert covered["T1566"].direct and [v.attack_id for v in covered["T1566"].via] == ["M1017"]
    assert not covered["T1204"].direct
    with pytest.raises(services.ControlError):
        services.add_technique(c, t2, user=owner)  # control owners don't edit mappings
    services.remove_technique(c, c.technique_links.get(technique=t3), user=rm)
    services.remove_mitigation(c, c.mitigation_links.get(), user=rm)
    assert {x.technique.attack_id for x in services.covered_techniques(c)} == {"T1566"}


def test_cannot_map_inactive_attack_objects(org, rm):
    c = make_control(org, "CTL-X")
    with pytest.raises(services.ControlError, match="revoked or deprecated"):
        services.add_technique(c, technique("T1086", is_revoked=True), user=rm)
    m = mitigation("M9999")
    m.is_deprecated = True
    m.save()
    with pytest.raises(services.ControlError, match="deprecated"):
        services.add_mitigation(c, m, user=rm)


# ----------------------------------------------------------------------------- evidence
def test_file_evidence_stored_privately_with_hash_and_audit(owned, owner):
    ev = services.add_file_evidence(
        owned,
        user=owner,
        upload=SimpleUploadedFile("../MFA policy.pdf", PDF),
        title="",
        valid_until=None,
    )
    assert ev.title == "MFA policy.pdf"
    assert ev.original_filename == "MFA policy.pdf"
    stored = ev.file.name or ""
    assert "/" in stored
    assert "MFA" not in stored
    assert "." not in stored.split("/")[-1]
    assert storages["evidence"].open(stored).read() == PDF
    event = AuditEvent.objects.get(action=Action.CREATE, object_type="controls.evidence")
    assert event.changes["sha256"] == [None, ev.sha256]


def test_evidence_upload_permissions(org, owned, owner, users):
    other = make_control(org, "CTL-OTHER")
    with pytest.raises(services.ControlError):
        services.add_file_evidence(
            other, user=owner, upload=SimpleUploadedFile("a.pdf", PDF), title="x"
        )
    with pytest.raises(services.ControlError):
        services.add_link_evidence(
            owned, user=users[Role.AUDITOR], url="https://x.example", title="x"
        )


def test_link_evidence_http_only(owned, owner):
    ev = services.add_link_evidence(
        owned, user=owner, url="https://wiki.example/mfa", title="Runbook"
    )
    assert ev.kind == Evidence.Kind.LINK
    with pytest.raises(ValidationError):
        services.add_link_evidence(owned, user=owner, url="javascript:alert(1)", title="x")


def test_archive_evidence_rules(owned, owner, rm, users):
    ev = services.add_link_evidence(owned, user=owner, url="https://x.example", title="t")
    with pytest.raises(services.ControlError):
        services.archive_evidence(ev, user=users[Role.AUDITOR])
    services.archive_evidence(ev, user=owner)
    ev.refresh_from_db()
    assert ev.archived_at is not None
    assert Evidence.objects.filter(pk=ev.pk).exists()  # retained, never deleted


# ----------------------------------------------------------------------------- testing
def test_record_test_updates_last_tested_only_when_newer(owned, owner):
    today = timezone.localdate()
    ev = services.add_link_evidence(
        owned, user=owner, url="https://x.example/report", title="Report"
    )
    services.record_test(
        owned, user=owner, tested_on=today, method="inspection", result="pass", evidence=[ev]
    )
    services.record_test(
        owned, user=owner, tested_on=today - timedelta(days=40), method="inquiry", result="fail"
    )
    owned.refresh_from_db()
    assert (owned.last_tested_at, owned.last_test_result) == (today, Result.PASS)
    assert owned.tests.count() == 2
    assert list(owned.tests.first().evidence.all()) == [ev]
    assert not owned.test_overdue


def test_record_test_validation(org, owned, owner):
    with pytest.raises(ValidationError):
        services.record_test(
            owned,
            user=owner,
            tested_on=timezone.localdate() + timedelta(days=1),
            method="inspection",
            result="pass",
        )
    other = make_control(org, "CTL-OTHER", owner=owner)
    foreign = services.add_link_evidence(other, user=owner, url="https://x.example", title="x")
    with pytest.raises(services.ControlError, match="belong"):
        services.record_test(
            owned,
            user=owner,
            tested_on=timezone.localdate(),
            method="inspection",
            result="pass",
            evidence=[foreign],
        )


def test_test_overdue_property(org):
    c = make_control(org, "C1", test_frequency_days=90)
    assert c.test_overdue  # never tested
    c.last_tested_at = timezone.localdate() - timedelta(days=91)
    assert c.test_overdue
    c.last_tested_at = timezone.localdate() - timedelta(days=10)
    assert not c.test_overdue
    assert c.next_test_due == c.last_tested_at + timedelta(days=90)


# ----------------------------------------------------------------------------- starter set
def test_seed_starter_controls_idempotent_with_missing_ids(org):
    technique("T1566")
    mitigation("M1017")
    result = services.seed_starter_controls(org)
    assert len(result.created) == 14
    assert {"CTL-MFA", "CTL-EDR", "CTL-BACKUP", "CTL-DLP", "CTL-PASSWORD", "CTL-IR"} <= set(
        result.created
    )
    assert set(Control.objects.values_list("status", flat=True)) == {"not_implemented"}
    aware = Control.objects.get(ref="CTL-AWARE")
    assert list(aware.mitigations.values_list("attack_id", flat=True)) == ["M1017"]
    assert aware.mitigation_links.get().source == "seed"
    assert "M1032" in result.missing_attack_ids  # not imported in this test
    again = services.seed_starter_controls(org)
    assert again.created == [] and len(again.skipped) == 14


def test_seed_controls_command(org):
    from io import StringIO

    from django.core.management import call_command

    out = StringIO()
    call_command("seed_controls", stdout=out)
    assert "Created 14" in out.getvalue()
    assert "ATT&CK IDs not found" in out.getvalue()


# ----------------------------------------------------------------------------- expiry alerts
def test_expiry_alerts_once_per_stage(owned, owner):
    today = timezone.localdate()
    ev = services.add_link_evidence(
        owned,
        user=owner,
        url="https://x.example",
        title="Pen test",
        valid_until=today + timedelta(days=25),
    )
    services.add_link_evidence(
        owned,
        user=owner,
        url="https://x.example/2",
        title="Far",
        valid_until=today + timedelta(days=200),
    )
    assert services.send_evidence_expiry_alerts(today) == 1
    assert "Pen test" in mail.outbox[0].body and "Far" not in mail.outbox[0].body
    assert services.send_evidence_expiry_alerts(today) == 0  # stage 1 already sent
    assert services.send_evidence_expiry_alerts(today + timedelta(days=19)) == 1  # 6 days left
    assert services.send_evidence_expiry_alerts(today + timedelta(days=26)) == 1  # expired
    assert "EXPIRED" in mail.outbox[-1].body
    assert services.send_evidence_expiry_alerts(today + timedelta(days=30)) == 0
    ev.refresh_from_db()
    assert ev.expiry_notice_stage == 3


def test_expiry_alert_goes_to_uploader_when_no_owner(org, owner):
    c = make_control(org, "CTL-NOOWNER")
    from threatledger.accounts.models import User

    rm_user = User.objects.get(username="risk_manager")
    services.add_link_evidence(
        c, user=rm_user, url="https://x.example", title="x", valid_until=timezone.localdate()
    )
    assert services.send_evidence_expiry_alerts() == 1
    assert mail.outbox[0].to == [rm_user.email]


def test_daily_task():
    from threatledger.controls.tasks import daily

    assert daily() == "evidence_alert_emails=0"
