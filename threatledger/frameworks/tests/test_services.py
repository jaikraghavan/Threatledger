from __future__ import annotations

import json
from io import StringIO
from unittest import mock

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from threatledger.accounts.roles import Role
from threatledger.attack.models import AttackRelease
from threatledger.audit.models import Action, AuditEvent
from threatledger.controls.models import Control
from threatledger.core.fetch import FetchError
from threatledger.frameworks import ctid_source, services
from threatledger.frameworks.compliance import ReqStatus
from threatledger.frameworks.importer import load, parse
from threatledger.frameworks.models import Framework, Requirement, TechniqueRequirement
from threatledger.risks.tests.helpers import make_control, technique

pytestmark = pytest.mark.django_db

FW_A = b"""
framework: {code: FW-A, name: Framework A, baselines: [low, moderate]}
requirements:
  - {ref: D, title: Domain, is_domain: true}
  - {ref: A-1, title: One, parent: D, baselines: [low, moderate]}
  - {ref: A-2, title: Two, parent: D, baselines: [moderate]}
  - {ref: A-3, title: Three, parent: D, baselines: [moderate]}
"""
FW_B = b"""
framework: {code: FW-B, name: Framework B}
requirements:
  - {ref: B-1, title: Uno}
  - {ref: B-2, title: Dos}
"""


@pytest.fixture
def fws():
    a = load(parse(FW_A, "a.yaml")).framework
    b = load(parse(FW_B, "b.yaml")).framework
    return a, b


def req(fw: Framework, ref: str) -> Requirement:
    return Requirement.objects.get(framework=fw, ref=ref)


@pytest.fixture
def rm(users):
    return users[Role.RISK_MANAGER]


def test_status_and_percent(org, fws, rm):
    a, _ = fws
    mfa = make_control(org, "MFA", status="implemented")
    edr = make_control(org, "EDR", status="planned")
    services.map_control(req(a, "A-1"), mfa, user=rm)
    services.map_control(req(a, "A-2"), mfa, user=rm)
    services.map_control(req(a, "A-2"), edr, user=rm)
    result = services.framework_result(a, org)
    s = result.summary
    assert s.by_requirement[req(a, "A-1").pk] is ReqStatus.MET
    assert s.by_requirement[req(a, "A-2").pk] is ReqStatus.PARTIAL
    assert s.by_requirement[req(a, "A-3").pk] is ReqStatus.NO_CONTROL
    assert (s.tracked, s.percent) == (3, 50.0)  # (1 + 0.5) / 3


def test_one_control_status_change_updates_every_framework(org, fws, rm):
    """The brief's core idea: one control change -> compliance % for every mapped framework."""
    a, b = fws
    ctl = make_control(org, "CTL-MFA", status="not_implemented")
    for r in (req(a, "A-1"), req(a, "A-2"), req(b, "B-1")):
        services.map_control(r, ctl, user=rm)
    before = (
        services.framework_result(a, org).summary.percent,
        services.framework_result(b, org).summary.percent,
    )
    assert before == (0.0, 0.0)
    Control.objects.filter(pk=ctl.pk).update(status="implemented")
    after = (
        services.framework_result(a, org).summary.percent,
        services.framework_result(b, org).summary.percent,
    )
    assert after == (round(200 / 3, 1), 50.0)


def test_baseline_and_not_applicable_scoping(org, fws, users):
    a, _ = fws
    admin = users[Role.ADMIN]
    assert services.framework_result(a, org).summary.tracked == 3  # default baseline "moderate"
    services.set_adoption(a, user=admin, adopted=True, baseline="low")
    assert services.framework_result(a, org).summary.tracked == 1
    services.set_adoption(a, user=admin, adopted=True, baseline="")
    with pytest.raises(services.FrameworkError, match="justification"):
        services.set_applicability(req(a, "A-3"), user=admin, applicable=False)
    services.set_applicability(
        req(a, "A-3"), user=admin, applicable=False, justification="No such systems"
    )
    result = services.framework_result(a, org)
    assert result.summary.tracked == 2
    assert req(a, "A-3").pk in result.not_applicable
    status, _, scope, _ = services.requirement_state(req(a, "A-3"), org)
    assert status is None and scope is not None and scope.justification == "No such systems"
    with pytest.raises(services.FrameworkError, match="Unknown baseline"):
        services.set_adoption(a, user=admin, adopted=True, baseline="extreme")
    assert AuditEvent.objects.filter(
        object_type="frameworks.requirement", action=Action.UPDATE
    ).exists()


def test_adoption_and_permissions(org, fws, users):
    a, b = fws
    services.set_adoption(b, user=users[Role.ADMIN], adopted=False)
    assert services.adopted_frameworks(org) == [a]
    for role in (Role.CONTROL_OWNER, Role.AUDITOR, Role.VIEWER):
        with pytest.raises(services.FrameworkError):
            services.set_adoption(a, user=users[role], adopted=False)
        with pytest.raises(services.FrameworkError):
            services.map_control(req(a, "A-1"), make_control(org, f"C-{role}"), user=users[role])


def test_mapping_rules_and_audit(org, fws, rm):
    a, _ = fws
    ctl = make_control(org, "CTL-1")
    with pytest.raises(services.FrameworkError, match="not to domains"):
        services.map_control(req(a, "D"), ctl, user=rm)
    assert services.map_control(req(a, "A-1"), ctl, user=rm)
    assert not services.map_control(req(a, "A-1"), ctl, user=rm)
    link = ctl.requirement_links.get()
    services.unmap_control(link, user=rm)
    changes = list(
        AuditEvent.objects.filter(object_id=str(ctl.pk)).values_list("changes", flat=True)
    )
    assert any("requirement_added" in c for c in changes)
    assert any("requirement_removed" in c for c in changes)
    from threatledger.org.models import Organisation

    foreign = make_control(Organisation.objects.create(name="Other"), "X")
    with pytest.raises(services.FrameworkError, match="not available"):
        services.map_control(req(a, "A-1"), foreign, user=rm)


def test_archived_controls_do_not_count(org, fws, rm):
    a, _ = fws
    from django.utils import timezone

    ctl = make_control(org, "OLD", status="implemented")
    services.map_control(req(a, "A-1"), ctl, user=rm)
    Control.objects.filter(pk=ctl.pk).update(archived_at=timezone.now())
    assert (
        services.framework_result(a, org).summary.by_requirement[req(a, "A-1").pk]
        is ReqStatus.NO_CONTROL
    )


def test_cross_framework_and_related(org, fws, rm):
    a, b = fws
    ctl = make_control(org, "CTL-MFA")
    for r in (req(a, "A-1"), req(a, "A-2"), req(b, "B-1")):
        services.map_control(r, ctl, user=rm)
    make_control(org, "CTL-SOLO")
    services.map_control(req(b, "B-2"), Control.objects.get(ref="CTL-SOLO"), user=rm)
    rows = services.cross_framework(org)
    assert [(r.control.ref, r.requirement_count, r.framework_count) for r in rows] == [
        ("CTL-MFA", 3, 2),
        ("CTL-SOLO", 1, 1),
    ]
    from threatledger.frameworks.models import RequirementMapping

    RequirementMapping.objects.create(from_requirement=req(a, "A-3"), to_requirement=req(b, "B-1"))
    related = services.related_requirements(req(b, "B-1"), org)
    assert [r.ref for r in related["crosswalk"]] == ["A-3"]
    assert [r.ref for r in related["shared"]] == ["A-1", "A-2"]


# ----------------------------------------------------------------------------- CTID
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AC-02", "AC-2"),
        ("AC-02(01)", "AC-2(1)"),
        ("si-4", "SI-4"),
        ("SC-07(12)", "SC-7(12)"),
        ("bogus", None),
    ],
)
def test_normalise_nist_id(raw, expected):
    assert services.normalise_nist_id(raw) == expected


def _nist_and_ctid():
    nist = b"""
framework: {code: NIST-800-53-R5, name: NIST}
requirements:
  - {ref: AC-2, title: Account Management}
  - {ref: SI-4, title: System Monitoring}
"""
    load(parse(nist, "n.yaml"))
    technique("T1078")
    technique("T1059")
    technique("T1086", is_revoked=True)
    return {
        "metadata": {
            "mapping_framework": "nist_800_53",
            "mapping_framework_version": "rev5",
            "attack_version": "16.1",
        },
        "mapping_objects": [
            {
                "capability_id": "AC-02",
                "attack_object_id": "T1078",
                "mapping_type": "mitigates",
                "status": "complete",
            },
            {"capability_id": "AC-02", "attack_object_id": "T1078", "mapping_type": "mitigates"},
            {"capability_id": "SI-04", "attack_object_id": "T1059", "mapping_type": "mitigates"},
            {"capability_id": "SI-04", "attack_object_id": "T1086", "mapping_type": "mitigates"},
            {"capability_id": "SI-04", "attack_object_id": "T9999", "mapping_type": "mitigates"},
            {"capability_id": "ZZ-01", "attack_object_id": "T1059", "mapping_type": "mitigates"},
            {"capability_id": None, "attack_object_id": "T1059", "status": "non_mappable"},
        ],
    }


def test_import_ctid(users):
    payload = _nist_and_ctid()
    from django.utils import timezone

    AttackRelease.objects.create(version="20.1", sha256="x", source="t", imported_at=timezone.now())
    report = services.import_ctid(payload, user=users[Role.ADMIN])
    assert (report.created, report.existing) == (2, 1)
    assert (
        report.skipped_revoked_technique,
        report.skipped_unknown_technique,
        report.skipped_unknown_control,
        report.non_mappable,
    ) == (1, 1, 1, 1)
    assert "v16.1" in report.warnings[0] and "v20.1" in report.warnings[0]
    assert services.import_ctid(payload).created == 0  # idempotent
    assert TechniqueRequirement.objects.count() == 2


def test_import_ctid_rejects_wrong_files():
    with pytest.raises(services.FrameworkError, match="Not a CTID"):
        services.import_ctid({"metadata": {"mapping_framework": "cri_profile"}})
    with pytest.raises(services.FrameworkError, match="Load NIST"):
        services.import_ctid(
            {"metadata": {"mapping_framework": "nist_800_53", "mapping_framework_version": "rev5"}}
        )


def test_ctid_source_url_and_file(tmp_path):
    assert ctid_source.ctid_url("16.1").endswith(
        "/attack-16.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-16.1-enterprise.json"
    )
    with pytest.raises(FetchError, match="invalid"):
        ctid_source.ctid_url("../16.1")
    path = tmp_path / "m.json"
    path.write_text(json.dumps({"metadata": {}}))
    _, source = ctid_source.load(file_path=str(path))
    assert source == "file:m.json"
    path.write_text("not json")
    with pytest.raises(FetchError, match="not valid JSON"):
        ctid_source.load(file_path=str(path))
    with pytest.raises(FetchError, match="no such file"):
        ctid_source.load(file_path=str(tmp_path / "missing.json"))


def test_ctid_download_is_allowlisted():
    with mock.patch("threatledger.core.fetch.urllib.request.urlopen") as op:
        op.side_effect = OSError("offline")
        with pytest.raises(FetchError, match="download failed"):
            ctid_source.load("16.1")
    assert op.call_args.args[0].full_url.startswith(ctid_source.REPO)


def test_import_ctid_command(tmp_path):
    payload = _nist_and_ctid()
    path = tmp_path / "ctid.json"
    path.write_text(json.dumps(payload))
    out = StringIO()
    call_command("import_ctid_mappings", "--file", str(path), stdout=out)
    assert "2 created" in out.getvalue()
    path.write_text(json.dumps({"metadata": {}}))
    with pytest.raises(CommandError, match="Not a CTID"):
        call_command("import_ctid_mappings", "--file", str(path), stdout=StringIO())
