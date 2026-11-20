from __future__ import annotations

import json
from io import StringIO
from unittest import mock

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone

from threatledger.attack import services, tasks
from threatledger.attack.importer.loader import load_bundle
from threatledger.attack.importer.parser import BundleError, parse_bundle
from threatledger.attack.models import (
    Analytic,
    AttackRelease,
    DataComponent,
    DetectionStrategyTechnique,
    Group,
    GroupSoftware,
    GroupTechnique,
    ImportRun,
    Mitigation,
    MitigationTechnique,
    Software,
    SoftwareTechnique,
    Tactic,
    Technique,
)
from threatledger.audit.models import Action, AuditEvent

from . import bundles

ALL_MODELS = [
    Tactic, Technique, Group, Software, Mitigation, DataComponent, Analytic,
    GroupTechnique, GroupSoftware, SoftwareTechnique, MitigationTechnique,
    DetectionStrategyTechnique, Technique.tactics.through, Analytic.strategies.through,
    Analytic.data_components.through,
]  # fmt: skip


def _release(version: str) -> AttackRelease:
    return AttackRelease.objects.create(
        version=version, sha256="x" * 64, source="test", imported_at=timezone.now()
    )


def _load(bundle: dict) -> dict:
    parsed = parse_bundle(bundle)
    release, _ = AttackRelease.objects.get_or_create(
        version=parsed.version,
        defaults={"sha256": "x" * 64, "source": "test", "imported_at": timezone.now()},
    )
    return load_bundle(parsed, release)


def _snapshot() -> dict[str, list]:
    return {
        m._meta.label: sorted(map(repr, m.objects.order_by("pk").values()))  # type: ignore[attr-defined]
        for m in ALL_MODELS
    }


def tid(attack_id: str) -> Technique:
    return Technique.objects.get(attack_id=attack_id)


# ------------------------------------------------------------------------------ parser
class TestParser:
    def test_reads_version_spec_and_tactic_order_from_matrix(self):
        p = parse_bundle(bundles.bundle_v1())
        assert p.version == "19.0"
        assert p.spec_version == "3.3.0"
        order = {t["shortname"]: t["order"] for t in p.tactics}
        assert order == {"initial-access": 0, "execution": 1, "stealth": 2}

    def test_extracts_techniques_tactics_hierarchy_and_revocations(self):
        p = parse_bundle(bundles.bundle_v1())
        assert p.technique_tactics[bundles.T_PS] == ["execution", "stealth"]
        assert p.subtechnique_of[bundles.T_PS] == bundles.T_CSI
        assert p.revoked_by[bundles.T_OLD_PS] == bundles.T_PS
        ps = next(t for t in p.techniques if t["stix_id"] == bundles.T_PS)
        assert ps["attack_id"] == "T1059.001"
        assert ps["url"] == "https://attack.mitre.org/techniques/T1059/001"
        assert ps["is_subtechnique"] is True

    def test_links_skip_revoked_relationships(self):
        p = parse_bundle(bundles.bundle_v1())
        group_links = {(s, t) for s, t, _ in p.links["group_technique"]}
        assert (bundles.G1, bundles.T_CSI) not in group_links  # relationship 11 is revoked
        assert (bundles.G1, bundles.T_PS) in group_links
        assert len(p.links["detection_technique"]) == 1
        assert p.analytic_strategies[bundles.AN1] == [bundles.DET1]
        assert p.analytic_components[bundles.AN1] == [bundles.DC1]

    def test_group_aliases_exclude_primary_name(self):
        p = parse_bundle(bundles.bundle_v1())
        assert p.groups[0]["aliases"] == ["Fancy Test", "Test Bear"]
        assert p.groups[0]["aliases_text"] == "Fancy Test | Test Bear"

    @pytest.mark.parametrize(
        ("bundle", "message"),
        [
            ([], "not a STIX bundle"),
            ({"type": "bundle", "objects": []}, "no objects"),
            ({"type": "bundle", "objects": [{"type": "x", "id": "x--1"}]}, "x-mitre-collection"),
        ],
    )
    def test_rejects_invalid_bundles(self, bundle, message):
        with pytest.raises(BundleError, match=message):
            parse_bundle(bundle)

    def test_rejects_bundle_without_matrix(self):
        b = bundles.bundle_v1()
        b["objects"] = [o for o in b["objects"] if o["type"] != "x-mitre-matrix"]
        with pytest.raises(BundleError, match="matrix"):
            parse_bundle(b)

    def test_ignores_objects_from_other_domains(self):
        b = bundles.bundle_v1()
        b["objects"].append(
            {
                **bundles.technique(50, "T0800", "ICS thing", ["execution"]),
                "x_mitre_domains": ["ics-attack"],
            }
        )
        assert "T0800" not in {t["attack_id"] for t in parse_bundle(b).techniques}


# ------------------------------------------------------------------------------ loader
@pytest.mark.django_db
class TestLoader:
    def test_first_import_creates_active_objects_only(self):
        stats = _load(bundles.bundle_v1())
        assert set(Technique.objects.values_list("attack_id", flat=True)) == {
            "T1566", "T1566.001", "T1059", "T1059.001"
        }  # fmt: skip
        assert stats["objects"]["techniques"]["skipped"] == 2  # revoked T1086, deprecated T9999
        assert stats["objects"]["mitigations"]["skipped"] == 1
        assert not MitigationTechnique.objects.filter(technique__attack_id="T1566").exists()

    def test_tactics_ordered_by_matrix(self):
        _load(bundles.bundle_v1())
        assert list(Tactic.objects.order_by("order").values_list("shortname", flat=True)) == [
            "initial-access", "execution", "stealth"
        ]  # fmt: skip

    def test_hierarchy_and_tactics(self):
        _load(bundles.bundle_v1())
        ps = tid("T1059.001")
        assert ps.parent == tid("T1059")
        assert sorted(ps.tactics.values_list("shortname", flat=True)) == ["execution", "stealth"]
        assert tid("T1059").parent is None

    def test_relationships_loaded(self):
        _load(bundles.bundle_v1())
        g = Group.objects.get(attack_id="G0001")
        assert set(g.technique_links.values_list("technique__attack_id", flat=True)) == {
            "T1566.001", "T1059.001"
        }  # fmt: skip
        assert GroupSoftware.objects.get().software.name == "TestRAT"
        assert SoftwareTechnique.objects.get().technique.attack_id == "T1059"
        assert MitigationTechnique.objects.get().mitigation.attack_id == "M1049"
        det = DetectionStrategyTechnique.objects.get()
        assert det.technique.attack_id == "T1059.001"
        analytic = det.strategy.analytics.get()
        assert list(analytic.data_components.values_list("name", flat=True)) == ["Process Creation"]
        assert Software.objects.get().aliases == ["TRAT"]

    def test_reimport_is_idempotent(self):
        _load(bundles.bundle_v1())
        before = _snapshot()
        stats = _load(bundles.bundle_v1())
        assert _snapshot() == before
        for counts in stats["objects"].values():
            assert counts["created"] == counts["updated"] == 0
        for counts in stats["links"].values():
            assert counts["created"] == counts["updated"] == counts["deleted"] == 0

    def test_upgrade_flags_revoked_and_never_deletes(self):
        _load(bundles.bundle_v1())
        pks = dict(Technique.objects.values_list("attack_id", "pk"))
        stats = _load(bundles.bundle_v2())

        revoked = tid("T1566.001")
        assert revoked.is_revoked
        assert revoked.pk == pks["T1566.001"]  # same row: user mappings keep pointing at it
        assert revoked.revoked_by == tid("T1566.002")
        assert revoked.replacement() == tid("T1566.002")
        assert stats["objects"]["techniques"]["flagged"] == 1
        for attack_id, pk in pks.items():
            assert Technique.objects.filter(pk=pk, attack_id=attack_id).exists()

    def test_upgrade_updates_changed_fields_and_links(self):
        _load(bundles.bundle_v1())
        _load(bundles.bundle_v2())
        assert tid("T1059").name == "Command and Scripting Interpreters"
        g = Group.objects.get(attack_id="G0001")
        assert set(g.technique_links.values_list("technique__attack_id", flat=True)) == {
            "T1566.002"
        }
        assert not MitigationTechnique.objects.exists()
        assert tid("T1566.002").parent == tid("T1566")

    def test_tactic_dropped_from_matrix_loses_order(self):
        _load(bundles.bundle_v1())
        _load(bundles.bundle_v2())
        assert Tactic.objects.get(shortname="stealth").order is None
        assert Tactic.objects.get(shortname="execution").order == 1

    def test_last_seen_release_tracks_latest_import(self):
        _load(bundles.bundle_v1())
        _load(bundles.bundle_v2())
        seen = tid("T1059").last_seen_release
        assert seen is not None
        assert seen.version == "20.0"

    def test_replacement_follows_chain_and_stops_at_cycle(self):
        _load(bundles.bundle_v1())
        a, b = tid("T1566"), tid("T1059")
        a.is_revoked, a.revoked_by = True, b
        b.is_revoked, b.revoked_by = True, a
        a.save()
        b.save()
        assert a.replacement() in (a, b)  # bounded, no infinite loop


# ------------------------------------------------------------------------------ services
@pytest.mark.django_db
class TestServices:
    def test_execute_from_file_records_release_run_and_audit(self, tmp_path, users):
        from threatledger.accounts.roles import Role

        path = bundles.write(bundles.bundle_v1(), tmp_path / "b.json")
        run = services.create_run(file_path=str(path), user=users[Role.ADMIN])
        services.execute(run, file_path=str(path))
        run.refresh_from_db()
        assert run.status == ImportRun.Status.SUCCEEDED, run.message
        assert run.release is not None
        assert run.release.version == "19.0"
        assert run.release.counts["techniques_active"] == 4
        assert "Imported ATT&CK v19.0" in run.message
        event = AuditEvent.objects.get(action=Action.IMPORT)
        assert event.actor == users[Role.ADMIN]
        assert event.changes["version"] == [None, "19.0"]

    def test_downgrade_refused_unless_allowed(self, tmp_path):
        services.execute(
            services.create_run(),
            file_path=str(bundles.write(bundles.bundle_v2(), tmp_path / "v2.json")),
        )
        old = str(bundles.write(bundles.bundle_v1(), tmp_path / "v1.json"))
        refused = services.execute(services.create_run(), file_path=old)
        assert refused.status == ImportRun.Status.FAILED
        assert "refusing to import v19.0 over newer v20.0" in refused.message
        allowed = services.execute(services.create_run(), file_path=old, allow_downgrade=True)
        assert allowed.status == ImportRun.Status.SUCCEEDED

    def test_requested_version_must_match_bundle(self, tmp_path):
        path = str(bundles.write(bundles.bundle_v1(), tmp_path / "b.json"))
        run = services.execute(services.create_run(version="20.1"), file_path=path)
        assert run.status == ImportRun.Status.FAILED
        assert "v20.1 was requested" in run.message

    def test_sha256_mismatch_fails(self, tmp_path):
        path = str(bundles.write(bundles.bundle_v1(), tmp_path / "b.json"))
        run = services.execute(services.create_run(), file_path=path, expected_sha256="0" * 64)
        assert run.status == ImportRun.Status.FAILED
        assert "SHA-256 mismatch" in run.message
        assert not AttackRelease.objects.exists()

    def test_invalid_json_fails_cleanly(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        run = services.execute(services.create_run(), file_path=str(path))
        assert run.status == ImportRun.Status.FAILED
        assert "not valid JSON" in run.message
        failed = AuditEvent.objects.get(action=Action.IMPORT)
        assert failed.changes["status"] == [None, "failed"]

    def test_failure_mid_load_rolls_back_everything(self, tmp_path):
        path = str(bundles.write(bundles.bundle_v1(), tmp_path / "b.json"))
        with mock.patch(
            "threatledger.attack.services.load_bundle", side_effect=RuntimeError("boom")
        ):
            run = services.execute(services.create_run(), file_path=path)
        assert run.status == ImportRun.Status.FAILED
        assert run.message == "unexpected error: RuntimeError"
        assert not AttackRelease.objects.exists()
        assert not Technique.objects.exists()

    def test_download_path_uses_source(self):
        payload = json.dumps(bundles.bundle_v1()).encode()
        from threatledger.attack.importer.source import FetchedBundle

        fetched = FetchedBundle(payload, "a" * 64, "https://raw.githubusercontent.com/x")
        with mock.patch("threatledger.attack.services.download", return_value=fetched) as dl:
            run = services.execute(services.create_run(version="19.0"))
        dl.assert_called_once_with("enterprise-attack", "19.0", None)
        assert run.status == ImportRun.Status.SUCCEEDED
        assert run.source == "https://raw.githubusercontent.com/x"

    def test_current_release_is_highest_version(self):
        _release("9.0")
        _release("20.1")
        _release("18.1")
        current = services.current_release()
        assert current is not None
        assert current.version == "20.1"


# ------------------------------------------------------------------------------ command & task
@pytest.mark.django_db
class TestCommandAndTask:
    def test_command_imports_file(self, tmp_path):
        path = bundles.write(bundles.bundle_v1(), tmp_path / "b.json")
        out = StringIO()
        call_command("import_attack", "--file", str(path), stdout=out)
        assert "Imported ATT&CK v19.0" in out.getvalue()
        assert Technique.objects.count() == 4

    def test_command_raises_on_failure(self, tmp_path):
        with pytest.raises(CommandError, match="no such file"):
            call_command(
                "import_attack", "--file", str(tmp_path / "missing.json"), stdout=StringIO()
            )

    def test_command_async_enqueues(self):
        with mock.patch("threatledger.attack.management.commands.import_attack.enqueue") as enq:
            call_command("import_attack", "--async", "--version", "20.1", stdout=StringIO())
        run = enq.call_args.args[0]
        assert run.requested_version == "20.1"
        assert run.status == ImportRun.Status.QUEUED

    def test_command_async_rejects_file(self, tmp_path):
        with pytest.raises(CommandError, match="--async supports --version only"):
            call_command("import_attack", "--async", "--file", "x.json", stdout=StringIO())

    def test_task_runs_queued_import(self):
        run = services.create_run(version="19.0")
        with mock.patch("threatledger.attack.tasks.execute", wraps=lambda r: r) as ex:
            tasks.run_import(run.pk)
        ex.assert_called_once()

    def test_task_skips_runs_that_already_started(self):
        run = services.create_run()
        run.status = ImportRun.Status.RUNNING
        run.save()
        assert tasks.run_import(run.pk) == f"run {run.pk} already running"

    def test_enqueue_hands_off_to_django_q(self):
        run = services.create_run()
        with mock.patch("django_q.tasks.async_task") as async_task:
            services.enqueue(run)
        async_task.assert_called_once_with(
            "threatledger.attack.tasks.run_import", run.pk, task_name=f"attack-import-{run.pk}"
        )
