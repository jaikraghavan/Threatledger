"""Backup/restore, demo seed and performance seeding."""

from __future__ import annotations

import io
import json
import tarfile
from io import StringIO
from pathlib import Path

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import override_settings

from threatledger.accounts.roles import Role
from threatledger.core import backup
from threatledger.risks.models import Asset, Risk, RiskAcceptance

pytestmark = pytest.mark.django_db

# Backups need a connection outside a test transaction; the PostgreSQL path (pg_dump) is
# exercised end to end in CI's Docker smoke test.
backup_test = pytest.mark.django_db(transaction=True)
sqlite_only = pytest.mark.skipif(
    connection.vendor != "sqlite", reason="SQLite backup path; PostgreSQL covered in Docker smoke"
)


# ----------------------------------------------------------------------------- backup
@backup_test
@sqlite_only
def test_backup_archive_contents_and_verify(tmp_path, users, settings):
    settings.MEDIA_ROOT = tmp_path / "media"
    (settings.MEDIA_ROOT / "evidence").mkdir(parents=True)
    (settings.MEDIA_ROOT / "evidence" / "f1").write_bytes(b"evidence")
    archive = backup.create_backup(tmp_path / "out")
    assert (
        archive.name.startswith("threatledger-backup-") and archive.stat().st_mode & 0o777 == 0o600
    )
    with tarfile.open(archive) as tar:
        assert sorted(tar.getnames()) == ["db.sql", "manifest.json", "media.tar"]
    v = backup.verify_backup(archive, tmp_path / "check")
    assert v.manifest["format"] == backup.FORMAT and v.manifest["engine"] == "sqlite"
    assert v.manifest["counts"]["audit_events"] >= 0
    assert set(v.manifest["files"]) == {"db.sql", "media.tar"}


def _rewrite(
    archive: Path,
    dest: Path,
    replace: dict[str, bytes] | None = None,
    extra: dict[str, bytes] | None = None,
) -> Path:
    with tarfile.open(archive) as src, tarfile.open(dest, "w:gz") as out:
        for m in src.getmembers():
            data = (replace or {}).get(m.name, src.extractfile(m).read())  # type: ignore[union-attr]
            info = tarfile.TarInfo(m.name)
            info.size = len(data)
            out.addfile(info, io.BytesIO(data))
        for name, data in (extra or {}).items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            out.addfile(info, io.BytesIO(data))
    return dest


@backup_test
@sqlite_only
def test_tampered_backup_is_rejected(tmp_path, users):
    archive = backup.create_backup(tmp_path)
    bad = _rewrite(
        archive, tmp_path / "bad.tar.gz", replace={"db.sql": b"DROP TABLE accounts_user;"}
    )
    with pytest.raises(backup.BackupError, match=r"checksum mismatch for db\.sql"):
        backup.verify_backup(bad, tmp_path / "x")


@backup_test
@sqlite_only
def test_unexpected_or_traversal_entries_rejected(tmp_path, users):
    archive = backup.create_backup(tmp_path)
    evil = _rewrite(
        archive, tmp_path / "evil.tar.gz", extra={"../../etc/cron.d/x": b"* * * * * root id"}
    )
    with pytest.raises(backup.BackupError, match="unexpected entry"):
        backup.verify_backup(evil, tmp_path / "y")
    with pytest.raises(backup.BackupError, match="no such file"):
        backup.verify_backup(tmp_path / "missing.tar.gz", tmp_path / "z")
    junk = tmp_path / "junk.tar.gz"
    junk.write_bytes(b"junk")
    with pytest.raises(backup.BackupError, match="not a readable"):
        backup.verify_backup(junk, tmp_path / "w")


@backup_test
@sqlite_only
def test_restore_guards(tmp_path, users):
    archive = backup.create_backup(tmp_path)
    with pytest.raises(backup.BackupError, match="not empty"):
        backup.restore_backup(archive)
    with pytest.raises(backup.BackupError, match="in-memory"):
        backup.restore_backup(archive, force=True)
    manifest_bad = json.dumps(
        {"format": backup.FORMAT, "engine": "postgresql", "files": {}}
    ).encode()
    pg = _rewrite(archive, tmp_path / "pg.tar.gz", replace={"manifest.json": manifest_bad})
    with pytest.raises(backup.BackupError, match="from postgresql"):
        backup.restore_backup(pg, force=True)


@backup_test
@sqlite_only
def test_backup_commands(tmp_path, users):
    out = StringIO()
    call_command("backup", "--output-dir", str(tmp_path), stdout=out)
    archive = next(tmp_path.glob("threatledger-backup-*.tar.gz"))
    assert str(archive) in out.getvalue()
    verified = StringIO()
    call_command("verify_backup", str(archive), stdout=verified)
    assert "all checksums match" in verified.getvalue()
    with pytest.raises(CommandError, match="not empty"):
        call_command("restore", str(archive), stdout=StringIO())


@pytest.mark.django_db
def test_backup_refuses_inside_transaction(tmp_path):
    with pytest.raises(backup.BackupError, match="outside a database transaction"):
        backup.create_backup(tmp_path)


# ----------------------------------------------------------------------------- demo seed
@override_settings(DEBUG=True)
def test_seed_demo_is_complete_and_idempotent(org):
    from threatledger.attack.tests import bundles
    from threatledger.attack.tests.test_importer import _load

    _load(bundles.bundle_v1())  # a few techniques; the rest are reported as missing
    out = StringIO()
    call_command("seed_demo", stdout=out)
    assert Risk.objects.count() == 30
    assert Asset.objects.count() == 60
    assert RiskAcceptance.objects.filter(status="approved").count() == 2
    assert RiskAcceptance.objects.filter(status="pending").count() == 1
    assert Risk.objects.filter(status="accepted").count() == 2
    assert "not loaded" in out.getvalue()
    org.refresh_from_db()
    assert org.name == "Acme Ltd"  # an existing, real organisation is never renamed
    # Phase 8 governance demo
    from threatledger.audits.models import Audit
    from threatledger.audits.services import audit_score
    from threatledger.findings.models import Finding, SecurityException
    from threatledger.policies.models import Policy
    from threatledger.policies.services import policy_state

    iso = Audit.objects.get(framework__code="ISO27001-2022")
    score = audit_score(iso)
    assert score.not_assessed == 0 and score.non_compliant >= 1
    assert Audit.objects.filter(campaign__isnull=False).count() == 2
    assert Finding.objects.count() == 5 and Finding.objects.filter(status="resolved").count() == 1
    assert SecurityException.objects.filter(status="approved").count() == 1
    states = {p.title: policy_state(p).status for p in Policy.objects.all()}
    assert states["Access control standard"] == "review_overdue"
    assert states["Incident response procedure"] == "in_review"
    assert "5 findings" in out.getvalue()
    # Phase 9 work management demo
    from threatledger.controls.models import ControlChangeRequest, Evidence
    from threatledger.work.models import Assignment, Comment, Task

    assert Task.objects.filter(previous__isnull=True).count() == 5
    assert Task.objects.filter(previous__isnull=False).count() == 1  # the done monthly check
    assert Assignment.objects.get(entity__isnull=True).status == "sent"
    assert Comment.objects.count() == 2
    assert Evidence.objects.filter(review_status="pending").count() == 1
    assert ControlChangeRequest.objects.filter(status="pending").count() == 1
    # Phase 10 vendors demo
    from threatledger.vendors.models import Contract, Entity
    from threatledger.vendors.services import postures

    assert Entity.objects.count() == 5 and Contract.objects.count() == 4
    nimbus = postures([Entity.objects.get(name="Nimbus Cloud Services")])[0]
    assert nimbus.score == 75.0 and nimbus.last_assessment.status == "accepted"
    ledger = postures([Entity.objects.get(name="Ledgerline Payments")])[0]
    assert ledger.pending == 1 and "contract notice window" in ledger.flags

    call_command("seed_demo", stdout=StringIO())
    assert Risk.objects.count() == 30
    assert Finding.objects.count() == 5 and Policy.objects.count() == 4
    assert Task.objects.count() == 6 and Comment.objects.count() == 2
    assert ControlChangeRequest.objects.count() == 1
    assert Entity.objects.count() == 5


@override_settings(DEBUG=False)
def test_seed_demo_refuses_production_without_flag():
    with pytest.raises(CommandError, match="allow-production"):
        call_command("seed_demo", stdout=StringIO())


# ----------------------------------------------------------------------------- performance seeding
def test_perf_seeding_and_page_timing(org, users):
    from threatledger.core.perf import ensure_risks, time_pages
    from threatledger.risks.tests.helpers import make_control, technique

    for i in range(30):
        technique(f"T1{i:03d}")
    make_control(org, "CTL-1")
    assert ensure_risks(200) == 200
    assert ensure_risks(200) == 0
    assert Risk.objects.count() == 200
    timings = time_pages(
        ["/risks/", "/risks/heatmap/", "/api/v1/risks/", "/coverage/?scope=risks"],
        username=users[Role.ADMIN].username,
    )
    assert all(t.status == 200 for t in timings), timings
    assert all(t.queries < 40 for t in timings), timings
