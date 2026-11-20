"""Backup and restore: database + media (evidence) in one checksummed archive.

Archive layout (``threatledger-backup-<UTC timestamp>.tar.gz``, mode 0600)::

    manifest.json   format, version, engine, created_at, sha256 of every file, row counts
    db.dump         PostgreSQL custom-format dump (pg_dump -Fc)   | or db.sql (SQLite, logical dump)
    media.tar       MEDIA_ROOT, including private evidence files (optional)

Restore verifies every checksum first, refuses to overwrite a non-empty database unless
``force`` is given, restores the database, then extracts media with tarfile's ``data``
filter (no absolute paths, traversal, links or device files).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess  # nosec B404 - fixed argv lists, no shell
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.conf import settings
from django.db import connection, connections
from django.utils import timezone

FORMAT = "threatledger-backup/1"


class BackupError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _db() -> dict[str, Any]:
    return settings.DATABASES["default"]


def _engine() -> str:
    return connection.vendor  # "postgresql" | "sqlite"


def _pg_env() -> dict[str, str]:
    """Connection settings via environment, so the password never appears in argv."""
    db = _db()
    env = {**os.environ, "PGDATABASE": str(db["NAME"]), "PGUSER": str(db.get("USER") or "")}
    if db.get("HOST"):
        env["PGHOST"] = str(db["HOST"])
    if db.get("PORT"):
        env["PGPORT"] = str(db["PORT"])
    if db.get("PASSWORD"):
        env["PGPASSWORD"] = str(db["PASSWORD"])
    return env


def _tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise BackupError(
            f"{name} not found; install the PostgreSQL client (the Docker image includes it)"
        )
    return path


def _counts() -> dict[str, int]:
    from threatledger.audit.models import AuditEvent
    from threatledger.controls.models import Control, Evidence
    from threatledger.risks.models import Risk

    return {
        "risks": Risk.objects.count(),
        "controls": Control.objects.count(),
        "evidence": Evidence.objects.count(),
        "audit_events": AuditEvent.objects.count(),
    }


def create_backup(output_dir: Path | None = None) -> Path:
    if connection.in_atomic_block:
        # A consistent snapshot needs its own connection state; SQLite's online backup would
        # retry forever against an open write transaction on the same connection.
        raise BackupError("run backups outside a database transaction")
    output_dir = Path(output_dir or settings.BACKUP_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = timezone.now().strftime("%Y%m%dT%H%M%SZ")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        files: list[Path] = []
        if _engine() == "postgresql":
            dump = work / "db.dump"
            subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
                [
                    _tool("pg_dump"),
                    "--format=custom",
                    "--no-owner",
                    "--no-privileges",
                    f"--file={dump}",
                ],
                env=_pg_env(),
                check=True,
                capture_output=True,
            )
            files.append(dump)
        elif _engine() == "sqlite":
            # Logical dump: lock-free and portable (local development only).
            dump = work / "db.sql"
            connection.ensure_connection()
            with dump.open("w", encoding="utf-8") as f:
                for line in connection.connection.iterdump():
                    f.write(f"{line}\n")
            files.append(dump)
        else:  # pragma: no cover
            raise BackupError(f"unsupported database engine {_engine()}")
        media_root = Path(settings.MEDIA_ROOT)
        if media_root.is_dir() and any(media_root.iterdir()):
            media = work / "media.tar"
            with tarfile.open(media, "w") as tar:
                tar.add(media_root, arcname="media")
            files.append(media)
        manifest = {
            "format": FORMAT,
            "version": settings.THREATLEDGER_VERSION,
            "engine": _engine(),
            "created_at": timezone.now().isoformat(),
            "files": {f.name: _sha256(f) for f in files},
            "counts": _counts(),
        }
        (work / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        archive = output_dir / f"threatledger-backup-{stamp}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for part in [work / "manifest.json", *files]:
                tar.add(part, arcname=part.name)
    os.chmod(archive, 0o600)
    return archive


@dataclass
class Verified:
    manifest: dict[str, Any]
    directory: Path


def _extract_archive(archive: Path, into: Path) -> None:
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            if (
                member.name not in ("manifest.json", "db.dump", "db.sql", "media.tar")
                or not member.isfile()
            ):
                raise BackupError(f"unexpected entry in archive: {member.name!r}")
        tar.extractall(into, filter="data")


def verify_backup(archive: Path, into: Path) -> Verified:
    if not archive.is_file():
        raise BackupError(f"no such file: {archive}")
    try:
        _extract_archive(archive, into)
        manifest = json.loads((into / "manifest.json").read_text(encoding="utf-8"))
    except (tarfile.TarError, OSError, json.JSONDecodeError) as exc:
        raise BackupError(f"not a readable ThreatLedger backup: {exc}") from exc
    if manifest.get("format") != FORMAT:
        raise BackupError("unknown backup format")
    for name, digest in manifest.get("files", {}).items():
        path = into / name
        if not path.is_file() or _sha256(path) != digest:
            raise BackupError(
                f"checksum mismatch for {name}: the archive is corrupt or was modified"
            )
    return Verified(manifest, into)


def database_has_data() -> bool:
    from threatledger.accounts.models import User
    from threatledger.audit.models import AuditEvent

    try:
        return User.objects.exists() or AuditEvent.objects.exists()
    except Exception:  # tables not created yet
        return False


def restore_backup(archive: Path, *, force: bool = False) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        v = verify_backup(Path(archive), Path(tmp))
        if v.manifest["engine"] != _engine():
            raise BackupError(
                f"backup is from {v.manifest['engine']}, this database is {_engine()}"
            )
        if database_has_data() and not force:
            raise BackupError("the database is not empty; re-run with --force to overwrite it")
        if _engine() == "postgresql":
            connections.close_all()
            subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
                [_tool("pg_restore"), "--clean", "--if-exists", "--no-owner", "--no-privileges",
                 "--single-transaction", f"--dbname={_db()['NAME']}", str(v.directory / "db.dump")],
                env=_pg_env(), check=True, capture_output=True,
            )  # fmt: skip
        else:
            name = str(_db()["NAME"])
            if name == ":memory:" or "mode=memory" in name:
                raise BackupError("cannot restore into an in-memory SQLite database")
            connections.close_all()
            rebuilt = Path(tmp) / "rebuilt.sqlite3"
            src = sqlite3.connect(rebuilt)
            try:
                src.executescript((v.directory / "db.sql").read_text(encoding="utf-8"))
                dest = sqlite3.connect(name)
                try:
                    src.backup(dest)
                finally:
                    dest.close()
            finally:
                src.close()
        media_tar = v.directory / "media.tar"
        if media_tar.is_file():
            media_root = Path(settings.MEDIA_ROOT)
            media_root.mkdir(parents=True, exist_ok=True)
            with tarfile.open(media_tar) as tar:
                members = [
                    m for m in tar.getmembers() if m.name == "media" or m.name.startswith("media/")
                ]
                tmp_media = Path(tmp) / "media-extract"
                tar.extractall(tmp_media, members=members, filter="data")
            shutil.copytree(tmp_media / "media", media_root, dirs_exist_ok=True)
        return v.manifest
