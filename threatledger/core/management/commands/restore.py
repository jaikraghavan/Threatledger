from __future__ import annotations

from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from threatledger.audit.models import Action
from threatledger.audit.services import record
from threatledger.core.backup import BackupError, restore_backup


class Command(BaseCommand):
    help = (
        "Restore a backup archive (verifies checksums first). Overwrites the database with --force."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("archive")
        parser.add_argument("--force", action="store_true", help="Overwrite a non-empty database")

    def handle(self, *args: Any, **opts: Any) -> None:
        try:
            manifest = restore_backup(Path(opts["archive"]), force=opts["force"])
        except BackupError as exc:
            raise CommandError(str(exc)) from exc
        except Exception as exc:
            raise CommandError(f"Restore failed: {type(exc).__name__}: {exc}") from exc
        from django.db import connections

        connections.close_all()
        record(
            Action.SYSTEM,
            object_type="core.backup",
            object_repr=Path(opts["archive"]).name,
            changes={
                "restored": [None, Path(opts["archive"]).name],
                "backup_created_at": [None, manifest["created_at"]],
            },
        )
        counts = ", ".join(f"{k} {v}" for k, v in manifest.get("counts", {}).items())
        self.stdout.write(
            self.style.SUCCESS(
                f"Restored backup from {manifest['created_at']} ({counts}). "
                "Run audit_verify to check the audit chain."
            )
        )
