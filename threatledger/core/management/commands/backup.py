from __future__ import annotations

from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from threatledger.audit.models import Action
from threatledger.audit.services import record
from threatledger.core.backup import BackupError, create_backup


class Command(BaseCommand):
    help = "Create a checksummed backup archive (database + media/evidence) in BACKUP_DIR."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--output-dir", help="Directory for the archive (default: BACKUP_DIR)")

    def handle(self, *args: Any, **opts: Any) -> None:
        try:
            archive = create_backup(Path(opts["output_dir"]) if opts["output_dir"] else None)
        except (BackupError, OSError) as exc:
            raise CommandError(f"Backup failed: {exc}") from exc
        except Exception as exc:  # pg_dump errors (CalledProcessError) etc.
            raise CommandError(f"Backup failed: {type(exc).__name__}") from exc
        record(
            Action.SYSTEM,
            object_type="core.backup",
            object_repr=archive.name,
            changes={"backup": [None, archive.name]},
        )
        self.stdout.write(self.style.SUCCESS(f"Backup written: {archive}"))
