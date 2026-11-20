from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from threatledger.core.backup import BackupError, verify_backup


class Command(BaseCommand):
    help = "Check a backup archive's structure and checksums without restoring it."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("archive")

    def handle(self, *args: Any, **opts: Any) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                v = verify_backup(Path(opts["archive"]), Path(tmp))
            except BackupError as exc:
                raise CommandError(str(exc)) from exc
        self.stdout.write(
            json.dumps(
                {k: v.manifest[k] for k in ("created_at", "engine", "version", "counts")}, indent=2
            )
        )
        self.stdout.write(self.style.SUCCESS("Backup OK: all checksums match."))
