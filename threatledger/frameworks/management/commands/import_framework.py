from __future__ import annotations

from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from threatledger.frameworks.importer import FrameworkImportError
from threatledger.frameworks.services import import_framework_bytes


class Command(BaseCommand):
    help = (
        "Import or update a framework from a JSON, YAML or CSV file (see frameworks/importer.py)."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("path")
        parser.add_argument(
            "--dry-run", action="store_true", help="Validate and report; change nothing"
        )
        parser.add_argument("--code", help="Framework code (CSV, or override)")
        parser.add_argument("--name", help="Framework name (CSV, or override)")
        parser.add_argument("--framework-version", dest="fw_version", help="Framework version")
        parser.add_argument("--content-level", choices=["full", "summary", "reference"])

    def handle(self, *args: Any, **opts: Any) -> None:
        path = Path(opts["path"])
        if not path.is_file():
            raise CommandError(f"no such file: {path}")
        meta = {
            "code": opts["code"],
            "name": opts["name"],
            "version": opts["fw_version"],
            "content_level": opts["content_level"],
        }
        try:
            result = import_framework_bytes(
                path.read_bytes(),
                path.name,
                meta={k: v for k, v in meta.items() if v},
                dry_run=opts["dry_run"],
            )
        except FrameworkImportError as exc:
            for err in exc.errors[:50]:
                self.stderr.write(f"  ✗ {err}")
            raise CommandError(f"{len(exc.errors)} validation error(s); nothing imported") from exc
        d = result.as_dict()
        prefix = "DRY RUN: would import" if d["dry_run"] else "Imported"
        self.stdout.write(
            self.style.SUCCESS(
                f"{prefix} {d['framework']}: {d['created']} created, {d['updated']} updated, "
                f"{d['unchanged']} unchanged, {d['missing']} not in file (kept)"
            )
        )
