from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from threatledger.attack.importer.source import DOMAINS
from threatledger.attack.models import ImportRun
from threatledger.attack.services import create_run, enqueue, execute


class Command(BaseCommand):
    help = (
        "Import MITRE ATT&CK from the official STIX 2.1 bundle (github.com/mitre-attack/"
        "attack-stix-data), or from a local file with --file. Safe to re-run."
    )

    def create_parser(self, prog_name: str, subcommand: str, **kwargs: Any) -> CommandParser:
        # Our --version (ATT&CK release) replaces Django's built-in --version flag.
        kwargs.setdefault("conflict_handler", "resolve")
        return super().create_parser(prog_name, subcommand, **kwargs)

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--version",
            dest="attack_version",
            default="",
            help="ATT&CK version, e.g. 20.1 (default: latest)",
        )
        parser.add_argument("--file", dest="file_path", help="Import an offline bundle file")
        parser.add_argument("--domain", default="enterprise-attack", choices=sorted(DOMAINS))
        parser.add_argument("--sha256", help="Expected SHA-256 of the bundle")
        parser.add_argument(
            "--allow-downgrade",
            action="store_true",
            help="Allow importing an older version than the newest imported",
        )
        parser.add_argument(
            "--async",
            dest="run_async",
            action="store_true",
            help="Queue on the background worker instead of running now",
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        if opts["run_async"] and (opts["file_path"] or opts["sha256"] or opts["allow_downgrade"]):
            raise CommandError("--async supports --version only")
        run = create_run(version=opts["attack_version"], file_path=opts["file_path"])
        run.domain = opts["domain"]
        run.save(update_fields=["domain"])
        if opts["run_async"]:
            enqueue(run)
            self.stdout.write(f"Queued import run #{run.pk}")
            return
        self.stdout.write("Importing ATT&CK… (the full Enterprise bundle takes a minute or two)")
        execute(
            run,
            file_path=opts["file_path"],
            expected_sha256=opts["sha256"],
            allow_downgrade=opts["allow_downgrade"],
        )
        if run.status != ImportRun.Status.SUCCEEDED:
            raise CommandError(f"Import failed: {run.message}")
        self.stdout.write(self.style.SUCCESS(run.message))
