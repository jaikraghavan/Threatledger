from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from threatledger.core.fetch import FetchError
from threatledger.frameworks import ctid_source
from threatledger.frameworks.services import FrameworkError, import_ctid


class Command(BaseCommand):
    help = (
        "Import ATT&CK ↔ NIST SP 800-53 r5 mappings from the Center for Threat-Informed "
        "Defense Mappings Explorer (Apache-2.0). Idempotent."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--attack-version",
            default=ctid_source.DEFAULT_ATTACK_VERSION,
            help="ATT&CK version of the CTID mapping set (default %(default)s)",
        )
        parser.add_argument("--file", dest="file_path", help="Offline mapping JSON file")

    def handle(self, *args: Any, **opts: Any) -> None:
        try:
            payload, source = ctid_source.load(opts["attack_version"], opts["file_path"])
            report = import_ctid(payload)
        except (FetchError, FrameworkError) as exc:
            raise CommandError(str(exc)) from exc
        for warning in report.warnings:
            self.stdout.write(self.style.WARNING(warning))
        self.stdout.write(
            self.style.SUCCESS(
                f"CTID mappings from {source}: {report.created} created, "
                f"{report.existing} already present; "
                f"skipped {report.skipped_unknown_technique} unknown technique(s), "
                f"{report.skipped_revoked_technique} revoked technique(s), "
                f"{report.skipped_unknown_control} unknown control(s), "
                f"{report.non_mappable} non-mappable"
            )
        )
