from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError, CommandParser

from threatledger.core.demo import seed_demo
from threatledger.org.models import Organisation


class Command(BaseCommand):
    help = (
        "Load demo data for a fictional mid-size company (Halcyon Freight Group): users, business "
        "units, 60 assets, 30 risks, control statuses, evidence, tests, acceptances, frameworks. "
        "Import ATT&CK first for technique links. Idempotent."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--allow-production", action="store_true")

    def handle(self, *args: Any, **opts: Any) -> None:
        if not settings.DEBUG and not opts["allow_production"]:
            raise CommandError(
                "DEBUG is off. Re-run with --allow-production if you really mean it."
            )
        call_command("seed", allow_production=True, stdout=self.stdout)
        org = Organisation.objects.current()
        if org is None:  # pragma: no cover - seed always creates one
            raise CommandError("No organisation.")
        r = seed_demo(org)
        self.stdout.write(
            f"Demo: +{r.assets} assets, +{r.risks} risks ({r.technique_links} technique links), "
            f"{r.acceptances} acceptances, {r.evidence} evidence items, {r.tests} control tests, "
            f"{r.audits} audits, {r.findings} findings, {r.exceptions} exceptions, "
            f"{r.policies} policies, {r.tasks} tasks, {r.questionnaires} questionnaires."
        )
        if r.missing_techniques:
            self.stdout.write(
                self.style.WARNING(
                    f"{len(r.missing_techniques)} ATT&CK technique(s) not loaded: "
                    "run import_attack, then seed_demo again "
                    "(existing risks are kept; links are added only for new risks)."
                )
            )
        self.stdout.write(self.style.SUCCESS("Demo data loaded."))
