from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from threatledger.reporting.services import snapshot_all_organisations


class Command(BaseCommand):
    help = "Record today's compliance, coverage and risk snapshots (idempotent; runs daily)."

    def handle(self, *args: Any, **opts: Any) -> None:
        n = snapshot_all_organisations()
        self.stdout.write(self.style.SUCCESS(f"Snapshots recorded for {n} organisation(s)."))
