from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from threatledger.controls.services import seed_starter_controls
from threatledger.org.models import Organisation


class Command(BaseCommand):
    help = (
        "Load the starter control library (14 controls with indicative ATT&CK mappings). "
        "Idempotent: existing controls are left untouched. Import ATT&CK first."
    )

    def handle(self, *args: Any, **opts: Any) -> None:
        org = Organisation.objects.current()
        if org is None:
            raise CommandError("No organisation exists yet. Run `manage.py seed` first.")
        result = seed_starter_controls(org)
        self.stdout.write(f"Created {len(result.created)}: {', '.join(result.created) or '—'}")
        if result.skipped:
            self.stdout.write(f"Already present: {', '.join(result.skipped)}")
        if result.missing_attack_ids:
            self.stdout.write(
                self.style.WARNING(
                    "ATT&CK IDs not found (import ATT&CK, then map manually): "
                    + ", ".join(sorted(set(result.missing_attack_ids)))
                )
            )
        self.stdout.write(self.style.SUCCESS("Starter controls loaded."))
