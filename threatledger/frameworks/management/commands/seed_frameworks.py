from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from threatledger.frameworks.services import seed_frameworks
from threatledger.org.models import Organisation


class Command(BaseCommand):
    help = (
        "Load the seeded frameworks (NIST 800-53 r5, ISO 27001:2022 Annex A, SOC 2 TSC, HIPAA "
        "Security Rule, CIS v8, India DPDP 2023), the indicative crosswalk and the indicative "
        "starter-control mappings. Idempotent."
    )

    def handle(self, *args: Any, **opts: Any) -> None:
        org = Organisation.objects.current()
        report = seed_frameworks(org)
        for fw in report.frameworks:
            self.stdout.write(
                f"  {fw['framework']:<16} +{fw['created']} created, {fw['updated']} updated, "
                f"{fw['unchanged']} unchanged"
            )
        self.stdout.write(f"Crosswalk links created: {report.crosswalk_created}")
        self.stdout.write(
            f"Starter control → requirement mappings created: {report.control_mappings_created}"
        )
        self.stdout.write(
            self.style.WARNING(
                "Seeded content and mappings are INDICATIVE: verify against official text."
            )
        )
        self.stdout.write(self.style.SUCCESS("Frameworks loaded."))
