from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from threatledger.audit.models import AuditEvent
from threatledger.audit.services import verify_chain


class Command(BaseCommand):
    help = "Verify the audit log hash chain. Exits non-zero if tampering is detected."

    def handle(self, *args: Any, **options: Any) -> None:
        events = AuditEvent.objects.order_by("id").iterator(chunk_size=2000)
        problems = verify_chain(events)
        total = AuditEvent.objects.count()
        if problems:
            for p in problems[:50]:
                self.stderr.write(f"event {p.event_id}: {p.reason}")
            raise CommandError(f"Audit chain INVALID: {len(problems)} problem(s) in {total} events")
        self.stdout.write(self.style.SUCCESS(f"Audit chain OK ({total} events)"))
