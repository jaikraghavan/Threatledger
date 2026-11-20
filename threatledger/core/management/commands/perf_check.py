from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from threatledger.core.perf import run


class Command(BaseCommand):
    help = (
        "Performance check: top the register up to --risks synthetic risks, then time key pages "
        "and API endpoints. Fails if any page is slower than --max-ms. Use on a test instance."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--risks", type=int, default=1000)
        parser.add_argument("--max-ms", type=float, default=1500.0)

    def handle(self, *args: Any, **opts: Any) -> None:
        added, timings, stats = run(opts["risks"])
        self.stdout.write(f"Added {added} synthetic risks. Dataset: {stats}")
        self.stdout.write(f"{'status':>6} {'ms':>8} {'queries':>7}  url")
        slow = []
        for t in timings:
            self.stdout.write(f"{t.status:>6} {t.ms:>8.1f} {t.queries:>7}  {t.url}")
            if t.status != 200 or t.ms > opts["max_ms"]:
                slow.append(t)
        if slow:
            raise CommandError(
                f"{len(slow)} page(s) failed or exceeded {opts['max_ms']} ms: "
                + ", ".join(t.url for t in slow)
            )
        self.stdout.write(
            self.style.SUCCESS(f"All {len(timings)} pages under {opts['max_ms']:.0f} ms.")
        )
