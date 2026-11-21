"""Register recurring Django-Q2 jobs after migrations (idempotent)."""

from __future__ import annotations

from typing import Any

from django.db import DatabaseError

JOBS = [
    # (name, function, schedule type "D" = daily, "I" = every N minutes)
    ("risk-register-daily", "threatledger.risks.tasks.daily", "D"),
    ("controls-daily", "threatledger.controls.tasks.daily", "D"),
    ("reporting-daily", "threatledger.reporting.tasks.daily", "D"),
    ("work-daily", "threatledger.work.tasks.daily", "D"),
    ("incident-deadlines", "threatledger.incidents.tasks.deadline_alerts", "I"),
]
MINUTES = {"incident-deadlines": 15}


def ensure_schedules(sender: Any = None, **kwargs: Any) -> None:
    try:
        from django_q.models import Schedule
    except ImportError:  # pragma: no cover
        return
    try:
        for name, func, schedule_type in JOBS:
            defaults: dict[str, Any] = {"func": func, "schedule_type": schedule_type, "repeats": -1}
            if name in MINUTES:
                defaults["minutes"] = MINUTES[name]
            Schedule.objects.update_or_create(name=name, defaults=defaults)
    except DatabaseError:  # django_q tables not migrated yet (e.g. partial migrate)
        return
