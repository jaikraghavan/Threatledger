from __future__ import annotations

from .services import send_deadline_alerts


def deadline_alerts() -> str:
    """Django-Q2 job every 15 minutes: regulatory notification deadline alerts."""
    return f"alerts={send_deadline_alerts()}"
