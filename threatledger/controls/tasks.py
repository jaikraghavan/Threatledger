from __future__ import annotations

from . import services


def daily() -> str:
    """Django-Q2 daily job: evidence expiry alerts."""
    return f"evidence_alert_emails={services.send_evidence_expiry_alerts()}"
