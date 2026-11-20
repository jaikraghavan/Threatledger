from __future__ import annotations

from . import services


def daily() -> str:
    """Django-Q2 daily job: lapse expired acceptances, then send review reminders."""
    expired = services.expire_acceptances()
    reminded = services.send_review_reminders()
    return f"expired={expired} reminder_emails={reminded}"
