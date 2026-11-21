from __future__ import annotations

from .digest import send_digests


def daily() -> str:
    """Django-Q2 daily job: email digests (tasks, findings, questionnaires, approvals)."""
    return f"digests={send_digests()}"
