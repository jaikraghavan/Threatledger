from __future__ import annotations

from typing import Any

from django.urls import reverse

from threatledger.accounts.permissions import can
from threatledger.accounts.roles import Cap


def tabs(user: Any) -> list[tuple[str, str, str]]:
    out = [
        ("mine", "My work", reverse("work:mine")),
        ("approvals", "Approvals", reverse("work:approvals")),
    ]
    if can(user, Cap.VIEW_TASKS):
        out += [
            ("board", "Board", reverse("work:board")),
            ("tasks", "Task list", reverse("work:tasks")),
            ("questionnaires", "Questionnaires", reverse("work:questionnaires")),
        ]
    return out
