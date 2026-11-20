from __future__ import annotations

from .models import ImportRun
from .services import execute


def run_import(run_id: int) -> str:
    """Django-Q2 entry point for UI-triggered imports."""
    run = ImportRun.objects.get(pk=run_id)
    if run.status != ImportRun.Status.QUEUED:
        return f"run {run_id} already {run.status}"
    return execute(run).status
