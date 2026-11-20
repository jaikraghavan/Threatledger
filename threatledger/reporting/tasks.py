from __future__ import annotations

from .services import snapshot_all_organisations


def daily() -> str:
    """Django-Q2 daily job: record trend snapshots."""
    return f"snapshotted_organisations={snapshot_all_organisations()}"
