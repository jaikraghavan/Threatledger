"""ATT&CK import orchestration: used by the management command and the background task."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from django.db import transaction
from django.utils import timezone

from threatledger.audit.models import Action
from threatledger.audit.services import record

from .importer.loader import load_bundle, summarise
from .importer.parser import BundleError, ParsedBundle, parse_bundle
from .importer.source import SourceError, download, read_file
from .models import AttackRelease, ImportRun, version_tuple

logger = logging.getLogger(__name__)


class ImportRefusedError(ValueError):
    """The import was refused by a safety rule (e.g. downgrade, version mismatch)."""


def current_release(domain: str = "enterprise-attack") -> AttackRelease | None:
    """The newest release imported for ``domain`` (by version, not by import time)."""
    releases = list(AttackRelease.objects.filter(domain=domain))
    return max(releases, key=lambda r: r.version_tuple, default=None)


def create_run(*, version: str = "", file_path: str | None = None, user: Any = None) -> ImportRun:
    return ImportRun.objects.create(
        requested_version=version or "",
        source=f"file:{Path(file_path).name}" if file_path else "download",
        requested_by=user if getattr(user, "is_authenticated", False) else None,
    )


def _check_version(parsed: ParsedBundle, run: ImportRun, allow_downgrade: bool) -> None:
    if run.requested_version and parsed.version != run.requested_version:
        raise ImportRefusedError(
            f"bundle is ATT&CK v{parsed.version}, but v{run.requested_version} was requested"
        )
    current = current_release(parsed.domain)
    if (
        current is not None
        and version_tuple(parsed.version) < current.version_tuple
        and not allow_downgrade
    ):
        raise ImportRefusedError(
            f"refusing to import v{parsed.version} over newer v{current.version} "
            "(use --allow-downgrade to override)"
        )


def execute(
    run: ImportRun,
    *,
    file_path: str | None = None,
    expected_sha256: str | None = None,
    allow_downgrade: bool = False,
) -> ImportRun:
    """Run an import end to end and record the outcome on ``run`` and in the audit log.

    Expected failures (bad source, bad bundle, refused) mark the run FAILED and return;
    unexpected errors do the same and are logged with a traceback.
    """
    run.status = ImportRun.Status.RUNNING
    run.started_at = timezone.now()
    run.save(update_fields=["status", "started_at"])
    actor = run.requested_by
    try:
        fetched = (
            read_file(file_path, expected_sha256)
            if file_path
            else download(run.domain, run.requested_version or None, expected_sha256)
        )
        try:
            raw = json.loads(fetched.data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BundleError(f"not valid JSON: {exc}") from exc
        parsed = parse_bundle(raw, run.domain)
        del raw
        _check_version(parsed, run, allow_downgrade)

        with transaction.atomic():  # release row and data commit together, or not at all
            release, _ = AttackRelease.objects.update_or_create(
                domain=parsed.domain,
                version=parsed.version,
                defaults={
                    "attack_spec_version": parsed.spec_version,
                    "sha256": fetched.sha256,
                    "source": fetched.source[:500],
                    "imported_at": timezone.now(),
                    "imported_by": actor,
                },
            )
            stats = load_bundle(parsed, release)
            totals = summarise(stats)
            release.counts = totals
            release.save(update_fields=["counts"])
    except (SourceError, BundleError, ImportRefusedError) as exc:
        return _fail(run, str(exc))
    except Exception as exc:
        logger.exception("ATT&CK import %s failed unexpectedly", run.pk)
        return _fail(run, f"unexpected error: {type(exc).__name__}")

    run.status = ImportRun.Status.SUCCEEDED
    run.release = release
    run.source = fetched.source[:500]
    run.finished_at = timezone.now()
    run.stats = stats
    run.message = (
        f"Imported ATT&CK v{release.version}: {totals['created']} created, "
        f"{totals['updated']} updated, {totals['flagged']} newly revoked/deprecated, "
        f"{totals['skipped']} skipped; links +{totals['links_created']} "
        f"-{totals['links_deleted']}."
    )
    run.save(update_fields=["status", "release", "source", "finished_at", "stats", "message"])
    record(
        Action.IMPORT,
        release,
        actor=actor,
        changes={
            "version": [None, release.version],
            "sha256": [None, release.sha256],
            **{k: [None, v] for k, v in totals.items()},
        },
    )
    logger.info("ATT&CK import %s succeeded: %s", run.pk, run.message)
    return run


def _fail(run: ImportRun, message: str) -> ImportRun:
    run.status = ImportRun.Status.FAILED
    run.finished_at = timezone.now()
    run.message = message[:2000]
    run.save(update_fields=["status", "finished_at", "message"])
    record(
        Action.IMPORT,
        run,
        actor=run.requested_by,
        object_type="attack.importrun",
        changes={"status": [None, "failed"], "error": [None, run.message[:300]]},
    )
    logger.warning("ATT&CK import %s failed: %s", run.pk, run.message)
    return run


def enqueue(run: ImportRun) -> None:
    """Hand the run to the Django-Q2 worker."""
    from django_q.tasks import async_task

    async_task("threatledger.attack.tasks.run_import", run.pk, task_name=f"attack-import-{run.pk}")
