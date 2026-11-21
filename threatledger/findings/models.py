"""Findings (gaps that need remediation) and exceptions (time-boxed, approved waivers).

Neither changes derived compliance or coverage (PLAN.md §4): a finding is a work item, and an
approved exception is shown next to the requirement or control it waives, never folded into
the derived status.
"""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from threatledger.audits.models import Audit
from threatledger.controls.models import Control
from threatledger.core.models import TimeStampedModel
from threatledger.frameworks.models import Requirement
from threatledger.org.models import BusinessUnit, Organisation
from threatledger.risks.models import Risk


class Severity(models.TextChoices):
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


# Default remediation window by severity (days).
DEFAULT_DUE_DAYS = {"critical": 30, "high": 60, "medium": 90, "low": 180}


class FindingStatus(models.TextChoices):
    OPEN = "open", "Open"
    IN_PROGRESS = "in_progress", "In progress"
    RESOLVED = "resolved", "Resolved (awaiting verification)"
    CLOSED = "closed", "Closed"


class Finding(TimeStampedModel):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    ref = models.CharField(max_length=16, editable=False)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MEDIUM)
    status = models.CharField(
        max_length=16, choices=FindingStatus.choices, default=FindingStatus.OPEN, db_index=True
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="owned_findings",
        help_text="Responsible for remediation.",
    )
    due_on = models.DateField(null=True, blank=True)
    business_unit = models.ForeignKey(
        BusinessUnit, null=True, blank=True, on_delete=models.PROTECT, related_name="findings"
    )
    audit = models.ForeignKey(
        Audit, null=True, blank=True, on_delete=models.PROTECT, related_name="findings"
    )
    requirement = models.ForeignKey(
        Requirement, null=True, blank=True, on_delete=models.PROTECT, related_name="findings"
    )
    control = models.ForeignKey(
        Control, null=True, blank=True, on_delete=models.PROTECT, related_name="findings"
    )
    risk = models.ForeignKey(
        Risk, null=True, blank=True, on_delete=models.PROTECT, related_name="findings"
    )
    remediation = models.TextField("remediation plan / progress", blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    closed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )

    class Meta:
        ordering = ["-created_at", "-id"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_finding_ref"),
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.title}"

    @property
    def is_open(self) -> bool:
        return self.status != FindingStatus.CLOSED

    @property
    def overdue(self) -> bool:
        return (
            self.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)
            and self.due_on is not None
            and self.due_on < timezone.localdate()
        )


class ExceptionStatus(models.TextChoices):
    REQUESTED = "requested", "Requested"
    APPROVED = "approved", "Approved"
    REJECTED = "rejected", "Rejected"
    REVOKED = "revoked", "Revoked"


MAX_EXCEPTION_DAYS = 366


class SecurityException(TimeStampedModel):
    """A formally approved, time-boxed deviation from a requirement or control."""

    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    ref = models.CharField(max_length=16, editable=False)
    title = models.CharField(max_length=200)
    justification = models.TextField(help_text="Why the requirement cannot be met now.")
    compensating_measures = models.TextField(blank=True)
    business_unit = models.ForeignKey(
        BusinessUnit, null=True, blank=True, on_delete=models.PROTECT, related_name="exceptions"
    )
    requirements = models.ManyToManyField(Requirement, blank=True, related_name="exceptions")
    controls = models.ManyToManyField(Control, blank=True, related_name="exceptions")
    risk = models.ForeignKey(
        Risk, null=True, blank=True, on_delete=models.PROTECT, related_name="exceptions"
    )
    finding = models.ForeignKey(
        Finding, null=True, blank=True, on_delete=models.PROTECT, related_name="exceptions"
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="owned_exceptions",
    )
    expires_on = models.DateField()
    status = models.CharField(
        max_length=16,
        choices=ExceptionStatus.choices,
        default=ExceptionStatus.REQUESTED,
        db_index=True,
    )
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_exception_ref"),
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.title}"

    @property
    def effective_status(self) -> str:
        """Approved exceptions past their expiry date read as *expired* (derived, not stored)."""
        if self.status == ExceptionStatus.APPROVED and self.expires_on < timezone.localdate():
            return "expired"
        return self.status

    @property
    def effective_status_label(self) -> str:
        status = self.effective_status
        return "Expired" if status == "expired" else ExceptionStatus(status).label

    @property
    def is_active(self) -> bool:
        return self.effective_status == ExceptionStatus.APPROVED

    @property
    def expires_soon(self) -> bool:
        return self.is_active and self.expires_on <= timezone.localdate() + timedelta(days=30)
