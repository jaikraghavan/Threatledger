"""Security incidents with a timeline, links to the threat model, and regulatory clocks."""

from __future__ import annotations

from django.conf import settings
from django.db import models
from django.utils import timezone

from threatledger.attack.models import Technique
from threatledger.controls.models import Control
from threatledger.core.models import TimeStampedModel
from threatledger.org.models import BusinessUnit, Organisation
from threatledger.risks.models import Asset, Risk
from threatledger.vendors.models import Entity


class Severity(models.TextChoices):
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


class IncidentStatus(models.TextChoices):
    REPORTED = "reported", "Reported"
    TRIAGE = "triage", "Triage"
    CONTAINED = "contained", "Contained"
    ERADICATED = "eradicated", "Eradicated"
    RECOVERED = "recovered", "Recovered"
    CLOSED = "closed", "Closed"
    FALSE_POSITIVE = "false_positive", "Not an incident"


OPEN_STATUSES = ("reported", "triage", "contained", "eradicated", "recovered")


class Incident(TimeStampedModel):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    ref = models.CharField(max_length=16, editable=False)
    title = models.CharField(max_length=200)
    description = models.TextField()
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MEDIUM)
    status = models.CharField(
        max_length=16,
        choices=IncidentStatus.choices,
        default=IncidentStatus.REPORTED,
        db_index=True,
    )
    occurred_at = models.DateTimeField(
        null=True, blank=True, help_text="When it started, if known."
    )
    aware_at = models.DateTimeField(
        default=timezone.now,
        help_text="When the organisation became aware: regulatory clocks start here.",
    )
    business_unit = models.ForeignKey(
        BusinessUnit, null=True, blank=True, on_delete=models.PROTECT, related_name="incidents"
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="managed_incidents",
        help_text="Incident manager.",
    )
    personal_data_breach = models.BooleanField(default=False)
    data_subjects_affected = models.PositiveIntegerField(null=True, blank=True)
    regimes = models.JSONField(
        default=list, blank=True, help_text="Applicable notification regimes."
    )
    assets = models.ManyToManyField(Asset, blank=True, related_name="incidents")
    techniques = models.ManyToManyField(Technique, blank=True, related_name="incidents")
    risks = models.ManyToManyField(Risk, blank=True, related_name="incidents")
    controls = models.ManyToManyField(
        Control, blank=True, related_name="incidents", help_text="Controls that failed or helped."
    )
    vendors = models.ManyToManyField(Entity, blank=True, related_name="incidents")
    root_cause = models.TextField(blank=True)
    lessons_learned = models.TextField(blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-aware_at", "-id"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_incident_ref"),
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.title}"

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_STATUSES


class EntryKind(models.TextChoices):
    NOTE = "note", "Note"
    ACTION = "action", "Action taken"
    EVIDENCE = "evidence", "Evidence"
    STATUS = "status", "Status change"
    NOTIFICATION = "notification", "Regulatory notification"


class TimelineEntry(models.Model):
    """Append-only incident log."""

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="timeline")
    at = models.DateTimeField(default=timezone.now)
    kind = models.CharField(max_length=16, choices=EntryKind.choices, default=EntryKind.NOTE)
    text = models.TextField()
    url = models.URLField(max_length=1000, blank=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["at", "id"]

    def __str__(self) -> str:
        return f"{self.incident.ref} {self.at:%Y-%m-%d %H:%M} {self.kind}"


class Notification(models.Model):
    """A regulatory notification step that was submitted, or recorded as not required."""

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="filings")
    regime = models.CharField(max_length=16)
    step = models.CharField(max_length=32)
    submitted_at = models.DateTimeField(null=True, blank=True)
    not_required = models.BooleanField(default=False)
    reference = models.CharField(max_length=200, blank=True, help_text="Authority's case number.")
    note = models.TextField(blank=True)
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+"
    )
    recorded_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["incident", "regime", "step"], name="uniq_incident_filing"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.incident.ref} {self.regime}/{self.step}"


class DeadlineAlert(models.Model):
    """Dedupe for deadline alerts (one per step and stage)."""

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="+")
    regime = models.CharField(max_length=16)
    step = models.CharField(max_length=32)
    stage = models.CharField(max_length=8)  # "soon" | "overdue"
    sent_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["incident", "regime", "step", "stage"], name="uniq_deadline_alert"
            ),
        ]

    def __str__(self) -> str:
        return f"{self.incident_id} {self.regime}/{self.step} {self.stage}"
