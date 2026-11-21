"""Compliance audits (assessments) and campaigns.

Hybrid model (PLAN.md §12, Q14): the live requirement status stays *derived* from controls
(``frameworks.compliance``) and is never stored. An audit records an auditor's *judgement* per
requirement at a point in time. When the auditor records a judgement, the derived status shown
to them is kept alongside it (``derived_at_judgement``) as part of the audit evidence; the live
derived status is compared on every read to highlight divergences.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models
from django.utils import timezone

from threatledger.controls.models import Evidence
from threatledger.core.models import TimeStampedModel
from threatledger.frameworks.models import Framework, Requirement
from threatledger.org.models import BusinessUnit, Organisation


class AuditStatus(models.TextChoices):
    PLANNED = "planned", "Planned"
    IN_PROGRESS = "in_progress", "In progress"
    IN_REVIEW = "in_review", "In review"
    CLOSED = "closed", "Closed"


class Recurrence(models.TextChoices):
    NONE = "none", "One-off"
    QUARTERLY = "quarterly", "Quarterly"
    SEMIANNUAL = "semiannual", "Every 6 months"
    ANNUAL = "annual", "Annual"


RECURRENCE_MONTHS = {"quarterly": 3, "semiannual": 6, "annual": 12}


class Judgement(models.TextChoices):
    NOT_ASSESSED = "not_assessed", "Not assessed"
    COMPLIANT = "compliant", "Compliant"
    PARTIAL = "partial", "Partially compliant"
    NON_COMPLIANT = "non_compliant", "Non-compliant"
    NOT_APPLICABLE = "not_applicable", "Not applicable"


class Campaign(TimeStampedModel):
    """A set of audits of one framework across several perimeters, optionally recurring."""

    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    ref = models.CharField(max_length=16, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    framework = models.ForeignKey(Framework, on_delete=models.PROTECT, related_name="campaigns")
    starts_on = models.DateField(default=timezone.localdate)
    due_on = models.DateField()
    recurrence = models.CharField(
        max_length=16, choices=Recurrence.choices, default=Recurrence.NONE
    )
    previous = models.OneToOneField(
        "self", null=True, blank=True, on_delete=models.PROTECT, related_name="next_cycle"
    )

    class Meta:
        ordering = ["-starts_on", "-id"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_campaign_ref"),
            models.CheckConstraint(
                condition=models.Q(due_on__gte=models.F("starts_on")),
                name="campaign_due_after_start",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.name}"


class Audit(TimeStampedModel):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    ref = models.CharField(max_length=16, editable=False)
    name = models.CharField(max_length=200)
    framework = models.ForeignKey(Framework, on_delete=models.PROTECT, related_name="audits")
    business_unit = models.ForeignKey(
        BusinessUnit,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="audits",
        help_text="Perimeter. Leave empty for the whole organisation.",
    )
    campaign = models.ForeignKey(
        Campaign, null=True, blank=True, on_delete=models.PROTECT, related_name="audits"
    )
    baseline = models.CharField(
        max_length=32, blank=True, help_text="Limit to a framework baseline (e.g. moderate)."
    )
    scope_note = models.TextField("scope and objectives", blank=True)
    lead_auditor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="led_audits",
    )
    due_on = models.DateField(null=True, blank=True)
    status = models.CharField(
        max_length=16, choices=AuditStatus.choices, default=AuditStatus.PLANNED, db_index=True
    )
    conclusion = models.TextField(blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    closed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )

    class Meta:
        ordering = ["-created_at", "-id"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_audit_ref"),
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.name}"

    @property
    def is_closed(self) -> bool:
        return self.status == AuditStatus.CLOSED

    @property
    def overdue(self) -> bool:
        return not self.is_closed and self.due_on is not None and self.due_on < timezone.localdate()


class AuditResult(models.Model):
    """The auditor's judgement on one requirement within one audit."""

    audit = models.ForeignKey(Audit, on_delete=models.CASCADE, related_name="results")
    requirement = models.ForeignKey(Requirement, on_delete=models.PROTECT, related_name="+")
    judgement = models.CharField(
        max_length=16, choices=Judgement.choices, default=Judgement.NOT_ASSESSED
    )
    maturity = models.PositiveSmallIntegerField(
        null=True, blank=True, help_text="0 (none) – 5 (optimised)"
    )
    observation = models.TextField(blank=True)
    derived_at_judgement = models.CharField(max_length=16, blank=True, editable=False)
    evidence = models.ManyToManyField(Evidence, blank=True, related_name="audit_results")
    assessed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    assessed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["requirement__order", "requirement_id"]
        constraints = [
            models.UniqueConstraint(fields=["audit", "requirement"], name="uniq_audit_result"),
            models.CheckConstraint(
                condition=models.Q(maturity__isnull=True) | models.Q(maturity__lte=5),
                name="audit_result_maturity_0_5",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.audit.ref} · {self.requirement.ref}: {self.get_judgement_display()}"
