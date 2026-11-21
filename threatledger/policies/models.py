"""Policies, standards and procedures, with versioned approval and periodic review.

A policy's published version, status and next review date are derived from its versions
(never stored on the policy).
"""

from __future__ import annotations

from django.conf import settings
from django.db import models
from django.utils import timezone

from threatledger.controls.models import Control
from threatledger.core.models import TimeStampedModel
from threatledger.frameworks.models import Requirement
from threatledger.org.models import Organisation


class PolicyKind(models.TextChoices):
    POLICY = "policy", "Policy"
    STANDARD = "standard", "Standard"
    PROCEDURE = "procedure", "Procedure"
    GUIDELINE = "guideline", "Guideline"


class VersionStatus(models.TextChoices):
    DRAFT = "draft", "Draft"
    IN_REVIEW = "in_review", "In review"
    APPROVED = "approved", "Approved"
    REJECTED = "rejected", "Rejected"
    SUPERSEDED = "superseded", "Superseded"


class Policy(TimeStampedModel):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    ref = models.CharField(max_length=16, editable=False)
    title = models.CharField(max_length=200)
    kind = models.CharField(max_length=16, choices=PolicyKind.choices, default=PolicyKind.POLICY)
    summary = models.TextField(blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="owned_policies",
    )
    review_interval_months = models.PositiveSmallIntegerField(
        default=12, help_text="How often the policy must be reviewed."
    )
    controls = models.ManyToManyField(Control, blank=True, related_name="policies")
    requirements = models.ManyToManyField(Requirement, blank=True, related_name="policies")
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["ref"]
        verbose_name_plural = "policies"
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_policy_ref"),
            models.CheckConstraint(
                condition=models.Q(review_interval_months__gte=1, review_interval_months__lte=60),
                name="policy_review_interval_1_60",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.title}"


class PolicyVersion(models.Model):
    policy = models.ForeignKey(Policy, on_delete=models.CASCADE, related_name="versions")
    number = models.PositiveIntegerField()
    body = models.TextField(help_text="Policy text. Plain text; blank lines separate paragraphs.")
    document_url = models.URLField(
        max_length=1000, blank=True, help_text="Optional link to the formatted document."
    )
    change_summary = models.CharField(max_length=500, blank=True)
    status = models.CharField(
        max_length=16, choices=VersionStatus.choices, default=VersionStatus.DRAFT, db_index=True
    )
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+")
    created_at = models.DateTimeField(default=timezone.now)
    submitted_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.CharField(max_length=500, blank=True)
    effective_on = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ["-number"]
        constraints = [
            models.UniqueConstraint(fields=["policy", "number"], name="uniq_policy_version"),
        ]

    def __str__(self) -> str:
        return f"{self.policy.ref} v{self.number} ({self.get_status_display()})"

    @property
    def label(self) -> str:
        return f"v{self.number}"
