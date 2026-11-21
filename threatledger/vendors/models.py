"""Third-party risk management: vendors (entities), the services they provide and contracts.

Assessment scores, contract state and posture are derived on read; only inputs are stored.
DORA register-of-information fields are captured here and exported by ``dora.py``.
"""

from __future__ import annotations

from datetime import date, timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from threatledger.core.models import TimeStampedModel
from threatledger.org.models import BusinessUnit, Organisation
from threatledger.risks.models import Asset, Risk


class Tier(models.TextChoices):
    CRITICAL = "critical", "Tier 1 · Critical"
    HIGH = "high", "Tier 2 · High"
    MEDIUM = "medium", "Tier 3 · Medium"
    LOW = "low", "Tier 4 · Low"


TIER_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
# Reassessment interval by tier (months).
REASSESS_MONTHS = {"critical": 12, "high": 12, "medium": 24, "low": 36}


class EntityStatus(models.TextChoices):
    PROSPECTIVE = "prospective", "Prospective (due diligence)"
    ACTIVE = "active", "Active"
    OFFBOARDING = "offboarding", "Offboarding"
    TERMINATED = "terminated", "Terminated"


class DataAccess(models.TextChoices):
    NONE = "none", "No access to our data"
    INTERNAL = "internal", "Internal data"
    CONFIDENTIAL = "confidential", "Confidential data"
    PERSONAL = "personal", "Personal data"
    SENSITIVE = "sensitive", "Sensitive / special-category personal data"


class Substitutability(models.TextChoices):
    EASY = "easy", "Easily substitutable"
    MEDIUM = "medium", "Substitutable with effort"
    HARD = "hard", "Highly complex to substitute"
    NOT = "not", "Not substitutable"


class Entity(TimeStampedModel):
    """A third party: supplier, ICT service provider, processor, partner."""

    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    ref = models.CharField(max_length=16, editable=False)
    name = models.CharField(max_length=200)
    legal_name = models.CharField(max_length=300, blank=True)
    lei = models.CharField(
        "LEI", max_length=20, blank=True, help_text="Legal Entity Identifier (ISO 17442), for DORA."
    )
    country = models.CharField(
        max_length=2, blank=True, help_text="ISO 3166-1 alpha-2 country of headquarters, e.g. IE."
    )
    website = models.URLField(max_length=500, blank=True)
    description = models.TextField(blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="owned_vendors",
        help_text="Relationship owner inside the organisation.",
    )
    business_unit = models.ForeignKey(
        BusinessUnit, null=True, blank=True, on_delete=models.PROTECT, related_name="vendors"
    )
    tier = models.CharField(max_length=16, choices=Tier.choices, default=Tier.MEDIUM)
    status = models.CharField(
        max_length=16, choices=EntityStatus.choices, default=EntityStatus.ACTIVE, db_index=True
    )
    data_access = models.CharField(
        max_length=16, choices=DataAccess.choices, default=DataAccess.NONE
    )
    ict_provider = models.BooleanField(
        "ICT third-party service provider", default=False, help_text="In scope of DORA RoI."
    )
    substitutability = models.CharField(
        max_length=8, choices=Substitutability.choices, default=Substitutability.MEDIUM
    )
    exit_plan = models.BooleanField(default=False, help_text="A tested exit strategy exists.")
    security_contact = models.EmailField(blank=True)
    external_rating = models.CharField(
        max_length=50, blank=True, help_text="Score from an external rating service, if any."
    )
    external_rating_source = models.CharField(max_length=100, blank=True)
    external_rating_date = models.DateField(null=True, blank=True)
    risks = models.ManyToManyField(Risk, blank=True, related_name="vendors")

    class Meta:
        ordering = ["name"]
        verbose_name_plural = "entities"
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_entity_ref"),
        ]

    def __str__(self) -> str:
        return self.name


class Solution(models.Model):
    """A service or product an entity provides (DORA: ICT service)."""

    entity = models.ForeignKey(Entity, on_delete=models.CASCADE, related_name="solutions")
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    ict_service_type = models.CharField(
        max_length=100, blank=True, help_text="e.g. Cloud IaaS, SaaS, Managed security service."
    )
    supported_function = models.CharField(
        max_length=200, blank=True, help_text="Business function it supports, e.g. Payments."
    )
    function_is_critical = models.BooleanField(
        "supports a critical or important function", default=False
    )
    data_locations = models.CharField(
        max_length=200,
        blank=True,
        help_text="Countries where data is stored/processed, e.g. IE, DE.",
    )
    assets = models.ManyToManyField(Asset, blank=True, related_name="vendor_solutions")

    class Meta:
        ordering = ["entity", "name"]

    def __str__(self) -> str:
        return f"{self.entity.name} · {self.name}"


class Contract(TimeStampedModel):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    ref = models.CharField(max_length=16, editable=False)
    entity = models.ForeignKey(Entity, on_delete=models.PROTECT, related_name="contracts")
    title = models.CharField(max_length=200)
    reference = models.CharField(max_length=100, blank=True, help_text="Contract number.")
    solutions = models.ManyToManyField(Solution, blank=True, related_name="contracts")
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    notice_days = models.PositiveIntegerField(default=90)
    auto_renew = models.BooleanField(default=False)
    annual_value = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True)
    currency = models.CharField(max_length=3, blank=True, default="EUR")
    governing_law = models.CharField(max_length=2, blank=True, help_text="ISO country code.")
    security_clauses = models.BooleanField(default=False)
    audit_rights = models.BooleanField(default=False)
    breach_notification_hours = models.PositiveIntegerField(null=True, blank=True)
    data_processing_agreement = models.BooleanField(default=False)
    exit_assistance = models.BooleanField(default=False)
    subcontracting_allowed = models.BooleanField(default=False)
    document_url = models.URLField(max_length=1000, blank=True)
    terminated_on = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ["end_date", "ref"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_contract_ref"),
            models.CheckConstraint(
                condition=models.Q(end_date__isnull=True)
                | models.Q(end_date__gte=models.F("start_date")),
                name="contract_end_after_start",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.title}"

    @property
    def notice_deadline(self) -> date | None:
        """Last day to give notice before the term ends (or auto-renews)."""
        if self.end_date is None:
            return None
        return self.end_date - timedelta(days=self.notice_days)

    @property
    def state(self) -> str:
        """active | notice_due | expired | terminated (derived)."""
        today = timezone.localdate()
        if self.terminated_on and self.terminated_on <= today:
            return "terminated"
        if self.end_date and self.end_date < today and not self.auto_renew:
            return "expired"
        deadline = self.notice_deadline
        if deadline and deadline - timedelta(days=60) <= today <= (self.end_date or today):
            return "notice_due"
        return "active"

    @property
    def state_label(self) -> str:
        return {
            "active": "Active",
            "notice_due": "Notice window",
            "expired": "Expired",
            "terminated": "Terminated",
        }[self.state]
