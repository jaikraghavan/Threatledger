from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import F
from django.utils import timezone

from threatledger.attack.models import Technique
from threatledger.controls.models import Control
from threatledger.core.models import TimeStampedModel
from threatledger.org.models import BusinessUnit, Organisation


# ----------------------------------------------------------------------------- risk matrix
class Band(models.TextChoices):
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


DEFAULT_LIKELIHOOD = ["Rare", "Unlikely", "Possible", "Likely", "Almost certain"]
DEFAULT_IMPACT = ["Minimal", "Minor", "Moderate", "Major", "Severe"]


def _default_likelihood() -> list[str]:
    return list(DEFAULT_LIKELIHOOD)


def _default_impact() -> list[str]:
    return list(DEFAULT_IMPACT)


class RiskMatrix(models.Model):
    """Per-organisation scoring configuration. Score = likelihood × impact."""

    organisation = models.OneToOneField(
        Organisation, on_delete=models.CASCADE, related_name="risk_matrix"
    )
    size = models.PositiveSmallIntegerField(default=5)
    likelihood_labels = models.JSONField(default=_default_likelihood)
    impact_labels = models.JSONField(default=_default_impact)
    # Band upper bounds (inclusive); anything above high_max is Critical.
    low_max = models.PositiveSmallIntegerField(default=4)
    medium_max = models.PositiveSmallIntegerField(default=9)
    high_max = models.PositiveSmallIntegerField(default=15)
    updated_at = models.DateTimeField(auto_now=True)

    MIN_SIZE, MAX_SIZE = 3, 10

    def __str__(self) -> str:
        return f"{self.size}×{self.size} matrix for {self.organisation}"

    @classmethod
    def for_org(cls, organisation: Organisation) -> RiskMatrix:
        matrix, _ = cls.objects.get_or_create(organisation=organisation)
        return matrix

    def clean(self) -> None:
        errors: dict[str, str] = {}
        if not (self.MIN_SIZE <= self.size <= self.MAX_SIZE):
            errors["size"] = f"Size must be between {self.MIN_SIZE} and {self.MAX_SIZE}."
        for field in ("likelihood_labels", "impact_labels"):
            labels = getattr(self, field)
            if (
                not isinstance(labels, list)
                or len(labels) != self.size
                or not all(isinstance(x, str) and x.strip() for x in labels)
            ):
                errors[field] = f"Provide exactly {self.size} non-empty labels."
        top = self.size * self.size
        if not (1 <= self.low_max < self.medium_max < self.high_max < top):
            errors["high_max"] = (
                f"Thresholds must satisfy 1 ≤ low < medium < high < {top} (the maximum score)."
            )
        if errors:
            raise ValidationError(errors)

    def band(self, score: int) -> Band:
        if score <= self.low_max:
            return Band.LOW
        if score <= self.medium_max:
            return Band.MEDIUM
        if score <= self.high_max:
            return Band.HIGH
        return Band.CRITICAL

    def band_range(self, band: Band | str) -> tuple[int, int]:
        top = self.size * self.size
        return {
            Band.LOW: (1, self.low_max),
            Band.MEDIUM: (self.low_max + 1, self.medium_max),
            Band.HIGH: (self.medium_max + 1, self.high_max),
            Band.CRITICAL: (self.high_max + 1, top),
        }[Band(band)]

    def likelihood_label(self, value: int) -> str:
        return self._label(self.likelihood_labels, value)

    def impact_label(self, value: int) -> str:
        return self._label(self.impact_labels, value)

    @staticmethod
    def _label(labels: list[str], value: int) -> str:
        return labels[value - 1] if 1 <= value <= len(labels) else str(value)

    @property
    def scale(self) -> range:
        return range(1, self.size + 1)


@dataclass(frozen=True)
class Score:
    likelihood: int
    impact: int

    @property
    def value(self) -> int:
        return self.likelihood * self.impact


# ----------------------------------------------------------------------------- assets
class Asset(TimeStampedModel):
    class Kind(models.TextChoices):
        APPLICATION = "application", "Application"
        SERVER = "server", "Server"
        ENDPOINT = "endpoint", "Endpoint"
        NETWORK = "network", "Network"
        DATA_STORE = "data_store", "Data store"
        CLOUD_SERVICE = "cloud_service", "Cloud service"
        SAAS = "saas", "SaaS"
        PEOPLE = "people", "People"
        FACILITY = "facility", "Facility"
        OTHER = "other", "Other"

    class Classification(models.TextChoices):
        PUBLIC = "public", "Public"
        INTERNAL = "internal", "Internal"
        CONFIDENTIAL = "confidential", "Confidential"
        RESTRICTED = "restricted", "Restricted"

    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="assets")
    business_unit = models.ForeignKey(
        BusinessUnit, null=True, blank=True, on_delete=models.PROTECT, related_name="assets"
    )
    name = models.CharField(max_length=200)
    kind = models.CharField("type", max_length=20, choices=Kind.choices, default=Kind.APPLICATION)
    description = models.TextField(blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="owned_assets",
    )
    criticality = models.PositiveSmallIntegerField(default=3, help_text="1 (low) – 5 (critical)")
    data_classification = models.CharField(
        max_length=16, choices=Classification.choices, default=Classification.INTERNAL
    )
    contains_personal_data = models.BooleanField(
        default=False, help_text="Holds personal data (relevant for GDPR / DPDP Act)."
    )
    archived_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "name"], name="uniq_asset_name"),
            models.CheckConstraint(
                condition=models.Q(criticality__gte=1, criticality__lte=5),
                name="asset_criticality_1_5",
            ),
        ]

    def __str__(self) -> str:
        return self.name


# ----------------------------------------------------------------------------- risks
class Category(models.TextChoices):
    CYBER = "cyber", "Cyber security"
    DATA_PRIVACY = "data_privacy", "Data protection & privacy"
    OPERATIONAL = "operational", "Operational resilience"
    THIRD_PARTY = "third_party", "Third party / supply chain"
    COMPLIANCE = "compliance", "Legal & compliance"
    FRAUD = "fraud", "Fraud"
    PEOPLE = "people", "People & insider"
    PHYSICAL = "physical", "Physical"
    STRATEGIC = "strategic", "Strategic"


class Treatment(models.TextChoices):
    MITIGATE = "mitigate", "Mitigate"
    ACCEPT = "accept", "Accept"
    TRANSFER = "transfer", "Transfer"
    AVOID = "avoid", "Avoid"


class RiskStatus(models.TextChoices):
    DRAFT = "draft", "Draft"
    OPEN = "open", "Open"
    IN_TREATMENT = "in_treatment", "In treatment"
    ACCEPTED = "accepted", "Accepted"
    CLOSED = "closed", "Closed"


class RiskQuerySet(models.QuerySet["Risk"]):
    def live(self) -> RiskQuerySet:
        return self.filter(archived_at__isnull=True)

    def with_scores(self) -> RiskQuerySet:
        return self.annotate(
            inherent_score=F("inherent_likelihood") * F("inherent_impact"),
            residual_score=F("residual_likelihood") * F("residual_impact"),
        )

    def review_overdue(self) -> RiskQuerySet:
        return self.filter(next_review_date__lt=timezone.localdate()).exclude(
            status=RiskStatus.CLOSED
        )


SCORE_FIELDS = ("inherent_likelihood", "inherent_impact", "residual_likelihood", "residual_impact")


class Risk(TimeStampedModel):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="risks")
    business_unit = models.ForeignKey(
        BusinessUnit, null=True, blank=True, on_delete=models.PROTECT, related_name="risks"
    )
    ref = models.CharField(max_length=16, editable=False)
    title = models.CharField(max_length=200)
    scenario = models.TextField(
        help_text="Threat → vulnerability → impact: what could happen, how, and what it would cost."
    )
    category = models.CharField(max_length=20, choices=Category.choices, default=Category.CYBER)
    assets = models.ManyToManyField(Asset, blank=True, related_name="risks")
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="owned_risks",
    )
    inherent_likelihood = models.PositiveSmallIntegerField(default=3)
    inherent_impact = models.PositiveSmallIntegerField(default=3)
    residual_likelihood = models.PositiveSmallIntegerField(default=3)
    residual_impact = models.PositiveSmallIntegerField(default=3)
    treatment = models.CharField(
        max_length=16, choices=Treatment.choices, default=Treatment.MITIGATE
    )
    status = models.CharField(
        max_length=16, choices=RiskStatus.choices, default=RiskStatus.OPEN, db_index=True
    )
    target_date = models.DateField(null=True, blank=True, help_text="Treatment due by")
    next_review_date = models.DateField(null=True, blank=True, db_index=True)
    last_reminder_on = models.DateField(null=True, blank=True, editable=False)
    archived_at = models.DateTimeField(null=True, blank=True)

    techniques = models.ManyToManyField(
        Technique, through="RiskTechnique", blank=True, related_name="risks"
    )
    controls = models.ManyToManyField(
        Control, through="RiskControl", blank=True, related_name="risks"
    )

    objects = RiskQuerySet.as_manager()

    class Meta:
        ordering = ["ref"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_risk_ref"),
            *[
                models.CheckConstraint(
                    condition=models.Q(**{f"{f}__gte": 1, f"{f}__lte": 10}), name=f"risk_{f}_range"
                )
                for f in SCORE_FIELDS
            ],
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.title}"

    @property
    def inherent(self) -> Score:
        return Score(self.inherent_likelihood, self.inherent_impact)

    @property
    def residual(self) -> Score:
        return Score(self.residual_likelihood, self.residual_impact)

    @property
    def review_overdue(self) -> bool:
        return bool(
            self.next_review_date
            and self.next_review_date < timezone.localdate()
            and self.status != RiskStatus.CLOSED
        )

    def scores(self) -> dict[str, Any]:
        return {f: getattr(self, f) for f in SCORE_FIELDS}


class RiskScoreHistory(models.Model):
    """Append-only trail of score changes (also captured in the audit log)."""

    risk = models.ForeignKey(Risk, on_delete=models.CASCADE, related_name="score_history")
    inherent_likelihood = models.PositiveSmallIntegerField()
    inherent_impact = models.PositiveSmallIntegerField()
    residual_likelihood = models.PositiveSmallIntegerField()
    residual_impact = models.PositiveSmallIntegerField()
    reason = models.CharField(max_length=500, blank=True)
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    changed_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-changed_at", "-id"]
        verbose_name_plural = "risk score history"

    def __str__(self) -> str:
        return f"{self.risk.ref} @ {self.changed_at:%Y-%m-%d}"

    @property
    def inherent_score(self) -> int:
        return self.inherent_likelihood * self.inherent_impact

    @property
    def residual_score(self) -> int:
        return self.residual_likelihood * self.residual_impact


class RiskTechnique(models.Model):
    """User-owned risk → ATT&CK mapping. PROTECT keeps it safe across ATT&CK re-imports."""

    risk = models.ForeignKey(Risk, on_delete=models.CASCADE, related_name="technique_links")
    technique = models.ForeignKey(Technique, on_delete=models.PROTECT, related_name="risk_links")
    rationale = models.CharField(max_length=500, blank=True)
    added_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["technique__attack_id"]
        constraints = [
            models.UniqueConstraint(fields=["risk", "technique"], name="uniq_risk_technique")
        ]

    def __str__(self) -> str:
        return f"{self.risk.ref} ↔ {self.technique.attack_id}"


class RiskControl(models.Model):
    risk = models.ForeignKey(Risk, on_delete=models.CASCADE, related_name="control_links")
    control = models.ForeignKey(Control, on_delete=models.PROTECT, related_name="risk_links")
    note = models.CharField(max_length=500, blank=True)
    added_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["control__ref"]
        constraints = [
            models.UniqueConstraint(fields=["risk", "control"], name="uniq_risk_control")
        ]

    def __str__(self) -> str:
        return f"{self.risk.ref} ↔ {self.control.ref}"


class RiskAcceptance(models.Model):
    """Formal acceptance (exception) of a risk, with segregation of duties and expiry."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending approval"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"
        EXPIRED = "expired", "Expired"
        WITHDRAWN = "withdrawn", "Withdrawn"

    risk = models.ForeignKey(Risk, on_delete=models.CASCADE, related_name="acceptances")
    justification = models.TextField()
    expires_on = models.DateField()
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+"
    )
    requested_at = models.DateTimeField(default=timezone.now)
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["-requested_at"]

    def __str__(self) -> str:
        return f"Acceptance of {self.risk.ref} ({self.get_status_display()})"

    @property
    def is_active(self) -> bool:
        return self.status == self.Status.APPROVED and self.expires_on >= timezone.localdate()
