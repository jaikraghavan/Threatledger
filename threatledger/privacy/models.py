"""Records of processing (GDPR Art. 30, India DPDP Act 2023) and data protection impact
assessments (GDPR Art. 35). Whether a DPIA is needed is derived from the processing's risk
indicators, never stored."""

from __future__ import annotations

from django.conf import settings
from django.db import models

from threatledger.controls.models import Control
from threatledger.core.models import TimeStampedModel
from threatledger.org.models import BusinessUnit, Organisation
from threatledger.risks.models import Asset, Risk
from threatledger.vendors.models import Entity


class Role(models.TextChoices):
    CONTROLLER = "controller", "Controller (data fiduciary)"
    JOINT = "joint", "Joint controller"
    PROCESSOR = "processor", "Processor"


class LegalBasis(models.TextChoices):
    CONSENT = "consent", "Consent"
    CONTRACT = "contract", "Performance of a contract"
    LEGAL_OBLIGATION = "legal_obligation", "Legal obligation"
    VITAL_INTERESTS = "vital_interests", "Vital interests"
    PUBLIC_TASK = "public_task", "Public task"
    LEGITIMATE_INTERESTS = "legitimate_interests", "Legitimate interests"
    LEGITIMATE_USE = "legitimate_use", "DPDP legitimate use (s. 7)"


DATA_CATEGORIES = [
    ("identity", "Identity (name, ID numbers)"),
    ("contact", "Contact details"),
    ("financial", "Financial / payment"),
    ("employment", "Employment / HR"),
    ("location", "Location"),
    ("online", "Online identifiers / device data"),
    ("communications", "Communications content"),
    ("health", "Health (special category)"),
    ("biometric", "Biometric (special category)"),
    ("criminal", "Criminal offences"),
    ("other_special", "Other special category"),
]
SPECIAL = {"health", "biometric", "criminal", "other_special"}
DATA_SUBJECTS = [
    ("customers", "Customers"),
    ("prospects", "Prospects"),
    ("employees", "Employees"),
    ("candidates", "Job applicants"),
    ("contractors", "Contractors"),
    ("suppliers", "Supplier contacts"),
    ("children", "Children"),
    ("public", "Members of the public"),
]


class TransferSafeguard(models.TextChoices):
    NONE = "", "No international transfer"
    ADEQUACY = "adequacy", "Adequacy decision / permitted country"
    SCC = "scc", "Standard contractual clauses"
    BCR = "bcr", "Binding corporate rules"
    DEROGATION = "derogation", "Derogation (Art. 49)"
    UNKNOWN = "unknown", "Transfer without documented safeguard"


class ProcessingStatus(models.TextChoices):
    DRAFT = "draft", "Draft"
    ACTIVE = "active", "Active"
    RETIRED = "retired", "Retired"


class Processing(TimeStampedModel):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    ref = models.CharField(max_length=16, editable=False)
    name = models.CharField(max_length=200)
    purpose = models.TextField()
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.CONTROLLER)
    legal_basis = models.CharField(
        max_length=24, choices=LegalBasis.choices, default=LegalBasis.CONTRACT
    )
    legal_basis_note = models.CharField(max_length=500, blank=True)
    status = models.CharField(
        max_length=16, choices=ProcessingStatus.choices, default=ProcessingStatus.ACTIVE
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="owned_processing",
    )
    business_unit = models.ForeignKey(
        BusinessUnit, null=True, blank=True, on_delete=models.PROTECT, related_name="processing"
    )
    data_categories = models.JSONField(default=list, blank=True)
    data_subjects = models.JSONField(default=list, blank=True)
    recipients = models.TextField(blank=True, help_text="Internal and external recipients.")
    processors = models.ManyToManyField(Entity, blank=True, related_name="processing")
    assets = models.ManyToManyField(Asset, blank=True, related_name="processing")
    controls = models.ManyToManyField(Control, blank=True, related_name="processing")
    transfer_countries = models.CharField(
        max_length=200,
        blank=True,
        help_text="Countries outside the home jurisdiction, e.g. US, IN.",
    )
    transfer_safeguard = models.CharField(
        max_length=16, choices=TransferSafeguard.choices, default=TransferSafeguard.NONE, blank=True
    )
    retention = models.CharField(max_length=300, help_text="e.g. 6 years after contract end.")
    security_measures = models.TextField(blank=True)
    # DPIA screening (GDPR Art. 35(3), EDPB criteria)
    large_scale = models.BooleanField(default=False)
    systematic_monitoring = models.BooleanField(default=False)
    automated_decisions = models.BooleanField(
        "automated decisions with legal or similar effect", default=False
    )
    new_technology = models.BooleanField("innovative technology (e.g. AI)", default=False)

    class Meta:
        ordering = ["ref"]
        verbose_name_plural = "processing activities"
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_processing_ref"),
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.name}"

    @property
    def special_category(self) -> bool:
        return bool(SPECIAL & set(self.data_categories or []))

    @property
    def dpia_triggers(self) -> list[str]:
        """EDPB-style screening: two or more criteria → DPIA expected (derived)."""
        out = []
        if self.special_category:
            out.append("special-category data")
        if "children" in (self.data_subjects or []):
            out.append("children's data")
        if self.large_scale:
            out.append("large scale")
        if self.systematic_monitoring:
            out.append("systematic monitoring")
        if self.automated_decisions:
            out.append("automated decisions")
        if self.new_technology:
            out.append("innovative technology")
        if self.transfer_safeguard == TransferSafeguard.UNKNOWN:
            out.append("unsafeguarded transfer")
        return out

    @property
    def dpia_required(self) -> bool:
        triggers = self.dpia_triggers
        return len(triggers) >= 2 or self.automated_decisions

    def category_labels(self) -> list[str]:
        names = dict(DATA_CATEGORIES)
        return [names.get(c, c) for c in self.data_categories or []]

    def subject_labels(self) -> list[str]:
        names = dict(DATA_SUBJECTS)
        return [names.get(c, c) for c in self.data_subjects or []]


class DpiaStatus(models.TextChoices):
    DRAFT = "draft", "Draft"
    IN_REVIEW = "in_review", "In review"
    APPROVED = "approved", "Approved"
    REJECTED = "rejected", "Rejected (rework)"


class ResidualRisk(models.TextChoices):
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High (prior consultation, Art. 36)"


class Dpia(TimeStampedModel):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    ref = models.CharField(max_length=16, editable=False)
    processing = models.ForeignKey(Processing, on_delete=models.PROTECT, related_name="dpias")
    description = models.TextField(help_text="Systematic description of the processing.")
    necessity = models.TextField(help_text="Necessity and proportionality.")
    risks_to_individuals = models.TextField()
    measures = models.TextField(help_text="Measures to address the risks.")
    residual_risk = models.CharField(
        max_length=8, choices=ResidualRisk.choices, default=ResidualRisk.MEDIUM
    )
    dpo_advice = models.TextField("DPO advice", blank=True)
    risks = models.ManyToManyField(Risk, blank=True, related_name="dpias")
    status = models.CharField(max_length=16, choices=DpiaStatus.choices, default=DpiaStatus.DRAFT)
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    decision_note = models.CharField(max_length=500, blank=True)
    review_due = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "DPIA"
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_dpia_ref"),
        ]

    def __str__(self) -> str:
        return f"{self.ref} DPIA for {self.processing.name}"
