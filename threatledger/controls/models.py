"""Security controls and their mappings to ATT&CK.

Phase 3 introduces the model so risks can link to controls and get suggestions; the control
library UI, starter set, evidence and testing records arrive in Phase 4.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models

from threatledger.attack.models import Mitigation, Technique
from threatledger.core.models import TimeStampedModel
from threatledger.org.models import Organisation


class ControlType(models.TextChoices):
    PREVENTIVE = "preventive", "Preventive"
    DETECTIVE = "detective", "Detective"
    CORRECTIVE = "corrective", "Corrective"


class ControlStatus(models.TextChoices):
    IMPLEMENTED = "implemented", "Implemented"
    PARTIAL = "partial", "Partially implemented"
    PLANNED = "planned", "Planned"
    NOT_IMPLEMENTED = "not_implemented", "Not implemented"


class TestResult(models.TextChoices):
    PASS = "pass", "Pass"
    PARTIAL = "partial", "Partial"
    FAIL = "fail", "Fail"
    NOT_TESTED = "not_tested", "Not tested"


class ControlQuerySet(models.QuerySet["Control"]):
    def live(self) -> ControlQuerySet:
        return self.filter(archived_at__isnull=True)


class Control(TimeStampedModel):
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name="controls"
    )
    ref = models.CharField(max_length=32)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="owned_controls",
    )
    control_type = models.CharField(
        "type", max_length=16, choices=ControlType.choices, default=ControlType.PREVENTIVE
    )
    status = models.CharField(
        max_length=20, choices=ControlStatus.choices, default=ControlStatus.PLANNED, db_index=True
    )
    effectiveness = models.PositiveSmallIntegerField(
        null=True, blank=True, help_text="1 (weak) – 5 (strong)"
    )
    last_tested_at = models.DateField(null=True, blank=True)
    last_test_result = models.CharField(
        max_length=16, choices=TestResult.choices, default=TestResult.NOT_TESTED
    )
    archived_at = models.DateTimeField(null=True, blank=True)

    techniques = models.ManyToManyField(
        Technique, through="ControlTechnique", blank=True, related_name="controls"
    )
    mitigations = models.ManyToManyField(
        Mitigation, through="ControlMitigation", blank=True, related_name="controls"
    )

    objects = ControlQuerySet.as_manager()

    class Meta:
        ordering = ["ref"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_control_ref"),
            models.CheckConstraint(
                condition=models.Q(effectiveness__isnull=True)
                | models.Q(effectiveness__gte=1, effectiveness__lte=5),
                name="control_effectiveness_1_5",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.name}"


class MappingSource(models.TextChoices):
    MANUAL = "manual", "Manual"
    SEED = "seed", "Seeded (indicative)"
    IMPORT = "import", "Imported"


class ControlTechnique(models.Model):
    """User-owned mapping. PROTECT: a technique with mappings can never be deleted."""

    control = models.ForeignKey(Control, on_delete=models.CASCADE, related_name="technique_links")
    technique = models.ForeignKey(Technique, on_delete=models.PROTECT, related_name="control_links")
    source = models.CharField(max_length=16, choices=MappingSource.choices, default="manual")
    note = models.CharField(max_length=500, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["control", "technique"], name="uniq_control_technique")
        ]

    def __str__(self) -> str:
        return f"{self.control.ref} → {self.technique.attack_id}"


class ControlMitigation(models.Model):
    """The control implements this ATT&CK mitigation (M-id)."""

    control = models.ForeignKey(Control, on_delete=models.CASCADE, related_name="mitigation_links")
    mitigation = models.ForeignKey(
        Mitigation, on_delete=models.PROTECT, related_name="control_links"
    )
    source = models.CharField(max_length=16, choices=MappingSource.choices, default="manual")

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["control", "mitigation"], name="uniq_control_mitigation"
            )
        ]

    def __str__(self) -> str:
        return f"{self.control.ref} implements {self.mitigation.attack_id}"
