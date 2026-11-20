"""Security controls and their mappings to ATT&CK.

Phase 3 introduces the model so risks can link to controls and get suggestions; the control
library UI, starter set, evidence and testing records arrive in Phase 4.
"""

from __future__ import annotations

import uuid
from datetime import date, timedelta
from typing import Any

from django.conf import settings
from django.core.files.storage import Storage
from django.db import models
from django.utils import timezone

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
    test_frequency_days = models.PositiveSmallIntegerField(
        default=365, help_text="How often the control must be tested (days)."
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

    @property
    def next_test_due(self) -> date | None:
        if self.last_tested_at is None:
            return None
        return self.last_tested_at + timedelta(days=self.test_frequency_days)

    @property
    def test_overdue(self) -> bool:
        """Never tested, or last test older than the testing frequency."""
        due = self.next_test_due
        return due is None or due < timezone.localdate()


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


# ----------------------------------------------------------------------------- testing
class ControlTest(models.Model):
    class Method(models.TextChoices):
        INQUIRY = "inquiry", "Inquiry (interview)"
        OBSERVATION = "observation", "Observation"
        INSPECTION = "inspection", "Inspection (documents / config)"
        REPERFORMANCE = "reperformance", "Re-performance"
        AUTOMATED = "automated", "Automated / continuous"

    control = models.ForeignKey(Control, on_delete=models.CASCADE, related_name="tests")
    tested_on = models.DateField()
    tester = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+")
    method = models.CharField(max_length=16, choices=Method.choices, default=Method.INSPECTION)
    result = models.CharField(max_length=16, choices=TestResult.choices)
    notes = models.TextField(blank=True)
    evidence: models.ManyToManyField[Evidence, Any] = models.ManyToManyField(
        "Evidence", blank=True, related_name="tests"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-tested_on", "-id"]

    def __str__(self) -> str:
        return f"{self.control.ref} test {self.tested_on} ({self.get_result_display()})"


# ----------------------------------------------------------------------------- evidence
def evidence_path(instance: Evidence, filename: str) -> str:
    """Random, extension-less storage name: user-supplied names never touch the filesystem."""
    return f"{instance.control.organisation_id}/{uuid.uuid4().hex}"


def evidence_storage() -> Storage:
    from django.core.files.storage import storages

    return storages["evidence"]


class Evidence(models.Model):
    class Kind(models.TextChoices):
        FILE = "file", "File"
        LINK = "link", "Link"

    control = models.ForeignKey(Control, on_delete=models.CASCADE, related_name="evidence")
    kind = models.CharField(max_length=8, choices=Kind.choices)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    file = models.FileField(
        upload_to=evidence_path, storage=evidence_storage, blank=True, max_length=200
    )
    url = models.URLField(max_length=1000, blank=True)
    original_filename = models.CharField(max_length=255, blank=True)
    content_type = models.CharField(max_length=100, blank=True)
    size = models.PositiveBigIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+"
    )
    uploaded_at = models.DateTimeField(default=timezone.now)
    valid_until = models.DateField(null=True, blank=True, help_text="Evidence expiry date")
    expiry_notice_stage = models.PositiveSmallIntegerField(default=0, editable=False)
    archived_at = models.DateTimeField(null=True, blank=True)

    AUDIT_EXCLUDE = ("file", "expiry_notice_stage")

    class Meta:
        ordering = ["-uploaded_at"]
        verbose_name_plural = "evidence"
        constraints = [
            models.CheckConstraint(
                condition=(models.Q(kind="file") & ~models.Q(file=""))
                | (models.Q(kind="link") & ~models.Q(url="")),
                name="evidence_file_or_link",
            )
        ]

    def __str__(self) -> str:
        return self.title

    @property
    def is_expired(self) -> bool:
        return self.valid_until is not None and self.valid_until < timezone.localdate()

    def expires_within(self, days: int) -> bool:
        if self.valid_until is None or self.is_expired:
            return False
        return (self.valid_until - timezone.localdate()).days <= days
