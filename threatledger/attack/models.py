"""MITRE ATT&CK knowledge base, imported from the official STIX 2.1 bundles.

Rows are keyed by STIX id and are **never deleted** by the importer: objects that MITRE
revokes or deprecates are flagged, so user mappings (risk↔technique, control↔technique, …)
that point at them keep working and can be re-pointed to the replacement.

The relationship tables in this module (``*Technique``, ``GroupSoftware``, …) are owned by
the importer and re-synchronised on every import. User-authored mappings live in other apps
and are never touched by an import.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models


class Domain(models.TextChoices):
    ENTERPRISE = "enterprise-attack", "Enterprise"


class AttackRelease(models.Model):
    domain = models.CharField(max_length=32, choices=Domain.choices, default=Domain.ENTERPRISE)
    version = models.CharField(max_length=16)
    attack_spec_version = models.CharField(max_length=16, blank=True)
    sha256 = models.CharField(max_length=64)
    source = models.CharField(max_length=500)
    imported_at = models.DateTimeField()
    imported_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    counts = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-imported_at"]
        constraints = [
            models.UniqueConstraint(fields=["domain", "version"], name="uniq_attack_release")
        ]

    def __str__(self) -> str:
        return f"ATT&CK {self.get_domain_display()} v{self.version}"

    @property
    def version_tuple(self) -> tuple[int, ...]:
        return version_tuple(self.version)


def version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split(".") if p.isdigit())


class ActiveQuerySet(models.QuerySet):
    def active(self):
        return self.filter(is_revoked=False, is_deprecated=False)


class AttackObject(models.Model):
    stix_id = models.CharField(max_length=100, unique=True)
    attack_id = models.CharField(max_length=20, db_index=True, blank=True)
    name = models.CharField(max_length=300, db_index=True)
    description = models.TextField(blank=True)
    url = models.URLField(max_length=300, blank=True)
    stix_modified = models.DateTimeField(null=True, blank=True)
    attack_version = models.CharField(max_length=16, blank=True)  # x_mitre_version of the object
    is_deprecated = models.BooleanField(default=False, db_index=True)
    is_revoked = models.BooleanField(default=False, db_index=True)
    last_seen_release = models.ForeignKey(
        AttackRelease, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )

    objects = ActiveQuerySet.as_manager()

    # Fields the importer owns and compares on re-import.
    SYNC_FIELDS: tuple[str, ...] = (
        "attack_id",
        "name",
        "description",
        "url",
        "stix_modified",
        "attack_version",
        "is_deprecated",
        "is_revoked",
    )

    class Meta:
        abstract = True
        ordering = ["attack_id"]

    def __str__(self) -> str:
        return f"{self.attack_id} {self.name}".strip()

    @property
    def is_active(self) -> bool:
        return not (self.is_revoked or self.is_deprecated)


class Tactic(AttackObject):
    shortname = models.SlugField(max_length=64, unique=True)
    # Position in the domain matrix (x-mitre-matrix.tactic_refs); None = not in current matrix.
    order = models.PositiveSmallIntegerField(null=True, blank=True)

    SYNC_FIELDS = (*AttackObject.SYNC_FIELDS, "shortname", "order")

    class Meta(AttackObject.Meta):
        ordering = ["order", "attack_id"]


class Technique(AttackObject):
    parent = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.PROTECT, related_name="subtechniques"
    )
    is_subtechnique = models.BooleanField(default=False)
    tactics = models.ManyToManyField(Tactic, blank=True, related_name="techniques")
    platforms = models.JSONField(default=list, blank=True)
    revoked_by = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="replaces"
    )

    SYNC_FIELDS = (*AttackObject.SYNC_FIELDS, "is_subtechnique", "platforms")

    def replacement(self, max_hops: int = 10) -> Technique | None:
        """Follow ``revoked_by`` to the first active technique (chains do occur)."""
        current: Technique | None = self.revoked_by
        hops = 0
        while current is not None and current.is_revoked and hops < max_hops:
            current = current.revoked_by
            hops += 1
        return current


class Group(AttackObject):
    aliases = models.JSONField(default=list, blank=True)
    aliases_text = models.TextField(blank=True)  # denormalised for simple, portable search
    revoked_by_stix_id = models.CharField(max_length=100, blank=True)

    SYNC_FIELDS = (*AttackObject.SYNC_FIELDS, "aliases", "aliases_text", "revoked_by_stix_id")


class Software(AttackObject):
    class Kind(models.TextChoices):
        MALWARE = "malware", "Malware"
        TOOL = "tool", "Tool"

    kind = models.CharField(max_length=16, choices=Kind.choices)
    aliases = models.JSONField(default=list, blank=True)
    platforms = models.JSONField(default=list, blank=True)
    revoked_by_stix_id = models.CharField(max_length=100, blank=True)

    SYNC_FIELDS = (*AttackObject.SYNC_FIELDS, "kind", "aliases", "platforms", "revoked_by_stix_id")

    class Meta(AttackObject.Meta):
        verbose_name_plural = "software"


class Mitigation(AttackObject):
    pass


class DataSource(AttackObject):
    """Deprecated by MITRE since v18; kept for bundles that still carry them."""


class DataComponent(AttackObject):
    data_source = models.ForeignKey(
        DataSource, null=True, blank=True, on_delete=models.SET_NULL, related_name="components"
    )
    log_sources = models.JSONField(default=list, blank=True)

    SYNC_FIELDS = (*AttackObject.SYNC_FIELDS, "log_sources")


class DetectionStrategy(AttackObject):
    class Meta(AttackObject.Meta):
        verbose_name_plural = "detection strategies"


class Analytic(AttackObject):
    platforms = models.JSONField(default=list, blank=True)
    strategies = models.ManyToManyField(DetectionStrategy, blank=True, related_name="analytics")
    data_components = models.ManyToManyField(DataComponent, blank=True, related_name="analytics")

    SYNC_FIELDS = (*AttackObject.SYNC_FIELDS, "platforms")


# --------------------------------------------------------------------- importer-owned links
class _Link(models.Model):
    description = models.TextField(blank=True)

    class Meta:
        abstract = True


class GroupTechnique(_Link):
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="technique_links")
    technique = models.ForeignKey(Technique, on_delete=models.CASCADE, related_name="group_links")

    class Meta:
        constraints = [models.UniqueConstraint(fields=["group", "technique"], name="uniq_grp_tech")]

    def __str__(self) -> str:
        return f"{self.group} uses {self.technique}"


class SoftwareTechnique(_Link):
    software = models.ForeignKey(Software, on_delete=models.CASCADE, related_name="technique_links")
    technique = models.ForeignKey(
        Technique, on_delete=models.CASCADE, related_name="software_links"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["software", "technique"], name="uniq_sw_tech")
        ]

    def __str__(self) -> str:
        return f"{self.software} uses {self.technique}"


class GroupSoftware(_Link):
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="software_links")
    software = models.ForeignKey(Software, on_delete=models.CASCADE, related_name="group_links")

    class Meta:
        constraints = [models.UniqueConstraint(fields=["group", "software"], name="uniq_grp_sw")]

    def __str__(self) -> str:
        return f"{self.group} uses {self.software}"


class MitigationTechnique(_Link):
    mitigation = models.ForeignKey(
        Mitigation, on_delete=models.CASCADE, related_name="technique_links"
    )
    technique = models.ForeignKey(
        Technique, on_delete=models.CASCADE, related_name="mitigation_links"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["mitigation", "technique"], name="uniq_mit_tech")
        ]

    def __str__(self) -> str:
        return f"{self.mitigation} mitigates {self.technique}"


class DetectionStrategyTechnique(_Link):
    strategy = models.ForeignKey(
        DetectionStrategy, on_delete=models.CASCADE, related_name="technique_links"
    )
    technique = models.ForeignKey(
        Technique, on_delete=models.CASCADE, related_name="detection_links"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["strategy", "technique"], name="uniq_det_tech")
        ]

    def __str__(self) -> str:
        return f"{self.strategy} detects {self.technique}"


class DataComponentTechnique(_Link):
    """Legacy (pre-v18) ``data-component --detects--> attack-pattern`` relationships."""

    data_component = models.ForeignKey(
        DataComponent, on_delete=models.CASCADE, related_name="technique_links"
    )
    technique = models.ForeignKey(
        Technique, on_delete=models.CASCADE, related_name="data_component_links"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["data_component", "technique"], name="uniq_dc_tech")
        ]

    def __str__(self) -> str:
        return f"{self.data_component} detects {self.technique}"


# --------------------------------------------------------------------- import runs
class ImportRun(models.Model):
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    domain = models.CharField(max_length=32, choices=Domain.choices, default=Domain.ENTERPRISE)
    requested_version = models.CharField(max_length=16, blank=True)  # blank = latest
    source = models.CharField(max_length=500, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.QUEUED)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    release = models.ForeignKey(
        AttackRelease, null=True, blank=True, on_delete=models.SET_NULL, related_name="runs"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    message = models.TextField(blank=True)
    stats = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Import #{self.pk} ({self.get_status_display()})"

    @property
    def is_finished(self) -> bool:
        return self.status in (self.Status.SUCCEEDED, self.Status.FAILED)
