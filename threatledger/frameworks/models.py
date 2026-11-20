"""Compliance frameworks, requirements and their mappings.

Requirement status is never stored: it is derived from the status of the controls mapped to
each requirement (see ``compliance.py``), so changing one control updates every framework
that control maps to.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models

from threatledger.attack.models import Technique
from threatledger.controls.models import Control, MappingSource
from threatledger.org.models import Organisation


class ContentLevel(models.TextChoices):
    FULL = "full", "Full official text"
    SUMMARY = "summary", "Titles + plain-language summaries"
    REFERENCE = "reference", "Identifiers + short titles only"


class Framework(models.Model):
    code = models.SlugField(max_length=40, unique=True)
    name = models.CharField(max_length=200)
    version = models.CharField(max_length=40, blank=True)
    publisher = models.CharField(max_length=200, blank=True)
    source_url = models.URLField(max_length=500, blank=True)
    licence_note = models.CharField(max_length=500, blank=True)
    description = models.TextField(blank=True)
    content_level = models.CharField(
        max_length=16, choices=ContentLevel.choices, default=ContentLevel.REFERENCE
    )
    baselines = models.JSONField(default=list, blank=True)  # e.g. ["low", "moderate", "high"]
    is_indicative = models.BooleanField(
        default=True, help_text="Seeded content/mappings: verify against the official text."
    )
    imported_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} {self.version}".strip()


class Requirement(models.Model):
    framework = models.ForeignKey(Framework, on_delete=models.CASCADE, related_name="requirements")
    parent = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.PROTECT, related_name="children"
    )
    ref = models.CharField(max_length=64)
    title = models.CharField(max_length=500)
    text = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)
    is_domain = models.BooleanField(default=False, help_text="Grouping node; not assessed.")
    baselines = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["framework", "order", "id"]
        constraints = [
            models.UniqueConstraint(fields=["framework", "ref"], name="uniq_requirement_ref")
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.title}"


class OrgFramework(models.Model):
    """An organisation's adoption of a framework (and optional baseline scoping)."""

    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    framework = models.ForeignKey(Framework, on_delete=models.CASCADE, related_name="adoptions")
    adopted = models.BooleanField(default=True)
    baseline = models.CharField(max_length=32, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organisation", "framework"], name="uniq_org_framework")
        ]

    def __str__(self) -> str:
        return f"{self.organisation} · {self.framework}"


class RequirementScope(models.Model):
    """Organisation-specific applicability (N/A with justification)."""

    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    requirement = models.ForeignKey(Requirement, on_delete=models.CASCADE, related_name="scopes")
    applicable = models.BooleanField(default=True)
    justification = models.CharField(max_length=500, blank=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["organisation", "requirement"], name="uniq_requirement_scope"
            )
        ]

    def __str__(self) -> str:
        return f"{self.requirement} ({'applicable' if self.applicable else 'N/A'})"


class ControlRequirement(models.Model):
    control = models.ForeignKey(Control, on_delete=models.CASCADE, related_name="requirement_links")
    requirement = models.ForeignKey(
        Requirement, on_delete=models.PROTECT, related_name="control_links"
    )
    source = models.CharField(max_length=16, choices=MappingSource.choices, default="manual")
    indicative = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["control", "requirement"], name="uniq_control_req")
        ]

    def __str__(self) -> str:
        return f"{self.control.ref} → {self.requirement.ref}"


class RequirementMapping(models.Model):
    """Cross-framework relationship between two requirements."""

    class Relationship(models.TextChoices):
        EQUIVALENT = "equivalent", "Equivalent"
        SUBSET = "subset", "Subset of"
        SUPERSET = "superset", "Superset of"
        RELATED = "related", "Related"

    from_requirement = models.ForeignKey(
        Requirement, on_delete=models.CASCADE, related_name="mappings_from"
    )
    to_requirement = models.ForeignKey(
        Requirement, on_delete=models.CASCADE, related_name="mappings_to"
    )
    relationship = models.CharField(
        max_length=16, choices=Relationship.choices, default=Relationship.RELATED
    )
    source = models.CharField(max_length=16, choices=MappingSource.choices, default="manual")
    indicative = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["from_requirement", "to_requirement"], name="uniq_requirement_mapping"
            )
        ]

    def __str__(self) -> str:
        return f"{self.from_requirement.ref} ~ {self.to_requirement.ref}"


class TechniqueRequirement(models.Model):
    """CTID Mappings Explorer: ATT&CK technique <-mitigated by- framework requirement."""

    technique = models.ForeignKey(
        Technique, on_delete=models.PROTECT, related_name="requirement_links"
    )
    requirement = models.ForeignKey(
        Requirement, on_delete=models.CASCADE, related_name="technique_links"
    )
    mapping_type = models.CharField(max_length=32, default="mitigates")
    source = models.CharField(max_length=32, default="ctid")
    attack_version = models.CharField(max_length=16, blank=True)
    comments = models.TextField(blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["technique", "requirement"], name="uniq_tech_req")
        ]

    def __str__(self) -> str:
        return f"{self.requirement.ref} mitigates {self.technique.attack_id}"
