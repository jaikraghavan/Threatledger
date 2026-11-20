from __future__ import annotations

from django.db import models
from django.utils.text import slugify


class OrganisationQuerySet(models.QuerySet["Organisation"]):
    def current(self) -> Organisation | None:
        """ThreatLedger runs one organisation per deployment (see PLAN.md Q11)."""
        return self.order_by("id").first()


class Organisation(models.Model):
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=200, unique=True)
    settings = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = OrganisationQuerySet.as_manager()

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)[:200]
        super().save(*args, **kwargs)


class BusinessUnit(models.Model):
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name="business_units"
    )
    name = models.CharField(max_length=200)
    code = models.CharField(max_length=32, blank=True)
    parent = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.PROTECT, related_name="children"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "name"], name="uniq_bu_name_per_org")
        ]

    def __str__(self) -> str:
        return self.name
