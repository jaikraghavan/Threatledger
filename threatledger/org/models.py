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

    # Workflow switches kept in ``settings`` (Phase 9). Defaults keep earlier behaviour.
    WORKFLOW_DEFAULTS = {
        "require_evidence_review": False,
        "control_status_approval": False,
    }

    def workflow(self, key: str) -> bool:
        return bool((self.settings or {}).get(key, self.WORKFLOW_DEFAULTS[key]))


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


def descendant_ids(organisation_id: int, roots: set[int] | frozenset[int]) -> set[int]:
    """``roots`` plus every business unit beneath them (one query; BUs number in the dozens)."""
    children: dict[int | None, list[int]] = {}
    for pk, parent in BusinessUnit.objects.filter(organisation_id=organisation_id).values_list(
        "pk", "parent_id"
    ):
        children.setdefault(parent, []).append(pk)
    out: set[int] = set()
    stack = list(roots)
    while stack:
        pk = stack.pop()
        if pk in out:
            continue
        out.add(pk)
        stack.extend(children.get(pk, []))
    return out


def tree(organisation_id: int) -> list[tuple[BusinessUnit, int]]:
    """Business units in depth-first order with their depth, for indented display."""
    units = list(BusinessUnit.objects.filter(organisation_id=organisation_id).order_by("name"))
    by_parent: dict[int | None, list[BusinessUnit]] = {}
    for bu in units:
        by_parent.setdefault(bu.parent_id, []).append(bu)
    out: list[tuple[BusinessUnit, int]] = []

    def walk(parent: int | None, depth: int) -> None:
        for bu in by_parent.get(parent, []):
            out.append((bu, depth))
            walk(bu.pk, depth + 1)

    walk(None, 0)
    return out
