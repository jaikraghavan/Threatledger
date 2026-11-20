"""Synchronise a :class:`ParsedBundle` into the database. Idempotent.

Rules (PLAN.md §6, Phase 2):
- Objects are matched on STIX id. New objects that are revoked or deprecated are skipped;
  existing ones are *flagged*, never deleted, so user mappings that reference them survive.
- Objects absent from the bundle are left untouched (``last_seen_release`` shows staleness).
- Importer-owned link tables are diff-synced: unchanged links keep their primary keys.
- Re-importing the same bundle changes nothing (all counters report zero changes).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from django.db import models, transaction

from ..models import (
    Analytic,
    AttackRelease,
    DataComponent,
    DataComponentTechnique,
    DataSource,
    DetectionStrategy,
    DetectionStrategyTechnique,
    Group,
    GroupSoftware,
    GroupTechnique,
    Mitigation,
    MitigationTechnique,
    Software,
    SoftwareTechnique,
    Tactic,
    Technique,
)
from .parser import ParsedBundle, Record

BATCH = 500
Stats = dict[str, dict[str, int]]


def _sync_objects(
    model: type[models.Model],
    records: Iterable[Record],
    release: AttackRelease,
) -> tuple[dict[str, int], dict[str, int]]:
    """Upsert ``records``; returns (stix_id -> pk for every row of the model, counters)."""
    fields: tuple[str, ...] = model.SYNC_FIELDS  # type: ignore[attr-defined]
    existing = {o.stix_id: o for o in model._default_manager.all()}  # type: ignore[attr-defined]
    counts = dict.fromkeys(("created", "updated", "unchanged", "skipped", "flagged", "missing"), 0)
    to_create: list[models.Model] = []
    to_update: list[models.Model] = []
    seen: set[str] = set()
    for rec in records:
        stix_id = rec["stix_id"]
        if stix_id in seen:
            continue
        seen.add(stix_id)
        obj = existing.get(stix_id)
        if obj is None:
            if rec["is_revoked"] or rec["is_deprecated"]:
                counts["skipped"] += 1
                continue
            to_create.append(
                model(stix_id=stix_id, last_seen_release=release, **{f: rec[f] for f in fields})
            )
            counts["created"] += 1
            continue
        was_active = not (obj.is_revoked or obj.is_deprecated)  # type: ignore[attr-defined]
        changed = [f for f in fields if getattr(obj, f) != rec[f]]
        for f in changed:
            setattr(obj, f, rec[f])
        release_changed = obj.last_seen_release_id != release.pk  # type: ignore[attr-defined]
        obj.last_seen_release = release  # type: ignore[attr-defined]
        if changed or release_changed:
            to_update.append(obj)
        if changed:
            counts["updated"] += 1
            if was_active and (rec["is_revoked"] or rec["is_deprecated"]):
                counts["flagged"] += 1
        else:
            counts["unchanged"] += 1
    counts["missing"] = len(set(existing) - seen)
    model._default_manager.bulk_create(to_create, batch_size=BATCH)
    if to_update:
        model._default_manager.bulk_update(
            to_update, [*fields, "last_seen_release"], batch_size=BATCH
        )
    ids = dict(model._default_manager.values_list("stix_id", "pk"))
    return ids, counts


def _sync_pairs(
    through: type[models.Model],
    left: str,
    right: str,
    desired: dict[tuple[int, int], str] | set[tuple[int, int]],
    scope_left: set[int] | None = None,
) -> dict[str, int]:
    """Diff-sync a link table. ``desired`` maps (left_pk, right_pk) -> description (or a set
    for plain M2M through tables). Only rows whose left side is in ``scope_left`` (or all rows
    when None) are candidates for deletion."""
    has_description = isinstance(desired, dict)
    wanted: dict[tuple[int, int], str] = (
        desired if isinstance(desired, dict) else dict.fromkeys(desired, "")
    )
    value_fields = ["pk", f"{left}_id", f"{right}_id"] + (
        ["description"] if has_description else []
    )
    qs = through._default_manager.all()
    if scope_left is not None:
        qs = qs.filter(**{f"{left}_id__in": scope_left})
    current: dict[tuple[int, int], tuple[int, str]] = {}
    for row in qs.values_list(*value_fields):
        current[(row[1], row[2])] = (row[0], row[3] if has_description else "")

    to_delete = [pk for key, (pk, _) in current.items() if key not in wanted]
    to_create = [
        through(
            **{f"{left}_id": a, f"{right}_id": b}, **({"description": d} if has_description else {})
        )
        for (a, b), d in wanted.items()
        if (a, b) not in current
    ]
    to_update = []
    if has_description:
        for key, (pk, desc) in current.items():
            if key in wanted and wanted[key] != desc:
                to_update.append(through(pk=pk, description=wanted[key]))
    if to_delete:
        through._default_manager.filter(pk__in=to_delete).delete()
    through._default_manager.bulk_create(to_create, batch_size=BATCH)
    if to_update:
        through._default_manager.bulk_update(to_update, ["description"], batch_size=BATCH)
    return {
        "created": len(to_create),
        "updated": len(to_update),
        "deleted": len(to_delete),
        "total": len(wanted),
    }


def _links(
    pairs: Iterable[tuple[str, str, str]], left_ids: dict[str, int], right_ids: dict[str, int]
) -> dict[tuple[int, int], str]:
    out: dict[tuple[int, int], str] = {}
    for src, tgt, desc in pairs:
        a, b = left_ids.get(src), right_ids.get(tgt)
        if a is not None and b is not None:
            out.setdefault((a, b), desc)
    return out


def _sync_fk(
    model: type[models.Model],
    field: str,
    desired: dict[int, int | None],
) -> int:
    """Set ``field_id`` on rows in ``desired``; returns number of rows changed."""
    attr = f"{field}_id"
    changed = []
    for pk, current in model._default_manager.filter(pk__in=desired).values_list("pk", attr):
        if current != desired[pk]:
            changed.append(model(pk=pk, **{attr: desired[pk]}))
    if changed:
        model._default_manager.bulk_update(changed, [field], batch_size=BATCH)
    return len(changed)


@transaction.atomic
def load_bundle(parsed: ParsedBundle, release: AttackRelease) -> dict[str, Any]:
    stats: dict[str, Any] = {"objects": {}, "links": {}}
    obj_stats: Stats = stats["objects"]

    _tactic_ids, obj_stats["tactics"] = _sync_objects(Tactic, parsed.tactics, release)
    tech_ids, obj_stats["techniques"] = _sync_objects(Technique, parsed.techniques, release)
    group_ids, obj_stats["groups"] = _sync_objects(Group, parsed.groups, release)
    sw_ids, obj_stats["software"] = _sync_objects(Software, parsed.software, release)
    mit_ids, obj_stats["mitigations"] = _sync_objects(Mitigation, parsed.mitigations, release)
    ds_ids, obj_stats["data_sources"] = _sync_objects(DataSource, parsed.data_sources, release)
    dc_ids, obj_stats["data_components"] = _sync_objects(
        DataComponent, parsed.data_components, release
    )
    det_ids, obj_stats["detection_strategies"] = _sync_objects(
        DetectionStrategy, parsed.detection_strategies, release
    )
    an_ids, obj_stats["analytics"] = _sync_objects(Analytic, parsed.analytics, release)

    # Tactics that dropped out of the matrix lose their order (e.g. v20 split Defense Evasion).
    in_bundle = {r["stix_id"] for r in parsed.tactics}
    Tactic.objects.exclude(stix_id__in=in_bundle).exclude(order=None).update(order=None)

    # Technique hierarchy and revocation pointers (only for techniques in this bundle).
    by_attack_id = dict(Technique.objects.values_list("attack_id", "pk"))
    parents: dict[int, int | None] = {}
    revoked: dict[int, int | None] = {}
    for rec in parsed.techniques:
        pk = tech_ids.get(rec["stix_id"])
        if pk is None:
            continue
        parent_pk = tech_ids.get(parsed.subtechnique_of.get(rec["stix_id"], ""))
        if parent_pk is None and rec["is_subtechnique"] and "." in rec["attack_id"]:
            parent_pk = by_attack_id.get(rec["attack_id"].split(".", 1)[0])
        parents[pk] = parent_pk if rec["is_subtechnique"] else None
        revoked[pk] = tech_ids.get(parsed.revoked_by.get(rec["stix_id"], ""))
    stats["hierarchy"] = {
        "parent_changes": _sync_fk(Technique, "parent", parents),
        "revoked_by_changes": _sync_fk(Technique, "revoked_by", revoked),
    }
    _sync_fk(
        DataComponent,
        "data_source",
        {
            dc_ids[r["stix_id"]]: ds_ids.get(parsed.data_component_source.get(r["stix_id"], ""))
            for r in parsed.data_components
            if r["stix_id"] in dc_ids
        },
    )

    # Plain M2M relations, scoped to objects present in this bundle.
    tactic_by_short = dict(Tactic.objects.values_list("shortname", "pk"))
    tech_scope = {tech_ids[r["stix_id"]] for r in parsed.techniques if r["stix_id"] in tech_ids}
    stats["links"]["technique_tactics"] = _sync_pairs(
        Technique.tactics.through,
        "technique",
        "tactic",
        {
            (tech_ids[stix], tactic_by_short[short])
            for stix, shorts in parsed.technique_tactics.items()
            if stix in tech_ids
            for short in shorts
            if short in tactic_by_short
        },
        scope_left=tech_scope,
    )
    an_scope = {an_ids[r["stix_id"]] for r in parsed.analytics if r["stix_id"] in an_ids}
    stats["links"]["analytic_strategies"] = _sync_pairs(
        Analytic.strategies.through,
        "analytic",
        "detectionstrategy",
        {
            (an_ids[a], det_ids[d])
            for a, ds in parsed.analytic_strategies.items()
            if a in an_ids
            for d in ds
            if d in det_ids
        },
        scope_left=an_scope,
    )
    stats["links"]["analytic_components"] = _sync_pairs(
        Analytic.data_components.through,
        "analytic",
        "datacomponent",
        {
            (an_ids[a], dc_ids[c])
            for a, cs in parsed.analytic_components.items()
            if a in an_ids
            for c in cs
            if c in dc_ids
        },
        scope_left=an_scope,
    )

    # Importer-owned relationship tables: full diff-sync.
    link_specs: list[tuple[str, type[models.Model], str, str, dict[str, int], dict[str, int]]] = [
        ("group_technique", GroupTechnique, "group", "technique", group_ids, tech_ids),
        ("software_technique", SoftwareTechnique, "software", "technique", sw_ids, tech_ids),
        ("group_software", GroupSoftware, "group", "software", group_ids, sw_ids),
        ("mitigation_technique", MitigationTechnique, "mitigation", "technique", mit_ids, tech_ids),
        (
            "detection_technique",
            DetectionStrategyTechnique,
            "strategy",
            "technique",
            det_ids,
            tech_ids,
        ),
        (
            "data_component_technique",
            DataComponentTechnique,
            "data_component",
            "technique",
            dc_ids,
            tech_ids,
        ),
    ]
    for name, through, left, right, left_ids, right_ids in link_specs:
        stats["links"][name] = _sync_pairs(
            through, left, right, _links(parsed.links.get(name, []), left_ids, right_ids)
        )
    return stats


def summarise(stats: dict[str, Any]) -> dict[str, int]:
    """Flat totals for messages and audit events."""
    objects = stats.get("objects", {})
    links = stats.get("links", {})
    return {
        "created": sum(c["created"] for c in objects.values()),
        "updated": sum(c["updated"] for c in objects.values()),
        "flagged": sum(c["flagged"] for c in objects.values()),
        "skipped": sum(c["skipped"] for c in objects.values()),
        "links_created": sum(c["created"] for c in links.values()),
        "links_deleted": sum(c["deleted"] for c in links.values()),
        "links_updated": sum(c["updated"] for c in links.values()),
        "techniques_active": Technique.objects.active().count(),
    }
