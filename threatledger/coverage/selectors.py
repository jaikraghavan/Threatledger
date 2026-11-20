"""Load the mapping graph from the database for the coverage engine (a fixed number of
queries, independent of how many techniques or controls exist)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from threatledger.attack.models import MitigationTechnique, Technique
from threatledger.controls.models import Control, ControlMitigation, ControlTechnique

from .engine import TechniqueCoverage, technique_coverage


def controls_by_technique(technique_ids: set[int], organisation_id: int) -> dict[int, set[int]]:
    """technique id -> ids of live controls mapped directly or via an implemented mitigation."""
    out: dict[int, set[int]] = defaultdict(set)
    if not technique_ids:
        return out
    for tid, cid in ControlTechnique.objects.filter(
        technique_id__in=technique_ids,
        control__organisation_id=organisation_id,
        control__archived_at__isnull=True,
    ).values_list("technique_id", "control_id"):
        out[tid].add(cid)
    mit_to_tech: dict[int, set[int]] = defaultdict(set)
    for mid, tid in MitigationTechnique.objects.filter(technique_id__in=technique_ids).values_list(
        "mitigation_id", "technique_id"
    ):
        mit_to_tech[mid].add(tid)
    if mit_to_tech:
        for mid, cid in ControlMitigation.objects.filter(
            mitigation_id__in=mit_to_tech,
            control__organisation_id=organisation_id,
            control__archived_at__isnull=True,
        ).values_list("mitigation_id", "control_id"):
            for tid in mit_to_tech[mid]:
                out[tid].add(cid)
    return out


def coverage_for(
    technique_ids: Iterable[int], organisation_id: int
) -> dict[int, TechniqueCoverage]:
    ids = set(technique_ids)
    parent_of = dict(
        Technique.objects.filter(pk__in=ids, parent__isnull=False).values_list("pk", "parent_id")
    )
    graph = controls_by_technique(ids | {p for p in parent_of.values() if p}, organisation_id)
    control_ids = {c for cs in graph.values() for c in cs}
    status = dict(Control.objects.filter(pk__in=control_ids).values_list("pk", "status"))
    return technique_coverage(ids, graph, status, parent_of)
