"""Threat-coverage rules (PLAN.md §4). Pure functions: no database access.

- A control covers a technique if mapped directly OR through an ATT&CK mitigation it
  implements (Q5).
- Technique status from the best mapped control: implemented → COVERED, partial → PARTIAL,
  anything else (or no control) → GAP.
- Sub-techniques inherit their parent's coverage: status = max(own, parent) (Q6). Parents
  do not roll up from children.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import IntEnum


class Coverage(IntEnum):
    GAP = 0
    PARTIAL = 1
    COVERED = 2

    @property
    def label(self) -> str:
        return {0: "Gap", 1: "Partial", 2: "Covered"}[self.value]

    @property
    def css(self) -> str:
        return {0: "gap", 1: "partial", 2: "covered"}[self.value]


STATUS_RANK = {"implemented": 3, "partial": 2, "planned": 1, "not_implemented": 0}


def coverage_from_statuses(statuses: Iterable[str]) -> Coverage:
    best = max((STATUS_RANK.get(s, 0) for s in statuses), default=0)
    if best >= 3:
        return Coverage.COVERED
    if best == 2:
        return Coverage.PARTIAL
    return Coverage.GAP


@dataclass(frozen=True)
class TechniqueCoverage:
    technique_id: int
    status: Coverage
    own_status: Coverage
    inherited: bool  # status came from the parent technique
    control_ids: frozenset[int]  # controls mapped to this technique (direct or via mitigation)


def technique_coverage(
    technique_ids: Iterable[int],
    controls_by_technique: Mapping[int, set[int]],
    control_status: Mapping[int, str],
    parent_of: Mapping[int, int | None],
) -> dict[int, TechniqueCoverage]:
    """Coverage for each requested technique.

    ``controls_by_technique`` must already include controls reached through mitigations.
    ``parent_of`` must contain the parents of requested sub-techniques (and their mappings
    must be present in ``controls_by_technique``).
    """

    def own(tid: int) -> Coverage:
        return coverage_from_statuses(
            control_status[c] for c in controls_by_technique.get(tid, ()) if c in control_status
        )

    result: dict[int, TechniqueCoverage] = {}
    for tid in technique_ids:
        mine = own(tid)
        parent = parent_of.get(tid)
        parent_cov = own(parent) if parent else Coverage.GAP
        status = max(mine, parent_cov)
        result[tid] = TechniqueCoverage(
            technique_id=tid,
            status=status,
            own_status=mine,
            inherited=parent_cov > mine,
            control_ids=frozenset(controls_by_technique.get(tid, ())),
        )
    return result


@dataclass(frozen=True)
class CoverageSummary:
    covered: int
    partial: int
    gap: int

    @property
    def total(self) -> int:
        return self.covered + self.partial + self.gap

    @property
    def percent(self) -> int:
        """Covered = 1, partial = 0.5 (same weighting as framework %)."""
        if not self.total:
            return 0
        return round(100 * (self.covered + 0.5 * self.partial) / self.total)


def summarise(coverages: Iterable[TechniqueCoverage]) -> CoverageSummary:
    counts = {Coverage.COVERED: 0, Coverage.PARTIAL: 0, Coverage.GAP: 0}
    for c in coverages:
        counts[c.status] += 1
    return CoverageSummary(counts[Coverage.COVERED], counts[Coverage.PARTIAL], counts[Coverage.GAP])
