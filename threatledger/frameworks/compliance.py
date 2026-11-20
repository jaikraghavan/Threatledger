"""Requirement status rules (PLAN.md §4, Q7). Pure functions.

- No mapped (live) controls             -> NO_CONTROL
- All mapped controls implemented       -> MET
- At least one implemented or partial   -> PARTIAL
- Mapped controls, none impl./partial   -> GAP

Framework % = (met + 0.5 × partial) ÷ tracked requirements (NO_CONTROL counts as 0).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum


class ReqStatus(StrEnum):
    MET = "met"
    PARTIAL = "partial"
    GAP = "gap"
    NO_CONTROL = "no_control"

    @property
    def label(self) -> str:
        return {"met": "Met", "partial": "Partial", "gap": "Gap", "no_control": "No control"}[
            self.value
        ]


def requirement_status(control_statuses: Iterable[str]) -> ReqStatus:
    statuses = list(control_statuses)
    if not statuses:
        return ReqStatus.NO_CONTROL
    if all(s == "implemented" for s in statuses):
        return ReqStatus.MET
    if any(s in ("implemented", "partial") for s in statuses):
        return ReqStatus.PARTIAL
    return ReqStatus.GAP


@dataclass
class Summary:
    met: int = 0
    partial: int = 0
    gap: int = 0
    no_control: int = 0
    by_requirement: dict[int, ReqStatus] = field(default_factory=dict)

    @property
    def tracked(self) -> int:
        return self.met + self.partial + self.gap + self.no_control

    @property
    def percent(self) -> float:
        if not self.tracked:
            return 0.0
        return round(100 * (self.met + 0.5 * self.partial) / self.tracked, 1)

    @property
    def bar(self) -> list[tuple[float, float, str]]:
        """(x %, width %, css class) segments for a CSP-safe SVG progress bar."""
        if not self.tracked:
            return []
        out, x = [], 0.0
        for count, css in (
            (self.met, "fill-green-500"),
            (self.partial, "fill-amber-400"),
            (self.gap, "fill-red-400"),
        ):
            width = round(100 * count / self.tracked, 2)
            if width:
                out.append((x, width, css))
            x += width
        return out

    def add(self, req_id: int, status: ReqStatus) -> None:
        self.by_requirement[req_id] = status
        setattr(self, status.value, getattr(self, status.value) + 1)


def summarise(statuses_by_requirement: dict[int, list[str]], tracked_ids: Iterable[int]) -> Summary:
    summary = Summary()
    for rid in tracked_ids:
        summary.add(rid, requirement_status(statuses_by_requirement.get(rid, [])))
    return summary
