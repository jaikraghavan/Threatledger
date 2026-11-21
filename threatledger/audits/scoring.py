"""Audit scoring and the derived-status suggestion. Pure functions (PLAN.md §12, Q14).

- Suggestion from the live derived status: Met → Compliant, Partial → Partially compliant,
  Gap / No control → Non-compliant, not tracked (N/A scope) → Not applicable.
- A judgement *diverges* when it was recorded and differs from today's suggestion.
- Score % = (compliant + 0.5 × partial) ÷ (compliant + partial + non-compliant).
- Progress % = judged requirements ÷ requirements in scope.
"""

from __future__ import annotations

from dataclasses import dataclass

from threatledger.frameworks.compliance import ReqStatus

from .models import Judgement

_SUGGESTION = {
    ReqStatus.MET: Judgement.COMPLIANT,
    ReqStatus.PARTIAL: Judgement.PARTIAL,
    ReqStatus.GAP: Judgement.NON_COMPLIANT,
    ReqStatus.NO_CONTROL: Judgement.NON_COMPLIANT,
}


def suggest(derived: ReqStatus | None) -> Judgement:
    return Judgement.NOT_APPLICABLE if derived is None else _SUGGESTION[derived]


def is_divergent(judgement: str, derived: ReqStatus | None) -> bool:
    return judgement != Judgement.NOT_ASSESSED and judgement != suggest(derived)


@dataclass
class AuditScore:
    total: int = 0
    compliant: int = 0
    partial: int = 0
    non_compliant: int = 0
    not_applicable: int = 0
    divergent: int = 0
    maturity_sum: int = 0
    maturity_n: int = 0

    def add(self, judgement: str, maturity: int | None, divergent: bool) -> None:
        self.total += 1
        if judgement == Judgement.COMPLIANT:
            self.compliant += 1
        elif judgement == Judgement.PARTIAL:
            self.partial += 1
        elif judgement == Judgement.NON_COMPLIANT:
            self.non_compliant += 1
        elif judgement == Judgement.NOT_APPLICABLE:
            self.not_applicable += 1
        if maturity is not None:
            self.maturity_sum += maturity
            self.maturity_n += 1
        self.divergent += int(divergent)

    @property
    def assessed(self) -> int:
        return self.compliant + self.partial + self.non_compliant + self.not_applicable

    @property
    def not_assessed(self) -> int:
        return self.total - self.assessed

    @property
    def progress(self) -> float:
        return round(100 * self.assessed / self.total, 1) if self.total else 0.0

    @property
    def score(self) -> float | None:
        judged = self.compliant + self.partial + self.non_compliant
        if not judged:
            return None
        return round(100 * (self.compliant + 0.5 * self.partial) / judged, 1)

    @property
    def maturity(self) -> float | None:
        return round(self.maturity_sum / self.maturity_n, 1) if self.maturity_n else None

    @property
    def bar(self) -> list[tuple[float, float, str]]:
        """(x %, width %, css class) segments for a CSP-safe SVG progress bar."""
        if not self.total:
            return []
        out, x = [], 0.0
        for count, css in (
            (self.compliant, "fill-green-500"),
            (self.partial, "fill-amber-400"),
            (self.non_compliant, "fill-red-400"),
            (self.not_applicable, "fill-slate-400"),
        ):
            width = round(100 * count / self.total, 2)
            if width:
                out.append((x, width, css))
            x += width
        return out
