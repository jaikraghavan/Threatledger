"""Dashboard KPIs, snapshots and trend series."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any

from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone

from threatledger.controls.models import Control, ControlStatus, Evidence
from threatledger.coverage.engine import Coverage, summarise
from threatledger.coverage.selectors import coverage_for
from threatledger.frameworks.services import adopted_frameworks, framework_result
from threatledger.org.models import Organisation
from threatledger.risks.models import (
    Band,
    Risk,
    RiskAcceptance,
    RiskMatrix,
    RiskStatus,
    RiskTechnique,
)

from .models import ComplianceSnapshot, CoverageSnapshot, RiskSnapshot


def _open_risks(org: Organisation, qs: Any = None) -> Any:
    base = qs if qs is not None else Risk.objects.filter(organisation=org)
    return base.live().exclude(status=RiskStatus.CLOSED)


def risk_band_counts(risks: list[Risk], matrix: RiskMatrix) -> tuple[Counter[str], Counter[str]]:
    residual = Counter(matrix.band(r.residual.value).value for r in risks)
    inherent = Counter(matrix.band(r.inherent.value).value for r in risks)
    return residual, inherent


def register_coverage(org: Organisation, risk_qs: Any = None) -> Any:
    risks = _open_risks(org, risk_qs)
    ids = set(
        RiskTechnique.objects.filter(risk__in=risks, technique__is_revoked=False).values_list(
            "technique_id", flat=True
        )
    )
    return coverage_for(ids, org.pk)


@dataclass
class ThreatGap:
    technique: Any
    status: Coverage
    risk_count: int


def top_threat_gaps(org: Organisation, risk_qs: Any = None, limit: int = 8) -> list[ThreatGap]:
    """Uncovered / partially covered techniques, ranked by how many open risks cite them."""
    from threatledger.attack.models import Technique

    cov = register_coverage(org, risk_qs)
    counts = Counter(
        RiskTechnique.objects.filter(
            risk__in=_open_risks(org, risk_qs), technique_id__in=cov
        ).values_list("technique_id", flat=True)
    )
    gaps = [tid for tid, tc in cov.items() if tc.status != Coverage.COVERED]
    techniques = Technique.objects.in_bulk(gaps)
    out = [ThreatGap(techniques[t], cov[t].status, counts[t]) for t in gaps]
    out.sort(key=lambda g: (-g.risk_count, g.status, g.technique.attack_id))
    return out[:limit]


@dataclass
class ControlPriority:
    control: Control
    requirements: int
    risks: int


def control_priorities(org: Organisation, limit: int = 6) -> list[ControlPriority]:
    """Not-yet-implemented controls whose implementation would move the most."""
    qs = (
        Control.objects.live()
        .filter(organisation=org)
        .exclude(status=ControlStatus.IMPLEMENTED)
        .annotate(
            req_count=Count("requirement_links", distinct=True),
            risk_count=Count(
                "risk_links", filter=Q(risk_links__risk__archived_at__isnull=True), distinct=True
            ),
        )
        .order_by("-req_count", "-risk_count", "ref")
    )
    return [
        ControlPriority(c, c.req_count, c.risk_count)
        for c in qs[:limit]
        if c.req_count or c.risk_count
    ]


def kpis(org: Organisation, risk_qs: Any = None) -> dict[str, Any]:
    """Headline numbers. ``risk_qs`` limits risk-based KPIs to what the viewer may see."""
    matrix = RiskMatrix.for_org(org)
    today = timezone.localdate()
    risks = list(_open_risks(org, risk_qs))
    residual, inherent = risk_band_counts(risks, matrix)
    cov = summarise(register_coverage(org, risk_qs).values())
    controls = Control.objects.live().filter(organisation=org)
    status_counts = dict(
        controls.values_list("status").annotate(n=Count("id")).values_list("status", "n")
    )
    n_controls = sum(status_counts.values())
    frameworks = [framework_result(fw, org) for fw in adopted_frameworks(org)]
    return {
        "matrix": matrix,
        "open_risks": len(risks),
        "residual": residual,
        "inherent": inherent,
        "critical_high": residual[Band.CRITICAL.value] + residual[Band.HIGH.value],
        "review_overdue": sum(
            1 for r in risks if r.next_review_date and r.next_review_date < today
        ),
        "coverage": cov,
        "controls_total": n_controls,
        "controls_implemented": status_counts.get(ControlStatus.IMPLEMENTED, 0),
        "controls_status": status_counts,
        "controls_pct": round(100 * status_counts.get(ControlStatus.IMPLEMENTED, 0) / n_controls)
        if n_controls
        else 0,
        "tests_overdue": sum(1 for c in controls if c.test_overdue),
        "evidence_expiring": Evidence.objects.filter(
            control__in=controls,
            archived_at__isnull=True,
            valid_until__isnull=False,
            valid_until__lte=today + timedelta(days=30),
        ).count(),
        "pending_acceptances": RiskAcceptance.objects.filter(
            risk__organisation=org, status=RiskAcceptance.Status.PENDING
        ).count(),
        "frameworks": frameworks,
        "top_risks": sorted(risks, key=lambda r: (-r.residual.value, -r.inherent.value, r.ref))[:8],
    }


# ----------------------------------------------------------------------------- snapshots
@transaction.atomic
def take_snapshots(org: Organisation, day: date | None = None) -> dict[str, int]:
    """Record today's numbers (idempotent: re-running the same day updates the rows)."""
    day = day or timezone.localdate()
    frameworks = 0
    for fw in adopted_frameworks(org):
        s = framework_result(fw, org).summary
        ComplianceSnapshot.objects.update_or_create(
            organisation=org,
            framework=fw,
            date=day,
            defaults={
                "met": s.met,
                "partial": s.partial,
                "gap": s.gap,
                "no_control": s.no_control,
                "tracked": s.tracked,
                "percent": s.percent,
            },
        )
        frameworks += 1
    cov = summarise(register_coverage(org).values())
    CoverageSnapshot.objects.update_or_create(
        organisation=org,
        date=day,
        defaults={
            "covered": cov.covered,
            "partial": cov.partial,
            "gap": cov.gap,
            "percent": cov.percent,
        },
    )
    matrix = RiskMatrix.for_org(org)
    risks = list(_open_risks(org))
    residual, inherent = risk_band_counts(risks, matrix)
    RiskSnapshot.objects.update_or_create(
        organisation=org,
        date=day,
        defaults={
            "open_risks": len(risks),
            "residual": {b.value: residual[b.value] for b in Band},
            "inherent": {b.value: inherent[b.value] for b in Band},
            "average_residual": round(sum(r.residual.value for r in risks) / len(risks), 2)
            if risks
            else 0,
        },
    )
    return {"frameworks": frameworks, "coverage": 1, "risks": 1}


def snapshot_all_organisations(day: date | None = None) -> int:
    n = 0
    for org in Organisation.objects.all():
        take_snapshots(org, day)
        n += 1
    return n


# ----------------------------------------------------------------------------- trend series
def _since(days: int) -> date:
    return timezone.localdate() - timedelta(days=days)


def compliance_series(org: Organisation, days: int = 365) -> dict[str, Any]:
    rows = ComplianceSnapshot.objects.filter(
        organisation=org, date__gte=_since(days)
    ).select_related("framework")
    dates = sorted({r.date for r in rows})
    by_fw: dict[str, dict[date, float]] = {}
    for r in rows:
        by_fw.setdefault(r.framework.name, {})[r.date] = r.percent
    return {
        "labels": [d.isoformat() for d in dates],
        "datasets": [
            {"label": name, "data": [vals.get(d) for d in dates]}
            for name, vals in sorted(by_fw.items())
        ],
    }


def risk_series(org: Organisation, days: int = 365) -> dict[str, Any]:
    rows = list(RiskSnapshot.objects.filter(organisation=org, date__gte=_since(days)))
    return {
        "labels": [r.date.isoformat() for r in rows],
        "datasets": [
            {"label": Band(b).label, "band": b, "data": [r.residual.get(b, 0) for r in rows]}
            for b in ("critical", "high", "medium", "low")
        ],
    }


def coverage_series(org: Organisation, days: int = 365) -> dict[str, Any]:
    rows = list(CoverageSnapshot.objects.filter(organisation=org, date__gte=_since(days)))
    return {
        "labels": [r.date.isoformat() for r in rows],
        "datasets": [{"label": "Threat coverage %", "data": [r.percent for r in rows]}],
    }


def risk_score_series(risk: Risk) -> dict[str, Any]:
    rows = list(risk.score_history.order_by("changed_at", "id"))
    return {
        "labels": [h.changed_at.date().isoformat() for h in rows],
        "datasets": [
            {"label": "Inherent", "data": [h.inherent_score for h in rows]},
            {"label": "Residual", "data": [h.residual_score for h in rows]},
        ],
    }
