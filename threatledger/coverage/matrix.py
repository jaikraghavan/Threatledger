"""ATT&CK coverage matrix and Navigator layer export.

Scopes (PLAN.md Phase 6):
- ``all``     every active technique
- ``risks``   techniques linked to the organisation's live risks (``mine`` = risks I own)
- ``group``   techniques used by one threat group
- ``sector``  techniques used by the groups curated for a sector (data/attack/sectors.yaml)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from django.conf import settings
from django.db.models import Prefetch

from threatledger.attack.models import Group, GroupTechnique, Tactic, Technique
from threatledger.controls.models import Control
from threatledger.org.models import Organisation

from .engine import Coverage, CoverageSummary, TechniqueCoverage, summarise
from .selectors import coverage_for

SECTORS_FILE = Path(settings.BASE_DIR) / "data" / "attack" / "sectors.yaml"
SCOPES = ("risks", "all", "group", "sector")
COLOURS = {Coverage.COVERED: "#22c55e", Coverage.PARTIAL: "#f59e0b", Coverage.GAP: "#ef4444"}


@lru_cache(maxsize=1)
def sectors() -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(SECTORS_FILE.read_text(encoding="utf-8"))
    return {
        k: {"label": v["label"], "groups": [str(g) for g in v["groups"]]}
        for k, v in data["sectors"].items()
    }


@dataclass
class Scope:
    kind: str
    value: str
    label: str
    technique_ids: set[int]
    groups: list[Group] = field(default_factory=list)

    @property
    def params(self) -> dict[str, str]:
        p = {"scope": self.kind}
        if self.kind in ("group", "sector") or (self.kind == "risks" and self.value):
            p["value"] = self.value
        return p


def resolve_scope(user: Any, kind: str, value: str = "") -> Scope:
    from threatledger.risks.models import RiskTechnique
    from threatledger.risks.services import visible_risks

    kind = kind if kind in SCOPES else "risks"
    active = Technique.objects.active()
    if kind == "all":
        return Scope(
            "all", "", "All Enterprise techniques", set(active.values_list("pk", flat=True))
        )
    if kind == "group":
        group = Group.objects.active().filter(attack_id__iexact=value).first()
        if group is None:
            return Scope("group", value, "Unknown group", set())
        ids = set(
            GroupTechnique.objects.filter(group=group, technique__in=active).values_list(
                "technique_id", flat=True
            )
        )
        return Scope("group", group.attack_id, f"{group.name} ({group.attack_id})", ids, [group])
    if kind == "sector":
        sector = sectors().get(value)
        if sector is None:
            return Scope("sector", value, "Unknown sector", set())
        groups = list(
            Group.objects.active().filter(attack_id__in=sector["groups"]).order_by("name")
        )
        ids = set(
            GroupTechnique.objects.filter(group__in=groups, technique__in=active).values_list(
                "technique_id", flat=True
            )
        )
        return Scope("sector", value, f"{sector['label']} ({len(groups)} groups)", ids, groups)
    risks = visible_risks(user).live()
    label = "Techniques in your risk register"
    if value == "mine":
        risks = risks.filter(owner=user)
        label = "Techniques in risks you own"
    ids = set(
        RiskTechnique.objects.filter(risk__in=risks, technique__in=active).values_list(
            "technique_id", flat=True
        )
    )
    return Scope("risks", "mine" if value == "mine" else "", label, ids)


@dataclass
class Cell:
    technique: Technique
    coverage: TechniqueCoverage
    in_scope: bool
    subtechniques: list[tuple[Technique, TechniqueCoverage, bool]]

    @property
    def sub_in_scope(self) -> int:
        return sum(1 for _, _, s in self.subtechniques if s)


@dataclass
class Matrix:
    scope: Scope
    columns: list[tuple[Tactic, list[Cell]]]
    summary: CoverageSummary
    coverage: dict[int, TechniqueCoverage]
    controls: dict[int, Control]
    techniques: dict[int, Technique] = field(default_factory=dict)
    tactic_shortnames: dict[int, list[str]] = field(
        default_factory=dict
    )  # technique -> own tactics


def build_matrix(scope: Scope, org: Organisation) -> Matrix:
    tactics = list(Tactic.objects.active().exclude(order=None).order_by("order"))
    techniques = list(
        Technique.objects.active()
        .prefetch_related(
            Prefetch("tactics", queryset=Tactic.objects.only("pk", "shortname", "order"))
        )
        .order_by("attack_id")
    )
    by_parent: dict[int, list[Technique]] = defaultdict(list)
    for t in techniques:
        if t.parent_id:
            by_parent[t.parent_id].append(t)
    in_scope = scope.technique_ids
    tops = [
        t
        for t in techniques
        if not t.is_subtechnique
        and (t.pk in in_scope or any(s.pk in in_scope for s in by_parent[t.pk]))
    ]
    shown = {t.pk for t in tops} | {s.pk for t in tops for s in by_parent[t.pk]}
    cov = coverage_for(shown, org.pk)
    columns: list[tuple[Tactic, list[Cell]]] = []
    for tactic in tactics:
        cells = []
        for t in tops:
            if tactic.pk not in {x.pk for x in t.tactics.all()}:
                continue
            subs = [(s, cov[s.pk], s.pk in in_scope) for s in by_parent[t.pk]]
            cells.append(Cell(t, cov[t.pk], t.pk in in_scope, subs))
        cells.sort(
            key=lambda c: (
                -int(c.in_scope or c.sub_in_scope > 0),
                c.coverage.status,
                c.technique.name,
            )
        )
        columns.append((tactic, cells))
    summary = summarise(cov[pk] for pk in in_scope if pk in cov)
    control_ids = {c for tc in cov.values() for c in tc.control_ids}
    controls = Control.objects.in_bulk(control_ids)
    order = {t.pk: t.order for t in tactics}
    return Matrix(
        scope,
        columns,
        summary,
        cov,
        controls,
        techniques={t.pk: t for t in techniques if t.pk in shown},
        tactic_shortnames={
            t.pk: [
                x.shortname
                for x in sorted(t.tactics.all(), key=lambda x: order.get(x.pk, 99))
                if x.pk in order
            ]
            for t in techniques
            if t.pk in shown
        },
    )


def navigator_layer(matrix: Matrix, attack_version: str, org_name: str) -> dict[str, Any]:
    """ATT&CK Navigator layer, format 4.5."""
    entries = []
    status_score = {Coverage.GAP: 0, Coverage.PARTIAL: 1, Coverage.COVERED: 2}
    in_scope = sorted(
        (pk for pk in matrix.scope.technique_ids if pk in matrix.techniques),
        key=lambda pk: matrix.techniques[pk].attack_id,
    )
    for pk in in_scope:
        technique, cov = matrix.techniques[pk], matrix.coverage[pk]
        controls = sorted(matrix.controls[c].ref for c in cov.control_ids if c in matrix.controls)
        comment = f"{cov.status.label}{' (via parent)' if cov.inherited else ''}" + (
            f" — controls: {', '.join(controls)}" if controls else " — no mapped control"
        )
        # One entry per technique-tactic pair, using the technique's OWN tactics: a
        # sub-technique can sit under tactics its parent doesn't (e.g. T1059.001).
        for shortname in matrix.tactic_shortnames.get(pk, []):
            entries.append(
                {
                    "techniqueID": technique.attack_id,
                    "tactic": shortname,
                    "score": status_score[cov.status],
                    "color": COLOURS[cov.status],
                    "comment": comment,
                    "enabled": True,
                    "metadata": [{"name": "controls", "value": ", ".join(controls) or "none"}],
                    "links": [],
                    "showSubtechniques": False,
                }
            )
    major = attack_version.split(".")[0] if attack_version else ""
    return {
        "name": f"ThreatLedger coverage — {matrix.scope.label}"[:200],
        "versions": {"attack": major, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Control coverage for {org_name}. Green = covered (implemented control), "
        "amber = partial, red = gap. Generated by ThreatLedger.",
        "filters": {"platforms": []},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": entries,
        "gradient": {
            "colors": [COLOURS[Coverage.GAP], COLOURS[Coverage.PARTIAL], COLOURS[Coverage.COVERED]],
            "minValue": 0,
            "maxValue": 2,
        },
        "legendItems": [
            {"label": c.label, "color": COLOURS[c]}
            for c in (Coverage.COVERED, Coverage.PARTIAL, Coverage.GAP)
        ],
        "metadata": [
            {"name": "scope", "value": matrix.scope.label},
            {"name": "coverage", "value": f"{matrix.summary.percent}%"},
        ],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }
