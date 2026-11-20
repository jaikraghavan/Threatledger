"""Risk list filtering and sorting from query parameters (shared by list, heatmap, export)."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from django.db.models import Q
from django.http import QueryDict
from django.utils import timezone

from .models import Band, Category, RiskMatrix, RiskQuerySet, RiskStatus

_CELL = re.compile(r"^(inherent|residual):(\d{1,2}):(\d{1,2})$")
SORTS = {
    "ref": ("ref",),
    "-ref": ("-ref",),
    "title": ("title",),
    "residual": ("-residual_score", "ref"),
    "inherent": ("-inherent_score", "ref"),
    "review": ("next_review_date", "ref"),
    "target": ("target_date", "ref"),
}
DEFAULT_SORT = "residual"


def parse(params: QueryDict) -> dict[str, str]:
    def get(key: str, limit: int = 100) -> str:
        return params.get(key, "").strip()[:limit]

    f = {
        "q": get("q"),
        "status": get("status", 20),
        "category": get("category", 20),
        "bu": get("bu", 10),
        "owner": get("owner", 10),
        "band": get("band", 10),
        "band_of": "inherent" if get("band_of") == "inherent" else "residual",
        "cell": get("cell", 20),
        "technique": get("technique", 12).upper(),
        "review": get("review", 10),
        "archived": "1" if get("archived") == "1" else "",
        "sort": get("sort", 12) if get("sort", 12) in SORTS else DEFAULT_SORT,
    }
    return f


def apply(qs: RiskQuerySet, f: dict[str, str], matrix: RiskMatrix, user: Any) -> RiskQuerySet:
    qs = qs.with_scores()
    qs = qs.filter(archived_at__isnull=False) if f["archived"] else qs.live()
    if f["q"]:
        qs = qs.filter(
            Q(ref__iexact=f["q"]) | Q(title__icontains=f["q"]) | Q(scenario__icontains=f["q"])
        )
    if f["status"] == "active":
        qs = qs.exclude(status=RiskStatus.CLOSED)
    elif f["status"] in RiskStatus.values:
        qs = qs.filter(status=f["status"])
    if f["category"] in Category.values:
        qs = qs.filter(category=f["category"])
    if f["bu"].isdigit():
        qs = qs.filter(business_unit_id=int(f["bu"]))
    if f["owner"] == "me":
        qs = qs.filter(owner=user)
    elif f["owner"].isdigit():
        qs = qs.filter(owner_id=int(f["owner"]))
    if f["band"] in Band.values:
        lo, hi = matrix.band_range(f["band"])
        field = f"{f['band_of']}_score"
        qs = qs.filter(**{f"{field}__gte": lo, f"{field}__lte": hi})
    m = _CELL.match(f["cell"])
    if m:
        kind, likelihood, impact = m.group(1), int(m.group(2)), int(m.group(3))
        qs = qs.filter(**{f"{kind}_likelihood": likelihood, f"{kind}_impact": impact})
    if f["technique"]:
        qs = qs.filter(techniques__attack_id=f["technique"])
    today = timezone.localdate()
    if f["review"] == "overdue":
        qs = qs.review_overdue()
    elif f["review"] == "due30":
        qs = qs.filter(
            next_review_date__gte=today, next_review_date__lte=today + timedelta(days=30)
        )
    return qs.distinct().order_by(*SORTS[f["sort"]])
