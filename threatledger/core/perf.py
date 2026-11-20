"""Performance check: N synthetic risks + timing of every key page (PLAN.md Phase 7)."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.db import connection, transaction
from django.test import Client
from django.test.utils import CaptureQueriesContext

PERF_TAG = "[perf]"


@transaction.atomic
def ensure_risks(total: int, seed: int = 42) -> int:
    """Top the register up to ``total`` risks with synthetic ones (bulk, no audit noise)."""
    from threatledger.attack.models import Technique
    from threatledger.controls.models import Control
    from threatledger.org.models import Organisation
    from threatledger.risks.models import (
        Category,
        Risk,
        RiskControl,
        RiskScoreHistory,
        RiskTechnique,
    )
    from threatledger.risks.services import next_ref

    org = Organisation.objects.current()
    if org is None:
        raise RuntimeError("No organisation; run seed first.")
    existing = Risk.objects.filter(organisation=org).count()
    missing = max(0, total - existing)
    if not missing:
        return 0
    rng = random.Random(seed)  # noqa: S311  # nosec B311 - synthetic perf data only
    techniques = list(Technique.objects.active().values_list("pk", flat=True))
    controls = list(Control.objects.filter(organisation=org).values_list("pk", flat=True))
    start = int(next_ref(org).split("-")[1])
    cats = Category.values
    risks = []
    for i in range(missing):
        il, ii = rng.randint(2, 5), rng.randint(2, 5)
        rl, ri = rng.randint(1, il), rng.randint(1, ii)
        risks.append(
            Risk(
                organisation=org,
                ref=f"R-{start + i:04d}",
                title=f"{PERF_TAG} Synthetic risk {start + i}",
                scenario="Synthetic scenario for performance testing.",
                category=rng.choice(cats),
                inherent_likelihood=il,
                inherent_impact=ii,
                residual_likelihood=rl,
                residual_impact=ri,
            )
        )
    Risk.objects.bulk_create(risks, batch_size=500)
    created = list(
        Risk.objects.filter(
            organisation=org, title__startswith=PERF_TAG, ref__in=[r.ref for r in risks]
        )
    )
    links, clinks, hist = [], [], []
    for r in created:
        for tid in rng.sample(techniques, k=min(len(techniques), rng.randint(2, 8))):
            links.append(RiskTechnique(risk=r, technique_id=tid))
        for cid in rng.sample(controls, k=min(len(controls), rng.randint(0, 3))):
            clinks.append(RiskControl(risk=r, control_id=cid))
        hist.append(RiskScoreHistory(risk=r, reason="perf", **r.scores()))
    RiskTechnique.objects.bulk_create(links, batch_size=1000, ignore_conflicts=True)
    RiskControl.objects.bulk_create(clinks, batch_size=1000, ignore_conflicts=True)
    RiskScoreHistory.objects.bulk_create(hist, batch_size=1000)
    return missing


@dataclass
class Timing:
    url: str
    status: int
    ms: float
    queries: int


def default_urls() -> list[str]:
    from threatledger.risks.models import Risk

    sample = Risk.objects.order_by("-id").values_list("ref", flat=True).first() or "R-0001"
    return [
        "/",
        "/risks/",
        "/risks/?q=synthetic",
        "/risks/?band=critical",
        "/risks/heatmap/",
        f"/risks/{sample}/",
        "/risks/export/?format=csv",
        "/coverage/?scope=risks",
        "/coverage/?scope=all",
        "/frameworks/",
        "/frameworks/NIST-800-53-R5/",
        "/attack/techniques/",
        "/controls/",
        "/reports/board/",
        "/api/v1/risks/",
        "/api/v1/coverage/?scope=risks",
    ]


def time_pages(urls: list[str], username: str = "admin") -> list[Timing]:
    from threatledger.accounts.models import User

    host = (settings.ALLOWED_HOSTS or ["localhost"])[0].lstrip(".")
    host = "localhost" if host in ("*", "") else host
    client = Client(HTTP_HOST=host)
    client.force_login(User.objects.get(username=username))
    out = []
    for url in urls:
        client.get(url, secure=True)  # warm caches
        start = time.perf_counter()
        with CaptureQueriesContext(connection) as q:
            response = client.get(url, secure=True)
            if hasattr(response, "streaming_content"):
                b"".join(response.streaming_content)
        out.append(
            Timing(
                url,
                response.status_code,
                round((time.perf_counter() - start) * 1000, 1),
                len(q.captured_queries),
            )
        )
    return out


def run(total: int = 1000) -> tuple[int, list[Timing], dict[str, Any]]:
    from threatledger.attack.models import Technique
    from threatledger.risks.models import Risk, RiskTechnique

    added = ensure_risks(total)
    timings = time_pages(default_urls())
    stats = {
        "risks": Risk.objects.count(),
        "risk_technique_links": RiskTechnique.objects.count(),
        "techniques": Technique.objects.active().count(),
    }
    return added, timings, stats
