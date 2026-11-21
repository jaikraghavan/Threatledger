from __future__ import annotations

from typing import Any

from django.http import Http404
from django.utils import timezone
from django.views.generic import TemplateView

from threatledger.accounts.permissions import (
    AccessControlMixin,
    can,
    current_organisation,
    get_role,
)
from threatledger.accounts.roles import Cap
from threatledger.risks.heatmaps import band_counts as _band_counts
from threatledger.risks.heatmaps import grid as _grid
from threatledger.risks.services import visible_risks

from . import services


def _org(request: Any) -> Any:
    org = current_organisation(request.user)
    if org is None:
        raise Http404("No organisation configured")
    return org


def dashboard_context(request: Any) -> dict[str, Any]:
    org = _org(request)
    risk_qs = visible_risks(request.user)
    k = services.kpis(org, risk_qs)
    from collections import Counter

    values = [
        (r.inherent_likelihood, r.inherent_impact, r.residual_likelihood, r.residual_impact)
        for r in services._open_risks(org, risk_qs)
    ]
    return {
        "org": org,
        "k": k,
        "role": get_role(request.user),
        "residual_grid": _grid(k["matrix"], Counter((v[2], v[3]) for v in values)),
        "inherent_grid": _grid(k["matrix"], Counter((v[0], v[1]) for v in values)),
        "impact_header": [(i, k["matrix"].impact_label(i)) for i in k["matrix"].scale],
        "band_counts": _band_counts(k["matrix"], values),
        "threat_gaps": services.top_threat_gaps(org, risk_qs),
        "priorities": services.control_priorities(org),
        "compliance_series": services.compliance_series(org),
        "risk_series": services.risk_series(org),
        "coverage_series": services.coverage_series(org),
        "can_view_frameworks": can(request.user, Cap.VIEW_FRAMEWORKS),
        "gov": services.governance_kpis(request.user),
        "generated_at": timezone.now(),
    }


class DashboardView(AccessControlMixin, TemplateView):
    tl_access = Cap.VIEW_DASHBOARD
    template_name = "reporting/dashboard.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        ctx.update(dashboard_context(self.request))
        return ctx


class BoardReportView(AccessControlMixin, TemplateView):
    tl_access = Cap.VIEW_DASHBOARD
    template_name = "reporting/board_report.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        ctx.update(dashboard_context(self.request))
        from threatledger.risks.models import RiskAcceptance

        ctx["acceptances"] = (
            RiskAcceptance.objects.filter(
                risk__in=visible_risks(self.request.user), status=RiskAcceptance.Status.APPROVED
            )
            .select_related("risk", "decided_by")
            .order_by("expires_on")
        )
        return ctx
