from __future__ import annotations

from collections import Counter
from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import F, Q, QuerySet
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views import View
from django.views.generic import DetailView, ListView, TemplateView

from threatledger.accounts.permissions import (
    AccessControlMixin,
    access,
    can,
    current_organisation,
)
from threatledger.accounts.roles import Cap
from threatledger.attack.models import Technique
from threatledger.audit.models import Action, AuditEvent
from threatledger.audit.services import record
from threatledger.controls.models import Control
from threatledger.coverage.engine import summarise
from threatledger.coverage.selectors import coverage_for

from . import exports, filters, services
from .forms import AcceptanceForm, AssetForm, DecisionForm, MatrixForm, RiskForm
from .models import (
    Asset,
    Band,
    Category,
    Risk,
    RiskAcceptance,
    RiskControl,
    RiskMatrix,
    RiskStatus,
    RiskTechnique,
)


def _matrix(request: HttpRequest) -> RiskMatrix:
    org = current_organisation(request.user)
    if org is None:
        raise Http404("No organisation configured")
    return RiskMatrix.for_org(org)


def _risk(request: HttpRequest, ref: str) -> Risk:
    return get_object_or_404(
        services.visible_risks(request.user).select_related("owner", "business_unit", "created_by"),
        ref=ref,
    )


def _is_htmx(request: HttpRequest) -> bool:
    return bool(getattr(request, "htmx", False))


# ----------------------------------------------------------------------------- register
class RiskListView(AccessControlMixin, ListView):
    tl_access = Cap.VIEW_RISKS
    template_name = "risks/risk_list.html"
    context_object_name = "risks"
    paginate_by = 25

    def get_template_names(self) -> list[str]:
        return ["risks/_risk_table.html"] if _is_htmx(self.request) else [self.template_name]

    def get_queryset(self) -> QuerySet[Risk]:
        self.matrix = _matrix(self.request)
        self.filters = filters.parse(self.request.GET)
        qs = services.visible_risks(self.request.user)
        return filters.apply(qs, self.filters, self.matrix, self.request.user).select_related(
            "owner", "business_unit"
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        params = self.request.GET.copy()
        params.pop("page", None)
        ctx.update(
            matrix=self.matrix,
            filters=self.filters,
            querystring=params.urlencode(),
            statuses=RiskStatus.choices,
            categories=Category.choices,
            bands=Band.choices,
            business_units=_bus(self.request.user),
            can_edit=can(self.request.user, Cap.EDIT_RISKS),
            can_export=can(self.request.user, Cap.EXPORT_DATA),
            sorts=[
                ("residual", "Residual score"),
                ("inherent", "Inherent score"),
                ("ref", "Reference"),
                ("title", "Title"),
                ("review", "Next review"),
                ("target", "Target date"),
            ],
        )
        return ctx


def _bus(user: Any) -> Any:
    from threatledger.core.forms import scoped_business_units

    return scoped_business_units(user)


class RiskDetailView(AccessControlMixin, DetailView):
    tl_access = Cap.VIEW_RISKS
    template_name = "risks/risk_detail.html"
    context_object_name = "risk"

    def get_object(self, queryset: QuerySet[Risk] | None = None) -> Risk:
        return _risk(self.request, self.kwargs["ref"])

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        risk: Risk = self.object
        ctx.update(_panel_context(self.request, risk))
        ctx["matrix"] = _matrix(self.request)
        ctx["history"] = risk.score_history.select_related("changed_by")[:20]
        ctx["acceptances"] = risk.acceptances.select_related("requested_by", "decided_by")
        ctx["can_request_acceptance"] = (
            ctx["can_edit"]
            and not risk.acceptances.filter(status=RiskAcceptance.Status.PENDING).exists()
        )
        ctx["acceptance_form"] = AcceptanceForm()
        ctx["can_decide"] = can(self.request.user, Cap.APPROVE_ACCEPTANCE)
        if can(self.request.user, Cap.VIEW_AUDIT_LOG):
            ctx["audit_events"] = AuditEvent.objects.filter(
                object_type="risks.risk", object_id=str(risk.pk)
            ).order_by("-id")[:15]
        return ctx


def _panel_context(request: HttpRequest, risk: Risk) -> dict[str, Any]:
    """Context for the technique and control panels (also used by HTMX refreshes)."""
    technique_links = list(
        risk.technique_links.select_related("technique", "technique__revoked_by").order_by(
            "technique__attack_id"
        )
    )
    cov = coverage_for((link.technique_id for link in technique_links), risk.organisation_id)
    controls = Control.objects.in_bulk({c for tc in cov.values() for c in tc.control_ids})
    rows = []
    for link in technique_links:
        tc = cov[link.technique_id]
        rows.append(
            {
                "link": link,
                "coverage": tc,
                "controls": sorted(
                    (controls[c] for c in tc.control_ids if c in controls), key=lambda c: c.ref
                ),
                "replacement": link.technique.replacement() if link.technique.is_revoked else None,
            }
        )
    return {
        "risk": risk,
        "technique_rows": rows,
        "coverage_summary": summarise(cov.values()),
        "control_links": risk.control_links.select_related("control", "control__owner"),
        "suggestions": services.suggested_controls(risk),
        "uncovered_mitigations": services.uncovered_mitigations(risk)[:10],
        "can_edit": services.can_edit_risk(request.user, risk),
    }


class RiskFormMixin(AccessControlMixin):
    tl_access = Cap.EDIT_RISKS
    template_name = "risks/risk_form.html"

    def render_form(self, request: HttpRequest, form: RiskForm, risk: Risk | None) -> HttpResponse:
        return render(
            request, self.template_name, {"form": form, "risk": risk, "matrix": form.matrix}
        )


class RiskCreateView(RiskFormMixin, View):
    def get(self, request: HttpRequest) -> HttpResponse:
        form = RiskForm(user=request.user, matrix=_matrix(request), initial={"owner": request.user})
        return self.render_form(request, form, None)

    def post(self, request: HttpRequest) -> HttpResponse:
        form = RiskForm(request.POST, user=request.user, matrix=_matrix(request))
        if form.is_valid():
            try:
                risk = services.create_risk(
                    user=request.user, data=form.model_data(), assets=form.cleaned_data["assets"]
                )
            except (services.RiskError, ValidationError) as exc:
                form.add_error(None, _message(exc))
            else:
                messages.success(
                    request, f"Created {risk.ref}. Now link ATT&CK techniques and controls."
                )
                return redirect("risks:detail", ref=risk.ref)
        return self.render_form(request, form, None)


class RiskUpdateView(RiskFormMixin, View):
    def _get(self, request: HttpRequest, ref: str) -> Risk:
        risk = _risk(request, ref)
        if not services.can_edit_risk(request.user, risk):
            raise PermissionDenied
        return risk

    def get(self, request: HttpRequest, ref: str) -> HttpResponse:
        risk = self._get(request, ref)
        form = RiskForm(instance=risk, user=request.user, matrix=_matrix(request))
        return self.render_form(request, form, risk)

    def post(self, request: HttpRequest, ref: str) -> HttpResponse:
        risk = self._get(request, ref)
        form = RiskForm(request.POST, instance=risk, user=request.user, matrix=_matrix(request))
        if form.is_valid():
            try:
                services.update_risk(
                    Risk.objects.get(pk=risk.pk),  # fresh copy: the form mutated `risk`
                    user=request.user,
                    data=form.model_data(),
                    assets=form.cleaned_data["assets"],
                    reason=form.cleaned_data.get("reason", ""),
                )
            except (services.RiskError, ValidationError) as exc:
                form.add_error(None, _message(exc))
            else:
                messages.success(request, f"Saved {ref}.")
                return redirect("risks:detail", ref=ref)
        return self.render_form(request, form, risk)


def _message(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return " ".join(exc.messages)
    return str(exc)


@access(Cap.EDIT_RISKS)
def risk_archive(request: HttpRequest, ref: str) -> HttpResponse:
    if request.method != "POST":
        return HttpResponse(status=405)
    risk = _risk(request, ref)
    try:
        if request.POST.get("restore"):
            services.restore_risk(risk, user=request.user)
            messages.success(request, f"Restored {ref}.")
        else:
            services.archive_risk(risk, user=request.user)
            messages.success(request, f"Archived {ref}.")
    except services.RiskError as exc:
        raise PermissionDenied(str(exc)) from exc
    return redirect("risks:detail", ref=ref)


# ----------------------------------------------------------------------------- panels (HTMX)
def _render_panel(request: HttpRequest, risk: Risk, template: str, **extra: Any) -> HttpResponse:
    ctx = _panel_context(request, risk)
    ctx.update(extra)
    return render(request, template, ctx)


def _post_only(request: HttpRequest) -> None:
    if request.method != "POST":
        raise PermissionDenied("POST required")


def _editable(request: HttpRequest, ref: str) -> Risk:
    risk = _risk(request, ref)
    if not services.can_edit_risk(request.user, risk):
        raise PermissionDenied
    return risk


@access(Cap.EDIT_RISKS)
def technique_search(request: HttpRequest, ref: str) -> HttpResponse:
    risk = _editable(request, ref)
    q = request.GET.get("q", "").strip()[:100]
    results: list[Technique] = []
    if len(q) >= 2:
        linked = risk.technique_links.values_list("technique_id", flat=True)
        results = list(
            Technique.objects.active()
            .filter(Q(attack_id__istartswith=q) | Q(name__icontains=q))
            .exclude(pk__in=linked)
            .select_related("parent")
            .order_by("attack_id")[:15]
        )
    return render(
        request, "risks/_technique_results.html", {"risk": risk, "results": results, "q": q}
    )


@access(Cap.EDIT_RISKS)
def technique_add(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    risk = _editable(request, ref)
    technique = get_object_or_404(Technique, pk=request.POST.get("technique"))
    error = None
    try:
        services.link_technique(risk, technique, user=request.user)
    except services.RiskError as exc:
        error = str(exc)
    return _render_panel(request, risk, "risks/_panels.html", panel_error=error)


@access(Cap.EDIT_RISKS)
def technique_remove(request: HttpRequest, ref: str, link_id: int) -> HttpResponse:
    _post_only(request)
    risk = _editable(request, ref)
    link = get_object_or_404(RiskTechnique, pk=link_id, risk=risk)
    services.unlink_technique(risk, link, user=request.user)
    return _render_panel(request, risk, "risks/_panels.html")


@access(Cap.EDIT_RISKS)
def technique_remap(request: HttpRequest, ref: str, link_id: int) -> HttpResponse:
    _post_only(request)
    risk = _editable(request, ref)
    link = get_object_or_404(RiskTechnique, pk=link_id, risk=risk)
    error = None
    try:
        services.remap_revoked_technique(risk, link, user=request.user)
    except services.RiskError as exc:
        error = str(exc)
    return _render_panel(request, risk, "risks/_panels.html", panel_error=error)


@access(Cap.EDIT_RISKS)
def control_search(request: HttpRequest, ref: str) -> HttpResponse:
    risk = _editable(request, ref)
    q = request.GET.get("q", "").strip()[:100]
    results: list[Control] = []
    if len(q) >= 1:
        linked = risk.control_links.values_list("control_id", flat=True)
        results = list(
            Control.objects.live()
            .filter(organisation_id=risk.organisation_id)
            .filter(Q(ref__icontains=q) | Q(name__icontains=q))
            .exclude(pk__in=linked)
            .order_by("ref")[:15]
        )
    return render(
        request, "risks/_control_results.html", {"risk": risk, "results": results, "q": q}
    )


@access(Cap.EDIT_RISKS)
def control_add(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    risk = _editable(request, ref)
    control = get_object_or_404(
        Control, pk=request.POST.get("control"), organisation=risk.organisation
    )
    error = None
    try:
        services.link_control(risk, control, user=request.user)
    except services.RiskError as exc:
        error = str(exc)
    return _render_panel(request, risk, "risks/_panels.html", panel_error=error)


@access(Cap.EDIT_RISKS)
def control_remove(request: HttpRequest, ref: str, link_id: int) -> HttpResponse:
    _post_only(request)
    risk = _editable(request, ref)
    link = get_object_or_404(RiskControl, pk=link_id, risk=risk)
    services.unlink_control(risk, link, user=request.user)
    return _render_panel(request, risk, "risks/_panels.html")


# ----------------------------------------------------------------------------- acceptance
@access(Cap.EDIT_RISKS)
def acceptance_request(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    risk = _editable(request, ref)
    form = AcceptanceForm(request.POST)
    if form.is_valid():
        try:
            services.request_acceptance(
                risk,
                user=request.user,
                justification=form.cleaned_data["justification"],
                expires_on=form.cleaned_data["expires_on"],
            )
            messages.success(request, "Acceptance requested. Another approver must decide it.")
        except services.RiskError as exc:
            messages.error(request, str(exc))
    else:
        messages.error(request, "Provide a justification and a valid expiry date.")
    return redirect("risks:detail", ref=ref)


@access(Cap.APPROVE_ACCEPTANCE)
def acceptance_decide(request: HttpRequest, pk: int) -> HttpResponse:
    _post_only(request)
    acc = get_object_or_404(
        RiskAcceptance.objects.select_related("risk"),
        pk=pk,
        risk__in=services.visible_risks(request.user),
    )
    form = DecisionForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Choose approve or reject.")
    else:
        try:
            services.decide_acceptance(
                acc,
                user=request.user,
                approve=form.cleaned_data["decision"] == "approve",
                note=form.cleaned_data["note"],
            )
            messages.success(request, f"Acceptance {acc.get_status_display().lower()}.")
        except services.RiskError as exc:
            messages.error(request, str(exc))
    if request.POST.get("next_page") == "queue":
        return redirect("risks:acceptances")
    return redirect("risks:detail", ref=acc.risk.ref)


class AcceptanceListView(AccessControlMixin, ListView):
    tl_access = Cap.VIEW_RISKS
    template_name = "risks/acceptance_list.html"
    context_object_name = "acceptances"
    paginate_by = 50

    def get_queryset(self) -> QuerySet[RiskAcceptance]:
        qs = RiskAcceptance.objects.filter(risk__in=services.visible_risks(self.request.user))
        status = self.request.GET.get("status", "pending")
        if status in RiskAcceptance.Status.values:
            qs = qs.filter(status=status)
        return qs.select_related("risk", "requested_by", "decided_by").order_by("expires_on")

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        ctx["status"] = self.request.GET.get("status", "pending")
        ctx["statuses"] = RiskAcceptance.Status.choices
        ctx["can_decide"] = can(self.request.user, Cap.APPROVE_ACCEPTANCE)
        return ctx


# ----------------------------------------------------------------------------- heatmap
class HeatmapView(AccessControlMixin, TemplateView):
    tl_access = Cap.VIEW_RISKS
    template_name = "risks/heatmap.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        matrix = _matrix(self.request)
        f = filters.parse(self.request.GET)
        f["cell"] = ""
        qs = filters.apply(services.visible_risks(self.request.user), f, matrix, self.request.user)
        values = list(qs.values_list(*[
            "inherent_likelihood", "inherent_impact", "residual_likelihood", "residual_impact"
        ]))  # fmt: skip
        ctx.update(
            matrix=matrix,
            filters=f,
            total=len(values),
            heatmaps=[
                ("inherent", "Inherent risk", _grid(matrix, Counter((v[0], v[1]) for v in values))),
                ("residual", "Residual risk", _grid(matrix, Counter((v[2], v[3]) for v in values))),
            ],
            band_counts=_band_counts(matrix, values),
            impact_header=[(i, matrix.impact_label(i)) for i in matrix.scale],
            statuses=RiskStatus.choices,
            categories=Category.choices,
            business_units=_bus(self.request.user),
        )
        return ctx


def _grid(matrix: RiskMatrix, counts: Counter[tuple[int, int]]) -> list[dict[str, Any]]:
    """Rows from highest likelihood down; each row has one cell per impact value."""
    rows = []
    for likelihood in reversed(matrix.scale):
        cells = []
        for impact in matrix.scale:
            score = likelihood * impact
            cells.append(
                {
                    "likelihood": likelihood,
                    "impact": impact,
                    "score": score,
                    "band": matrix.band(score),
                    "count": counts.get((likelihood, impact), 0),
                }
            )
        rows.append(
            {"likelihood": likelihood, "label": matrix.likelihood_label(likelihood), "cells": cells}
        )
    return rows


def _band_counts(matrix: RiskMatrix, values: list[tuple[int, ...]]) -> list[dict[str, Any]]:
    out = []
    for band in Band:
        out.append(
            {
                "band": band,
                "inherent": sum(1 for v in values if matrix.band(v[0] * v[1]) == band),
                "residual": sum(1 for v in values if matrix.band(v[2] * v[3]) == band),
            }
        )
    return out


# ----------------------------------------------------------------------------- export
@access(Cap.EXPORT_DATA)
def export(request: HttpRequest) -> HttpResponse:
    fmt = request.GET.get("format", "csv")
    if fmt not in ("csv", "xlsx"):
        raise Http404
    matrix = _matrix(request)
    f = filters.parse(request.GET)
    qs = filters.apply(services.visible_risks(request.user), f, matrix, request.user)
    stamp = timezone.localdate().isoformat()
    data = list(exports.rows(qs, matrix))
    if fmt == "csv":
        body, ctype = exports.to_csv(data), "text/csv; charset=utf-8"
    else:
        body = exports.to_xlsx(data)
        ctype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    record(
        Action.EXPORT,
        actor=request.user,
        object_type="risks.risk",
        object_repr=f"Risk register ({fmt}, {len(data)} rows)",
        changes={
            "format": [None, fmt],
            "rows": [None, len(data)],
            "filters": [None, {k: v for k, v in f.items() if v}],
        },
    )
    response = HttpResponse(body, content_type=ctype)
    response["Content-Disposition"] = f'attachment; filename="risk-register-{stamp}.{fmt}"'
    response["X-Content-Type-Options"] = "nosniff"
    return response


# ----------------------------------------------------------------------------- matrix settings
class MatrixSettingsView(AccessControlMixin, View):
    tl_access = Cap.MANAGE_SETTINGS
    template_name = "risks/matrix_settings.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        matrix = _matrix(request)
        form = MatrixForm(initial=MatrixForm.initial_for(matrix))
        return render(request, self.template_name, {"form": form, "matrix": matrix})

    def post(self, request: HttpRequest) -> HttpResponse:
        matrix = _matrix(request)
        form = MatrixForm(request.POST)
        if form.is_valid():
            try:
                services.update_matrix(matrix, user=request.user, data=form.matrix_data())
            except ValidationError as exc:
                for field, errors in exc.message_dict.items():
                    form.add_error(field if field in form.fields else None, errors)
                matrix.refresh_from_db()
            else:
                messages.success(request, "Risk matrix saved.")
                return redirect("risks:matrix")
        return render(request, self.template_name, {"form": form, "matrix": matrix})


# ----------------------------------------------------------------------------- assets
class AssetListView(AccessControlMixin, ListView):
    tl_access = Cap.VIEW_RISKS
    template_name = "risks/asset_list.html"
    context_object_name = "assets"
    paginate_by = 50

    def get_queryset(self) -> QuerySet[Asset]:
        from django.db.models import Count

        qs = services.visible_assets(self.request.user).filter(archived_at__isnull=True)
        q = self.request.GET.get("q", "").strip()[:100]
        if q:
            qs = qs.filter(name__icontains=q)
        if self.request.GET.get("personal") == "1":
            qs = qs.filter(contains_personal_data=True)
        return (
            qs.select_related("owner", "business_unit")
            .annotate(risk_count=Count("risks", filter=Q(risks__archived_at__isnull=True)))
            .order_by("-criticality", "name")
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        ctx["q"] = self.request.GET.get("q", "")
        ctx["personal"] = self.request.GET.get("personal") == "1"
        params = self.request.GET.copy()
        params.pop("page", None)
        ctx["querystring"] = params.urlencode()
        ctx["can_edit"] = can(self.request.user, Cap.EDIT_RISKS)
        return ctx


class AssetDetailView(AccessControlMixin, DetailView):
    tl_access = Cap.VIEW_RISKS
    template_name = "risks/asset_detail.html"
    context_object_name = "asset"

    def get_object(self, queryset: QuerySet[Asset] | None = None) -> Asset:
        return get_object_or_404(services.visible_assets(self.request.user), pk=self.kwargs["pk"])

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        ctx["risks"] = (
            services.visible_risks(self.request.user)
            .live()
            .with_scores()
            .filter(assets=self.object)
            .order_by((F("residual_likelihood") * F("residual_impact")).desc(), "ref")
        )
        ctx["matrix"] = _matrix(self.request)
        ctx["can_edit"] = can(self.request.user, Cap.EDIT_RISKS)
        return ctx


class AssetFormView(AccessControlMixin, View):
    tl_access = Cap.EDIT_RISKS
    template_name = "risks/asset_form.html"

    def _asset(self, request: HttpRequest, pk: int | None) -> Asset | None:
        if pk is None:
            return None
        return get_object_or_404(services.visible_assets(request.user), pk=pk)

    def get(self, request: HttpRequest, pk: int | None = None) -> HttpResponse:
        asset = self._asset(request, pk)
        form = AssetForm(instance=asset, user=request.user)
        return render(request, self.template_name, {"form": form, "asset": asset})

    def post(self, request: HttpRequest, pk: int | None = None) -> HttpResponse:
        asset = self._asset(request, pk)
        form = AssetForm(request.POST, instance=asset, user=request.user)
        if form.is_valid():
            try:
                saved = services.save_asset(form.save(commit=False), user=request.user)
            except (services.RiskError, ValidationError) as exc:
                form.add_error(None, _message(exc))
            else:
                messages.success(request, f"Saved asset {saved.name}.")
                return redirect(reverse("risks:asset_detail", args=[saved.pk]))
        return render(request, self.template_name, {"form": form, "asset": asset})
