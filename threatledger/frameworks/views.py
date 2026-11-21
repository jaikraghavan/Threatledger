from __future__ import annotations

from collections import OrderedDict
from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from django.views.generic import TemplateView

from threatledger.accounts.permissions import AccessControlMixin, access, can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.controls.models import Control
from threatledger.coverage.selectors import coverage_for

from . import services
from .compliance import ReqStatus
from .importer import FrameworkImportError
from .models import ControlRequirement, Framework, Requirement

STATUS_FILTERS = {
    "gaps": {ReqStatus.GAP, ReqStatus.NO_CONTROL},
    "met": {ReqStatus.MET},
    "partial": {ReqStatus.PARTIAL},
    "gap": {ReqStatus.GAP},
    "no_control": {ReqStatus.NO_CONTROL},
}


def _org(request: HttpRequest) -> Any:
    org = current_organisation(request.user)
    if org is None:
        raise Http404("No organisation configured")
    return org


def _framework(code: str) -> Framework:
    return get_object_or_404(Framework, code=code)


def _post_only(request: HttpRequest) -> None:
    if request.method != "POST":
        raise PermissionDenied("POST required")


class FrameworkListView(AccessControlMixin, TemplateView):
    tl_access = Cap.VIEW_FRAMEWORKS
    template_name = "frameworks/framework_list.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        org = _org(self.request)
        results = [services.framework_result(fw, org) for fw in Framework.objects.order_by("name")]
        ctx["adopted"] = [r for r in results if r.settings.adopted]
        ctx["not_adopted"] = [r for r in results if not r.settings.adopted]
        ctx["can_edit"] = can(self.request.user, Cap.EDIT_FRAMEWORKS)
        ctx["can_import"] = can(self.request.user, Cap.RUN_IMPORTS)
        return ctx


class FrameworkDetailView(AccessControlMixin, TemplateView):
    tl_access = Cap.VIEW_FRAMEWORKS
    template_name = "frameworks/framework_detail.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        fw = _framework(self.kwargs["code"])
        org = _org(self.request)
        result = services.framework_result(fw, org)
        status_filter = self.request.GET.get("status", "")
        wanted = STATUS_FILTERS.get(status_filter)
        q = self.request.GET.get("q", "").strip()[:100].lower()
        show_untracked = self.request.GET.get("untracked") == "1"
        domains: OrderedDict[int | None, dict[str, Any]] = OrderedDict()
        reqs = list(Requirement.objects.filter(framework=fw).order_by("order", "id"))
        by_id = {r.pk: r for r in reqs}
        for r in reqs:
            if r.is_domain and r.parent_id is None:
                domains[r.pk] = {"domain": r, "rows": [], "counts": dict.fromkeys(ReqStatus, 0)}
        for r in reqs:
            if r.is_domain:
                continue
            status = result.summary.by_requirement.get(r.pk)
            top = r
            while top.parent_id and top.parent_id in by_id:
                top = by_id[top.parent_id]
            group = domains.setdefault(
                top.pk if top.is_domain else None,
                {
                    "domain": top if top.is_domain else None,
                    "rows": [],
                    "counts": dict.fromkeys(ReqStatus, 0),
                },
            )
            if status:
                group["counts"][status] += 1
            if status is None and not show_untracked:
                continue
            if wanted is not None and status not in wanted:
                continue
            if q and q not in r.ref.lower() and q not in r.title.lower():
                continue
            group["rows"].append(
                {
                    "req": r,
                    "status": status,
                    "controls": sorted(
                        result.controls_by_requirement.get(r.pk, []), key=lambda c: c.ref
                    ),
                    "na": r.pk in result.not_applicable,
                    "parent": by_id.get(r.parent_id)
                    if r.parent_id and not by_id[r.parent_id].is_domain
                    else None,
                }
            )
        ctx.update(
            framework=fw,
            result=result,
            summary=result.summary,
            groups=[g for g in domains.values() if g["rows"]],
            status_filter=status_filter,
            q=self.request.GET.get("q", ""),
            show_untracked=show_untracked,
            can_edit=can(self.request.user, Cap.EDIT_FRAMEWORKS),
            filtered=bool(wanted or q),
        )
        return ctx


@access(Cap.EDIT_FRAMEWORKS)
def framework_settings(request: HttpRequest, code: str) -> HttpResponse:
    _post_only(request)
    fw = _framework(code)
    try:
        services.set_adoption(
            fw,
            user=request.user,
            adopted=request.POST.get("adopted") == "1",
            baseline=request.POST.get("baseline") if "baseline" in request.POST else None,
        )
        messages.success(request, f"Updated {fw.name}.")
    except services.FrameworkError as exc:
        messages.error(request, str(exc))
    if request.POST.get("next") == "list":
        return redirect("frameworks:list")
    return redirect("frameworks:detail", code=fw.code)


class RequirementDetailView(AccessControlMixin, TemplateView):
    tl_access = Cap.VIEW_FRAMEWORKS
    template_name = "frameworks/requirement_detail.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        fw = _framework(self.kwargs["code"])
        req = get_object_or_404(
            Requirement.objects.select_related("parent"), pk=self.kwargs["pk"], framework=fw
        )
        org = _org(self.request)
        ctx.update(_requirement_panel(self.request, req, org))
        ctx["framework"] = fw
        ctx["related"] = services.related_requirements(req, org)
        ctx["children"] = req.children.order_by("order")
        technique_links = list(
            req.technique_links.select_related("technique")
            .filter(technique__is_revoked=False)
            .order_by("technique__attack_id")
        )
        cov = coverage_for((t.technique_id for t in technique_links), org.pk)
        ctx["techniques"] = [(t.technique, cov[t.technique_id]) for t in technique_links]
        ctx["can_scope"] = can(self.request.user, Cap.EDIT_FRAMEWORKS)
        from threatledger.controls.views import governance_links

        ctx.update(governance_links(self.request.user, requirement=req))
        ctx["can_request_exception"] = can(self.request.user, Cap.REQUEST_EXCEPTION)
        ctx["exception_query"] = f"requirement={req.pk}"
        return ctx


def _requirement_panel(
    request: HttpRequest, req: Requirement, org: Any, error: str | None = None
) -> dict[str, Any]:
    status, controls, scope, in_baseline = services.requirement_state(req, org)
    links = {
        link.control_id: link
        for link in ControlRequirement.objects.filter(requirement=req, control__organisation=org)
    }
    return {
        "req": req,
        "status": status,
        "controls": [(c, links.get(c.pk)) for c in controls],
        "scope": scope,
        "in_baseline": in_baseline,
        "can_map": can(request.user, Cap.EDIT_MAPPINGS) and not req.is_domain,
        "panel_error": error,
    }


@access(Cap.EDIT_MAPPINGS)
def requirement_control_search(request: HttpRequest, code: str, pk: int) -> HttpResponse:
    req = get_object_or_404(Requirement, pk=pk, framework__code=code)
    org = _org(request)
    q = request.GET.get("q", "").strip()[:100]
    results: list[Control] = []
    if q:
        linked = ControlRequirement.objects.filter(requirement=req).values_list(
            "control_id", flat=True
        )
        results = list(
            Control.objects.filter(organisation=org, archived_at__isnull=True)
            .filter(Q(ref__icontains=q) | Q(name__icontains=q))
            .exclude(pk__in=linked)
            .order_by("ref")[:15]
        )
    return render(
        request, "frameworks/_control_results.html", {"req": req, "results": results, "q": q}
    )


@access(Cap.EDIT_MAPPINGS)
def requirement_map(request: HttpRequest, code: str, pk: int) -> HttpResponse:
    _post_only(request)
    req = get_object_or_404(Requirement, pk=pk, framework__code=code)
    org = _org(request)
    error = None
    try:
        if request.POST.get("remove"):
            link = get_object_or_404(
                ControlRequirement,
                pk=request.POST["remove"],
                requirement=req,
                control__organisation=org,
            )
            services.unmap_control(link, user=request.user)
        else:
            control = get_object_or_404(Control, pk=request.POST.get("control"), organisation=org)
            services.map_control(req, control, user=request.user)
    except services.FrameworkError as exc:
        error = str(exc)
    return render(
        request, "frameworks/_requirement_panel.html", _requirement_panel(request, req, org, error)
    )


@access(Cap.EDIT_FRAMEWORKS)
def requirement_scope(request: HttpRequest, code: str, pk: int) -> HttpResponse:
    _post_only(request)
    req = get_object_or_404(Requirement, pk=pk, framework__code=code)
    try:
        services.set_applicability(
            req,
            user=request.user,
            applicable=request.POST.get("applicable") == "1",
            justification=request.POST.get("justification", ""),
        )
        messages.success(request, "Scope updated.")
    except services.FrameworkError as exc:
        messages.error(request, str(exc))
    return redirect("frameworks:requirement", code=code, pk=pk)


class CrossFrameworkView(AccessControlMixin, TemplateView):
    tl_access = Cap.VIEW_FRAMEWORKS
    template_name = "frameworks/cross_framework.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        rows = services.cross_framework(_org(self.request))
        q = self.request.GET.get("q", "").strip().lower()[:100]
        if q:
            rows = [r for r in rows if q in r.control.ref.lower() or q in r.control.name.lower()]
        ctx["rows"] = rows
        ctx["q"] = self.request.GET.get("q", "")
        return ctx


class ImportView(AccessControlMixin, View):
    tl_access = Cap.RUN_IMPORTS
    template_name = "frameworks/import.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        return render(request, self.template_name, {})

    def post(self, request: HttpRequest) -> HttpResponse:
        if request.POST.get("action") == "seed":
            report = services.seed_frameworks(_org(request))
            messages.success(
                request,
                f"Loaded {len(report.frameworks)} frameworks, "
                f"{report.crosswalk_created} crosswalk links, "
                f"{report.control_mappings_created} starter-control mappings (all indicative).",
            )
            return redirect("frameworks:list")
        upload = request.FILES.get("file")
        ctx: dict[str, Any] = {"dry_run": request.POST.get("dry_run") == "1"}
        if upload is None:
            ctx["errors"] = ["Choose a file to import."]
            return render(request, self.template_name, ctx)
        if upload.size and upload.size > 10 * 1024 * 1024:
            ctx["errors"] = ["File exceeds 10 MB."]
            return render(request, self.template_name, ctx)
        meta = {
            k: request.POST.get(k, "").strip() for k in ("code", "name", "version", "content_level")
        }
        try:
            result = services.import_framework_bytes(
                upload.read(),
                upload.name or "upload",
                user=request.user,
                meta={k: v for k, v in meta.items() if v},
                dry_run=ctx["dry_run"],
                indicative=False,
            )
        except FrameworkImportError as exc:
            ctx["errors"] = exc.errors[:100]
            return render(request, self.template_name, ctx)
        ctx["result"] = result.as_dict()
        ctx["missing"] = result.missing[:50]
        return render(request, self.template_name, ctx)
