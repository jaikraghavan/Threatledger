from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any
from urllib.parse import urlencode

from django.contrib import messages
from django.core.cache import cache
from django.db.models import Count, Prefetch, Q, QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import DetailView, ListView, TemplateView

from threatledger.accounts.permissions import AccessControlMixin
from threatledger.accounts.roles import Cap

from . import services
from .importer.source import VERSION_RE
from .models import (
    Analytic,
    DetectionStrategyTechnique,
    Group,
    GroupSoftware,
    GroupTechnique,
    ImportRun,
    MitigationTechnique,
    SoftwareTechnique,
    Tactic,
    Technique,
)

_TECH_ID = re.compile(r"^T\d{1,4}(\.\d{0,3})?$", re.IGNORECASE)
_GROUP_ID = re.compile(r"^G\d{1,4}$", re.IGNORECASE)


def matrix_tactics() -> list[Tactic]:
    return list(Tactic.objects.active().exclude(order=None).order_by("order"))


def all_platforms() -> list[str]:
    """Distinct platforms across active techniques (cached; changes only on import)."""
    release = services.current_release()
    key = f"attack:platforms:{release.pk if release else 0}"
    platforms = cache.get(key)
    if platforms is None:
        found: set[str] = set()
        for plist in Technique.objects.active().values_list("platforms", flat=True):
            found.update(plist or [])
        platforms = sorted(found)
        cache.set(key, platforms, 3600)
    return platforms


class _HtmxPartialMixin:
    partial_template_name = ""

    def get_template_names(self) -> list[str]:
        if getattr(self.request, "htmx", False) and not self.request.htmx.boosted:  # type: ignore[attr-defined]
            return [self.partial_template_name]
        return super().get_template_names()  # type: ignore[misc]


class TechniqueListView(AccessControlMixin, _HtmxPartialMixin, ListView):
    tl_access = Cap.VIEW_ATTACK
    template_name = "attack/technique_list.html"
    partial_template_name = "attack/_technique_table.html"
    context_object_name = "techniques"
    paginate_by = 50

    def filters(self) -> dict[str, str]:
        g = self.request.GET
        return {
            "q": g.get("q", "").strip()[:100],
            "tactic": g.get("tactic", "").strip()[:64],
            "platform": g.get("platform", "").strip()[:64],
            "level": g.get("level", "all") if g.get("level") in ("all", "top", "sub") else "all",
            "revoked": "1" if g.get("revoked") == "1" else "",
        }

    def get_queryset(self) -> QuerySet[Technique]:
        f = self.filters()
        qs = Technique.objects.all() if f["revoked"] else Technique.objects.active()
        if f["q"]:
            q = f["q"]
            if _TECH_ID.match(q):
                qs = qs.filter(attack_id__istartswith=q)
            else:
                qs = qs.filter(Q(name__icontains=q) | Q(attack_id__iexact=q))
        if f["tactic"]:
            qs = qs.filter(tactics__shortname=f["tactic"])
        if f["platform"]:
            # JSON list membership, portable across SQLite and PostgreSQL.
            qs = qs.filter(platforms__icontains=f'"{f["platform"]}"')
        if f["level"] == "top":
            qs = qs.filter(is_subtechnique=False)
        elif f["level"] == "sub":
            qs = qs.filter(is_subtechnique=True)
        return (
            qs.distinct()
            .select_related("parent")
            .prefetch_related(Prefetch("tactics", queryset=Tactic.objects.order_by("order")))
            .annotate(
                sub_count=Count(
                    "subtechniques",
                    filter=Q(subtechniques__is_revoked=False, subtechniques__is_deprecated=False),
                    distinct=True,
                )
            )
            .order_by("attack_id")
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        ctx["filters"] = self.filters()
        ctx["tactics"] = matrix_tactics()
        ctx["platforms"] = all_platforms()
        ctx["release"] = services.current_release()
        params = self.request.GET.copy()
        params.pop("page", None)
        ctx["querystring"] = params.urlencode()
        return ctx


class TechniqueDetailView(AccessControlMixin, DetailView):
    tl_access = Cap.VIEW_ATTACK
    template_name = "attack/technique_detail.html"
    context_object_name = "technique"

    def get_object(self, queryset: QuerySet[Technique] | None = None) -> Technique:
        return get_object_or_404(
            Technique.objects.select_related("parent", "revoked_by"),
            attack_id__iexact=self.kwargs["attack_id"],
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        t: Technique = self.object
        ctx["tactics"] = t.tactics.order_by("order")
        ctx["subtechniques"] = t.subtechniques.active().order_by("attack_id")
        ctx["mitigations"] = (
            MitigationTechnique.objects.filter(
                technique=t, mitigation__is_revoked=False, mitigation__is_deprecated=False
            )
            .select_related("mitigation")
            .order_by("mitigation__attack_id")
        )
        ctx["groups"] = (
            GroupTechnique.objects.filter(
                technique=t, group__is_revoked=False, group__is_deprecated=False
            )
            .select_related("group")
            .order_by("group__name")
        )
        ctx["software"] = (
            SoftwareTechnique.objects.filter(
                technique=t, software__is_revoked=False, software__is_deprecated=False
            )
            .select_related("software")
            .order_by("software__name")
        )
        ctx["detections"] = (
            DetectionStrategyTechnique.objects.filter(
                technique=t, strategy__is_revoked=False, strategy__is_deprecated=False
            )
            .select_related("strategy")
            .prefetch_related(
                Prefetch(
                    "strategy__analytics",
                    queryset=Analytic.objects.active()
                    .prefetch_related("data_components")
                    .order_by("attack_id"),
                )
            )
            .order_by("strategy__attack_id")
        )
        ctx["legacy_components"] = t.data_component_links.select_related("data_component").order_by(
            "data_component__name"
        )
        ctx["replacement"] = t.replacement() if t.is_revoked else None
        ctx["replaces"] = t.replaces.order_by("attack_id")
        ctx.update(_org_context(self.request.user, t))
        return ctx


def _org_context(user: Any, technique: Technique) -> dict[str, Any]:
    """This organisation's coverage of the technique and the risks that cite it."""
    from threatledger.accounts.permissions import can, current_organisation
    from threatledger.accounts.roles import Cap
    from threatledger.controls.models import Control
    from threatledger.coverage.selectors import coverage_for
    from threatledger.risks.services import visible_risks

    org = current_organisation(user)
    if org is None:
        return {}
    cov = coverage_for([technique.pk], org.pk)[technique.pk]
    ids = set(cov.control_ids)
    if technique.parent_id:
        ids |= coverage_for([technique.parent_id], org.pk)[technique.parent_id].control_ids
    return {
        "org_coverage": cov,
        "org_controls": Control.objects.filter(pk__in=ids).order_by("ref")
        if can(user, Cap.VIEW_CONTROLS)
        else [],
        "org_risks": visible_risks(user).live().filter(techniques=technique).order_by("ref"),
        "framework_requirements": technique.requirement_links.select_related(
            "requirement__framework"
        ).order_by("requirement__order")
        if can(user, Cap.VIEW_FRAMEWORKS)
        else [],
    }


class GroupListView(AccessControlMixin, _HtmxPartialMixin, ListView):
    tl_access = Cap.VIEW_ATTACK
    template_name = "attack/group_list.html"
    partial_template_name = "attack/_group_table.html"
    context_object_name = "groups"
    paginate_by = 50

    def get_queryset(self) -> QuerySet[Group]:
        q = self.request.GET.get("q", "").strip()[:100]
        qs = Group.objects.active()
        if q:
            if _GROUP_ID.match(q):
                qs = qs.filter(attack_id__istartswith=q)
            else:
                qs = qs.filter(Q(name__icontains=q) | Q(aliases_text__icontains=q))
        return qs.annotate(
            technique_count=Count("technique_links", distinct=True),
            software_count=Count("software_links", distinct=True),
        ).order_by("name")

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        ctx["q"] = self.request.GET.get("q", "").strip()[:100]
        ctx["querystring"] = urlencode({"q": ctx["q"]}) if ctx["q"] else ""
        return ctx


class GroupDetailView(AccessControlMixin, DetailView):
    tl_access = Cap.VIEW_ATTACK
    template_name = "attack/group_detail.html"
    context_object_name = "group"

    def get_object(self, queryset: QuerySet[Group] | None = None) -> Group:
        return get_object_or_404(Group, attack_id__iexact=self.kwargs["attack_id"])

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        links = list(
            GroupTechnique.objects.filter(
                group=self.object, technique__is_revoked=False, technique__is_deprecated=False
            )
            .select_related("technique", "technique__parent")
            .prefetch_related("technique__tactics")
            .order_by("technique__attack_id")
        )
        by_tactic: OrderedDict[Tactic, list[GroupTechnique]] = OrderedDict(
            (t, []) for t in matrix_tactics()
        )
        for link in links:
            for tactic in link.technique.tactics.all():
                if tactic in by_tactic:
                    by_tactic[tactic].append(link)
        ctx["techniques_by_tactic"] = [(t, ls) for t, ls in by_tactic.items() if ls]
        ctx["technique_count"] = len(links)
        ctx["software"] = (
            GroupSoftware.objects.filter(group=self.object, software__is_revoked=False)
            .select_related("software")
            .order_by("software__name")
        )
        return ctx


class AttackDataView(AccessControlMixin, TemplateView):
    """Import status and manual import trigger. Admins only."""

    tl_access = Cap.RUN_IMPORTS
    template_name = "attack/data.html"

    def get_template_names(self) -> list[str]:
        if getattr(self.request, "htmx", False):
            return ["attack/_runs.html"]
        return [self.template_name]

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        runs = list(ImportRun.objects.select_related("requested_by", "release")[:15])
        ctx["runs"] = runs
        ctx["active_run"] = any(not r.is_finished for r in runs)
        ctx["release"] = services.current_release()
        ctx["counts"] = {
            "techniques": Technique.objects.active().filter(is_subtechnique=False).count(),
            "subtechniques": Technique.objects.active().filter(is_subtechnique=True).count(),
            "tactics": Tactic.objects.active().exclude(order=None).count(),
            "groups": Group.objects.active().count(),
            "revoked": Technique.objects.filter(is_revoked=True).count(),
        }
        return ctx

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        version = request.POST.get("version", "").strip()
        if version and not VERSION_RE.match(version):
            messages.error(request, "Version must look like 20.1, or be left blank for latest.")
            return redirect("attack:data")
        if ImportRun.objects.filter(
            status__in=[ImportRun.Status.QUEUED, ImportRun.Status.RUNNING]
        ).exists():
            messages.error(request, "An import is already queued or running.")
            return redirect("attack:data")
        run = services.create_run(version=version, user=request.user)
        services.enqueue(run)
        messages.success(request, f"Import #{run.pk} queued. This page updates automatically.")
        return redirect("attack:data")
