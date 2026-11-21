from __future__ import annotations

from datetime import timedelta
from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Count, Q, QuerySet
from django.http import FileResponse, Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View
from django.views.generic import DetailView, ListView

from threatledger.accounts.permissions import AccessControlMixin, access, can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.attack.models import Mitigation, Technique
from threatledger.risks.services import visible_risks

from . import services
from .forms import (
    ControlForm,
    ControlTestForm,
    EvidenceFileForm,
    EvidenceLinkForm,
    OwnerControlForm,
)
from .models import (
    Control,
    ControlMitigation,
    ControlStatus,
    ControlTechnique,
    ControlType,
    Evidence,
)
from .uploads import max_bytes as max_upload_bytes


def _control(request: HttpRequest, ref: str) -> Control:
    return get_object_or_404(
        services.visible_controls(request.user).select_related("owner"), ref__iexact=ref
    )


def _message(exc: Exception) -> str:
    return " ".join(exc.messages) if isinstance(exc, ValidationError) else str(exc)


def _form_errors(form: Any) -> str:
    return " ".join(str(e) for errs in form.errors.values() for e in errs)


def _post_only(request: HttpRequest) -> None:
    if request.method != "POST":
        raise PermissionDenied("POST required")


# ----------------------------------------------------------------------------- library
class ControlListView(AccessControlMixin, ListView):
    tl_access = Cap.VIEW_CONTROLS
    template_name = "controls/control_list.html"
    context_object_name = "controls"
    paginate_by = 50

    def get_template_names(self) -> list[str]:
        if getattr(self.request, "htmx", False):
            return ["controls/_control_table.html"]
        return [self.template_name]

    def filters(self) -> dict[str, str]:
        g = self.request.GET
        return {
            "q": g.get("q", "").strip()[:100],
            "status": g.get("status", "") if g.get("status") in ControlStatus.values else "",
            "type": g.get("type", "") if g.get("type") in ControlType.values else "",
            "owner": "me" if g.get("owner") == "me" else "",
            "test": "overdue" if g.get("test") == "overdue" else "",
            "archived": "1" if g.get("archived") == "1" else "",
        }

    def get_queryset(self) -> QuerySet[Control]:
        f = self.filters()
        qs = services.visible_controls(self.request.user)
        qs = qs.filter(archived_at__isnull=not f["archived"])
        if f["q"]:
            qs = qs.filter(Q(ref__icontains=f["q"]) | Q(name__icontains=f["q"]))
        if f["status"]:
            qs = qs.filter(status=f["status"])
        if f["type"]:
            qs = qs.filter(control_type=f["type"])
        if f["owner"]:
            qs = qs.filter(owner_id=self.request.user.pk)
        if f["test"]:
            # Per-control frequency: compute the overdue ids exactly (controls number in the
            # dozens-to-hundreds, so this is cheap) and keep pagination consistent.
            today = timezone.localdate()
            overdue = [
                pk
                for pk, last, freq in qs.values_list("pk", "last_tested_at", "test_frequency_days")
                if last is None or last + timedelta(days=freq) < today
            ]
            qs = qs.filter(pk__in=overdue)
        return (
            qs.select_related("owner")
            .annotate(
                mitigation_count=Count("mitigation_links", distinct=True),
                technique_count=Count("technique_links", distinct=True),
                risk_count=Count(
                    "risk_links",
                    filter=Q(risk_links__risk__archived_at__isnull=True),
                    distinct=True,
                ),
                evidence_count=Count(
                    "evidence", filter=Q(evidence__archived_at__isnull=True), distinct=True
                ),
            )
            .order_by("ref")
        )

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        f = self.filters()
        org = current_organisation(self.request.user)
        params = self.request.GET.copy()
        params.pop("page", None)
        ctx.update(
            filters=f,
            querystring=params.urlencode(),
            statuses=ControlStatus.choices,
            types=ControlType.choices,
            can_create=services.can_edit_fully(self.request.user),
            library_empty=not Control.objects.filter(organisation=org).exists(),
            status_counts=dict(
                services.visible_controls(self.request.user)
                .filter(archived_at__isnull=True)
                .values_list("status")
                .annotate(n=Count("id"))
                .values_list("status", "n")
            ),
        )
        return ctx


@access(Cap.EDIT_ANY_CONTROL)
def seed_starter(request: HttpRequest) -> HttpResponse:
    _post_only(request)
    org = current_organisation(request.user)
    if org is None:
        raise Http404
    result = services.seed_starter_controls(org, user=request.user)
    msg = (
        f"Loaded {len(result.created)} starter controls "
        "(status: not implemented — assess and update them)."
    )
    if result.missing_attack_ids:
        msg += " Some ATT&CK IDs were missing; import ATT&CK first, then re-run."
    messages.success(request, msg)
    return redirect("controls:list")


class ControlDetailView(AccessControlMixin, DetailView):
    tl_access = Cap.VIEW_CONTROLS
    template_name = "controls/control_detail.html"
    context_object_name = "control"

    def get_object(self, queryset: QuerySet[Control] | None = None) -> Control:
        return _control(self.request, self.kwargs["ref"])

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        control: Control = self.object
        user = self.request.user
        ctx.update(_mapping_context(user, control))
        ctx["risks"] = (
            visible_risks(user)
            .live()
            .with_scores()
            .filter(control_links__control=control)
            .distinct()
            .order_by("ref")
        )
        ctx["can_edit"] = services.can_edit(user, control)
        ctx["can_edit_fully"] = services.can_edit_fully(user) and control.archived_at is None
        ctx["can_upload"] = services.can_upload(user, control)
        ctx["can_view_evidence"] = can(user, Cap.VIEW_EVIDENCE)
        ctx["evidence"] = control.evidence.filter(archived_at__isnull=True).select_related(
            "uploaded_by"
        )
        ctx["tests"] = control.tests.select_related("tester").prefetch_related("evidence")[:20]
        ctx["file_form"] = EvidenceFileForm()
        ctx["link_form"] = EvidenceLinkForm()
        ctx["test_form"] = ControlTestForm(control=control)
        ctx["max_upload_mb"] = max_upload_bytes() // (1024 * 1024)
        ctx["requirements_by_framework"] = _requirements_by_framework(control)
        ctx.update(governance_links(user, control=control))
        return ctx


def governance_links(user: Any, **target: Any) -> dict[str, Any]:
    """Open findings, live exceptions and policies attached to a control or requirement."""
    from threatledger.findings.models import ExceptionStatus, FindingStatus
    from threatledger.findings.services import visible_exceptions, visible_findings
    from threatledger.policies.services import visible_policies

    ((field, obj),) = target.items()
    out: dict[str, Any] = {"show_governance": can(user, Cap.VIEW_FINDINGS)}
    if out["show_governance"]:
        out["open_findings"] = list(
            visible_findings(user)
            .filter(**{field: obj})
            .exclude(status=FindingStatus.CLOSED)
            .select_related("owner")[:20]
        )
        out["live_exceptions"] = [
            e
            for e in visible_exceptions(user)
            .filter(**{f"{field}s": obj})
            .filter(status__in=[ExceptionStatus.REQUESTED, ExceptionStatus.APPROVED])
            if e.effective_status != "expired"
        ]
    out["linked_policies"] = list(
        visible_policies(user).filter(**{f"{field}s": obj}, retired_at__isnull=True)
    )
    return out


def _requirements_by_framework(control: Control) -> list[tuple[Any, list[Any]]]:
    from threatledger.frameworks.models import ControlRequirement

    grouped: dict[Any, list[Any]] = {}
    for link in (
        ControlRequirement.objects.filter(control=control)
        .select_related("requirement__framework")
        .order_by("requirement__framework__name", "requirement__order")
    ):
        grouped.setdefault(link.requirement.framework, []).append(link.requirement)
    return list(grouped.items())


def _mapping_context(user: Any, control: Control) -> dict[str, Any]:
    return {
        "control": control,
        "mitigation_links": control.mitigation_links.select_related("mitigation").order_by(
            "mitigation__attack_id"
        ),
        "technique_links": control.technique_links.select_related("technique").order_by(
            "technique__attack_id"
        ),
        "covered": services.covered_techniques(control),
        "can_map": services.can_map(user, control),
    }


class ControlFormView(AccessControlMixin, View):
    """Create (risk managers) or edit (risk managers: all fields; owners: operational)."""

    tl_access = Cap.EDIT_OWN_CONTROL
    template_name = "controls/control_form.html"

    def _setup(self, request: HttpRequest, ref: str | None) -> tuple[Control | None, type]:
        if ref is None:
            if not services.can_edit_fully(request.user):
                raise PermissionDenied
            return None, ControlForm
        control = _control(request, ref)
        if not services.can_edit(request.user, control):
            raise PermissionDenied
        return control, ControlForm if services.can_edit_fully(request.user) else OwnerControlForm

    def get(self, request: HttpRequest, ref: str | None = None) -> HttpResponse:
        control, form_class = self._setup(request, ref)
        form = form_class(instance=control, user=request.user)
        return render(request, self.template_name, {"form": form, "control": control})

    def post(self, request: HttpRequest, ref: str | None = None) -> HttpResponse:
        control, form_class = self._setup(request, ref)
        form = form_class(request.POST, instance=control, user=request.user)
        if form.is_valid():
            data = form.data_for_service()
            try:
                if control is None:
                    saved = services.create_control(user=request.user, data=data)
                else:
                    saved = services.update_control(
                        Control.objects.get(pk=control.pk), user=request.user, data=data
                    )
            except (services.ControlError, ValidationError) as exc:
                if isinstance(exc, ValidationError) and hasattr(exc, "error_dict"):
                    for field, errs in exc.message_dict.items():
                        form.add_error(field if field in form.fields else None, errs)
                else:
                    form.add_error(None, _message(exc))
            else:
                messages.success(request, f"Saved {saved.ref}.")
                return redirect("controls:detail", ref=saved.ref)
        return render(request, self.template_name, {"form": form, "control": control})


@access(Cap.EDIT_ANY_CONTROL)
def control_archive(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    control = _control(request, ref)
    services.set_archived(control, user=request.user, archived=not request.POST.get("restore"))
    messages.success(
        request, f"{'Restored' if request.POST.get('restore') else 'Archived'} {control.ref}."
    )
    return redirect("controls:detail", ref=control.ref)


# ----------------------------------------------------------------------------- mappings (HTMX)
def _mappable(request: HttpRequest, ref: str) -> Control:
    control = _control(request, ref)
    if not services.can_map(request.user, control):
        raise PermissionDenied
    return control


def _mappings(request: HttpRequest, control: Control, error: str | None = None) -> HttpResponse:
    ctx = _mapping_context(request.user, control)
    ctx["mapping_error"] = error
    return render(request, "controls/_mappings.html", ctx)


@access(Cap.EDIT_MAPPINGS)
def mapping_search(request: HttpRequest, ref: str) -> HttpResponse:
    control = _mappable(request, ref)
    kind = "mitigation" if request.GET.get("kind") == "mitigation" else "technique"
    q = request.GET.get("q", "").strip()[:100]
    results: list[Any] = []
    if len(q) >= 2:
        if kind == "mitigation":
            linked = control.mitigation_links.values_list("mitigation_id", flat=True)
            results = list(
                Mitigation.objects.active()
                .filter(Q(attack_id__istartswith=q) | Q(name__icontains=q))
                .exclude(pk__in=linked)
                .order_by("attack_id")[:15]
            )
        else:
            linked_t = control.technique_links.values_list("technique_id", flat=True)
            results = list(
                Technique.objects.active()
                .filter(Q(attack_id__istartswith=q) | Q(name__icontains=q))
                .exclude(pk__in=linked_t)
                .select_related("parent")
                .order_by("attack_id")[:15]
            )
    return render(
        request,
        "controls/_mapping_results.html",
        {"control": control, "results": results, "kind": kind, "q": q},
    )


@access(Cap.EDIT_MAPPINGS)
def mapping_add(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    control = _mappable(request, ref)
    error = None
    try:
        if request.POST.get("kind") == "mitigation":
            services.add_mitigation(
                control, get_object_or_404(Mitigation, pk=request.POST.get("id")), user=request.user
            )
        else:
            services.add_technique(
                control, get_object_or_404(Technique, pk=request.POST.get("id")), user=request.user
            )
    except services.ControlError as exc:
        error = str(exc)
    return _mappings(request, control, error)


@access(Cap.EDIT_MAPPINGS)
def mapping_remove(request: HttpRequest, ref: str, kind: str, link_id: int) -> HttpResponse:
    _post_only(request)
    control = _mappable(request, ref)
    if kind == "mitigation":
        services.remove_mitigation(
            control,
            get_object_or_404(ControlMitigation, pk=link_id, control=control),
            user=request.user,
        )
    elif kind == "technique":
        services.remove_technique(
            control,
            get_object_or_404(ControlTechnique, pk=link_id, control=control),
            user=request.user,
        )
    else:
        raise Http404
    return _mappings(request, control)


# ----------------------------------------------------------------------------- evidence
@access(Cap.UPLOAD_EVIDENCE)
def evidence_add(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    control = _control(request, ref)
    if not services.can_upload(request.user, control):
        raise PermissionDenied
    try:
        if request.POST.get("kind") == "link":
            form: Any = EvidenceLinkForm(request.POST)
            if not form.is_valid():
                raise ValidationError(_form_errors(form))
            services.add_link_evidence(control, user=request.user, **form.cleaned_data)
        else:
            form = EvidenceFileForm(request.POST, request.FILES)
            if not form.is_valid():
                raise ValidationError(_form_errors(form))
            services.add_file_evidence(
                control,
                user=request.user,
                upload=form.cleaned_data["file"],
                title=form.cleaned_data["title"],
                description=form.cleaned_data["description"],
                valid_until=form.cleaned_data["valid_until"],
            )
    except (services.ControlError, ValidationError) as exc:
        messages.error(request, f"Evidence not added: {_message(exc)}")
    else:
        messages.success(request, "Evidence added.")
    return redirect("controls:detail", ref=control.ref)


@access(Cap.VIEW_EVIDENCE)
def evidence_download(request: HttpRequest, pk: int) -> FileResponse:
    evidence = get_object_or_404(
        Evidence.objects.select_related("control"),
        pk=pk,
        kind=Evidence.Kind.FILE,
        control__in=services.visible_controls(request.user),
    )
    services.record_download(evidence, request.user)
    response = FileResponse(
        evidence.file.open("rb"),
        as_attachment=True,
        filename=evidence.original_filename or "evidence",
        content_type=evidence.content_type or "application/octet-stream",
    )
    response["X-Content-Type-Options"] = "nosniff"
    response["Content-Security-Policy"] = "default-src 'none'; sandbox"
    response["Cache-Control"] = "private, no-store"
    return response


@access(Cap.UPLOAD_EVIDENCE)
def evidence_archive(request: HttpRequest, pk: int) -> HttpResponse:
    _post_only(request)
    evidence = get_object_or_404(
        Evidence.objects.select_related("control"),
        pk=pk,
        control__in=services.visible_controls(request.user),
    )
    try:
        services.archive_evidence(evidence, user=request.user)
        messages.success(request, "Evidence archived (kept for audit, hidden from the control).")
    except services.ControlError as exc:
        messages.error(request, str(exc))
    return redirect("controls:detail", ref=evidence.control.ref)


class EvidenceListView(AccessControlMixin, ListView):
    """Evidence across all controls, with an expiry focus."""

    tl_access = Cap.VIEW_EVIDENCE
    template_name = "controls/evidence_list.html"
    context_object_name = "evidence_items"
    paginate_by = 50

    def get_queryset(self) -> QuerySet[Evidence]:
        qs = Evidence.objects.filter(
            archived_at__isnull=True, control__in=services.visible_controls(self.request.user)
        ).select_related("control", "uploaded_by")
        due = self.request.GET.get("due", "")
        today = timezone.localdate()
        if due == "expired":
            qs = qs.filter(valid_until__lt=today)
        elif due == "30":
            qs = qs.filter(valid_until__gte=today, valid_until__lte=today + timedelta(days=30))
        return qs.order_by("valid_until", "control__ref")

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        ctx["due"] = self.request.GET.get("due", "")
        return ctx


# ----------------------------------------------------------------------------- testing
@access(Cap.EDIT_OWN_CONTROL)
def test_record(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    control = _control(request, ref)
    if not services.can_edit(request.user, control):
        raise PermissionDenied
    form = ControlTestForm(request.POST, control=control)
    if form.is_valid():
        try:
            services.record_test(
                control,
                user=request.user,
                tested_on=form.cleaned_data["tested_on"],
                method=form.cleaned_data["method"],
                result=form.cleaned_data["result"],
                notes=form.cleaned_data["notes"],
                evidence=list(form.cleaned_data["evidence"]),
            )
            messages.success(request, "Test recorded.")
        except (services.ControlError, ValidationError) as exc:
            messages.error(request, f"Test not recorded: {_message(exc)}")
    else:
        messages.error(
            request,
            "Test not recorded: " + _form_errors(form),
        )
    return redirect("controls:detail", ref=control.ref)
