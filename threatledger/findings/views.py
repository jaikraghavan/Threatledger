from __future__ import annotations

from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from threatledger.accounts.permissions import access, can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.audits.services import visible_audits
from threatledger.controls.models import Control
from threatledger.frameworks.models import Requirement
from threatledger.risks.services import visible_risks

from . import services
from .forms import DecisionForm, ExceptionForm, FindingForm, FindingStatusForm, OwnerFindingForm
from .models import ExceptionStatus, FindingStatus, Severity

STATUS_LABELS = dict(FindingStatus.choices)


def _post_only(request: HttpRequest) -> None:
    if request.method != "POST":
        raise PermissionDenied("POST required")


def _apply_errors(form: Any, exc: Exception) -> None:
    if isinstance(exc, ValidationError) and hasattr(exc, "message_dict"):
        for field, errs in exc.message_dict.items():
            form.add_error(field if field in form.fields else None, errs)
    else:
        form.add_error(None, " ".join(getattr(exc, "messages", [str(exc)])))


def _finding(request: HttpRequest, ref: str) -> Any:
    return get_object_or_404(
        services.visible_findings(request.user).select_related(
            "owner", "audit", "requirement__framework", "control", "risk", "business_unit"
        ),
        ref__iexact=ref,
    )


# ----------------------------------------------------------------------------- findings
@access(Cap.VIEW_FINDINGS)
def finding_list(request: HttpRequest) -> HttpResponse:
    g = request.GET
    f = {
        "status": (
            g.get("status", "active")
            if g.get("status") in ("", "active", *FindingStatus.values)
            else "active"
        ),
        "severity": g.get("severity", "") if g.get("severity") in Severity.values else "",
        "owner": "me" if g.get("owner") == "me" else "",
        "overdue": "1" if g.get("overdue") == "1" else "",
    }
    qs = services.visible_findings(request.user).select_related("owner", "audit", "requirement")
    if f["status"] == "active":  # anything not closed
        qs = qs.exclude(status=FindingStatus.CLOSED)
    elif f["status"]:
        qs = qs.filter(status=f["status"])
    if f["severity"]:
        qs = qs.filter(severity=f["severity"])
    if f["owner"]:
        qs = qs.filter(owner_id=request.user.pk)
    if f["overdue"]:
        qs = qs.filter(
            status__in=[FindingStatus.OPEN, FindingStatus.IN_PROGRESS],
            due_on__lt=timezone.localdate(),
        )
    return render(
        request,
        "findings/finding_list.html",
        {
            "findings": qs[:500],
            "filters": f,
            "statuses": FindingStatus.choices,
            "severities": Severity.choices,
            "can_raise": services.can_raise(request.user),
        },
    )


def _prefill(request: HttpRequest) -> dict[str, Any]:
    g = request.GET
    initial: dict[str, Any] = {}
    if g.get("audit"):
        audit = visible_audits(request.user).filter(ref__iexact=g["audit"]).first()
        if audit:
            initial["audit"] = audit
            initial["business_unit"] = audit.business_unit
            if g.get("requirement", "").isdigit():
                req = Requirement.objects.filter(
                    pk=int(g["requirement"]), framework=audit.framework
                ).first()
                if req:
                    initial["requirement"] = req.pk
                    initial["title"] = f"{req.ref}: {req.title}"[:200]
    if g.get("control"):
        control = Control.objects.filter(
            organisation=current_organisation(request.user), ref__iexact=g["control"]
        ).first()
        if control:
            initial["control"] = control
            initial.setdefault("owner", control.owner)
    if g.get("entity"):
        from threatledger.vendors.services import visible_entities

        entity = visible_entities(request.user).filter(ref__iexact=g["entity"]).first()
        if entity:
            initial["entity"] = entity
            initial.setdefault("owner", entity.owner)
            initial.setdefault("business_unit", entity.business_unit)
    if g.get("risk"):
        risk = visible_risks(request.user).filter(ref__iexact=g["risk"]).first()
        if risk:
            initial["risk"] = risk
            initial.setdefault("business_unit", risk.business_unit)
    return initial


@access(Cap.RAISE_FINDINGS)
def finding_create(request: HttpRequest) -> HttpResponse:
    form = FindingForm(request.POST or None, initial=_prefill(request), user=request.user)
    if request.method == "POST" and form.is_valid():
        try:
            finding = services.create_finding(user=request.user, data=dict(form.cleaned_data))
        except (ValidationError, services.FindingError) as exc:
            _apply_errors(form, exc)
        else:
            messages.success(request, f"Finding {finding.ref} raised.")
            return redirect("findings:detail", finding.ref)
    return render(request, "findings/finding_form.html", {"form": form, "finding": None})


@access(Cap.VIEW_FINDINGS)
def finding_edit(request: HttpRequest, ref: str) -> HttpResponse:
    finding = _finding(request, ref)
    full = services.can_edit(request.user, finding)
    if not full and not services.can_update(request.user, finding):
        raise PermissionDenied("You cannot edit this finding.")
    form_class = FindingForm if full else OwnerFindingForm
    form = form_class(request.POST or None, instance=finding, user=request.user)
    if request.method == "POST" and form.is_valid():
        data = {k: form.cleaned_data[k] for k in form.cleaned_data}
        try:
            services.update_finding(finding, user=request.user, data=data)
        except (ValidationError, services.FindingError) as exc:
            _apply_errors(form, exc)
        else:
            messages.success(request, "Finding updated.")
            return redirect("findings:detail", finding.ref)
    return render(request, "findings/finding_form.html", {"form": form, "finding": finding})


@access(Cap.VIEW_FINDINGS)
def finding_detail(request: HttpRequest, ref: str) -> HttpResponse:
    finding = _finding(request, ref)
    return render(
        request,
        "findings/finding_detail.html",
        {
            "finding": finding,
            "transitions": [
                (s, STATUS_LABELS[s]) for s in services.finding_transitions(request.user, finding)
            ],
            "can_edit": services.can_edit(request.user, finding)
            or services.can_update(request.user, finding),
            "exceptions": finding.exceptions.all(),
            "can_request_exception": can(request.user, Cap.REQUEST_EXCEPTION) and finding.is_open,
        },
    )


@access(Cap.VIEW_FINDINGS)
def finding_status(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    finding = _finding(request, ref)
    form = FindingStatusForm(request.POST)
    if form.is_valid():
        try:
            services.set_finding_status(
                finding,
                user=request.user,
                status=form.cleaned_data["status"],
                note=form.cleaned_data["note"],
            )
        except services.FindingError as exc:
            messages.error(request, str(exc))
        else:
            messages.success(request, f"Finding is now {finding.get_status_display().lower()}.")
    return redirect("findings:detail", finding.ref)


# ----------------------------------------------------------------------------- exceptions
def _exception(request: HttpRequest, ref: str) -> Any:
    return get_object_or_404(
        services.visible_exceptions(request.user).select_related(
            "owner", "risk", "finding", "business_unit", "decided_by", "created_by"
        ),
        ref__iexact=ref,
    )


@access(Cap.VIEW_FINDINGS)
def exception_list(request: HttpRequest) -> HttpResponse:
    show = request.GET.get("show", "current")
    qs = services.visible_exceptions(request.user).select_related("owner")
    today = timezone.localdate()
    if show == "current":
        qs = qs.filter(status=ExceptionStatus.REQUESTED) | qs.filter(
            status=ExceptionStatus.APPROVED, expires_on__gte=today
        )
    return render(
        request,
        "findings/exception_list.html",
        {
            "exceptions": qs.order_by("-created_at")[:500],
            "show": "all" if show == "all" else "current",
            "can_request": can(request.user, Cap.REQUEST_EXCEPTION),
        },
    )


@access(Cap.REQUEST_EXCEPTION)
def exception_create(request: HttpRequest) -> HttpResponse:
    initial: dict[str, Any] = {}
    g = request.GET
    if g.get("requirement", "").isdigit():
        req = (
            Requirement.objects.filter(pk=int(g["requirement"])).select_related("framework").first()
        )
        if req:
            initial["requirement_refs"] = f"{req.framework.code} {req.ref}"
    if g.get("finding"):
        finding = services.visible_findings(request.user).filter(ref__iexact=g["finding"]).first()
        if finding:
            initial.update(title=finding.title, business_unit=finding.business_unit)
            if finding.requirement:
                initial["requirement_refs"] = (
                    f"{finding.requirement.framework.code} {finding.requirement.ref}"
                )
            if finding.control:
                initial["controls"] = [finding.control]
    finding = None
    if request.method == "POST" and request.POST.get("finding"):
        finding = (
            services.visible_findings(request.user)
            .filter(ref__iexact=request.POST["finding"])
            .first()
        )
    form = ExceptionForm(request.POST or None, initial=initial, user=request.user)
    if request.method == "POST" and form.is_valid():
        data = dict(form.cleaned_data)
        requirements = data.pop("requirement_refs")
        controls = data.pop("controls")
        data["finding"] = finding
        try:
            exc = services.request_exception(
                user=request.user, data=data, requirements=requirements, controls=controls
            )
        except (ValidationError, services.FindingError) as err:
            _apply_errors(form, err)
        else:
            messages.success(
                request, f"Exception {exc.ref} requested; it needs another person's approval."
            )
            return redirect("findings:exception", exc.ref)
    return render(
        request,
        "findings/exception_form.html",
        {"form": form, "finding_ref": g.get("finding") or request.POST.get("finding", "")},
    )


@access(Cap.VIEW_FINDINGS)
def exception_detail(request: HttpRequest, ref: str) -> HttpResponse:
    exc = _exception(request, ref)
    approver = can(request.user, Cap.APPROVE_EXCEPTION)
    return render(
        request,
        "findings/exception_detail.html",
        {
            "exc": exc,
            "requirements": exc.requirements.select_related("framework"),
            "controls": exc.controls.all(),
            "can_decide": approver
            and exc.status == ExceptionStatus.REQUESTED
            and exc.created_by_id != request.user.pk,
            "own_request": exc.created_by_id == request.user.pk,
            "can_revoke": approver and exc.status == ExceptionStatus.APPROVED,
        },
    )


@access(Cap.APPROVE_EXCEPTION)
def exception_decide(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    exc = _exception(request, ref)
    form = DecisionForm(request.POST)
    if form.is_valid():
        decision, note = form.cleaned_data["decision"], form.cleaned_data["note"]
        try:
            if decision == "revoke":
                services.revoke_exception(exc, user=request.user, note=note)
            else:
                services.decide_exception(
                    exc, user=request.user, approve=decision == "approve", note=note
                )
        except services.FindingError as err:
            messages.error(request, str(err))
        else:
            messages.success(request, f"Exception {exc.ref} {exc.get_status_display().lower()}.")
    return redirect("findings:exception", exc.ref)
