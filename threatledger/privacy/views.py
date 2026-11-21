from __future__ import annotations

import csv
import io
from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from threatledger.accounts.permissions import access, can
from threatledger.accounts.roles import Cap
from threatledger.audit.models import Action
from threatledger.audit.services import record
from threatledger.risks.exports import neutralise

from . import services
from .forms import DpiaForm, ProcessingForm
from .models import DpiaStatus

LINKS = ("processors", "assets", "controls")


def _apply_errors(form: Any, exc: Exception) -> None:
    if isinstance(exc, ValidationError) and hasattr(exc, "message_dict"):
        for field, errs in exc.message_dict.items():
            form.add_error(field if field in form.fields else None, errs)
    else:
        form.add_error(None, " ".join(getattr(exc, "messages", [str(exc)])))


def _processing(request: HttpRequest, ref: str) -> Any:
    return get_object_or_404(
        services.visible_processing(request.user).select_related("owner", "business_unit"),
        ref__iexact=ref,
    )


@access(Cap.VIEW_PRIVACY)
def processing_list(request: HttpRequest) -> HttpResponse:
    items = list(
        services.visible_processing(request.user)
        .select_related("owner")
        .prefetch_related("dpias", "processors")
    )
    rows = []
    for p in items:
        dpias = sorted(p.dpias.all(), key=lambda d: d.created_at, reverse=True)
        rows.append((p, services.dpia_state(p, dpias[0] if dpias else None)))
    state = request.GET.get("dpia", "")
    if state:
        rows = [(p, s) for p, s in rows if s == state]
    return render(
        request,
        "privacy/processing_list.html",
        {
            "rows": rows,
            "state": state,
            "can_manage": can(request.user, Cap.MANAGE_PRIVACY),
            "can_export": can(request.user, Cap.EXPORT_DATA),
        },
    )


@access(Cap.MANAGE_PRIVACY)
def processing_form(request: HttpRequest, ref: str | None = None) -> HttpResponse:
    p = _processing(request, ref) if ref else None
    form = ProcessingForm(request.POST or None, instance=p, user=request.user)
    if request.method == "POST" and form.is_valid():
        data = dict(form.cleaned_data)
        links = {name: data.pop(name) for name in LINKS}
        try:
            if p:
                p = services.update_processing(p, user=request.user, data=data, links=links)
            else:
                p = services.create_processing(user=request.user, data=data, links=links)
        except (ValidationError, services.PrivacyError) as exc:
            _apply_errors(form, exc)
        else:
            messages.success(request, f"{p.ref} saved.")
            return redirect("privacy:detail", p.ref)
    return render(request, "privacy/processing_form.html", {"form": form, "p": p})


@access(Cap.VIEW_PRIVACY)
def processing_detail(request: HttpRequest, ref: str) -> HttpResponse:
    p = _processing(request, ref)
    dpia = services.current_dpia(p)
    return render(
        request,
        "privacy/processing_detail.html",
        {
            "p": p,
            "dpia": dpia,
            "dpia_state": services.dpia_state(p, dpia),
            "dpias": p.dpias.order_by("-created_at"),
            "can_manage": can(request.user, Cap.MANAGE_PRIVACY),
        },
    )


@access(Cap.MANAGE_PRIVACY)
def dpia_create(request: HttpRequest, ref: str) -> HttpResponse:
    p = _processing(request, ref)
    form = DpiaForm(
        request.POST or None,
        user=request.user,
        initial={"description": p.purpose, "measures": p.security_measures},
    )
    if request.method == "POST" and form.is_valid():
        data = dict(form.cleaned_data)
        risks = data.pop("risks")
        try:
            dpia = services.create_dpia(p, user=request.user, data=data, risks=risks)
        except (ValidationError, services.PrivacyError) as exc:
            _apply_errors(form, exc)
        else:
            return redirect("privacy:dpia", dpia.ref)
    return render(request, "privacy/dpia_form.html", {"form": form, "p": p, "dpia": None})


def _dpia(request: HttpRequest, ref: str) -> Any:
    return get_object_or_404(
        services.visible_dpias(request.user).select_related("processing", "decided_by"),
        ref__iexact=ref,
    )


@access(Cap.MANAGE_PRIVACY)
def dpia_edit(request: HttpRequest, ref: str) -> HttpResponse:
    dpia = _dpia(request, ref)
    form = DpiaForm(request.POST or None, instance=dpia, user=request.user)
    if request.method == "POST" and form.is_valid():
        data = dict(form.cleaned_data)
        risks = data.pop("risks")
        try:
            services.update_dpia(dpia, user=request.user, data=data, risks=risks)
            if request.POST.get("submit") == "1":
                services.submit_dpia(dpia, user=request.user)
        except (ValidationError, services.PrivacyError) as exc:
            _apply_errors(form, exc)
        else:
            messages.success(request, "DPIA saved.")
            return redirect("privacy:dpia", dpia.ref)
    return render(
        request, "privacy/dpia_form.html", {"form": form, "p": dpia.processing, "dpia": dpia}
    )


@access(Cap.VIEW_PRIVACY)
def dpia_detail(request: HttpRequest, ref: str) -> HttpResponse:
    dpia = _dpia(request, ref)
    authors = {dpia.created_by_id, dpia.updated_by_id}
    return render(
        request,
        "privacy/dpia_detail.html",
        {
            "dpia": dpia,
            "risks": dpia.risks.all(),
            "can_edit": can(request.user, Cap.MANAGE_PRIVACY)
            and dpia.status in (DpiaStatus.DRAFT, DpiaStatus.REJECTED),
            "can_decide": can(request.user, Cap.APPROVE_DPIA)
            and dpia.status == DpiaStatus.IN_REVIEW
            and request.user.pk not in authors,
        },
    )


@access(Cap.APPROVE_DPIA)
def dpia_decide(request: HttpRequest, ref: str) -> HttpResponse:
    if request.method != "POST":
        raise PermissionDenied("POST required")
    dpia = _dpia(request, ref)
    try:
        services.decide_dpia(
            dpia,
            user=request.user,
            approve=request.POST.get("decision") == "approve",
            note=request.POST.get("note", ""),
        )
    except services.PrivacyError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, f"{dpia.ref} {dpia.get_status_display().lower()}.")
    return redirect("privacy:dpia", dpia.ref)


@access(Cap.EXPORT_DATA)
def ropa_export(request: HttpRequest) -> HttpResponse:
    if not can(request.user, Cap.VIEW_PRIVACY):
        raise PermissionDenied("You cannot view privacy records.")
    items = services.visible_processing(request.user).prefetch_related("processors", "controls")
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL)
    writer.writerow(
        [
            "Ref",
            "Processing activity",
            "Role",
            "Purpose",
            "Legal basis",
            "Categories of data subjects",
            "Categories of personal data",
            "Recipients",
            "Processors",
            "International transfers",
            "Transfer safeguard",
            "Retention",
            "Security measures",
            "Status",
            "DPIA",
        ]
    )
    n = 0
    for p in items:
        n += 1
        writer.writerow(
            [
                neutralise(v)
                for v in (
                    p.ref,
                    p.name,
                    p.get_role_display(),
                    p.purpose,
                    p.get_legal_basis_display(),
                    "; ".join(p.subject_labels()),
                    "; ".join(p.category_labels()),
                    p.recipients,
                    "; ".join(e.name for e in p.processors.all()),
                    p.transfer_countries,
                    p.get_transfer_safeguard_display() if p.transfer_safeguard else "",
                    p.retention,
                    "; ".join([p.security_measures, *(c.ref for c in p.controls.all())]).strip(
                        "; "
                    ),
                    p.get_status_display(),
                    services.dpia_state(p),
                )
            ]
        )
    record(
        Action.EXPORT,
        actor=request.user,
        object_type="privacy.processing",
        object_repr=f"Records of processing (csv, {n} rows)",
    )
    response = HttpResponse(
        ("﻿" + buffer.getvalue()).encode("utf-8"), content_type="text/csv; charset=utf-8"
    )
    stamp = timezone.localdate().isoformat()
    response["Content-Disposition"] = f'attachment; filename="records-of-processing-{stamp}.csv"'
    response["X-Content-Type-Options"] = "nosniff"
    return response
