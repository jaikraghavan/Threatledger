from __future__ import annotations

from datetime import datetime
from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from threatledger.accounts.permissions import AUTHENTICATED, access, can
from threatledger.accounts.roles import Cap

from . import services
from .forms import IncidentForm, ReportForm
from .models import EntryKind, IncidentStatus

LINKS = ("assets", "techniques", "risks", "controls", "vendors")
STATUS_LABELS = dict(IncidentStatus.choices)


def _post_only(request: HttpRequest) -> None:
    if request.method != "POST":
        raise PermissionDenied("POST required")


def _incident(request: HttpRequest, ref: str) -> Any:
    return get_object_or_404(
        services.visible_incidents(request.user).select_related("owner", "business_unit"),
        ref__iexact=ref,
    )


def _apply_errors(form: Any, exc: Exception) -> None:
    if isinstance(exc, ValidationError) and hasattr(exc, "message_dict"):
        for field, errs in exc.message_dict.items():
            form.add_error(field if field in form.fields else None, errs)
    else:
        form.add_error(None, " ".join(getattr(exc, "messages", [str(exc)])))


def _parse_dt(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return timezone.make_aware(datetime.strptime(value, "%Y-%m-%dT%H:%M"))
    except ValueError:
        return None


@access(AUTHENTICATED)
def incident_list(request: HttpRequest) -> HttpResponse:
    show = request.GET.get("show", "open")
    qs = (
        services.visible_incidents(request.user).select_related("owner").prefetch_related("filings")
    )
    if show == "open":
        qs = qs.filter(status__in=services.OPEN_STATUSES)
    rows = []
    for i in qs[:300]:
        pending = services.pending_obligations(i)
        rows.append((i, pending[0] if pending else None))
    return render(
        request,
        "incidents/incident_list.html",
        {
            "rows": rows,
            "show": show,
            "can_report": can(request.user, Cap.REPORT_INCIDENT),
            "sees_all": can(request.user, Cap.VIEW_INCIDENTS),
        },
    )


@access(Cap.REPORT_INCIDENT)
def incident_report(request: HttpRequest) -> HttpResponse:
    form = ReportForm(request.POST or None, user=request.user)
    if request.method == "POST" and form.is_valid():
        try:
            incident = services.report_incident(user=request.user, data=dict(form.cleaned_data))
        except (ValidationError, services.IncidentError) as exc:
            _apply_errors(form, exc)
        else:
            messages.success(
                request, f"{incident.ref} reported. The incident team has been notified."
            )
            return redirect("incidents:detail", incident.ref)
    return render(request, "incidents/report_form.html", {"form": form})


@access(AUTHENTICATED)
def incident_edit(request: HttpRequest, ref: str) -> HttpResponse:
    incident = _incident(request, ref)
    if not services.can_manage(request.user, incident):
        raise PermissionDenied("You cannot edit this incident.")
    form = IncidentForm(request.POST or None, instance=incident, user=request.user)
    if request.method == "POST" and form.is_valid():
        data = dict(form.cleaned_data)
        links = {name: data.pop(name) for name in LINKS}
        try:
            services.update_incident(incident, user=request.user, data=data, links=links)
        except (ValidationError, services.IncidentError) as exc:
            _apply_errors(form, exc)
        else:
            messages.success(request, "Incident updated.")
            return redirect("incidents:detail", incident.ref)
    return render(
        request,
        "incidents/incident_form.html",
        {"form": form, "incident": incident, "suggested": services.suggested_regimes(incident)},
    )


@access(AUTHENTICATED)
def incident_detail(request: HttpRequest, ref: str) -> HttpResponse:
    incident = _incident(request, ref)
    manage = services.can_manage(request.user, incident)
    return render(
        request,
        "incidents/incident_detail.html",
        {
            "incident": incident,
            "obligations": services.obligations(incident),
            "timeline": incident.timeline.select_related("author"),
            "can_manage": manage,
            "transitions": [
                (s, STATUS_LABELS[s]) for s in services.TRANSITIONS.get(incident.status, ())
            ]
            if manage
            else [],
            "entry_kinds": [
                (k, label)
                for k, label in EntryKind.choices
                if k in (EntryKind.NOTE, EntryKind.ACTION, EntryKind.EVIDENCE)
            ],
            "suggested": [
                r for r in services.suggested_regimes(incident) if r not in incident.regimes
            ],
            "techniques": incident.techniques.all(),
            "now": timezone.now(),
        },
    )


@access(AUTHENTICATED)
def incident_status(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    incident = _incident(request, ref)
    try:
        services.set_status(
            incident,
            user=request.user,
            status=request.POST.get("status", ""),
            note=request.POST.get("note", ""),
        )
    except services.IncidentError as exc:
        messages.error(request, str(exc))
    return redirect("incidents:detail", incident.ref)


@access(AUTHENTICATED)
def incident_entry(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    incident = _incident(request, ref)
    try:
        services.add_entry(
            incident,
            user=request.user,
            kind=request.POST.get("kind", "note"),
            text=request.POST.get("text", ""),
            url=request.POST.get("url", ""),
            at=_parse_dt(request.POST.get("at", "")),
        )
    except services.IncidentError as exc:
        messages.error(request, str(exc))
    return redirect(f"/incidents/{incident.ref}/#timeline")


@access(AUTHENTICATED)
def incident_filing(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    incident = _incident(request, ref)
    try:
        services.record_filing(
            incident,
            user=request.user,
            regime=request.POST.get("regime", ""),
            step=request.POST.get("step", ""),
            submitted_at=_parse_dt(request.POST.get("submitted_at", "")),
            reference=request.POST.get("reference", ""),
            note=request.POST.get("note", ""),
            not_required=request.POST.get("not_required") == "1",
        )
    except services.IncidentError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, "Notification recorded.")
    return redirect("incidents:detail", incident.ref)
