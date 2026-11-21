from __future__ import annotations

import csv
import io
from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Count, Q
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from threatledger.accounts.permissions import access, can
from threatledger.accounts.roles import Cap
from threatledger.audit.models import Action
from threatledger.audit.services import record
from threatledger.controls.models import Evidence
from threatledger.frameworks.models import Requirement
from threatledger.risks.exports import neutralise

from . import services
from .forms import AuditForm, CampaignForm, JudgementForm, StatusForm
from .models import AuditStatus, Judgement, Recurrence

ROW_FILTERS = {
    "": "All",
    "todo": "Not assessed",
    "divergent": "Differs from derived",
    "non_compliant": "Non-compliant",
    "partial": "Partial",
}


def _post_only(request: HttpRequest) -> None:
    if request.method != "POST":
        raise PermissionDenied("POST required")


def _audit(request: HttpRequest, ref: str) -> Any:
    return get_object_or_404(
        services.visible_audits(request.user).select_related(
            "framework", "business_unit", "lead_auditor", "campaign", "closed_by"
        ),
        ref__iexact=ref,
    )


def _apply_errors(form: Any, exc: Exception) -> None:
    if isinstance(exc, ValidationError) and hasattr(exc, "message_dict"):
        for field, errs in exc.message_dict.items():
            form.add_error(field if field in form.fields else None, errs)
    else:
        form.add_error(None, " ".join(getattr(exc, "messages", [str(exc)])))


# ----------------------------------------------------------------------------- audits
@access(Cap.VIEW_AUDITS)
def audit_list(request: HttpRequest) -> HttpResponse:
    status = request.GET.get("status", "")
    qs = services.visible_audits(request.user).select_related(
        "framework", "business_unit", "lead_auditor", "campaign"
    )
    if status in AuditStatus.values:
        qs = qs.filter(status=status)
    audits = list(qs[:200])
    scores = services.list_scores(audits)
    return render(
        request,
        "audits/audit_list.html",
        {
            "audits": audits,
            "scores": scores,
            "status": status,
            "statuses": AuditStatus.choices,
            "can_manage": services.can_manage(request.user),
        },
    )


@access(Cap.MANAGE_AUDITS)
def audit_form(request: HttpRequest, ref: str | None = None) -> HttpResponse:
    audit = _audit(request, ref) if ref else None
    if audit and audit.is_closed:
        messages.error(request, "Closed audits cannot be edited.")
        return redirect("audits:detail", audit.ref)
    form = AuditForm(request.POST or None, instance=audit, user=request.user)
    if request.method == "POST" and form.is_valid():
        data = dict(form.cleaned_data)
        try:
            if audit:
                audit = services.update_audit(audit, user=request.user, data=data)
            else:
                audit = services.create_audit(user=request.user, data=data)
        except (ValidationError, services.AuditError) as exc:
            _apply_errors(form, exc)
        else:
            messages.success(request, f"Audit {audit.ref} saved.")
            return redirect("audits:detail", audit.ref)
    return render(request, "audits/audit_form.html", {"form": form, "audit": audit})


@access(Cap.VIEW_AUDITS)
def audit_detail(request: HttpRequest, ref: str) -> HttpResponse:
    audit = _audit(request, ref)
    rows, score = services.audit_rows(audit)
    show = request.GET.get("show", "")
    if show == "todo":
        rows = [r for r in rows if r.judgement == Judgement.NOT_ASSESSED]
    elif show == "divergent":
        rows = [r for r in rows if r.divergent]
    elif show in (Judgement.NON_COMPLIANT, Judgement.PARTIAL):
        rows = [r for r in rows if r.judgement == show]
    findings = (
        audit.findings.select_related("owner", "requirement").order_by("-created_at")
        if can(request.user, Cap.VIEW_FINDINGS)
        else []
    )
    return render(
        request,
        "audits/audit_detail.html",
        {
            "audit": audit,
            "rows": rows,
            "score": score,
            "show": show,
            "row_filters": ROW_FILTERS,
            "can_manage": services.can_manage(request.user, audit),
            "can_perform": services.can_perform(request.user, audit),
            "transitions": [
                (s, AuditStatus(s).label) for s in services.allowed_transitions(request.user, audit)
            ],
            "findings": findings,
        },
    )


def _evidence_choices(controls: list[Any]) -> list[tuple[int, str]]:
    evidence = Evidence.objects.filter(
        control__in=[c.pk for c in controls], archived_at__isnull=True
    ).select_related("control")
    return [(e.pk, f"{e.control.ref} · {e.title}") for e in evidence]


@access(Cap.VIEW_AUDITS)
def audit_requirement(request: HttpRequest, ref: str, pk: int) -> HttpResponse:
    audit = _audit(request, ref)
    requirement = get_object_or_404(Requirement, pk=pk, framework=audit.framework, is_domain=False)
    rows, _ = services.audit_rows(audit)
    index = next((i for i, r in enumerate(rows) if r.requirement.pk == requirement.pk), None)
    if index is None:
        raise Http404("Requirement outside the audit scope")
    row = rows[index]
    can_perform = services.can_perform(request.user, audit)
    choices = _evidence_choices(row.controls) if can(request.user, Cap.VIEW_EVIDENCE) else []
    initial: dict[str, Any] = {"judgement": row.suggestion}
    if row.result and row.result.judgement != Judgement.NOT_ASSESSED:
        initial = {
            "judgement": row.result.judgement,
            "maturity": row.result.maturity,
            "observation": row.result.observation,
            "evidence": [e.pk for e in row.result.evidence.all()],
        }
    form = JudgementForm(
        request.POST if request.method == "POST" else None,
        initial=initial,
        evidence_choices=choices,
    )
    if request.method == "POST":
        if not can_perform:
            raise PermissionDenied("You cannot record judgements in this audit.")
        if form.is_valid():
            try:
                services.record_judgement(
                    audit,
                    requirement,
                    user=request.user,
                    judgement=form.cleaned_data["judgement"],
                    maturity=form.cleaned_data["maturity"],
                    observation=form.cleaned_data["observation"],
                    evidence_ids=form.cleaned_data["evidence"],
                )
            except services.AuditError as exc:
                form.add_error(None, str(exc))
            else:
                messages.success(request, f"{requirement.ref} recorded.")
                nxt = next(
                    (
                        r
                        for r in rows[index + 1 :] + rows[:index]
                        if r.judgement == Judgement.NOT_ASSESSED
                    ),
                    None,
                )
                if nxt and request.POST.get("next") == "1":
                    return redirect("audits:requirement", audit.ref, nxt.requirement.pk)
                return redirect("audits:detail", audit.ref)
    return render(
        request,
        "audits/audit_requirement.html",
        {
            "audit": audit,
            "row": row,
            "form": form,
            "can_perform": can_perform,
            "can_raise": can(request.user, Cap.RAISE_FINDINGS) and not audit.is_closed,
            "prev": rows[index - 1] if index > 0 else None,
            "next": rows[index + 1] if index + 1 < len(rows) else None,
            "position": index + 1,
            "total": len(rows),
        },
    )


@access(Cap.PERFORM_AUDITS)
def audit_accept(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    audit = _audit(request, ref)
    try:
        n = services.accept_suggestions(audit, user=request.user)
    except services.AuditError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, f"Accepted the derived status for {n} requirement(s).")
    return redirect("audits:detail", audit.ref)


@access(Cap.VIEW_AUDITS)
def audit_status(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    audit = _audit(request, ref)
    form = StatusForm(request.POST)
    if form.is_valid():
        try:
            services.set_status(
                audit,
                user=request.user,
                status=form.cleaned_data["status"],
                conclusion=form.cleaned_data["conclusion"],
            )
        except services.AuditError as exc:
            messages.error(request, str(exc))
        else:
            messages.success(request, f"Audit is now {audit.get_status_display().lower()}.")
    return redirect("audits:detail", audit.ref)


@access(Cap.EXPORT_DATA)
def audit_export(request: HttpRequest, ref: str) -> HttpResponse:
    audit = _audit(request, ref)
    rows, _ = services.audit_rows(audit)
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL)
    writer.writerow(
        [
            "Requirement",
            "Title",
            "Judgement",
            "Maturity",
            "Observation",
            "Derived status now",
            "Derived when judged",
            "Differs",
            "Assessed by",
            "Assessed at",
            "Evidence",
        ]
    )
    for r in rows:
        res = r.result
        writer.writerow(
            [
                neutralise(v)
                for v in (
                    r.requirement.ref,
                    r.requirement.title,
                    Judgement(r.judgement).label,
                    res.maturity if res else None,
                    res.observation if res else "",
                    r.derived.label if r.derived else "Not applicable",
                    res.derived_at_judgement if res else "",
                    r.divergent,
                    str(res.assessed_by) if res and res.assessed_by else "",
                    res.assessed_at.isoformat() if res and res.assessed_at else "",
                    "; ".join(e.title for e in res.evidence.all()) if res else "",
                )
            ]
        )
    record(
        Action.EXPORT,
        audit,
        actor=request.user,
        changes={"format": [None, "csv"], "rows": [None, len(rows)]},
    )
    response = HttpResponse(
        ("﻿" + buffer.getvalue()).encode("utf-8"), content_type="text/csv; charset=utf-8"
    )
    stamp = timezone.localdate().isoformat()
    response["Content-Disposition"] = f'attachment; filename="audit-{audit.ref}-{stamp}.csv"'
    response["X-Content-Type-Options"] = "nosniff"
    return response


# ----------------------------------------------------------------------------- campaigns
@access(Cap.VIEW_AUDITS)
def campaign_list(request: HttpRequest) -> HttpResponse:
    campaigns = list(
        services.visible_campaigns(request.user)
        .select_related("framework")
        .prefetch_related("audits")
        .annotate(
            n_audits=Count("audits"), n_closed=Count("audits", filter=Q(audits__status="closed"))
        )
    )
    return render(
        request,
        "audits/campaign_list.html",
        {
            "rows": [(c, services.campaign_status(c.audits.all())) for c in campaigns],
            "can_manage": services.can_manage(request.user),
        },
    )


@access(Cap.MANAGE_AUDITS)
def campaign_create(request: HttpRequest) -> HttpResponse:
    form = CampaignForm(request.POST or None, user=request.user)
    if request.method == "POST" and form.is_valid():
        data = dict(form.cleaned_data)
        perimeters: list[Any] = list(data.pop("perimeters") or [])
        if data.pop("organisation_wide"):
            perimeters.insert(0, None)
        try:
            campaign = services.create_campaign(user=request.user, data=data, perimeters=perimeters)
        except (ValidationError, services.AuditError) as exc:
            _apply_errors(form, exc)
        else:
            messages.success(
                request, f"Campaign {campaign.ref} launched with {len(perimeters)} audit(s)."
            )
            return redirect("audits:campaign", campaign.ref)
    return render(request, "audits/campaign_form.html", {"form": form})


@access(Cap.VIEW_AUDITS)
def campaign_detail(request: HttpRequest, ref: str) -> HttpResponse:
    campaign = get_object_or_404(
        services.visible_campaigns(request.user).select_related("framework", "previous"),
        ref__iexact=ref,
    )
    visible = services.visible_audits(request.user)
    audits = list(visible.filter(campaign=campaign).select_related("business_unit", "lead_auditor"))
    scores = services.list_scores(audits)
    nxt = type(campaign).objects.filter(previous=campaign).first()
    return render(
        request,
        "audits/campaign_detail.html",
        {
            "campaign": campaign,
            "rows": [(a, scores[a.pk]) for a in audits],
            "status": services.campaign_status(audits),
            "next_cycle": nxt,
            "can_launch_next": services.can_manage(request.user)
            and campaign.recurrence != Recurrence.NONE
            and nxt is None,
        },
    )


@access(Cap.MANAGE_AUDITS)
def campaign_next(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    campaign = get_object_or_404(services.visible_campaigns(request.user), ref__iexact=ref)
    try:
        new = services.launch_next_cycle(campaign, user=request.user)
    except (ValidationError, services.AuditError) as exc:
        messages.error(request, " ".join(getattr(exc, "messages", [str(exc)])))
        return redirect("audits:campaign", campaign.ref)
    messages.success(request, f"Next cycle {new.ref} launched.")
    return redirect("audits:campaign", new.ref)
