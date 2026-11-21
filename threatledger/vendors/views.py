from __future__ import annotations

from typing import Any

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.mail import send_mail
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.permissions import access, can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.audit.models import Action
from threatledger.audit.services import record
from threatledger.work import services as work_services
from threatledger.work.models import Assignment

from . import dora, services
from .forms import ContractForm, EntityForm, SendAssessmentForm, SolutionForm
from .models import EntityStatus, Tier


def _post_only(request: HttpRequest) -> None:
    if request.method != "POST":
        raise PermissionDenied("POST required")


def _entity(request: HttpRequest, ref: str) -> Any:
    return get_object_or_404(
        services.visible_entities(request.user).select_related("owner", "business_unit"),
        ref__iexact=ref,
    )


def _apply_errors(form: Any, exc: Exception) -> None:
    if isinstance(exc, ValidationError) and hasattr(exc, "message_dict"):
        for field, errs in exc.message_dict.items():
            form.add_error(field if field in form.fields else None, errs)
    else:
        form.add_error(None, " ".join(getattr(exc, "messages", [str(exc)])))


@access(Cap.VIEW_VENDORS)
def vendor_list(request: HttpRequest) -> HttpResponse:
    g = request.GET
    qs = services.visible_entities(request.user).select_related("owner")
    tier = g.get("tier", "")
    if tier in Tier.values:
        qs = qs.filter(tier=tier)
    status = g.get("status", "current")
    if status == "current":
        qs = qs.filter(status__in=[EntityStatus.ACTIVE, EntityStatus.OFFBOARDING])
    elif status in EntityStatus.values:
        qs = qs.filter(status=status)
    rows = services.postures(list(qs))
    if g.get("attention") == "1":
        rows = [p for p in rows if p.flags]
    tiers = [
        (value, label, [p for p in rows if p.entity.tier == value]) for value, label in Tier.choices
    ]
    return render(
        request,
        "vendors/vendor_list.html",
        {
            "tiers": tiers,
            "total": len(rows),
            "tier": tier,
            "status": status,
            "attention": g.get("attention") == "1",
            "tier_choices": Tier.choices,
            "status_choices": EntityStatus.choices,
            "can_manage": can(request.user, Cap.MANAGE_VENDORS),
            "can_export": can(request.user, Cap.EXPORT_DATA),
        },
    )


@access(Cap.MANAGE_VENDORS)
def vendor_form(request: HttpRequest, ref: str | None = None) -> HttpResponse:
    entity = _entity(request, ref) if ref else None
    form = EntityForm(request.POST or None, instance=entity, user=request.user)
    if request.method == "POST" and form.is_valid():
        data = dict(form.cleaned_data)
        risks = data.pop("risks")
        try:
            if entity:
                entity = services.update_entity(entity, user=request.user, data=data, risks=risks)
            else:
                entity = services.create_entity(user=request.user, data=data, risks=risks)
        except (ValidationError, services.VendorError) as exc:
            _apply_errors(form, exc)
        else:
            messages.success(request, f"{entity.name} saved.")
            return redirect("vendors:detail", entity.ref)
    return render(request, "vendors/vendor_form.html", {"form": form, "entity": entity})


@access(Cap.VIEW_VENDORS)
def vendor_detail(request: HttpRequest, ref: str) -> HttpResponse:
    entity = _entity(request, ref)
    (posture,) = services.postures([entity])
    assessments = (
        Assignment.objects.filter(entity=entity)
        .select_related("questionnaire")
        .prefetch_related("links", "answers__question")
        .order_by("-created_at")
    )
    manage = can(request.user, Cap.MANAGE_VENDORS)
    findings = (
        entity.findings.select_related("owner").order_by("-created_at")
        if can(request.user, Cap.VIEW_FINDINGS)
        else []
    )
    return render(
        request,
        "vendors/vendor_detail.html",
        {
            "entity": entity,
            "p": posture,
            "solutions": entity.solutions.prefetch_related("assets"),
            "assessments": [(a, work_services.assessment_score(a)) for a in assessments],
            "risks": entity.risks.all(),
            "findings": findings,
            "can_manage": manage,
            "solution_form": SolutionForm(user=request.user, prefix="s") if manage else None,
            "send_form": SendAssessmentForm(
                org=current_organisation(request.user),
                prefix="x",
                initial={"contact_email": entity.security_contact},
            )
            if manage
            else None,
            "now": timezone.now(),
        },
    )


@access(Cap.MANAGE_VENDORS)
def solution_add(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    entity = _entity(request, ref)
    form = SolutionForm(request.POST, user=request.user, prefix="s")
    if form.is_valid():
        data = dict(form.cleaned_data)
        assets = data.pop("assets")
        try:
            services.add_solution(entity, user=request.user, data=data, assets=assets)
        except (ValidationError, services.VendorError) as exc:
            messages.error(request, " ".join(getattr(exc, "messages", [str(exc)])))
        else:
            messages.success(request, "Service added.")
    else:
        messages.error(request, "Give the service a name.")
    return redirect("vendors:detail", entity.ref)


@access(Cap.MANAGE_VENDORS)
def solution_remove(request: HttpRequest, ref: str, pk: int) -> HttpResponse:
    _post_only(request)
    entity = _entity(request, ref)
    solution = get_object_or_404(entity.solutions, pk=pk)
    try:
        services.remove_solution(solution, user=request.user)
    except services.VendorError as exc:
        messages.error(request, str(exc))
    return redirect("vendors:detail", entity.ref)


# ----------------------------------------------------------------------------- contracts
@access(Cap.VIEW_VENDORS)
def contract_list(request: HttpRequest) -> HttpResponse:
    contracts = list(services.visible_contracts(request.user).select_related("entity"))
    state = request.GET.get("state", "")
    if state:
        contracts = [c for c in contracts if c.state == state]
    return render(
        request,
        "vendors/contract_list.html",
        {
            "contracts": contracts,
            "state": state,
            "can_manage": can(request.user, Cap.MANAGE_VENDORS),
        },
    )


@access(Cap.MANAGE_VENDORS)
def contract_form(request: HttpRequest, ref: str, contract_ref: str | None = None) -> HttpResponse:
    entity = _entity(request, ref)
    contract = (
        get_object_or_404(entity.contracts, ref__iexact=contract_ref) if contract_ref else None
    )
    form = ContractForm(request.POST or None, instance=contract, entity=entity)
    if request.method == "POST" and form.is_valid():
        data = dict(form.cleaned_data)
        solutions = data.pop("solutions")
        try:
            if contract:
                services.update_contract(
                    contract, user=request.user, data=data, solutions=solutions
                )
            else:
                services.create_contract(entity, user=request.user, data=data, solutions=solutions)
        except (ValidationError, services.VendorError) as exc:
            _apply_errors(form, exc)
        else:
            messages.success(request, "Contract saved.")
            return redirect("vendors:detail", entity.ref)
    return render(
        request,
        "vendors/contract_form.html",
        {"form": form, "entity": entity, "contract": contract},
    )


# ----------------------------------------------------------------------------- assessments
def _link_page(request: HttpRequest, a: Assignment, token: str, emailed: bool) -> HttpResponse:
    url = f"{settings.SITE_URL.rstrip('/')}{reverse('respond:start')}?token={token}"
    response = render(
        request, "vendors/link_created.html", {"a": a, "url": url, "emailed": emailed}
    )
    response["Cache-Control"] = "no-store"
    return response


def _email_link(a: Assignment, token: str, sender: Any) -> bool:
    url = f"{settings.SITE_URL.rstrip('/')}{reverse('respond:start')}?token={token}"
    due = f" by {a.due_on:%d %B %Y}" if a.due_on else ""
    try:
        send_mail(
            f"Security questionnaire: {a.questionnaire.title}",
            f"Hello {a.external_name or ''},\n\n"
            f"{a.organisation.name} asks you to complete the questionnaire "
            f"“{a.questionnaire.title}”{due}.\n\n"
            f"{a.message + chr(10) + chr(10) if a.message else ''}"
            f"Open this personal link (valid until "
            f"{a.links.first().expires_at:%d %B %Y}; do not forward it):\n{url}\n\n"  # type: ignore[union-attr]
            f"Questions: reply to {sender.email or settings.DEFAULT_FROM_EMAIL}.",
            settings.DEFAULT_FROM_EMAIL,
            [a.external_email],
        )
    except Exception:
        return False
    record(
        Action.EXPORT,
        a,
        actor=sender,
        changes={"emailed_link_to": [None, a.external_email]},
    )
    return True


@access(Cap.MANAGE_VENDORS)
def assessment_send(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    entity = _entity(request, ref)
    form = SendAssessmentForm(request.POST, org=current_organisation(request.user), prefix="x")
    if not form.is_valid():
        messages.error(request, "Choose a questionnaire and a valid contact email.")
        return redirect("vendors:detail", entity.ref)
    d = form.cleaned_data
    try:
        a, token = work_services.send_external_assessment(
            entity,
            user=request.user,
            questionnaire=d["questionnaire"],
            name=d["contact_name"],
            email=d["contact_email"],
            due_on=d["due_on"],
            days=d["days"],
            message=d["message"],
        )
    except work_services.WorkError as exc:
        messages.error(request, str(exc))
        return redirect("vendors:detail", entity.ref)
    emailed = _email_link(a, token, request.user) if d["send_email"] else False
    return _link_page(request, a, token, emailed)


def _vendor_assignment(request: HttpRequest, ref: str, aref: str) -> Assignment:
    entity = _entity(request, ref)
    return get_object_or_404(Assignment.objects.filter(entity=entity), ref__iexact=aref)


@access(Cap.MANAGE_VENDORS)
def assessment_link(request: HttpRequest, ref: str, aref: str) -> HttpResponse:
    _post_only(request)
    a = _vendor_assignment(request, ref, aref)
    if request.POST.get("action") == "revoke":
        n = work_services.revoke_links(a, user=request.user)
        messages.success(request, f"Revoked {n} link(s).")
        return redirect("vendors:detail", ref)
    if not a.editable_by_respondent:
        messages.error(request, "This assessment is no longer open for answers.")
        return redirect("vendors:detail", ref)
    try:
        token = work_services.issue_link(
            a, user=request.user, days=int(request.POST.get("days", 30))
        )
    except (ValueError, work_services.WorkError) as exc:
        messages.error(request, str(exc))
        return redirect("vendors:detail", ref)
    emailed = (
        _email_link(a, token, request.user) if request.POST.get("send_email") == "on" else False
    )
    return _link_page(request, a, token, emailed)


# ----------------------------------------------------------------------------- DORA
@access(Cap.EXPORT_DATA)
def dora_register(request: HttpRequest) -> HttpResponse:
    if not can(request.user, Cap.VIEW_VENDORS):
        raise PermissionDenied("You cannot view third parties.")
    org = current_organisation(request.user)
    entities = list(services.visible_entities(request.user).prefetch_related("solutions"))
    sheets = dora.build_register(org, entities)
    body = dora.to_xlsx(sheets)
    record(
        Action.EXPORT,
        actor=request.user,
        object_type="vendors.entity",
        object_repr="DORA register of information (xlsx)",
        changes={"providers": [None, len(sheets["B_05.01 Providers"][1])]},
    )
    response = HttpResponse(
        body, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    stamp = timezone.localdate().isoformat()
    response["Content-Disposition"] = f'attachment; filename="dora-register-{stamp}.xlsx"'
    response["X-Content-Type-Options"] = "nosniff"
    return response
