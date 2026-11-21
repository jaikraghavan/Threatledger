from __future__ import annotations

from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from threatledger.accounts.permissions import access, can
from threatledger.accounts.roles import Cap

from . import services
from .forms import DecisionForm, PolicyForm, VersionForm
from .models import PolicyKind, VersionStatus


def _post_only(request: HttpRequest) -> None:
    if request.method != "POST":
        raise PermissionDenied("POST required")


def _policy(request: HttpRequest, ref: str) -> Any:
    return get_object_or_404(
        services.visible_policies(request.user).select_related("owner"), ref__iexact=ref
    )


def _apply_errors(form: Any, exc: Exception) -> None:
    if isinstance(exc, ValidationError) and hasattr(exc, "message_dict"):
        for field, errs in exc.message_dict.items():
            form.add_error(field if field in form.fields else None, errs)
    else:
        form.add_error(None, " ".join(getattr(exc, "messages", [str(exc)])))


@access(Cap.VIEW_POLICIES)
def policy_list(request: HttpRequest) -> HttpResponse:
    kind = request.GET.get("kind", "")
    qs = (
        services.visible_policies(request.user).select_related("owner").prefetch_related("versions")
    )
    if kind in PolicyKind.values:
        qs = qs.filter(kind=kind)
    show_retired = request.GET.get("retired") == "1"
    if not show_retired:
        qs = qs.filter(retired_at__isnull=True)
    rows = [(p, services.policy_state(p, list(p.versions.all()))) for p in qs]
    status = request.GET.get("status", "")
    if status:
        rows = [(p, s) for p, s in rows if s.status == status]
    return render(
        request,
        "policies/policy_list.html",
        {
            "rows": rows,
            "kind": kind,
            "kinds": PolicyKind.choices,
            "status": status,
            "show_retired": show_retired,
            "can_create": services.can_edit(request.user),
        },
    )


@access(Cap.EDIT_POLICIES)
def policy_form(request: HttpRequest, ref: str | None = None) -> HttpResponse:
    policy = _policy(request, ref) if ref else None
    form = PolicyForm(request.POST or None, instance=policy, user=request.user)
    if request.method == "POST" and form.is_valid():
        data = dict(form.cleaned_data)
        controls = data.pop("controls")
        try:
            if policy:
                policy = services.update_policy(
                    policy, user=request.user, data=data, controls=controls
                )
            else:
                body = data.pop("body", "")
                policy = services.create_policy(
                    user=request.user, data=data, body=body, controls=controls
                )
        except (ValidationError, services.PolicyError) as exc:
            _apply_errors(form, exc)
        else:
            messages.success(request, f"Policy {policy.ref} saved.")
            return redirect("policies:detail", policy.ref)
    return render(request, "policies/policy_form.html", {"form": form, "policy": policy})


@access(Cap.VIEW_POLICIES)
def policy_detail(request: HttpRequest, ref: str) -> HttpResponse:
    policy = _policy(request, ref)
    versions = list(policy.versions.select_related("author", "decided_by"))
    state = services.policy_state(policy, versions)
    number = request.GET.get("v", "")
    shown = next((v for v in versions if str(v.number) == number), None) or (
        state.published or state.open_version or (versions[0] if versions else None)
    )
    approver = can(request.user, Cap.APPROVE_POLICIES)
    return render(
        request,
        "policies/policy_detail.html",
        {
            "policy": policy,
            "state": state,
            "versions": versions,
            "shown": shown,
            "can_edit": services.can_edit(request.user, policy),
            "can_decide": approver
            and shown is not None
            and shown.status == VersionStatus.IN_REVIEW
            and shown.author_id != request.user.pk,
            "can_confirm_review": approver
            and services.can_edit(request.user, policy)
            and state.published is not None
            and state.open_version is None
            and state.published.author_id != request.user.pk,
            "controls": policy.controls.all(),
        },
    )


@access(Cap.EDIT_POLICIES)
def policy_revise(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    policy = _policy(request, ref)
    try:
        version = services.start_revision(policy, user=request.user)
    except services.PolicyError as exc:
        messages.error(request, str(exc))
        return redirect("policies:detail", policy.ref)
    return redirect("policies:version_edit", policy.ref, version.number)


@access(Cap.EDIT_POLICIES)
def version_edit(request: HttpRequest, ref: str, number: int) -> HttpResponse:
    policy = _policy(request, ref)
    version = get_object_or_404(policy.versions, number=number)
    if version.status != VersionStatus.DRAFT:
        messages.error(request, "Only drafts can be edited.")
        return redirect("policies:detail", policy.ref)
    form = VersionForm(request.POST or None, instance=version)
    if request.method == "POST" and form.is_valid():
        try:
            services.edit_version(version, user=request.user, data=dict(form.cleaned_data))
            if request.POST.get("submit") == "1":
                services.submit_version(version, user=request.user)
        except (ValidationError, services.PolicyError) as exc:
            _apply_errors(form, exc)
        else:
            messages.success(
                request,
                "Submitted for approval." if request.POST.get("submit") == "1" else "Draft saved.",
            )
            return redirect(f"{policy_url(policy)}?v={version.number}")
    return render(
        request, "policies/version_form.html", {"form": form, "policy": policy, "version": version}
    )


def policy_url(policy: Any) -> str:
    from django.urls import reverse

    return reverse("policies:detail", args=[policy.ref])


@access(Cap.APPROVE_POLICIES)
def version_decide(request: HttpRequest, ref: str, number: int) -> HttpResponse:
    _post_only(request)
    policy = _policy(request, ref)
    version = get_object_or_404(policy.versions, number=number)
    form = DecisionForm(request.POST)
    if form.is_valid():
        try:
            services.decide_version(
                version,
                user=request.user,
                approve=form.cleaned_data["decision"] == "approve",
                note=form.cleaned_data["note"],
            )
        except services.PolicyError as exc:
            messages.error(request, str(exc))
        else:
            messages.success(request, f"{version.label} {version.get_status_display().lower()}.")
    return redirect(f"{policy_url(policy)}?v={version.number}")


@access(Cap.APPROVE_POLICIES)
def policy_confirm_review(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    policy = _policy(request, ref)
    try:
        services.confirm_review(policy, user=request.user, note=request.POST.get("note", ""))
    except services.PolicyError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, "Review recorded; next review date reset.")
    return redirect("policies:detail", policy.ref)


@access(Cap.EDIT_POLICIES)
def policy_retire(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    policy = _policy(request, ref)
    services.set_retired(policy, user=request.user, retired=request.POST.get("restore") != "1")
    messages.success(request, "Policy updated.")
    return redirect("policies:detail", policy.ref)
