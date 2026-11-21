from __future__ import annotations

from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Count
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from threatledger.accounts.permissions import access, current_organisation
from threatledger.accounts.roles import Cap

from . import services
from .forms import BusinessUnitForm
from .models import BusinessUnit, tree

INDENT = ("", "pl-6", "pl-12", "pl-18", "pl-24")


def _unit(request: HttpRequest, pk: int) -> BusinessUnit:
    return get_object_or_404(BusinessUnit, pk=pk, organisation=current_organisation(request.user))


@access(Cap.MANAGE_SETTINGS)
def unit_list(request: HttpRequest) -> HttpResponse:
    org = current_organisation(request.user)
    counts = {
        row["pk"]: row
        for row in BusinessUnit.objects.filter(organisation=org)
        .annotate(
            n_risks=Count("risks", distinct=True),
            n_assets=Count("assets", distinct=True),
            n_members=Count("members", distinct=True),
        )
        .values("pk", "n_risks", "n_assets", "n_members")
    }
    rows: list[tuple[BusinessUnit, str, Any]] = (
        [(bu, INDENT[min(depth, 4)], counts.get(bu.pk, {})) for bu, depth in tree(org.pk)]
        if org
        else []
    )
    return render(request, "org/unit_list.html", {"rows": rows})


@access(Cap.MANAGE_SETTINGS)
def unit_form(request: HttpRequest, pk: int | None = None) -> HttpResponse:
    unit = _unit(request, pk) if pk else None
    form = BusinessUnitForm(request.POST or None, instance=unit, user=request.user)
    if request.method == "POST" and form.is_valid():
        data = {k: form.cleaned_data[k] for k in ("name", "code", "parent")}
        try:
            if unit:
                services.update_business_unit(unit, user=request.user, data=data)
            else:
                services.create_business_unit(user=request.user, data=data)
        except ValidationError as exc:
            for field, errs in exc.message_dict.items():
                form.add_error(field if field in form.fields else None, errs)
        except services.OrgError as exc:
            form.add_error(None, str(exc))
        else:
            messages.success(request, "Business unit saved.")
            return redirect("org:units")
    return render(request, "org/unit_form.html", {"form": form, "unit": unit})


@access(Cap.MANAGE_SETTINGS)
def unit_delete(request: HttpRequest, pk: int) -> HttpResponse:
    if request.method != "POST":
        raise PermissionDenied("POST required")
    unit = _unit(request, pk)
    try:
        services.delete_business_unit(unit, user=request.user)
    except services.OrgError as exc:
        messages.error(request, f"Cannot delete {unit.name}: {exc}")
    else:
        messages.success(request, "Business unit deleted.")
    return redirect("org:units")
