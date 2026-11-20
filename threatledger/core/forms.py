"""Form helpers shared by every app."""

from __future__ import annotations

from typing import Any

from django import forms

from threatledger.accounts.models import User
from threatledger.accounts.permissions import business_unit_scope, current_organisation
from threatledger.org.models import BusinessUnit

DATE = forms.DateInput(attrs={"type": "date", "class": "field"}, format="%Y-%m-%d")


def style_form(form: forms.BaseForm) -> None:
    """Apply the design-system classes and stable ids to every widget."""
    for name, field in form.fields.items():
        widget = field.widget
        if isinstance(widget, forms.CheckboxInput):
            widget.attrs.setdefault("class", "rounded border-slate-300")
        elif isinstance(widget, forms.CheckboxSelectMultiple):
            continue
        else:
            widget.attrs.setdefault("class", "field")
        widget.attrs.setdefault("id", f"id_{name}")


def org_users(user: Any) -> Any:
    org = current_organisation(user)
    return User.objects.filter(is_active=True, memberships__organisation=org).order_by(
        "first_name", "username"
    )


def scoped_business_units(user: Any) -> Any:
    org = current_organisation(user)
    qs = BusinessUnit.objects.filter(organisation=org)
    scope = business_unit_scope(user)
    return qs.filter(pk__in=scope) if scope is not None else qs
