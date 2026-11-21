from __future__ import annotations

from typing import Any

from django import forms

from threatledger.accounts.permissions import current_organisation
from threatledger.core.forms import style_form

from .models import BusinessUnit


class BusinessUnitForm(forms.ModelForm):
    class Meta:
        model = BusinessUnit
        fields = ["name", "code", "parent"]
        help_texts = {"parent": "Leave empty for a top-level unit."}

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        qs = BusinessUnit.objects.filter(organisation=current_organisation(user))
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        self.fields["parent"].queryset = qs  # type: ignore[attr-defined]
        self.fields["parent"].required = False
        style_form(self)
