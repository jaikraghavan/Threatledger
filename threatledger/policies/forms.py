from __future__ import annotations

from typing import Any

from django import forms

from threatledger.accounts.permissions import current_organisation
from threatledger.controls.models import Control
from threatledger.core.forms import org_users, style_form

from .models import Policy, PolicyVersion


class PolicyForm(forms.ModelForm):
    controls: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 6}),
        help_text="Controls this policy mandates.",
    )
    body = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 12}),
        required=False,
        label="Policy text (first draft)",
    )

    class Meta:
        model = Policy
        fields = ["title", "kind", "owner", "review_interval_months", "summary"]
        widgets = {"summary": forms.Textarea(attrs={"rows": 3})}

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["owner"].queryset = org_users(user)  # type: ignore[attr-defined]
        self.fields["controls"].queryset = Control.objects.filter(  # type: ignore[attr-defined]
            organisation=current_organisation(user)
        ).live()
        if self.instance.pk:
            del self.fields["body"]
            self.initial["controls"] = list(self.instance.controls.all())
        style_form(self)


class VersionForm(forms.ModelForm):
    document_url = forms.URLField(
        max_length=1000,
        required=False,
        assume_scheme="https",
        help_text="Optional link to the formatted document.",
    )

    class Meta:
        model = PolicyVersion
        fields = ["body", "document_url", "change_summary"]
        widgets = {"body": forms.Textarea(attrs={"rows": 18})}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["body"].required = False
        style_form(self)


class DecisionForm(forms.Form):
    decision = forms.ChoiceField(choices=[("approve", "Approve"), ("changes", "Request changes")])
    note = forms.CharField(max_length=500, required=False)
