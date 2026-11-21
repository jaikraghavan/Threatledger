from __future__ import annotations

from typing import Any

from django import forms

from threatledger.core.forms import DATE, org_users, scoped_business_units, style_form
from threatledger.frameworks.models import Framework

from .models import Audit, Campaign, Judgement

MATURITY = [("", "Not rated")] + [
    (str(i), f"{i} – {label}")
    for i, label in enumerate(["None", "Initial", "Repeatable", "Defined", "Managed", "Optimised"])
]


class AuditForm(forms.ModelForm):
    class Meta:
        model = Audit
        fields = [
            "name",
            "framework",
            "business_unit",
            "baseline",
            "lead_auditor",
            "due_on",
            "scope_note",
        ]
        widgets = {"due_on": DATE, "scope_note": forms.Textarea(attrs={"rows": 4})}
        labels = {"business_unit": "Perimeter"}

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["framework"].queryset = Framework.objects.order_by("name")  # type: ignore[attr-defined]
        self.fields["business_unit"].queryset = scoped_business_units(user)  # type: ignore[attr-defined]
        self.fields["lead_auditor"].queryset = org_users(user)  # type: ignore[attr-defined]
        if self.instance.pk:
            del self.fields["framework"]
        style_form(self)


class CampaignForm(forms.ModelForm):
    baseline = forms.CharField(
        max_length=32, required=False, help_text="Optional framework baseline, e.g. moderate."
    )
    perimeters: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False,
        widget=forms.CheckboxSelectMultiple,
        help_text="One audit is created per perimeter.",
    )
    organisation_wide = forms.BooleanField(
        required=False, initial=True, label="Include an organisation-wide audit"
    )

    class Meta:
        model = Campaign
        fields = ["name", "framework", "starts_on", "due_on", "recurrence", "description"]
        widgets = {
            "starts_on": DATE,
            "due_on": DATE,
            "description": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["framework"].queryset = Framework.objects.order_by("name")  # type: ignore[attr-defined]
        self.fields["perimeters"].queryset = scoped_business_units(user)  # type: ignore[attr-defined]
        style_form(self)

    def clean(self) -> dict[str, Any]:
        data = super().clean() or {}
        if not data.get("perimeters") and not data.get("organisation_wide"):
            raise forms.ValidationError("Choose at least one perimeter.")
        return data


class JudgementForm(forms.Form):
    judgement = forms.ChoiceField(
        choices=[(v, label) for v, label in Judgement.choices if v != Judgement.NOT_ASSESSED],
        widget=forms.RadioSelect,
    )
    maturity = forms.TypedChoiceField(
        choices=MATURITY, coerce=int, empty_value=None, required=False
    )
    observation = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 4}),
        required=False,
        help_text="Required unless compliant: what you saw and why.",
    )
    evidence = forms.TypedMultipleChoiceField(
        coerce=int, required=False, widget=forms.CheckboxSelectMultiple
    )

    def __init__(self, *args: Any, evidence_choices: list[tuple[int, str]], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["evidence"].choices = evidence_choices  # type: ignore[attr-defined]
        style_form(self)
        self.fields["judgement"].widget.attrs.pop("class", None)


class StatusForm(forms.Form):
    status = forms.CharField(max_length=16)
    conclusion = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 4}))
