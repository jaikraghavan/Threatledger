from __future__ import annotations

from typing import Any

from django import forms

from threatledger.accounts.permissions import current_organisation
from threatledger.attack.models import Technique
from threatledger.controls.models import Control
from threatledger.core.forms import org_users, scoped_business_units, style_form
from threatledger.risks.services import visible_assets, visible_risks
from threatledger.vendors.services import visible_entities

from .models import Incident
from .regimes import REGIME_CHOICES

DT = forms.DateTimeInput(
    attrs={"type": "datetime-local", "class": "field"}, format="%Y-%m-%dT%H:%M"
)


class ReportForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = ["title", "severity", "occurred_at", "business_unit", "description"]
        widgets = {"occurred_at": DT, "description": forms.Textarea(attrs={"rows": 5})}
        help_texts = {"description": "What happened, what you saw, who else knows."}
        labels = {"severity": "How bad does it look?"}

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["business_unit"].queryset = scoped_business_units(user)  # type: ignore[attr-defined]
        self.fields["occurred_at"].input_formats = ["%Y-%m-%dT%H:%M"]  # type: ignore[attr-defined]
        style_form(self)


class IncidentForm(forms.ModelForm):
    regimes = forms.MultipleChoiceField(
        choices=REGIME_CHOICES,
        required=False,
        widget=forms.CheckboxSelectMultiple,
        label="Notification regimes",
        help_text="Clocks start at the awareness time.",
    )
    assets: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None, required=False, widget=forms.SelectMultiple(attrs={"size": 4})
    )
    techniques: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 6}),
        label="ATT&CK techniques observed",
    )
    risks: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 4}),
        label="Risks that materialised",
    )
    controls: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 4}),
        label="Controls involved",
    )
    vendors: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None, required=False, widget=forms.SelectMultiple(attrs={"size": 3})
    )

    class Meta:
        model = Incident
        fields = [
            "title",
            "severity",
            "owner",
            "business_unit",
            "occurred_at",
            "aware_at",
            "personal_data_breach",
            "data_subjects_affected",
            "description",
            "root_cause",
            "lessons_learned",
        ]
        widgets = {
            "occurred_at": DT,
            "aware_at": DT,
            "description": forms.Textarea(attrs={"rows": 4}),
            "root_cause": forms.Textarea(attrs={"rows": 3}),
            "lessons_learned": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        org = current_organisation(user)
        f = self.fields
        f["owner"].queryset = org_users(user)  # type: ignore[attr-defined]
        f["business_unit"].queryset = scoped_business_units(user)  # type: ignore[attr-defined]
        f["assets"].queryset = visible_assets(user)  # type: ignore[attr-defined]
        f["techniques"].queryset = Technique.objects.active().order_by("attack_id")  # type: ignore[attr-defined]
        f["risks"].queryset = visible_risks(user).live()  # type: ignore[attr-defined]
        f["controls"].queryset = Control.objects.filter(organisation=org).live()  # type: ignore[attr-defined]
        f["vendors"].queryset = visible_entities(user)  # type: ignore[attr-defined]
        for name in ("occurred_at", "aware_at"):
            f[name].input_formats = ["%Y-%m-%dT%H:%M"]  # type: ignore[attr-defined]
        if self.instance.pk:
            for name in ("assets", "techniques", "risks", "controls", "vendors"):
                self.initial[name] = list(getattr(self.instance, name).all())
            self.initial["regimes"] = self.instance.regimes
        style_form(self)
