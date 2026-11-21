from __future__ import annotations

from typing import Any

from django import forms

from threatledger.accounts.permissions import current_organisation
from threatledger.controls.models import Control
from threatledger.core.forms import org_users, scoped_business_units, style_form
from threatledger.risks.services import visible_assets, visible_risks
from threatledger.vendors.services import visible_entities

from .models import DATA_CATEGORIES, DATA_SUBJECTS, Dpia, Processing


class ProcessingForm(forms.ModelForm):
    data_categories = forms.MultipleChoiceField(
        choices=DATA_CATEGORIES, widget=forms.CheckboxSelectMultiple
    )
    data_subjects = forms.MultipleChoiceField(
        choices=DATA_SUBJECTS, widget=forms.CheckboxSelectMultiple, required=False
    )
    processors: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 4}),
        help_text="Third parties processing this data for you.",
    )
    assets: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None, required=False, widget=forms.SelectMultiple(attrs={"size": 4})
    )
    controls: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 4}),
        help_text="Security measures (Art. 32) from your control library.",
    )

    class Meta:
        model = Processing
        fields = [
            "name",
            "purpose",
            "role",
            "legal_basis",
            "legal_basis_note",
            "status",
            "owner",
            "business_unit",
            "recipients",
            "retention",
            "transfer_countries",
            "transfer_safeguard",
            "security_measures",
            "large_scale",
            "systematic_monitoring",
            "automated_decisions",
            "new_technology",
        ]
        widgets = {
            "purpose": forms.Textarea(attrs={"rows": 3}),
            "recipients": forms.Textarea(attrs={"rows": 2}),
            "security_measures": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        org = current_organisation(user)
        f = self.fields
        f["owner"].queryset = org_users(user)  # type: ignore[attr-defined]
        f["business_unit"].queryset = scoped_business_units(user)  # type: ignore[attr-defined]
        f["processors"].queryset = visible_entities(user)  # type: ignore[attr-defined]
        f["assets"].queryset = visible_assets(user)  # type: ignore[attr-defined]
        f["controls"].queryset = Control.objects.filter(organisation=org).live()  # type: ignore[attr-defined]
        if self.instance.pk:
            for name in ("processors", "assets", "controls"):
                self.initial[name] = list(getattr(self.instance, name).all())
            self.initial["data_categories"] = self.instance.data_categories
            self.initial["data_subjects"] = self.instance.data_subjects
        style_form(self)


class DpiaForm(forms.ModelForm):
    risks: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 5}),
        help_text="Risks in the register this DPIA identified or relies on.",
    )

    class Meta:
        model = Dpia
        fields = [
            "description",
            "necessity",
            "risks_to_individuals",
            "measures",
            "residual_risk",
            "dpo_advice",
        ]
        widgets = {
            name: forms.Textarea(attrs={"rows": 4})
            for name in (
                "description",
                "necessity",
                "risks_to_individuals",
                "measures",
                "dpo_advice",
            )
        }

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["risks"].queryset = visible_risks(user).live()  # type: ignore[attr-defined]
        if self.instance.pk:
            self.initial["risks"] = list(self.instance.risks.all())
        style_form(self)
