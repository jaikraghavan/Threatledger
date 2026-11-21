from __future__ import annotations

from typing import Any

from django import forms

from threatledger.core.forms import DATE, org_users, scoped_business_units, style_form
from threatledger.risks.services import visible_assets, visible_risks
from threatledger.work.models import Questionnaire

from .models import Contract, Entity, Solution


class EntityForm(forms.ModelForm):
    website = forms.URLField(max_length=500, required=False, assume_scheme="https")
    risks: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 5}),
        help_text="Risks in the register that involve this third party.",
    )

    class Meta:
        model = Entity
        fields = [
            "name",
            "legal_name",
            "tier",
            "status",
            "owner",
            "business_unit",
            "data_access",
            "ict_provider",
            "substitutability",
            "exit_plan",
            "lei",
            "country",
            "website",
            "security_contact",
            "external_rating",
            "external_rating_source",
            "external_rating_date",
            "description",
        ]
        widgets = {
            "external_rating_date": DATE,
            "description": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["owner"].queryset = org_users(user)  # type: ignore[attr-defined]
        self.fields["business_unit"].queryset = scoped_business_units(user)  # type: ignore[attr-defined]
        self.fields["risks"].queryset = visible_risks(user).live()  # type: ignore[attr-defined]
        if self.instance.pk:
            self.initial["risks"] = list(self.instance.risks.all())
        style_form(self)


class SolutionForm(forms.ModelForm):
    assets: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None, required=False, widget=forms.SelectMultiple(attrs={"size": 4})
    )

    class Meta:
        model = Solution
        fields = [
            "name",
            "ict_service_type",
            "supported_function",
            "function_is_critical",
            "data_locations",
            "description",
        ]
        widgets = {"description": forms.Textarea(attrs={"rows": 2})}

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["assets"].queryset = visible_assets(user)  # type: ignore[attr-defined]
        style_form(self)


class ContractForm(forms.ModelForm):
    document_url = forms.URLField(max_length=1000, required=False, assume_scheme="https")
    solutions: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None, required=False, widget=forms.CheckboxSelectMultiple, label="Services covered"
    )

    class Meta:
        model = Contract
        fields = [
            "title",
            "reference",
            "start_date",
            "end_date",
            "notice_days",
            "auto_renew",
            "annual_value",
            "currency",
            "governing_law",
            "breach_notification_hours",
            "security_clauses",
            "audit_rights",
            "data_processing_agreement",
            "exit_assistance",
            "subcontracting_allowed",
            "document_url",
            "terminated_on",
        ]
        widgets = {"start_date": DATE, "end_date": DATE, "terminated_on": DATE}

    def __init__(self, *args: Any, entity: Entity, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["solutions"].queryset = entity.solutions.all()  # type: ignore[attr-defined]
        if self.instance.pk:
            self.initial["solutions"] = list(self.instance.solutions.all())
        style_form(self)


class SendAssessmentForm(forms.Form):
    questionnaire: forms.ModelChoiceField = forms.ModelChoiceField(queryset=None)
    contact_name = forms.CharField(max_length=200, required=False)
    contact_email = forms.EmailField()
    due_on = forms.DateField(required=False, widget=DATE)
    days = forms.IntegerField(min_value=1, max_value=90, initial=30, label="Link valid for (days)")
    message = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 2}))
    send_email = forms.BooleanField(
        required=False, initial=True, label="Email the link to the contact"
    )

    def __init__(self, *args: Any, org: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["questionnaire"].queryset = Questionnaire.objects.filter(  # type: ignore[attr-defined]
            organisation=org, archived_at__isnull=True, questions__isnull=False
        ).distinct()
        style_form(self)
