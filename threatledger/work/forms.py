from __future__ import annotations

from typing import Any

from django import forms

from threatledger.accounts.permissions import current_organisation
from threatledger.audits.services import visible_audits
from threatledger.controls.models import Control
from threatledger.core.forms import DATE, org_users, scoped_business_units, style_form
from threatledger.findings.services import visible_findings
from threatledger.policies.services import visible_policies
from threatledger.risks.services import visible_risks

from .models import Question, QuestionKind, Task


class TaskForm(forms.ModelForm):
    assignees: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None, required=False, widget=forms.SelectMultiple(attrs={"size": 5})
    )

    class Meta:
        model = Task
        fields = [
            "title",
            "priority",
            "due_on",
            "recurrence",
            "business_unit",
            "control",
            "risk",
            "finding",
            "policy",
            "audit",
            "requires_evidence",
            "description",
        ]
        widgets = {"due_on": DATE, "description": forms.Textarea(attrs={"rows": 4})}

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        org = current_organisation(user)
        f = self.fields
        f["assignees"].queryset = org_users(user)  # type: ignore[attr-defined]
        f["business_unit"].queryset = scoped_business_units(user)  # type: ignore[attr-defined]
        f["control"].queryset = Control.objects.filter(organisation=org).live()  # type: ignore[attr-defined]
        f["risk"].queryset = visible_risks(user)  # type: ignore[attr-defined]
        f["finding"].queryset = visible_findings(user).exclude(status="closed")  # type: ignore[attr-defined]
        f["policy"].queryset = visible_policies(user).filter(retired_at__isnull=True)  # type: ignore[attr-defined]
        f["audit"].queryset = visible_audits(user).exclude(status="closed")  # type: ignore[attr-defined]
        if self.instance.pk:
            self.initial["assignees"] = list(self.instance.assignees.all())
        style_form(self)


class TaskStatusForm(forms.Form):
    status = forms.CharField(max_length=16)
    note = forms.CharField(required=False, max_length=5000)


class QuestionnaireForm(forms.Form):
    title = forms.CharField(max_length=200)
    description = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 3}))

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        style_form(self)


class QuestionForm(forms.ModelForm):
    choices_text = forms.CharField(
        required=False,
        label="Choices",
        help_text="For single choice: one option per line.",
        widget=forms.Textarea(attrs={"rows": 3}),
    )

    class Meta:
        model = Question
        fields = ["text", "help_text", "kind", "required", "evidence_required"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        style_form(self)

    def data_for_service(self) -> dict[str, Any]:
        d = dict(self.cleaned_data)
        d["choices"] = [c for c in (d.pop("choices_text") or "").splitlines() if c.strip()]
        if d["kind"] != QuestionKind.CHOICE:
            d["choices"] = []
        return d


class AssignForm(forms.Form):
    respondents: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None, widget=forms.SelectMultiple(attrs={"size": 5})
    )
    due_on = forms.DateField(required=False, widget=DATE)
    control: forms.ModelChoiceField = forms.ModelChoiceField(
        queryset=None, required=False, help_text="Optional: the control this is about."
    )
    business_unit: forms.ModelChoiceField = forms.ModelChoiceField(queryset=None, required=False)
    message = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 2}))

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        org = current_organisation(user)
        self.fields["respondents"].queryset = org_users(user)  # type: ignore[attr-defined]
        self.fields["control"].queryset = Control.objects.filter(organisation=org).live()  # type: ignore[attr-defined]
        self.fields["business_unit"].queryset = scoped_business_units(user)  # type: ignore[attr-defined]
        style_form(self)


class PreferenceForm(forms.Form):
    email_digest = forms.BooleanField(
        required=False,
        label="Send me a daily email when something is due, overdue or waiting for me",
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        style_form(self)
