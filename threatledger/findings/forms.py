from __future__ import annotations

from typing import Any

from django import forms

from threatledger.accounts.permissions import current_organisation
from threatledger.audits.services import visible_audits
from threatledger.controls.models import Control
from threatledger.core.forms import DATE, org_users, scoped_business_units, style_form
from threatledger.frameworks.models import Requirement
from threatledger.risks.services import visible_risks

from .models import Finding, SecurityException


class FindingForm(forms.ModelForm):
    class Meta:
        model = Finding
        fields = [
            "title",
            "severity",
            "owner",
            "due_on",
            "business_unit",
            "audit",
            "requirement",
            "control",
            "risk",
            "entity",
            "description",
            "remediation",
        ]
        widgets = {
            "due_on": DATE,
            "description": forms.Textarea(attrs={"rows": 4}),
            "remediation": forms.Textarea(attrs={"rows": 4}),
            "requirement": forms.NumberInput(),
        }
        help_texts = {
            "due_on": "Defaults by severity: critical 30, high 60, medium 90, low 180 days."
        }

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        org = current_organisation(user)
        f = self.fields
        f["owner"].queryset = org_users(user)  # type: ignore[attr-defined]
        f["business_unit"].queryset = scoped_business_units(user)  # type: ignore[attr-defined]
        f["audit"].queryset = visible_audits(user).exclude(status="closed")  # type: ignore[attr-defined]
        f["control"].queryset = Control.objects.filter(organisation=org).live()  # type: ignore[attr-defined]
        f["risk"].queryset = visible_risks(user)  # type: ignore[attr-defined]
        from threatledger.vendors.services import visible_entities

        f["entity"].queryset = visible_entities(user)  # type: ignore[attr-defined]
        f["entity"].label = "Vendor"
        audit = self.initial.get("audit") or getattr(self.instance, "audit", None)
        reqs = Requirement.objects.filter(is_domain=False)
        if audit is not None:
            audit_id = audit.pk if hasattr(audit, "pk") else audit
            reqs = reqs.filter(framework__audits=audit_id)
        f["requirement"].queryset = reqs  # type: ignore[attr-defined]
        f["requirement"].widget = forms.HiddenInput()
        style_form(self)


class OwnerFindingForm(forms.ModelForm):
    class Meta:
        model = Finding
        fields = ["remediation"]
        widgets = {"remediation": forms.Textarea(attrs={"rows": 5})}

    def __init__(self, *args: Any, user: Any = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        style_form(self)


class FindingStatusForm(forms.Form):
    status = forms.CharField(max_length=16)
    note = forms.CharField(max_length=500, required=False)


class ExceptionForm(forms.ModelForm):
    requirement_refs = forms.CharField(
        required=False,
        label="Requirements",
        help_text="Framework code and refs, one per line, e.g. nist-800-53-r5 AC-2",
        widget=forms.Textarea(attrs={"rows": 3}),
    )
    controls: forms.ModelMultipleChoiceField = forms.ModelMultipleChoiceField(
        queryset=None, required=False, widget=forms.SelectMultiple(attrs={"size": 6})
    )

    class Meta:
        model = SecurityException
        fields = [
            "title",
            "expires_on",
            "owner",
            "business_unit",
            "risk",
            "justification",
            "compensating_measures",
        ]
        widgets = {
            "expires_on": DATE,
            "justification": forms.Textarea(attrs={"rows": 4}),
            "compensating_measures": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        org = current_organisation(user)
        f = self.fields
        f["owner"].queryset = org_users(user)  # type: ignore[attr-defined]
        f["business_unit"].queryset = scoped_business_units(user)  # type: ignore[attr-defined]
        f["risk"].queryset = visible_risks(user)  # type: ignore[attr-defined]
        f["controls"].queryset = Control.objects.filter(organisation=org).live()  # type: ignore[attr-defined]
        style_form(self)

    def clean_requirement_refs(self) -> list[Requirement]:
        out: list[Requirement] = []
        for line in (self.cleaned_data.get("requirement_refs") or "").splitlines():
            parts = line.split(None, 1)
            if not parts:
                continue
            if len(parts) != 2:
                raise forms.ValidationError(f"“{line.strip()}”: use “<framework code> <ref>”.")
            req = Requirement.objects.filter(
                framework__code__iexact=parts[0], ref__iexact=parts[1].strip(), is_domain=False
            ).first()
            if req is None:
                raise forms.ValidationError(f"Unknown requirement “{line.strip()}”.")
            out.append(req)
        return out


class DecisionForm(forms.Form):
    decision = forms.ChoiceField(
        choices=[("approve", "Approve"), ("reject", "Reject"), ("revoke", "Revoke")]
    )
    note = forms.CharField(max_length=500, required=False)
