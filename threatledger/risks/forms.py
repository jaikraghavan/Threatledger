from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from django import forms
from django.core.exceptions import ValidationError
from django.utils import timezone

from threatledger.accounts.models import User
from threatledger.accounts.permissions import business_unit_scope, current_organisation
from threatledger.org.models import BusinessUnit

from . import services
from .models import SCORE_FIELDS, Asset, Risk, RiskMatrix, RiskStatus

DATE = forms.DateInput(attrs={"type": "date", "class": "field"})


def _style(form: forms.BaseForm) -> None:
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


class RiskForm(forms.ModelForm):
    reason = forms.CharField(
        required=False,
        max_length=500,
        label="Reason for change",
        help_text="Recorded in the score history when scores change.",
    )

    class Meta:
        model = Risk
        fields = [
            "title",
            "scenario",
            "category",
            "business_unit",
            "owner",
            "assets",
            *SCORE_FIELDS,
            "treatment",
            "status",
            "target_date",
            "next_review_date",
        ]
        widgets = {
            "scenario": forms.Textarea(attrs={"rows": 5}),
            "target_date": DATE,
            "next_review_date": DATE,
            "assets": forms.SelectMultiple(attrs={"size": 6}),
        }

    def __init__(self, *args: Any, user: Any, matrix: RiskMatrix, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.user, self.matrix = user, matrix
        self.fields["owner"].queryset = org_users(user)  # type: ignore[attr-defined]
        self.fields["business_unit"].queryset = scoped_business_units(user)  # type: ignore[attr-defined]
        self.fields["assets"].queryset = services.visible_assets(user).filter(  # type: ignore[attr-defined]
            archived_at__isnull=True
        )
        likelihood = [(i, f"{i} · {matrix.likelihood_label(i)}") for i in matrix.scale]
        impact = [(i, f"{i} · {matrix.impact_label(i)}") for i in matrix.scale]
        for field in SCORE_FIELDS:
            self.fields[field] = forms.TypedChoiceField(
                choices=likelihood if field.endswith("likelihood") else impact,
                coerce=int,
                label=self.fields[field].label,
                initial=self.initial.get(field, getattr(self.instance, field, 3)),
            )
        # "Accepted" is reached only through the approval workflow.
        current = self.instance.status if self.instance.pk else None
        self.fields["status"].choices = [  # type: ignore[attr-defined]
            c for c in RiskStatus.choices if c[0] != RiskStatus.ACCEPTED or c[0] == current
        ]
        if not self.instance.pk:
            self.fields["next_review_date"].initial = timezone.localdate() + timedelta(days=90)
            self.fields.pop("reason")
        _style(self)

    def clean_next_review_date(self) -> date | None:
        value: date | None = self.cleaned_data.get("next_review_date")
        if value and value < date(2000, 1, 1):
            raise ValidationError("Enter a realistic date.")
        return value

    def clean(self) -> dict[str, Any]:
        data = super().clean() or {}
        scores = {f: data.get(f) for f in SCORE_FIELDS}
        if all(isinstance(v, int) for v in scores.values()):
            try:
                services.validate_scores(self.matrix, scores)
            except ValidationError as exc:
                for field, messages in exc.message_dict.items():
                    self.add_error(field if field in self.fields else None, messages)
        target = data.get("target_date")
        if (
            not self.instance.pk
            and target
            and target < timezone.localdate()
            and data.get("status") != RiskStatus.CLOSED
        ):
            self.add_error("target_date", "Target date is in the past.")
        return data

    def model_data(self) -> dict[str, Any]:
        return {k: v for k, v in self.cleaned_data.items() if k not in ("assets", "reason")}


class AssetForm(forms.ModelForm):
    class Meta:
        model = Asset
        fields = [
            "name",
            "kind",
            "business_unit",
            "owner",
            "criticality",
            "data_classification",
            "contains_personal_data",
            "description",
        ]
        widgets = {"description": forms.Textarea(attrs={"rows": 3})}

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.user = user
        self.fields["owner"].queryset = org_users(user)  # type: ignore[attr-defined]
        self.fields["business_unit"].queryset = scoped_business_units(user)  # type: ignore[attr-defined]
        self.fields["criticality"] = forms.TypedChoiceField(
            choices=[(i, str(i)) for i in range(1, 6)], coerce=int, initial=3
        )
        _style(self)

    def clean_name(self) -> str:
        name: str = self.cleaned_data["name"].strip()
        org = current_organisation(self.user)
        clash = Asset.objects.filter(organisation=org, name__iexact=name)
        if self.instance.pk:
            clash = clash.exclude(pk=self.instance.pk)
        if clash.exists():
            raise ValidationError("An asset with this name already exists.")
        return name


class MatrixForm(forms.Form):
    size = forms.TypedChoiceField(
        choices=[(n, f"{n} × {n}") for n in range(RiskMatrix.MIN_SIZE, RiskMatrix.MAX_SIZE + 1)],
        coerce=int,
    )
    likelihood_labels = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 6}), help_text="One label per line, lowest first."
    )
    impact_labels = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 6}), help_text="One label per line, lowest first."
    )
    low_max = forms.IntegerField(min_value=1, label="Low: score up to")
    medium_max = forms.IntegerField(min_value=2, label="Medium: score up to")
    high_max = forms.IntegerField(min_value=3, label="High: score up to (above = Critical)")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        _style(self)

    @staticmethod
    def initial_for(matrix: RiskMatrix) -> dict[str, Any]:
        return {
            "size": matrix.size,
            "likelihood_labels": "\n".join(matrix.likelihood_labels),
            "impact_labels": "\n".join(matrix.impact_labels),
            "low_max": matrix.low_max,
            "medium_max": matrix.medium_max,
            "high_max": matrix.high_max,
        }

    def matrix_data(self) -> dict[str, Any]:
        d = dict(self.cleaned_data)
        for key in ("likelihood_labels", "impact_labels"):
            d[key] = [line.strip() for line in d[key].splitlines() if line.strip()]
        return d


class AcceptanceForm(forms.Form):
    justification = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 4}),
        max_length=4000,
        help_text="Why is this risk acceptable? Include compensating measures and business reason.",
    )
    expires_on = forms.DateField(widget=DATE, help_text="Acceptance lapses on this date.")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        _style(self)


class DecisionForm(forms.Form):
    decision = forms.ChoiceField(choices=[("approve", "Approve"), ("reject", "Reject")])
    note = forms.CharField(required=False, max_length=500)
