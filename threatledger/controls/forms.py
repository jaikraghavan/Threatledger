from __future__ import annotations

from typing import Any

from django import forms
from django.utils import timezone

from threatledger.core.forms import DATE, org_users
from threatledger.core.forms import style_form as _style

from .models import Control, ControlTest, Evidence, TestResult

EFFECTIVENESS = [("", "Not assessed")] + [(str(i), f"{i} – {label}") for i, label in enumerate(
    ["Weak", "Limited", "Moderate", "Strong", "Very strong"], start=1
)]  # fmt: skip


class _EffectivenessMixin(forms.ModelForm):
    effectiveness = forms.TypedChoiceField(
        choices=EFFECTIVENESS, coerce=int, empty_value=None, required=False
    )


class ControlForm(_EffectivenessMixin):
    class Meta:
        model = Control
        fields = [
            "ref",
            "name",
            "description",
            "owner",
            "control_type",
            "status",
            "effectiveness",
            "test_frequency_days",
        ]
        widgets = {"description": forms.Textarea(attrs={"rows": 4})}
        help_texts = {"ref": "Short unique reference, e.g. CTL-MFA."}

    def __init__(self, *args: Any, user: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["owner"].queryset = org_users(user)  # type: ignore[attr-defined]
        _style(self)

    def data_for_service(self) -> dict[str, Any]:
        return dict(self.cleaned_data)


class OwnerControlForm(_EffectivenessMixin):
    """What a Control Owner may change on their own control."""

    class Meta:
        model = Control
        fields = ["status", "effectiveness", "description"]
        widgets = {"description": forms.Textarea(attrs={"rows": 4})}

    def __init__(self, *args: Any, user: Any = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        _style(self)

    def data_for_service(self) -> dict[str, Any]:
        return dict(self.cleaned_data)


class EvidenceFileForm(forms.Form):
    title = forms.CharField(max_length=200, required=False, help_text="Defaults to the file name.")
    file = forms.FileField()
    valid_until = forms.DateField(required=False, widget=DATE, label="Valid until")
    description = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 2}))

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        _style(self)
        self.fields["file"].widget.attrs["accept"] = (
            ".pdf,.png,.jpg,.jpeg,.txt,.log,.md,.csv,.json,.docx,.xlsx,.pptx"
        )


class EvidenceLinkForm(forms.Form):
    title = forms.CharField(max_length=200)
    url = forms.URLField(max_length=1000, assume_scheme="https", label="URL")
    valid_until = forms.DateField(required=False, widget=DATE, label="Valid until")
    description = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 2}))

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        _style(self)
        for name in self.fields:
            self.fields[name].widget.attrs["id"] = f"link_{name}"


class ControlTestForm(forms.ModelForm):
    evidence = forms.ModelMultipleChoiceField(
        queryset=Evidence.objects.none(), required=False, widget=forms.CheckboxSelectMultiple
    )

    class Meta:
        model = ControlTest
        fields = ["tested_on", "method", "result", "notes"]
        widgets = {"tested_on": DATE, "notes": forms.Textarea(attrs={"rows": 3})}

    def __init__(self, *args: Any, control: Control, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["evidence"].queryset = control.evidence.filter(archived_at__isnull=True)  # type: ignore[attr-defined]
        result_field: Any = self.fields["result"]
        result_field.choices = [c for c in TestResult.choices if c[0] != TestResult.NOT_TESTED]
        self.fields["tested_on"].initial = timezone.localdate()
        _style(self)
        for name in self.fields:
            self.fields[name].widget.attrs["id"] = f"test_{name}"
