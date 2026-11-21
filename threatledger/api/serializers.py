from __future__ import annotations

from typing import Any

from rest_framework import serializers

from threatledger.accounts.models import User
from threatledger.attack.models import Technique
from threatledger.audit.models import AuditEvent
from threatledger.controls.models import Control
from threatledger.findings.models import Finding
from threatledger.org.models import BusinessUnit
from threatledger.risks.models import SCORE_FIELDS, Category, Risk, RiskStatus, Treatment


class ScoreSerializer(serializers.Serializer):
    likelihood = serializers.IntegerField()
    impact = serializers.IntegerField()
    score = serializers.IntegerField()
    band = serializers.CharField()


class RiskSerializer(serializers.ModelSerializer):
    owner = serializers.SlugRelatedField(
        slug_field="username",
        queryset=User.objects.filter(is_active=True),
        allow_null=True,
        required=False,
    )
    business_unit = serializers.PrimaryKeyRelatedField(
        queryset=BusinessUnit.objects.all(), allow_null=True, required=False
    )
    inherent = serializers.SerializerMethodField()
    residual = serializers.SerializerMethodField()
    techniques = serializers.SerializerMethodField()
    controls = serializers.SerializerMethodField()
    category = serializers.ChoiceField(choices=Category.choices, required=False)
    treatment = serializers.ChoiceField(choices=Treatment.choices, required=False)
    status = serializers.ChoiceField(
        choices=[c for c in RiskStatus.choices if c[0] != RiskStatus.ACCEPTED],
        required=False,
        help_text="'accepted' is set only by an approved risk acceptance.",
    )

    class Meta:
        model = Risk
        fields = [
            "ref",
            "title",
            "scenario",
            "category",
            "status",
            "treatment",
            "owner",
            "business_unit",
            *SCORE_FIELDS,
            "inherent",
            "residual",
            "target_date",
            "next_review_date",
            "techniques",
            "controls",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["ref", "created_at", "updated_at"]

    def _score(self, obj: Risk, kind: str) -> dict[str, Any]:
        s = getattr(obj, kind)
        matrix = self.context["matrix"]
        return {
            "likelihood": s.likelihood,
            "impact": s.impact,
            "score": s.value,
            "band": matrix.band(s.value).value,
        }

    def get_inherent(self, obj: Risk) -> dict[str, Any]:
        return self._score(obj, "inherent")

    def get_residual(self, obj: Risk) -> dict[str, Any]:
        return self._score(obj, "residual")

    def get_techniques(self, obj: Risk) -> list[str]:
        return sorted(t.attack_id for t in obj.techniques.all())

    def get_controls(self, obj: Risk) -> list[str]:
        return sorted(c.ref for c in obj.controls.all())


class LinkTechniqueSerializer(serializers.Serializer):
    attack_id = serializers.RegexField(r"^T\d{4}(\.\d{3})?$")
    rationale = serializers.CharField(required=False, allow_blank=True, max_length=500)


class ControlSerializer(serializers.ModelSerializer):
    owner: serializers.SlugRelatedField[Any] = serializers.SlugRelatedField(
        slug_field="username", read_only=True
    )
    mitigations = serializers.SerializerMethodField()
    techniques = serializers.SerializerMethodField()
    test_overdue = serializers.BooleanField(read_only=True)

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
            "last_tested_at",
            "last_test_result",
            "test_frequency_days",
            "test_overdue",
            "mitigations",
            "techniques",
            "updated_at",
        ]
        read_only_fields = [
            f for f in fields if f not in ("status", "effectiveness", "description")
        ]

    def get_mitigations(self, obj: Control) -> list[str]:
        return sorted(m.attack_id for m in obj.mitigations.all())

    def get_techniques(self, obj: Control) -> list[str]:
        return sorted(t.attack_id for t in obj.techniques.all())


class TechniqueSerializer(serializers.ModelSerializer):
    tactics = serializers.SerializerMethodField()
    # Not named "parent": DRF fields use .parent internally for the enclosing serializer.
    parent_technique: serializers.SlugRelatedField[Any] = serializers.SlugRelatedField(
        source="parent", slug_field="attack_id", read_only=True
    )
    coverage = serializers.SerializerMethodField()

    class Meta:
        model = Technique
        fields = [
            "attack_id",
            "name",
            "is_subtechnique",
            "parent_technique",
            "tactics",
            "platforms",
            "url",
            "is_revoked",
            "is_deprecated",
            "coverage",
        ]

    def get_tactics(self, obj: Technique) -> list[str]:
        return [t.shortname for t in obj.tactics.all()]

    def get_coverage(self, obj: Technique) -> str | None:
        cov = self.context.get("coverage", {}).get(obj.pk)
        return cov.status.css if cov else None


class AuditEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditEvent
        fields = [
            "id",
            "at",
            "actor_label",
            "action",
            "object_type",
            "object_id",
            "object_repr",
            "changes",
            "request_id",
            "ip",
            "hash",
            "prev_hash",
        ]


# ----------------------------------------------------------------------------- Phase 8
class AuditSerializer(serializers.Serializer):
    ref = serializers.CharField()
    name = serializers.CharField()
    framework = serializers.CharField(source="framework.code")
    business_unit = serializers.CharField(source="business_unit.name", allow_null=True)
    campaign = serializers.CharField(source="campaign.ref", allow_null=True)
    baseline = serializers.CharField()
    status = serializers.CharField()
    lead_auditor = serializers.CharField(source="lead_auditor.username", allow_null=True)
    due_on = serializers.DateField(allow_null=True)
    closed_at = serializers.DateTimeField(allow_null=True)
    conclusion = serializers.CharField()
    score = serializers.SerializerMethodField()

    def get_score(self, obj: Any) -> dict[str, Any]:
        s = self.context["scores"][obj.pk]
        return {
            "requirements": s.total,
            "assessed": s.assessed,
            "progress": s.progress,
            "score": s.score,
            "maturity": s.maturity,
            "compliant": s.compliant,
            "partial": s.partial,
            "non_compliant": s.non_compliant,
            "not_applicable": s.not_applicable,
        }


class AuditResultSerializer(serializers.Serializer):
    requirement = serializers.CharField(source="requirement.ref")
    judgement = serializers.CharField()
    maturity = serializers.IntegerField(allow_null=True)
    observation = serializers.CharField()
    derived_now = serializers.CharField()
    derived_at_judgement = serializers.CharField()
    divergent = serializers.BooleanField()
    assessed_by = serializers.CharField(allow_null=True)
    assessed_at = serializers.DateTimeField(allow_null=True)


class FindingSerializer(serializers.ModelSerializer):
    owner = serializers.SlugRelatedField(
        slug_field="username",
        queryset=User.objects.filter(is_active=True),
        allow_null=True,
        required=False,
    )
    business_unit = serializers.PrimaryKeyRelatedField(
        queryset=BusinessUnit.objects.all(), allow_null=True, required=False
    )
    audit: serializers.SlugRelatedField[Any] = serializers.SlugRelatedField(
        slug_field="ref", read_only=True
    )
    control: serializers.SlugRelatedField[Any] = serializers.SlugRelatedField(
        slug_field="ref", read_only=True
    )
    risk: serializers.SlugRelatedField[Any] = serializers.SlugRelatedField(
        slug_field="ref", read_only=True
    )
    requirement = serializers.SerializerMethodField()
    overdue = serializers.BooleanField(read_only=True)

    class Meta:
        model = Finding
        fields = [
            "ref",
            "title",
            "description",
            "severity",
            "status",
            "owner",
            "due_on",
            "overdue",
            "business_unit",
            "audit",
            "requirement",
            "control",
            "risk",
            "remediation",
            "created_at",
            "resolved_at",
            "closed_at",
        ]
        read_only_fields = ["ref", "created_at", "resolved_at", "closed_at"]

    def get_requirement(self, obj: Any) -> str | None:
        r = obj.requirement
        return f"{r.framework.code} {r.ref}" if r else None


class ExceptionSerializer(serializers.Serializer):
    ref = serializers.CharField()
    title = serializers.CharField()
    status = serializers.CharField(source="effective_status")
    justification = serializers.CharField()
    compensating_measures = serializers.CharField()
    expires_on = serializers.DateField()
    owner = serializers.CharField(source="owner.username", allow_null=True)
    requirements = serializers.SerializerMethodField()
    controls = serializers.SerializerMethodField()

    def get_requirements(self, obj: Any) -> list[str]:
        return [f"{r.framework.code} {r.ref}" for r in obj.requirements.all()]

    def get_controls(self, obj: Any) -> list[str]:
        return [c.ref for c in obj.controls.all()]


class PolicySerializer(serializers.Serializer):
    ref = serializers.CharField()
    title = serializers.CharField()
    kind = serializers.CharField()
    owner = serializers.CharField(source="owner.username", allow_null=True)
    status = serializers.SerializerMethodField()
    published_version = serializers.SerializerMethodField()
    effective_on = serializers.SerializerMethodField()
    next_review_on = serializers.SerializerMethodField()
    controls = serializers.SerializerMethodField()

    def _state(self, obj: Any) -> Any:
        from threatledger.policies.services import policy_state

        return policy_state(obj, list(obj.versions.all()))  # versions are prefetched

    def get_status(self, obj: Any) -> str:
        return str(self._state(obj).status)

    def get_published_version(self, obj: Any) -> int | None:
        v = self._state(obj).published
        return v.number if v else None

    def get_effective_on(self, obj: Any) -> str | None:
        v = self._state(obj).published
        return v.effective_on.isoformat() if v and v.effective_on else None

    def get_next_review_on(self, obj: Any) -> str | None:
        d = self._state(obj).next_review_on
        return d.isoformat() if d else None

    def get_controls(self, obj: Any) -> list[str]:
        return [c.ref for c in obj.controls.all()]


# ----------------------------------------------------------------------------- Phase 9
class TaskSerializer(serializers.Serializer):
    ref = serializers.CharField(read_only=True)
    title = serializers.CharField(read_only=True)
    status = serializers.ChoiceField(
        choices=["todo", "in_progress", "blocked", "done", "cancelled"]
    )
    note = serializers.CharField(write_only=True, required=False, allow_blank=True)
    priority = serializers.CharField(read_only=True)
    due_on = serializers.DateField(read_only=True)
    recurrence = serializers.CharField(read_only=True)
    requires_evidence = serializers.BooleanField(read_only=True)
    assignees = serializers.SerializerMethodField()
    control = serializers.CharField(source="control.ref", read_only=True, allow_null=True)
    overdue = serializers.BooleanField(read_only=True)
    completed_at = serializers.DateTimeField(read_only=True)

    def get_assignees(self, obj: Any) -> list[str]:
        return [u.get_username() for u in obj.assignees.all()]
