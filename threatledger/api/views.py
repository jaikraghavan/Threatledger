"""REST API v1. Every write goes through the same services as the UI (permissions + audit)."""

from __future__ import annotations

from datetime import date
from typing import Any

from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.models import Prefetch, Q, QuerySet
from django.shortcuts import get_object_or_404
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import exceptions, mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from threatledger.accounts.permissions import (
    AUTHENTICATED,
    capabilities,
    current_organisation,
    get_role,
)
from threatledger.accounts.roles import Cap
from threatledger.attack.models import Tactic, Technique
from threatledger.attack.services import current_release
from threatledger.audit.models import Action, AuditEvent
from threatledger.audit.services import record
from threatledger.audits import services as audit_services
from threatledger.audits.models import Audit
from threatledger.controls import services as control_services
from threatledger.controls.models import Control
from threatledger.coverage.matrix import build_matrix, navigator_layer, resolve_scope
from threatledger.coverage.selectors import coverage_for
from threatledger.findings import services as finding_services
from threatledger.findings.models import Finding, SecurityException
from threatledger.frameworks import services as fw_services
from threatledger.frameworks.models import Framework, Requirement
from threatledger.incidents import services as incident_services
from threatledger.incidents.models import Incident
from threatledger.policies import services as policy_services
from threatledger.policies.models import Policy
from threatledger.privacy import services as privacy_services
from threatledger.privacy.models import Processing
from threatledger.risks import services as risk_services
from threatledger.risks.models import Risk, RiskMatrix
from threatledger.vendors import services as vendor_services
from threatledger.work import services as work_services
from threatledger.work.models import Task

from .serializers import (
    AuditEventSerializer,
    AuditResultSerializer,
    AuditSerializer,
    ControlSerializer,
    ExceptionSerializer,
    FindingSerializer,
    IncidentSerializer,
    LinkTechniqueSerializer,
    PolicySerializer,
    ProcessingSerializer,
    RiskSerializer,
    TaskSerializer,
    TechniqueSerializer,
    VendorSerializer,
)


def _org(request: Request) -> Any:
    org = current_organisation(request.user)
    if org is None:
        raise exceptions.NotFound("No organisation configured")
    return org


def _body(request: Request) -> dict[str, Any]:
    data = request.data
    return data if isinstance(data, dict) else {}


def _as_drf(exc: Exception) -> exceptions.APIException:
    if isinstance(exc, DjangoValidationError):
        return exceptions.ValidationError(
            exc.message_dict if hasattr(exc, "error_dict") else exc.messages
        )
    if isinstance(
        exc,
        (
            risk_services.RiskError,
            control_services.ControlError,
            fw_services.FrameworkError,
            finding_services.FindingError,
        ),
    ):
        return exceptions.PermissionDenied(str(exc))
    raise exc


class MeView(APIView):
    """The authenticated user's identity, role and capabilities."""

    tl_access = AUTHENTICATED

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request: Request) -> Response:
        role = get_role(request.user)
        return Response(
            {
                "username": request.user.get_username(),
                "role": role.value if role else None,
                "capabilities": sorted(c.value for c in capabilities(request.user)),
                "auth": "token" if request.auth is not None else "session",
            }
        )


class RiskViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.CreateModelMixin,
                  mixins.UpdateModelMixin, viewsets.GenericViewSet):  # fmt: skip
    """Risk register. Writes require ``edit_risks`` and respect business-unit scope."""

    tl_access = Cap.VIEW_RISKS
    tl_write_access = Cap.EDIT_RISKS
    serializer_class = RiskSerializer
    lookup_field = "ref"
    http_method_names = ["get", "post", "patch", "head", "options"]

    def get_queryset(self) -> QuerySet[Risk]:
        if getattr(self, "swagger_fake_view", False):  # OpenAPI generation: no real user/org
            return Risk.objects.none()
        qs = (
            risk_services.visible_risks(self.request.user)
            .live()
            .select_related("owner", "business_unit")
        )
        qs = qs.prefetch_related(Prefetch("techniques"), Prefetch("controls"))
        status_ = self.request.query_params.get("status")
        if status_:
            qs = qs.filter(status=status_)
        technique = self.request.query_params.get("technique")
        if technique:
            qs = qs.filter(techniques__attack_id=technique.upper())
        return qs.order_by("ref").distinct()

    def get_serializer_context(self) -> dict[str, Any]:
        ctx = dict(super().get_serializer_context())
        if not getattr(self, "swagger_fake_view", False):
            ctx["matrix"] = RiskMatrix.for_org(_org(self.request))
        return ctx

    def perform_create(self, serializer: Any) -> None:
        try:
            serializer.instance = risk_services.create_risk(
                user=self.request.user, data=dict(serializer.validated_data)
            )
        except Exception as exc:
            raise _as_drf(exc) from exc

    def perform_update(self, serializer: Any) -> None:
        try:
            serializer.instance = risk_services.update_risk(
                serializer.instance,
                user=self.request.user,
                data=dict(serializer.validated_data),
                reason=str(_body(self.request).get("reason", ""))[:500],
            )
        except Exception as exc:
            raise _as_drf(exc) from exc

    @extend_schema(request=LinkTechniqueSerializer, responses={200: RiskSerializer})
    @action(detail=True, methods=["post"], url_path="techniques")
    def link_technique(self, request: Request, ref: str | None = None) -> Response:
        """Link an ATT&CK technique to the risk (idempotent)."""
        risk = self.get_object()
        body = LinkTechniqueSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        technique = get_object_or_404(Technique, attack_id=body.validated_data["attack_id"])
        try:
            risk_services.link_technique(
                risk,
                technique,
                user=request.user,
                rationale=body.validated_data.get("rationale", ""),
            )
        except Exception as exc:
            raise _as_drf(exc) from exc
        risk.refresh_from_db()
        return Response(self.get_serializer(risk).data)


class ControlViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Controls. PATCH ``status`` / ``effectiveness`` / ``description`` (owners: own controls)."""

    tl_access = Cap.VIEW_CONTROLS
    tl_write_access = Cap.EDIT_OWN_CONTROL
    serializer_class = ControlSerializer
    lookup_field = "ref"
    http_method_names = ["get", "patch", "head", "options"]

    def get_queryset(self) -> QuerySet[Control]:
        if getattr(self, "swagger_fake_view", False):  # OpenAPI generation: no real user/org
            return Control.objects.none()
        qs = control_services.visible_controls(self.request.user).live().select_related("owner")
        status_ = self.request.query_params.get("status")
        if status_:
            qs = qs.filter(status=status_)
        return qs.prefetch_related("mitigations", "techniques").order_by("ref")

    def perform_update(self, serializer: Any) -> None:
        try:
            serializer.instance = control_services.update_control(
                serializer.instance, user=self.request.user, data=dict(serializer.validated_data)
            )
        except Exception as exc:
            raise _as_drf(exc) from exc


class TechniqueViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Active ATT&CK techniques with this organisation's coverage (covered / partial / gap)."""

    tl_access = Cap.VIEW_ATTACK
    serializer_class = TechniqueSerializer
    lookup_field = "attack_id"
    lookup_value_regex = r"T\d{4}(?:\.\d{3})?"

    @extend_schema(parameters=[OpenApiParameter("q", str), OpenApiParameter("tactic", str)])
    def list(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return super().list(request, *args, **kwargs)

    def get_queryset(self) -> QuerySet[Technique]:
        if getattr(self, "swagger_fake_view", False):  # OpenAPI generation: no real user/org
            return Technique.objects.none()
        qs = Technique.objects.all() if self.action == "retrieve" else Technique.objects.active()
        q = self.request.query_params.get("q", "").strip()
        if q:
            qs = qs.filter(Q(attack_id__istartswith=q) | Q(name__icontains=q))
        tactic = self.request.query_params.get("tactic")
        if tactic:
            qs = qs.filter(tactics__shortname=tactic)
        return (
            qs.select_related("parent")
            .prefetch_related(Prefetch("tactics", queryset=Tactic.objects.order_by("order")))
            .order_by("attack_id")
            .distinct()
        )

    def get_serializer(self, *args: Any, **kwargs: Any) -> Any:
        if getattr(self, "swagger_fake_view", False):
            return super().get_serializer(*args, **kwargs)
        instance = args[0] if args else None
        items = (
            list(instance)
            if isinstance(instance, list)
            else ([instance] if instance is not None else [])
        )
        kwargs.setdefault("context", self.get_serializer_context())
        kwargs["context"]["coverage"] = (
            coverage_for((t.pk for t in items), _org(self.request).pk) if items else {}
        )
        return super().get_serializer(*args, **kwargs)


class FrameworkView(APIView):
    """Adopted frameworks with derived compliance."""

    tl_access = Cap.VIEW_FRAMEWORKS

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request: Request) -> Response:
        org = _org(request)
        out = []
        for fw in fw_services.adopted_frameworks(org):
            r = fw_services.framework_result(fw, org)
            s = r.summary
            out.append(
                {
                    "code": fw.code,
                    "name": fw.name,
                    "version": fw.version,
                    "baseline": r.settings.baseline,
                    "percent": s.percent,
                    "tracked": s.tracked,
                    "met": s.met,
                    "partial": s.partial,
                    "gap": s.gap,
                    "no_control": s.no_control,
                    "indicative": fw.is_indicative,
                }
            )
        return Response(out)


class FrameworkRequirementsView(APIView):
    """Tracked requirements of one framework with status and mapped controls."""

    tl_access = Cap.VIEW_FRAMEWORKS

    @extend_schema(
        parameters=[OpenApiParameter("status", str, enum=["met", "partial", "gap", "no_control"])],
        responses={200: OpenApiTypes.OBJECT},
    )
    def get(self, request: Request, code: str) -> Response:
        fw = get_object_or_404(Framework, code=code)
        org = _org(request)
        result = fw_services.framework_result(fw, org)
        wanted = request.query_params.get("status")
        reqs = Requirement.objects.in_bulk(result.summary.by_requirement.keys())
        rows = []
        for pk, st in result.summary.by_requirement.items():
            if wanted and st.value != wanted:
                continue
            r = reqs[pk]
            rows.append(
                (
                    r.order,
                    {
                        "ref": r.ref,
                        "title": r.title,
                        "status": st.value,
                        "controls": sorted(
                            c.ref for c in result.controls_by_requirement.get(pk, [])
                        ),
                    },
                )
            )
        rows.sort(key=lambda pair: pair[0])
        return Response(
            {
                "framework": fw.code,
                "percent": result.summary.percent,
                "requirements": [r for _, r in rows],
            }
        )


class CoverageView(APIView):
    """ATT&CK coverage summary for a scope (risks | all | group | sector)."""

    tl_access = Cap.VIEW_ATTACK

    @extend_schema(
        parameters=[
            OpenApiParameter("scope", str, enum=["risks", "all", "group", "sector"]),
            OpenApiParameter("value", str),
        ],
        responses={200: OpenApiTypes.OBJECT},
    )
    def get(self, request: Request) -> Response:
        scope = resolve_scope(
            request.user,
            request.query_params.get("scope", "risks"),
            request.query_params.get("value", ""),
        )
        m = build_matrix(scope, _org(request))
        s = m.summary
        return Response(
            {
                "scope": scope.label,
                "covered": s.covered,
                "partial": s.partial,
                "gap": s.gap,
                "total": s.total,
                "percent": s.percent,
            }
        )


class NavigatorView(APIView):
    """ATT&CK Navigator layer (v4.5) for a scope."""

    tl_access = Cap.EXPORT_DATA

    @extend_schema(
        parameters=[OpenApiParameter("scope", str), OpenApiParameter("value", str)],
        responses={200: OpenApiTypes.OBJECT},
    )
    def get(self, request: Request) -> Response:
        org = _org(request)
        scope = resolve_scope(
            request.user,
            request.query_params.get("scope", "risks"),
            request.query_params.get("value", ""),
        )
        release = current_release()
        layer = navigator_layer(
            build_matrix(scope, org), release.version if release else "", org.name
        )
        record(
            Action.EXPORT,
            actor=request.user,
            object_type="coverage.navigator",
            object_repr=f"API Navigator layer: {scope.label}"[:300],
            changes={"scope": [None, scope.params]},
        )
        return Response(layer, status=status.HTTP_200_OK)


class AuditEventViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """Audit log (read-only). Filters: ``action``, ``object_type``, ``since`` (ISO date)."""

    tl_access = Cap.VIEW_AUDIT_LOG
    serializer_class = AuditEventSerializer

    def get_queryset(self) -> QuerySet[AuditEvent]:
        qs = AuditEvent.objects.order_by("-id")
        p = self.request.query_params
        if p.get("action"):
            qs = qs.filter(action=p["action"])
        if p.get("object_type"):
            qs = qs.filter(object_type=p["object_type"])
        if p.get("since"):
            try:
                since = date.fromisoformat(p["since"])
            except ValueError as exc:
                raise exceptions.ValidationError(
                    {"since": "Use an ISO date, e.g. 2026-01-31."}
                ) from exc
            qs = qs.filter(at__date__gte=since)
        return qs


# ----------------------------------------------------------------------------- Phase 8
class AuditViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Compliance audits with progress, score and maturity (``?status=``)."""

    tl_access = Cap.VIEW_AUDITS
    serializer_class = AuditSerializer
    lookup_field = "ref"

    def get_queryset(self) -> QuerySet[Any]:
        if getattr(self, "swagger_fake_view", False):
            return Audit.objects.none()
        qs = audit_services.visible_audits(self.request.user).select_related(
            "framework", "business_unit", "campaign", "lead_auditor"
        )
        status_ = self.request.query_params.get("status")
        if status_:
            qs = qs.filter(status=status_)
        return qs.order_by("ref")

    def get_serializer_context(self) -> dict[str, Any]:
        ctx = dict(super().get_serializer_context())
        if not getattr(self, "swagger_fake_view", False):
            objs = getattr(self, "_page_objects", None)
            ctx["scores"] = audit_services.list_scores(objs if objs is not None else [])
        return ctx

    def list(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        page = self.paginate_queryset(self.get_queryset())
        self._page_objects = list(page if page is not None else self.get_queryset())
        data = self.get_serializer(self._page_objects, many=True).data
        return self.get_paginated_response(data) if page is not None else Response(data)

    def retrieve(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        audit = self.get_object()
        self._page_objects = [audit]
        return Response(self.get_serializer(audit).data)

    @extend_schema(responses={200: AuditResultSerializer(many=True)})
    @action(detail=True, methods=["get"])
    def results(self, request: Request, ref: str | None = None) -> Response:
        """Every requirement in scope: judgement, live derived status and divergence."""
        audit = self.get_object()
        rows, _ = audit_services.audit_rows(audit)
        data = [
            {
                "requirement": r.requirement,
                "judgement": r.judgement,
                "maturity": r.result.maturity if r.result else None,
                "observation": r.result.observation if r.result else "",
                "derived_now": str(r.derived) if r.derived else "not_applicable",
                "derived_at_judgement": r.result.derived_at_judgement if r.result else "",
                "divergent": r.divergent,
                "assessed_by": (
                    r.result.assessed_by.get_username()
                    if r.result and r.result.assessed_by
                    else None
                ),
                "assessed_at": r.result.assessed_at if r.result else None,
            }
            for r in rows
        ]
        return Response(AuditResultSerializer(data, many=True).data)


class FindingViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Findings. POST raises one (``raise_findings``); PATCH updates it, including ``status``.

    Who may change what (owners: remediation and progress; verification by someone other
    than the owner) is enforced by the same services as the UI.
    """

    tl_access = Cap.VIEW_FINDINGS
    tl_write_access = Cap.VIEW_FINDINGS  # fine-grained rules live in findings.services
    serializer_class = FindingSerializer
    lookup_field = "ref"
    http_method_names = ["get", "post", "patch", "head", "options"]

    def get_queryset(self) -> QuerySet[Any]:
        if getattr(self, "swagger_fake_view", False):
            return Finding.objects.none()
        qs = finding_services.visible_findings(self.request.user).select_related(
            "owner", "audit", "requirement__framework", "control", "risk"
        )
        for param in ("status", "severity"):
            value = self.request.query_params.get(param)
            if value:
                qs = qs.filter(**{param: value})
        return qs.order_by("-created_at")

    def perform_create(self, serializer: Any) -> None:
        data = dict(serializer.validated_data)
        data.pop("status", None)
        try:
            serializer.instance = finding_services.create_finding(user=self.request.user, data=data)
        except Exception as exc:
            raise _as_drf(exc) from exc

    def perform_update(self, serializer: Any) -> None:
        data = dict(serializer.validated_data)
        new_status = data.pop("status", None)
        finding = serializer.instance
        try:
            if data:
                finding = finding_services.update_finding(
                    finding, user=self.request.user, data=data
                )
            if new_status and new_status != finding.status:
                finding = finding_services.set_finding_status(
                    finding, user=self.request.user, status=new_status
                )
        except Exception as exc:
            raise _as_drf(exc) from exc
        serializer.instance = finding


class ExceptionViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Security exceptions (``status`` reads *expired* once an approval lapses)."""

    tl_access = Cap.VIEW_FINDINGS
    serializer_class = ExceptionSerializer
    lookup_field = "ref"

    def get_queryset(self) -> QuerySet[Any]:
        if getattr(self, "swagger_fake_view", False):
            return SecurityException.objects.none()
        return (
            finding_services.visible_exceptions(self.request.user)
            .select_related("owner")
            .prefetch_related("requirements__framework", "controls")
            .order_by("-created_at")
        )


class PolicyViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Policies with their published version and next review date."""

    tl_access = Cap.VIEW_POLICIES
    serializer_class = PolicySerializer
    lookup_field = "ref"

    def get_queryset(self) -> QuerySet[Any]:
        if getattr(self, "swagger_fake_view", False):
            return Policy.objects.none()
        return (
            policy_services.visible_policies(self.request.user)
            .select_related("owner")
            .prefetch_related("versions", "controls")
            .order_by("ref")
        )


# ----------------------------------------------------------------------------- Phase 9
class TaskViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """Tasks visible to you (``?mine=1``, ``?status=``). PATCH ``status`` (+ ``note``) to move one;
    completing a periodic task creates its next occurrence."""

    tl_access = AUTHENTICATED  # everyone sees and updates the tasks assigned to them
    serializer_class = TaskSerializer
    lookup_field = "ref"
    http_method_names = ["get", "patch", "head", "options"]

    def get_queryset(self) -> QuerySet[Any]:
        if getattr(self, "swagger_fake_view", False):
            return Task.objects.none()
        qs = (
            work_services.visible_tasks(self.request.user)
            .select_related("control")
            .prefetch_related("assignees")
        )
        if self.request.query_params.get("mine") == "1":
            qs = qs.filter(Q(assignees=self.request.user.pk))
        status_ = self.request.query_params.get("status")
        if status_:
            qs = qs.filter(status=status_)
        return qs.order_by("due_on", "id")

    def perform_update(self, serializer: Any) -> None:
        data = serializer.validated_data
        try:
            serializer.instance = work_services.set_task_status(
                serializer.instance,
                user=self.request.user,
                status=data["status"],
                note=data.get("note", ""),
            )
        except work_services.WorkError as exc:
            raise exceptions.PermissionDenied(str(exc)) from exc


# ----------------------------------------------------------------------------- Phase 10
@extend_schema(parameters=[OpenApiParameter("ref", OpenApiTypes.STR, OpenApiParameter.PATH)])
class VendorViewSet(viewsets.ViewSet):
    """Third parties with derived posture (assessment score, reassessment, contracts, flags)."""

    tl_access = Cap.VIEW_VENDORS
    serializer_class = VendorSerializer
    lookup_field = "ref"

    @extend_schema(responses={200: VendorSerializer(many=True)})
    def list(self, request: Request) -> Response:
        entities = list(vendor_services.visible_entities(request.user).order_by("ref"))
        tier = request.query_params.get("tier")
        if tier:
            entities = [e for e in entities if e.tier == tier]
        return Response(VendorSerializer(vendor_services.postures(entities), many=True).data)

    @extend_schema(responses={200: VendorSerializer})
    def retrieve(self, request: Request, ref: str | None = None) -> Response:
        entity = get_object_or_404(vendor_services.visible_entities(request.user), ref__iexact=ref)
        return Response(VendorSerializer(vendor_services.postures([entity])[0]).data)


# ----------------------------------------------------------------------------- Phase 11
class IncidentViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Incidents visible to you, with derived regulatory notification deadlines."""

    tl_access = AUTHENTICATED  # reporters see their own; incident viewers see all in scope
    serializer_class = IncidentSerializer
    lookup_field = "ref"

    def get_queryset(self) -> QuerySet[Any]:
        if getattr(self, "swagger_fake_view", False):
            return Incident.objects.none()
        return (
            incident_services.visible_incidents(self.request.user)
            .prefetch_related("techniques", "filings")
            .order_by("-aware_at")
        )


class ProcessingViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Records of processing with DPIA screening and state."""

    tl_access = Cap.VIEW_PRIVACY
    serializer_class = ProcessingSerializer
    lookup_field = "ref"

    def get_queryset(self) -> QuerySet[Any]:
        if getattr(self, "swagger_fake_view", False):
            return Processing.objects.none()
        return privacy_services.visible_processing(self.request.user).order_by("ref")
