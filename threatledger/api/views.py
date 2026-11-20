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
from threatledger.controls import services as control_services
from threatledger.controls.models import Control
from threatledger.coverage.matrix import build_matrix, navigator_layer, resolve_scope
from threatledger.coverage.selectors import coverage_for
from threatledger.frameworks import services as fw_services
from threatledger.frameworks.models import Framework, Requirement
from threatledger.risks import services as risk_services
from threatledger.risks.models import Risk, RiskMatrix

from .serializers import (
    AuditEventSerializer,
    ControlSerializer,
    LinkTechniqueSerializer,
    RiskSerializer,
    TechniqueSerializer,
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
        exc, (risk_services.RiskError, control_services.ControlError, fw_services.FrameworkError)
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
