from __future__ import annotations

import json
from typing import Any

from django.http import Http404, HttpRequest, HttpResponse
from django.utils import timezone
from django.utils.text import slugify
from django.views.generic import TemplateView

from threatledger.accounts.permissions import AccessControlMixin, access, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.attack.models import Group
from threatledger.attack.services import current_release
from threatledger.audit.models import Action
from threatledger.audit.services import record

from .matrix import build_matrix, navigator_layer, resolve_scope, sectors


def _matrix_for(request: HttpRequest) -> Any:
    org = current_organisation(request.user)
    if org is None:
        raise Http404
    scope = resolve_scope(
        request.user, request.GET.get("scope", "risks"), request.GET.get("value", "").strip()[:40]
    )
    return org, build_matrix(scope, org)


class CoverageMatrixView(AccessControlMixin, TemplateView):
    tl_access = Cap.VIEW_ATTACK
    template_name = "coverage/matrix.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        _, matrix = _matrix_for(self.request)
        ctx.update(
            matrix=matrix,
            scope=matrix.scope,
            sectors=sorted(sectors().items(), key=lambda kv: kv[1]["label"]),
            groups=Group.objects.active().order_by("name").only("attack_id", "name"),
            release=current_release(),
        )
        return ctx


@access(Cap.EXPORT_DATA)
def navigator_export(request: HttpRequest) -> HttpResponse:
    org, matrix = _matrix_for(request)
    release = current_release()
    layer = navigator_layer(matrix, release.version if release else "", org.name)
    record(
        Action.EXPORT,
        actor=request.user,
        object_type="coverage.navigator",
        object_repr=f"Navigator layer: {matrix.scope.label}"[:300],
        changes={
            "scope": [None, matrix.scope.params],
            "techniques": [None, len(layer["techniques"])],
        },
    )
    name = (
        f"threatledger-{slugify(matrix.scope.label)[:60]}-{timezone.localdate().isoformat()}.json"
    )
    response = HttpResponse(json.dumps(layer, indent=2), content_type="application/json")
    response["Content-Disposition"] = f'attachment; filename="{name}"'
    return response
