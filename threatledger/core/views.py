from __future__ import annotations

import logging
from typing import Any

from django.core.cache import cache
from django.db import connection
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.views.generic import TemplateView

from threatledger.accounts.permissions import PUBLIC, AccessControlMixin, access, get_role
from threatledger.accounts.roles import Cap

logger = logging.getLogger(__name__)


class HomeView(AccessControlMixin, TemplateView):
    tl_access = Cap.VIEW_DASHBOARD
    template_name = "core/home.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        ctx["role"] = get_role(self.request.user)
        return ctx


@never_cache
@access(PUBLIC)
def healthz(request: HttpRequest) -> JsonResponse:
    """Liveness: the process is up and serving requests. No dependencies checked."""
    return JsonResponse({"status": "ok"})


@never_cache
@access(PUBLIC)
def readyz(request: HttpRequest) -> JsonResponse:
    """Readiness: database and cache reachable. Reports component names only, no detail."""
    checks: dict[str, str] = {}
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        checks["database"] = "ok"
    except Exception:
        logger.exception("readiness: database check failed")
        checks["database"] = "fail"
    try:
        cache.set("readyz", "1", 5)
        checks["cache"] = "ok" if cache.get("readyz") == "1" else "fail"
    except Exception:
        logger.exception("readiness: cache check failed")
        checks["cache"] = "fail"
    healthy = all(v == "ok" for v in checks.values())
    return JsonResponse(
        {"status": "ok" if healthy else "fail", "checks": checks}, status=200 if healthy else 503
    )


def permission_denied(request: HttpRequest, exception: Exception | None = None) -> HttpResponse:
    return render(request, "errors/403.html", status=403)


def page_not_found(request: HttpRequest, exception: Exception | None = None) -> HttpResponse:
    return render(request, "errors/404.html", status=404)


def server_error(request: HttpRequest) -> HttpResponse:
    return render(request, "errors/500.html", status=500)
