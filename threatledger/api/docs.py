"""OpenAPI schema + a self-hosted, CSP-safe documentation page (no third-party JS/CDN)."""

from __future__ import annotations

from typing import Any

from django.views.generic import TemplateView
from drf_spectacular.generators import SchemaGenerator
from drf_spectacular.views import SpectacularAPIView

from threatledger.accounts.permissions import AUTHENTICATED, AccessControlMixin


class SchemaView(SpectacularAPIView):
    """OpenAPI 3 schema (YAML by default; ``?format=json`` for JSON)."""

    tl_access = AUTHENTICATED
    permission_classes = SpectacularAPIView.permission_classes


class DocsView(AccessControlMixin, TemplateView):
    tl_access = AUTHENTICATED
    template_name = "api/docs.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        schema = SchemaGenerator().get_schema(request=None, public=True)
        operations = []
        for path, methods in sorted(schema.get("paths", {}).items()):
            for method, op in methods.items():
                if method not in ("get", "post", "patch", "put", "delete"):
                    continue
                operations.append(
                    {
                        "method": method.upper(),
                        "path": path,
                        "summary": (op.get("description") or op.get("summary") or "").split("\n")[
                            0
                        ],
                        "params": [
                            p["name"] for p in op.get("parameters", []) if p.get("in") == "query"
                        ],
                        "tag": (op.get("tags") or ["api"])[0],
                    }
                )
        ctx["operations"] = operations
        ctx["info"] = schema.get("info", {})
        return ctx
