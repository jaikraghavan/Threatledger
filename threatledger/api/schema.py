"""OpenAPI description of ThreatLedger's bearer-token authentication (drf-spectacular)."""

from __future__ import annotations

from typing import Any

from drf_spectacular.extensions import OpenApiAuthenticationExtension


class ApiTokenScheme(OpenApiAuthenticationExtension):
    target_class = "threatledger.api.authentication.ApiTokenAuthentication"
    name = "ApiToken"

    def get_security_definition(self, auto_schema: Any) -> dict[str, Any]:
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "tl_<prefix>_<secret>",
            "description": "Personal API token (Account → API tokens). Acts with the owner's role.",
        }
