from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from django.http import HttpRequest, HttpResponse

from .context import (
    RequestContext,
    client_ip,
    get_context,
    new_request_id,
    reset_context,
    set_context,
)


class RequestContextMiddleware:
    """Assign a request id and client IP before anything else runs."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        request_id = new_request_id(request.META.get("HTTP_X_REQUEST_ID"))
        request.request_id = request_id  # type: ignore[attr-defined]
        token = set_context(RequestContext(request_id=request_id, ip=client_ip(request)))
        try:
            response = self.get_response(request)
        finally:
            reset_context(token)
        response["X-Request-ID"] = request_id
        return response


class UserContextMiddleware:
    """Add the authenticated user to the request context (runs after AuthenticationMiddleware)."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            token = set_context(replace(get_context(), user=user))
            try:
                return self.get_response(request)
            finally:
                reset_context(token)
        return self.get_response(request)
