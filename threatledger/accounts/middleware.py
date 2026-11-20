from __future__ import annotations

import time
from collections.abc import Callable
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse

_LAST_SEEN = "_tl_last_seen"
_TOUCH_EVERY = 60  # seconds between session writes


def _redirect(request: HttpRequest, url: str) -> HttpResponse:
    if getattr(request, "htmx", False) or request.headers.get("HX-Request"):
        response = HttpResponse(status=401)
        response["HX-Redirect"] = url
        return response
    return redirect(url)


class IdleTimeoutMiddleware:
    """Sign users out after ``SESSION_IDLE_TIMEOUT`` seconds without activity."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        timeout = settings.SESSION_IDLE_TIMEOUT
        if timeout and request.user.is_authenticated and hasattr(request, "session"):
            now = int(time.time())
            last = request.session.get(_LAST_SEEN)
            if last is not None and now - int(last) > timeout:
                logout(request)
                messages.info(request, "You were signed out after a period of inactivity.")
                return _redirect(
                    request,
                    reverse("accounts:login") + "?" + urlencode({"next": request.get_full_path()}),
                )
            if last is None or now - int(last) >= _TOUCH_EVERY:
                request.session[_LAST_SEEN] = now
        return self.get_response(request)


class MfaEnforcementMiddleware:
    """A session that has not completed its second factor may only reach the MFA pages.

    - Users with a confirmed authenticator must verify a code after password login.
    - Users whose role is in ``MFA_REQUIRED_ROLES`` must enrol before doing anything else.
    API requests authenticated by bearer token are not session logins and are unaffected.
    """

    EXEMPT_PREFIXES = ("/static/", "/healthz", "/readyz")

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        user = request.user
        if not user.is_authenticated or request.path.startswith(self.EXEMPT_PREFIXES):
            return self.get_response(request)
        if getattr(user, "is_verified", lambda: False)():
            return self.get_response(request)
        from .mfa import mfa_required, session_has_mfa

        allowed = {
            reverse("accounts:logout"),
            reverse("accounts:mfa_verify"),
            reverse("accounts:mfa_setup"),
        }
        if request.path in allowed:
            return self.get_response(request)
        if session_has_mfa(request):
            return _redirect(
                request,
                reverse("accounts:mfa_verify") + "?" + urlencode({"next": request.get_full_path()}),
            )
        if mfa_required(user):
            return _redirect(request, reverse("accounts:mfa_setup"))
        return self.get_response(request)
