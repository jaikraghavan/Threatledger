from __future__ import annotations

from typing import Any

from django.contrib import messages
from django.contrib.auth import views as auth_views
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django_otp import login as otp_login
from django_otp import match_token

from threatledger.audit.models import Action
from threatledger.audit.services import record

from . import mfa
from .permissions import AUTHENTICATED, PUBLIC, AccessControlMixin


class LoginView(AccessControlMixin, auth_views.LoginView):
    tl_access = PUBLIC
    template_name = "registration/login.html"
    redirect_authenticated_user = True


class LogoutView(AccessControlMixin, auth_views.LogoutView):
    tl_access = PUBLIC  # POST-only (Django 5); harmless when anonymous


class PasswordChangeView(AccessControlMixin, auth_views.PasswordChangeView):
    tl_access = AUTHENTICATED
    template_name = "registration/password_change.html"
    success_url = reverse_lazy("accounts:password_change_done")


class PasswordChangeDoneView(AccessControlMixin, auth_views.PasswordChangeDoneView):
    tl_access = AUTHENTICATED
    template_name = "registration/password_change_done.html"


def _safe_next(request: HttpRequest, default: str = "/") -> str:
    target = request.POST.get("next") or request.GET.get("next") or default
    if url_has_allowed_host_and_scheme(
        target, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return target
    return default


class MfaSetupView(AccessControlMixin, View):
    """Enrol an authenticator app (TOTP) and receive one-time recovery codes."""

    tl_access = AUTHENTICATED
    template_name = "registration/mfa_setup.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        user: Any = request.user
        enabled = mfa.has_mfa(user)
        ctx: dict[str, Any] = {
            "enabled": enabled,
            "required": mfa.mfa_required(user),
            "remaining": mfa.remaining_recovery_codes(user) if enabled else 0,
        }
        if not enabled:
            device = mfa.pending_device(user) or mfa.start_enrolment(user)
            ctx.update(qr_svg=mfa.qr_svg(device), manual_key=mfa.manual_key(device))
        return render(request, self.template_name, ctx)

    def post(self, request: HttpRequest) -> HttpResponse:
        user: Any = request.user
        action = request.POST.get("action")
        if action == "disable":
            if mfa.mfa_required(user):
                messages.error(request, "Your role requires two-factor authentication.")
            elif (
                not user.is_verified()
                or match_token(user, request.POST.get("otp_token", "")) is None
            ):
                messages.error(
                    request, "Enter a current code to turn two-factor authentication off."
                )
            else:
                mfa.disable(user)
                request.session[mfa.SESSION_FLAG] = False
                messages.success(request, "Two-factor authentication is off.")
            return redirect("accounts:mfa_setup")
        device = mfa.pending_device(user)
        codes = (
            mfa.confirm_enrolment(user, device, request.POST.get("otp_token", ""))
            if device
            else None
        )
        if codes is None:
            messages.error(
                request, "That code didn't match. Check your device clock and try again."
            )
            return redirect("accounts:mfa_setup")
        otp_login(request, user.totpdevice_set.get(confirmed=True))
        request.session[mfa.SESSION_FLAG] = True
        return render(request, "registration/mfa_codes.html", {"codes": codes})


class MfaVerifyView(AccessControlMixin, View):
    """Second step of sign-in for users with an authenticator."""

    tl_access = AUTHENTICATED
    template_name = "registration/mfa_verify.html"

    def get(self, request: HttpRequest) -> HttpResponse:
        user: Any = request.user
        if user.is_verified():
            return redirect(_safe_next(request))
        return render(request, self.template_name, {"next": _safe_next(request)})

    def post(self, request: HttpRequest) -> HttpResponse:
        user: Any = request.user
        token = request.POST.get("otp_token", "").strip().replace(" ", "")
        device = match_token(user, token) if token else None
        if device is None:
            record(
                Action.LOGIN_FAILED,
                user,
                actor=user,
                changes={"factor": [None, "otp"]},
            )
            messages.error(request, "Invalid or expired code.")
            return render(request, self.template_name, {"next": _safe_next(request)}, status=400)
        otp_login(request, device)
        record(
            Action.LOGIN,
            user,
            actor=user,
            changes={"factor": [None, device.__class__.__name__]},
        )
        return redirect(_safe_next(request))


class ApiTokenView(AccessControlMixin, View):
    """Personal API tokens: create (secret shown once), list, revoke."""

    tl_access = AUTHENTICATED
    template_name = "registration/api_tokens.html"
    DURATIONS = {"30": 30, "90": 90, "365": 365}

    def _render(self, request: HttpRequest, new_token: str | None = None) -> HttpResponse:
        user: Any = request.user
        from threatledger.api.models import ApiToken

        tokens = ApiToken.objects.filter(user=user)
        return render(request, self.template_name, {"tokens": tokens, "new_token": new_token})

    def get(self, request: HttpRequest) -> HttpResponse:
        return self._render(request)

    def post(self, request: HttpRequest) -> HttpResponse:
        user: Any = request.user
        from django.utils import timezone

        from threatledger.api.models import ApiToken

        if request.POST.get("revoke"):
            token = ApiToken.objects.filter(
                user=user, pk=request.POST["revoke"], revoked_at=None
            ).first()
            if token:
                token.revoked_at = timezone.now()
                token.save(update_fields=["revoked_at"])
                record(Action.UPDATE, token, actor=user, changes={"revoked": [False, True]})
                messages.success(request, f"Revoked “{token.name}”.")
            return redirect("accounts:tokens")
        name = request.POST.get("name", "").strip()
        days = self.DURATIONS.get(request.POST.get("days", ""), 90)
        if not name:
            messages.error(request, "Give the token a name (e.g. “CI pipeline”).")
            return redirect("accounts:tokens")
        if (
            ApiToken.objects.filter(
                user=user, revoked_at=None, expires_at__gt=timezone.now()
            ).count()
            >= 10
        ):
            messages.error(request, "You already have 10 active tokens. Revoke one first.")
            return redirect("accounts:tokens")
        token, raw = ApiToken.issue(user, name, days)
        record(
            Action.CREATE,
            token,
            actor=user,
            changes={
                "name": [None, token.name],
                "expires_at": [None, token.expires_at.isoformat()],
            },
        )
        return self._render(request, new_token=raw)
