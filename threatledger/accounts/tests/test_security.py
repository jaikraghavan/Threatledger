"""Phase 7 hardening: headers/CSP, template CSP hygiene, lockout, idle timeout, MFA."""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
from django.conf import settings
from django.test import Client, override_settings
from django.urls import reverse
from django_otp.oath import TOTP
from django_otp.plugins.otp_static.models import StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

from conftest import TEST_PASSWORD
from threatledger.accounts import mfa
from threatledger.accounts.roles import Role
from threatledger.audit.models import Action, AuditEvent

pytestmark = pytest.mark.django_db
HOME = reverse("core:home")


def code_for(device: TOTPDevice, offset: int = 0) -> str:
    totp = TOTP(device.bin_key, device.step, device.t0, device.digits, device.drift)
    totp.time = time.time() + offset * device.step
    return f"{totp.token():0{device.digits}d}"


# ----------------------------------------------------------------------------- headers & CSP
def test_strict_security_headers_on_pages(client_for):
    response = client_for(Role.VIEWER).get(HOME)
    csp = response["Content-Security-Policy"]
    assert "default-src 'self'" in csp and "script-src 'self'" in csp and "style-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp
    assert response["X-Frame-Options"] == "DENY"
    assert response["X-Content-Type-Options"] == "nosniff"
    assert response["Referrer-Policy"] == "same-origin"
    assert response["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response["Cross-Origin-Resource-Policy"] == "same-origin"
    assert "camera=()" in response["Permissions-Policy"]
    assert response["Cache-Control"] == "private, no-store"


@override_settings(SECURE_HSTS_SECONDS=31536000, SECURE_HSTS_INCLUDE_SUBDOMAINS=True)
def test_hsts_on_https(client_for):
    response = client_for(Role.VIEWER).get(HOME, secure=True)
    assert response["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"


def test_htmx_configured_without_eval_or_injected_styles(client_for):
    body = client_for(Role.VIEWER).get(HOME).content.decode()
    assert '"includeIndicatorStyles": false' in body and '"allowEval": false' in body


TEMPLATES = sorted((Path(settings.BASE_DIR) / "templates").rglob("*.html"))
INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.I)
EVENT_HANDLER = re.compile(r"\son[a-z]+\s*=\s*['\"]", re.I)


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: str(p.relative_to(settings.BASE_DIR)))
def test_templates_are_csp_clean(path):
    """No inline scripts, inline styles, event-handler attributes or javascript: URLs."""
    text = path.read_text(encoding="utf-8")
    assert not INLINE_SCRIPT.search(text), "inline <script>"
    assert "style=" not in text, "inline style attribute"
    assert "<style" not in text, "inline <style> block"
    assert not EVENT_HANDLER.search(text), "inline event handler"
    assert "javascript:" not in text.lower()


def test_qr_code_svg_has_no_inline_styles(users):
    svg = mfa.qr_svg(mfa.start_enrolment(users[Role.VIEWER]))
    assert (
        svg.lstrip().startswith(("<svg", "<?xml")) and "style=" not in svg and "<script" not in svg
    )


# ----------------------------------------------------------------------------- lockout
def _login(c: Client, password: str):
    return c.post(
        reverse("accounts:login"),
        {"username": "viewer", "password": password},
        REMOTE_ADDR="198.51.100.4",
    )


def test_lockout_after_repeated_failures(users):
    c = Client()
    for _ in range(settings.AXES_FAILURE_LIMIT - 1):
        assert _login(c, "wrong-password-xyz").status_code == 200
    assert _login(c, "wrong-password-xyz").status_code == 429  # the limit-th failure locks
    locked = _login(c, TEST_PASSWORD)  # even the right password is refused while locked
    assert locked.status_code == 429
    assert b"Too many failed sign-in attempts" in locked.content
    assert AuditEvent.objects.filter(
        action=Action.LOGIN_FAILED, changes__locked_out=[None, True]
    ).exists()


def test_success_resets_failure_count(users):
    c = Client()
    for _ in range(settings.AXES_FAILURE_LIMIT - 1):
        _login(c, "wrong-password-xyz")
    assert _login(c, TEST_PASSWORD).status_code == 302
    c.post(reverse("accounts:logout"))
    assert _login(Client(), "wrong-password-xyz").status_code == 200  # counter was reset


# ----------------------------------------------------------------------------- idle timeout
def _age_session(c: Client, seconds: int) -> None:
    s = c.session
    s["_tl_last_seen"] = int(time.time()) - seconds
    s.save()


def test_idle_session_is_signed_out(client_for):
    c = client_for(Role.VIEWER)
    c.get(HOME)
    _age_session(c, settings.SESSION_IDLE_TIMEOUT + 5)
    response = c.get(HOME)
    assert response.status_code == 302
    assert response["Location"].startswith(reverse("accounts:login"))
    assert c.get(HOME).status_code == 302  # really logged out


def test_idle_timeout_htmx_redirect(client_for):
    c = client_for(Role.VIEWER)
    c.get(HOME)
    _age_session(c, settings.SESSION_IDLE_TIMEOUT + 5)
    response = c.get(reverse("risks:list"), HTTP_HX_REQUEST="true")
    assert response.status_code == 401 and response["HX-Redirect"].startswith(
        reverse("accounts:login")
    )


def test_active_session_is_kept(client_for):
    c = client_for(Role.VIEWER)
    c.get(HOME)
    _age_session(c, 60)
    assert c.get(HOME).status_code == 200


# ----------------------------------------------------------------------------- MFA
def _enrol(c: Client, user) -> list[str]:
    assert c.get(reverse("accounts:mfa_setup")).status_code == 200
    device = TOTPDevice.objects.get(user=user, confirmed=False)
    response = c.post(
        reverse("accounts:mfa_setup"), {"action": "enable", "otp_token": code_for(device)}
    )
    assert response.status_code == 200
    return response.context["codes"]


def _password_login(user) -> Client:
    c = Client()
    assert (
        c.post(
            reverse("accounts:login"), {"username": user.username, "password": TEST_PASSWORD}
        ).status_code
        == 302
    )
    return c


def test_enrolment_then_second_factor_required(users):
    user = users[Role.RISK_MANAGER]
    codes = _enrol(_password_login(user), user)
    assert len(codes) == 10
    user.refresh_from_db()
    assert user.mfa_enabled
    c = _password_login(user)
    blocked = c.get(reverse("risks:list"))
    assert blocked.status_code == 302 and blocked["Location"].startswith(
        reverse("accounts:mfa_verify")
    )
    assert c.get(reverse("api:me")).status_code == 302  # session API calls are gated too
    bad = c.post(reverse("accounts:mfa_verify"), {"otp_token": "000000", "next": "/risks/"})
    assert bad.status_code == 400
    assert AuditEvent.objects.filter(
        action=Action.LOGIN_FAILED, changes__factor=[None, "otp"]
    ).exists()
    device = TOTPDevice.objects.get(user=user, confirmed=True)
    good = code_for(device, offset=1)
    throttled = c.post(reverse("accounts:mfa_verify"), {"otp_token": good, "next": "/risks/"})
    assert (
        throttled.status_code == 400
    )  # brute-force throttle: right code refused right after a wrong one
    device.throttle_reset()
    ok = c.post(reverse("accounts:mfa_verify"), {"otp_token": good, "next": "/risks/"})
    assert ok.status_code == 302 and ok["Location"] == "/risks/"
    assert c.get(reverse("risks:list")).status_code == 200


def test_recovery_code_works_once(users):
    user = users[Role.VIEWER]
    codes = _enrol(_password_login(user), user)
    c = _password_login(user)
    assert c.post(reverse("accounts:mfa_verify"), {"otp_token": codes[0]}).status_code == 302
    assert not StaticToken.objects.filter(token=codes[0]).exists()
    c2 = _password_login(user)
    assert c2.post(reverse("accounts:mfa_verify"), {"otp_token": codes[0]}).status_code == 400


def test_verify_rejects_open_redirect(users):
    user = users[Role.VIEWER]
    codes = _enrol(_password_login(user), user)
    c = _password_login(user)
    response = c.post(
        reverse("accounts:mfa_verify"), {"otp_token": codes[1], "next": "https://evil.example/"}
    )
    assert response["Location"] == "/"


def test_disable_requires_current_code(users):
    user = users[Role.VIEWER]
    c = _password_login(user)
    _enrol(c, user)
    c.post(reverse("accounts:mfa_setup"), {"action": "disable", "otp_token": "123456"})
    assert TOTPDevice.objects.filter(user=user).exists()
    device = TOTPDevice.objects.get(user=user)
    device.throttle_reset()  # the wrong code above engaged the brute-force throttle
    c.post(
        reverse("accounts:mfa_setup"),
        {"action": "disable", "otp_token": code_for(device, offset=1)},
    )
    assert not TOTPDevice.objects.filter(user=user).exists()
    user.refresh_from_db()
    assert not user.mfa_enabled


def test_wrong_enrolment_code_rejected(users):
    user = users[Role.VIEWER]
    c = _password_login(user)
    c.get(reverse("accounts:mfa_setup"))
    c.post(reverse("accounts:mfa_setup"), {"action": "enable", "otp_token": "000000"})
    assert not TOTPDevice.objects.filter(user=user, confirmed=True).exists()


@override_settings(MFA_REQUIRED_ROLES=["admin"])
def test_required_role_must_enrol(users):
    admin = users[Role.ADMIN]
    c = _password_login(admin)
    response = c.get(reverse("risks:list"))
    assert response.status_code == 302 and response["Location"] == reverse("accounts:mfa_setup")
    _enrol(c, admin)
    assert c.get(reverse("risks:list")).status_code == 200
    device = TOTPDevice.objects.get(user=admin)
    c.post(
        reverse("accounts:mfa_setup"),
        {"action": "disable", "otp_token": code_for(device, offset=1)},
    )
    assert TOTPDevice.objects.filter(user=admin).exists()  # cannot disable when required
    viewer = _password_login(users[Role.VIEWER])
    assert viewer.get(reverse("risks:list")).status_code == 200  # other roles unaffected
