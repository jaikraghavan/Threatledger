"""TOTP two-factor authentication (django-otp), optional per user, enforceable per role."""

from __future__ import annotations

import secrets
from typing import Any

from django.conf import settings
from django.db import transaction
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

from threatledger.audit.models import Action
from threatledger.audit.services import record

from .permissions import get_role

RECOVERY_CODES = 10


SESSION_FLAG = "_tl_mfa"


def has_mfa(user: Any) -> bool:
    return bool(
        user.is_authenticated and TOTPDevice.objects.filter(user=user, confirmed=True).exists()
    )


def session_has_mfa(request: Any) -> bool:
    """Cached per session: set at login and whenever the user enables/disables MFA."""
    flag = request.session.get(SESSION_FLAG)
    if flag is None:
        flag = has_mfa(request.user)
        request.session[SESSION_FLAG] = flag
    return bool(flag)


def mfa_required(user: Any) -> bool:
    role = get_role(user)
    return bool(role and role.value in settings.MFA_REQUIRED_ROLES)


def start_enrolment(user: Any) -> TOTPDevice:
    """Fresh unconfirmed device (any previous unconfirmed one is discarded)."""
    TOTPDevice.objects.filter(user=user, confirmed=False).delete()
    return TOTPDevice.objects.create(user=user, name="Authenticator app", confirmed=False)


def pending_device(user: Any) -> TOTPDevice | None:
    return TOTPDevice.objects.filter(user=user, confirmed=False).order_by("-id").first()


def qr_svg(device: TOTPDevice) -> str:
    """Inline SVG QR code for the otpauth:// URI (no external service, no inline styles)."""
    import qrcode
    import qrcode.image.svg

    url = device.config_url.replace(
        "otpauth://totp/", f"otpauth://totp/{settings.OTP_TOTP_ISSUER}:", 1
    )
    img = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    return img.to_string(encoding="unicode")


def manual_key(device: TOTPDevice) -> str:
    import base64

    raw = base64.b32encode(device.bin_key).decode().rstrip("=")
    return " ".join(raw[i : i + 4] for i in range(0, len(raw), 4))


@transaction.atomic
def confirm_enrolment(user: Any, device: TOTPDevice, token: str) -> list[str] | None:
    """Verify the first code; returns freshly generated recovery codes, or None if wrong."""
    if (
        device.user_id != user.pk
        or device.confirmed
        or not device.verify_token(token.strip().replace(" ", ""))
    ):
        return None
    device.confirmed = True
    device.save(update_fields=["confirmed"])
    TOTPDevice.objects.filter(user=user).exclude(pk=device.pk).delete()
    StaticDevice.objects.filter(user=user).delete()
    static = StaticDevice.objects.create(user=user, name="Recovery codes", confirmed=True)
    codes = [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(RECOVERY_CODES)]
    StaticToken.objects.bulk_create([StaticToken(device=static, token=c) for c in codes])
    user.mfa_enabled = True
    user.save(update_fields=["mfa_enabled"])
    record(Action.UPDATE, user, actor=user, changes={"mfa_enabled": [False, True]})
    return codes


@transaction.atomic
def disable(user: Any) -> None:
    TOTPDevice.objects.filter(user=user).delete()
    StaticDevice.objects.filter(user=user).delete()
    user.mfa_enabled = False
    user.save(update_fields=["mfa_enabled"])
    record(Action.UPDATE, user, actor=user, changes={"mfa_enabled": [True, False]})


def remaining_recovery_codes(user: Any) -> int:
    return StaticToken.objects.filter(device__user=user).count()
