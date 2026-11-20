from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from django.utils import timezone
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header

from .models import ApiToken

TOKEN_RE = re.compile(r"^tl_([0-9a-f]{8})_[A-Za-z0-9_-]{20,}$")
GENERIC_ERROR = "Invalid or expired token."


class ApiTokenAuthentication(BaseAuthentication):
    """``Authorization: Bearer tl_<prefix>_<secret>``. Errors never reveal which part failed."""

    keyword = b"bearer"

    def authenticate(self, request: Any) -> tuple[Any, ApiToken] | None:
        parts = get_authorization_header(request).split()
        if not parts or parts[0].lower() != self.keyword:
            return None
        if len(parts) != 2:
            raise exceptions.AuthenticationFailed(GENERIC_ERROR)
        try:
            raw = parts[1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise exceptions.AuthenticationFailed(GENERIC_ERROR) from exc
        m = TOKEN_RE.match(raw)
        token = (
            ApiToken.objects.select_related("user").filter(prefix=m.group(1)).first() if m else None
        )
        if (
            token is None
            or not token.matches(raw)
            or not token.is_active
            or not token.user.is_active
        ):
            raise exceptions.AuthenticationFailed(GENERIC_ERROR)
        now = timezone.now()
        if token.last_used_at is None or now - token.last_used_at > timedelta(minutes=1):
            ApiToken.objects.filter(pk=token.pk).update(last_used_at=now)
        return token.user, token

    def authenticate_header(self, request: Any) -> str:
        return 'Bearer realm="api"'
