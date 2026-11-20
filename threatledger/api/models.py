"""Personal API tokens. Only a SHA-256 hash is stored; the secret is shown once at creation."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

PREFIX_LEN = 8


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ApiToken(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_tokens"
    )
    name = models.CharField(max_length=100)
    prefix = models.CharField(max_length=PREFIX_LEN, unique=True, db_index=True)
    token_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    AUDIT_EXCLUDE = ("token_hash",)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.name} (tl_{self.prefix}_…)"

    @classmethod
    def issue(cls, user: object, name: str, days: int) -> tuple[ApiToken, str]:
        while True:
            prefix = secrets.token_hex(PREFIX_LEN // 2)
            if not cls.objects.filter(prefix=prefix).exists():
                break
        raw = f"tl_{prefix}_{secrets.token_urlsafe(32)}"
        token = cls.objects.create(
            user=user,
            name=name[:100],
            prefix=prefix,
            token_hash=hash_token(raw),
            expires_at=timezone.now() + timedelta(days=days),
        )
        return token, raw

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and self.expires_at > timezone.now()

    def matches(self, raw: str) -> bool:
        return hmac.compare_digest(self.token_hash, hash_token(raw))
