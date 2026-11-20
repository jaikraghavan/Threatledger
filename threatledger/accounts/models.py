from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db import models

from threatledger.org.models import BusinessUnit, Organisation

from .roles import Role


class User(AbstractUser):
    email = models.EmailField("email address", unique=True)
    mfa_enabled = models.BooleanField(default=False)

    class Meta:
        ordering = ["username"]

    def __str__(self) -> str:
        return self.get_full_name() or self.username


class Membership(models.Model):
    """A user's role in an organisation, optionally scoped to business units."""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="memberships")
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name="memberships"
    )
    role = models.CharField(max_length=32, choices=Role.choices, default=Role.VIEWER)
    business_units = models.ManyToManyField(BusinessUnit, blank=True, related_name="members")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["organisation", "user"]
        constraints = [
            models.UniqueConstraint(fields=["user", "organisation"], name="uniq_membership")
        ]

    def __str__(self) -> str:
        return f"{self.user} — {self.get_role_display()} @ {self.organisation}"
