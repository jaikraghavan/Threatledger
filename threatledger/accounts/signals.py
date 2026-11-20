"""Authentication events -> audit log. Passwords are never recorded."""

from __future__ import annotations

from typing import Any

from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from threatledger.audit.models import Action
from threatledger.audit.services import record


@receiver(user_logged_in)
def on_login(sender: Any, request: Any, user: Any, **kwargs: Any) -> None:
    record(Action.LOGIN, user, actor=user)


@receiver(user_logged_out)
def on_logout(sender: Any, request: Any, user: Any, **kwargs: Any) -> None:
    if user is not None:
        record(Action.LOGOUT, user, actor=user)


@receiver(user_login_failed)
def on_login_failed(
    sender: Any, credentials: dict[str, Any], request: Any = None, **kwargs: Any
) -> None:
    # ``credentials`` is already scrubbed by Django, but only the username is kept regardless.
    username = str(credentials.get("username", ""))[:150]
    record(
        Action.LOGIN_FAILED,
        object_type="accounts.user",
        object_repr=username,
        changes={"username": username},
    )
