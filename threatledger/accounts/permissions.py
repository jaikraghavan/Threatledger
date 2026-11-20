"""Server-side authorisation. Deny by default.

Every view must declare ``tl_access``: ``PUBLIC``, ``AUTHENTICATED`` or a :class:`Cap`.
- Class-based views: inherit :class:`AccessControlMixin` and set ``tl_access``.
- Function views: decorate with ``@access(...)``.
- DRF views: set ``tl_access``; :class:`HasCapability` is the default permission class.

A view without a declaration is refused at runtime, and ``tests/test_url_sweep.py`` fails
the build if any URL resolves to an undeclared view.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, Final

from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.http import HttpRequest, HttpResponse
from django.http.response import HttpResponseBase
from rest_framework.permissions import BasePermission

from .roles import ROLE_CAPABILITIES, Cap, Role

PUBLIC: Final = "public"
AUTHENTICATED: Final = "authenticated"
Access = Cap | str

# Ownership-scoped capability -> capability that lifts the ownership restriction.
_OWNERSHIP_OVERRIDES: dict[Cap, Cap] = {
    Cap.EDIT_OWN_CONTROL: Cap.EDIT_ANY_CONTROL,
    Cap.UPLOAD_EVIDENCE: Cap.EDIT_ANY_CONTROL,
}

_ROLE_CACHE_ATTR = "_tl_role_cache"


def get_role(user: Any) -> Role | None:
    """The user's role in the deployment's organisation, or None."""
    if user is None or not getattr(user, "is_authenticated", False) or not user.is_active:
        return None
    if user.is_superuser:
        return Role.ADMIN
    if hasattr(user, _ROLE_CACHE_ATTR):
        return getattr(user, _ROLE_CACHE_ATTR)
    from .models import Membership

    membership = (
        Membership.objects.filter(user=user).order_by("organisation_id").only("role").first()
    )
    role = Role(membership.role) if membership else None
    setattr(user, _ROLE_CACHE_ATTR, role)
    return role


def clear_role_cache(user: Any) -> None:
    if hasattr(user, _ROLE_CACHE_ATTR):
        delattr(user, _ROLE_CACHE_ATTR)


def capabilities(user: Any) -> frozenset[Cap]:
    role = get_role(user)
    return ROLE_CAPABILITIES[role] if role else frozenset()


def can(user: Any, cap: Cap, obj: Any = None) -> bool:
    """May ``user`` exercise ``cap`` (optionally on ``obj``)?"""
    caps = capabilities(user)
    if cap not in caps:
        return False
    override = _OWNERSHIP_OVERRIDES.get(cap)
    if obj is not None and override is not None and override not in caps:
        return getattr(obj, "owner_id", None) == user.pk
    return True


def check_access(user: Any, rule: Access) -> bool:
    if rule == PUBLIC:
        return True
    if not getattr(user, "is_authenticated", False):
        return False
    if rule == AUTHENTICATED:
        return True
    if isinstance(rule, Cap):
        return can(user, rule)
    raise ImproperlyConfigured(f"Unknown access rule: {rule!r}")


def _deny(request: HttpRequest, rule: Access) -> HttpResponse:
    if not request.user.is_authenticated:
        if getattr(request, "htmx", False):
            from django.conf import settings
            from django.shortcuts import resolve_url

            response = HttpResponse(status=401)
            response["HX-Redirect"] = resolve_url(settings.LOGIN_URL)
            return response
        return redirect_to_login(request.get_full_path())
    from threatledger.audit.services import record_permission_denied

    record_permission_denied(request, str(rule))
    raise PermissionDenied


def access(
    rule: Access,
) -> Callable[[Callable[..., HttpResponseBase]], Callable[..., HttpResponseBase]]:
    """Decorator for function views."""

    def decorator(view: Callable[..., HttpResponseBase]) -> Callable[..., HttpResponseBase]:
        @functools.wraps(view)
        def wrapped(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
            if not check_access(request.user, rule):
                return _deny(request, rule)
            return view(request, *args, **kwargs)

        wrapped.tl_access = rule  # type: ignore[attr-defined]
        return wrapped

    return decorator


class AccessControlMixin:
    """Mixin for class-based views. Subclasses MUST set ``tl_access``."""

    tl_access: Access | None = None

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if self.tl_access is None:
            raise ImproperlyConfigured(f"{type(self).__name__} does not declare tl_access")
        if not check_access(request.user, self.tl_access):
            return _deny(request, self.tl_access)
        return super().dispatch(request, *args, **kwargs)  # type: ignore[misc]


SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def _api_rule(request: Any, view: Any) -> Access | None:
    """``tl_access`` for reads; ``tl_write_access`` (if set) for unsafe methods."""
    if request.method not in SAFE_METHODS and getattr(view, "tl_write_access", None) is not None:
        return view.tl_write_access
    return getattr(view, "tl_access", None)


class HasCapability(BasePermission):
    """DRF default permission class. Views declare ``tl_access`` (reads) and optionally
    ``tl_write_access`` (POST/PUT/PATCH/DELETE), just like template views."""

    def has_permission(self, request: Any, view: Any) -> bool:
        rule = _api_rule(request, view)
        if rule is None:
            return False
        return check_access(request.user, rule)

    def has_object_permission(self, request: Any, view: Any, obj: Any) -> bool:
        rule = _api_rule(request, view)
        if isinstance(rule, Cap):
            return can(request.user, rule, obj)
        return rule in (PUBLIC, AUTHENTICATED)


_BU_CACHE_ATTR = "_tl_bu_scope_cache"


def business_unit_scope(user: Any) -> frozenset[int] | None:
    """Business units the user is limited to, or None for organisation-wide access.

    Admins are never limited. Other roles are limited only if their membership lists
    business units (PLAN.md Q11: optional BU scoping).
    """
    role = get_role(user)
    if role is None:
        return frozenset()
    if role == Role.ADMIN:
        return None
    if hasattr(user, _BU_CACHE_ATTR):
        return getattr(user, _BU_CACHE_ATTR)
    from .models import Membership

    ids = frozenset(
        Membership.objects.filter(user=user).values_list("business_units", flat=True)
    ) - {None}
    scope = ids or None
    setattr(user, _BU_CACHE_ATTR, scope)
    return scope


def current_organisation(user: Any) -> Any:
    """The organisation the user works in (one per deployment; see Q11)."""
    from threatledger.org.models import Organisation

    from .models import Membership

    if getattr(user, "is_authenticated", False) and not user.is_superuser:
        membership = Membership.objects.filter(user=user).select_related("organisation").first()
        if membership:
            return membership.organisation
    return Organisation.objects.current()
