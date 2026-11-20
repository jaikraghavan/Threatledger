from __future__ import annotations

from django.contrib.auth import views as auth_views
from django.urls import reverse_lazy

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
