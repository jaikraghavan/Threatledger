from django.urls import path

from . import views

app_name = "accounts"
urlpatterns = [
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("password/", views.PasswordChangeView.as_view(), name="password_change"),
    path("password/done/", views.PasswordChangeDoneView.as_view(), name="password_change_done"),
    path("mfa/", views.MfaSetupView.as_view(), name="mfa_setup"),
    path("mfa/verify/", views.MfaVerifyView.as_view(), name="mfa_verify"),
    path("tokens/", views.ApiTokenView.as_view(), name="tokens"),
]
