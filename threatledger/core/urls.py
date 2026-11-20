from django.urls import path

from threatledger.reporting.views import DashboardView

from . import views

app_name = "core"
urlpatterns = [
    path("", DashboardView.as_view(), name="home"),
    path("healthz", views.healthz, name="healthz"),
    path("readyz", views.readyz, name="readyz"),
]
