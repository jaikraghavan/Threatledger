from django.urls import path

from . import views

app_name = "coverage"
urlpatterns = [
    path("", views.CoverageMatrixView.as_view(), name="matrix"),
    path("navigator.json", views.navigator_export, name="navigator"),
]
