from django.urls import path

from . import views

app_name = "org"

urlpatterns = [
    path("units/", views.unit_list, name="units"),
    path("units/new/", views.unit_form, name="unit_create"),
    path("units/<int:pk>/edit/", views.unit_form, name="unit_edit"),
    path("units/<int:pk>/delete/", views.unit_delete, name="unit_delete"),
    path("workflow/", views.workflow, name="workflow"),
]
