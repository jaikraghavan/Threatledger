from django.urls import path, re_path

from . import views

app_name = "privacy"
PREF = r"(?P<ref>PA-\d{1,6})"
DREF = r"(?P<ref>DPIA-\d{1,6})"

urlpatterns = [
    path("", views.processing_list, name="list"),
    path("new/", views.processing_form, name="create"),
    path("records.csv", views.ropa_export, name="export"),
    re_path(rf"^{PREF}/$", views.processing_detail, name="detail"),
    re_path(rf"^{PREF}/edit/$", views.processing_form, name="edit"),
    re_path(rf"^{PREF}/dpia/$", views.dpia_create, name="dpia_create"),
    re_path(rf"^dpia/{DREF}/$", views.dpia_detail, name="dpia"),
    re_path(rf"^dpia/{DREF}/edit/$", views.dpia_edit, name="dpia_edit"),
    re_path(rf"^dpia/{DREF}/decide/$", views.dpia_decide, name="dpia_decide"),
]
