from django.urls import path, re_path

from . import views

app_name = "findings"
FREF = r"(?P<ref>F-\d{1,6})"
EREF = r"(?P<ref>EX-\d{1,6})"

urlpatterns = [
    path("", views.finding_list, name="list"),
    path("new/", views.finding_create, name="create"),
    path("exceptions/", views.exception_list, name="exceptions"),
    path("exceptions/new/", views.exception_create, name="exception_create"),
    re_path(rf"^exceptions/{EREF}/$", views.exception_detail, name="exception"),
    re_path(rf"^exceptions/{EREF}/decide/$", views.exception_decide, name="exception_decide"),
    re_path(rf"^{FREF}/$", views.finding_detail, name="detail"),
    re_path(rf"^{FREF}/edit/$", views.finding_edit, name="edit"),
    re_path(rf"^{FREF}/status/$", views.finding_status, name="status"),
]
