from django.urls import path, re_path

from . import views

app_name = "vendors"
VREF = r"(?P<ref>V-\d{1,6})"

urlpatterns = [
    path("", views.vendor_list, name="list"),
    path("new/", views.vendor_form, name="create"),
    path("contracts/", views.contract_list, name="contracts"),
    path("dora-register.xlsx", views.dora_register, name="dora"),
    re_path(rf"^{VREF}/$", views.vendor_detail, name="detail"),
    re_path(rf"^{VREF}/edit/$", views.vendor_form, name="edit"),
    re_path(rf"^{VREF}/services/$", views.solution_add, name="solution_add"),
    re_path(
        rf"^{VREF}/services/(?P<pk>\d+)/remove/$", views.solution_remove, name="solution_remove"
    ),
    re_path(rf"^{VREF}/contracts/new/$", views.contract_form, name="contract_create"),
    re_path(
        rf"^{VREF}/contracts/(?P<contract_ref>CT-\d{{1,6}})/$",
        views.contract_form,
        name="contract_edit",
    ),
    re_path(rf"^{VREF}/assessments/$", views.assessment_send, name="assessment_send"),
    re_path(
        rf"^{VREF}/assessments/(?P<aref>QA-\d{{1,6}})/link/$",
        views.assessment_link,
        name="assessment_link",
    ),
]
