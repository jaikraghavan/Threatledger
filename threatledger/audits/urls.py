from django.urls import path, re_path

from . import views

app_name = "audits"
REF = r"(?P<ref>[A-Za-z]-\d{1,6})"

urlpatterns = [
    path("", views.audit_list, name="list"),
    path("new/", views.audit_form, name="create"),
    path("campaigns/", views.campaign_list, name="campaigns"),
    path("campaigns/new/", views.campaign_create, name="campaign_create"),
    re_path(rf"^campaigns/{REF}/$", views.campaign_detail, name="campaign"),
    re_path(rf"^campaigns/{REF}/next/$", views.campaign_next, name="campaign_next"),
    re_path(rf"^{REF}/$", views.audit_detail, name="detail"),
    re_path(rf"^{REF}/edit/$", views.audit_form, name="edit"),
    re_path(rf"^{REF}/status/$", views.audit_status, name="status"),
    re_path(rf"^{REF}/accept/$", views.audit_accept, name="accept"),
    re_path(rf"^{REF}/export/$", views.audit_export, name="export"),
    re_path(rf"^{REF}/requirements/(?P<pk>\d+)/$", views.audit_requirement, name="requirement"),
]
