from django.urls import path, re_path

from . import views

app_name = "incidents"
REF = r"(?P<ref>INC-\d{1,6})"

urlpatterns = [
    path("", views.incident_list, name="list"),
    path("report/", views.incident_report, name="report"),
    re_path(rf"^{REF}/$", views.incident_detail, name="detail"),
    re_path(rf"^{REF}/edit/$", views.incident_edit, name="edit"),
    re_path(rf"^{REF}/status/$", views.incident_status, name="status"),
    re_path(rf"^{REF}/timeline/$", views.incident_entry, name="entry"),
    re_path(rf"^{REF}/notifications/$", views.incident_filing, name="filing"),
]
