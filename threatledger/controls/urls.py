from django.urls import path, re_path

from . import views

app_name = "controls"
REF = r"(?P<ref>[A-Za-z0-9][A-Za-z0-9._-]{0,31})"

urlpatterns = [
    path("", views.ControlListView.as_view(), name="list"),
    path("new/", views.ControlFormView.as_view(), name="create"),
    path("starter/", views.seed_starter, name="seed_starter"),
    path("evidence/", views.EvidenceListView.as_view(), name="evidence_list"),
    path("evidence/<int:pk>/download/", views.evidence_download, name="evidence_download"),
    path("evidence/<int:pk>/archive/", views.evidence_archive, name="evidence_archive"),
    re_path(rf"^{REF}/$", views.ControlDetailView.as_view(), name="detail"),
    re_path(rf"^{REF}/edit/$", views.ControlFormView.as_view(), name="edit"),
    re_path(rf"^{REF}/archive/$", views.control_archive, name="archive"),
    re_path(rf"^{REF}/mappings/search/$", views.mapping_search, name="mapping_search"),
    re_path(rf"^{REF}/mappings/add/$", views.mapping_add, name="mapping_add"),
    re_path(
        rf"^{REF}/mappings/(?P<kind>mitigation|technique)/(?P<link_id>\d+)/remove/$",
        views.mapping_remove,
        name="mapping_remove",
    ),
    re_path(rf"^{REF}/evidence/$", views.evidence_add, name="evidence_add"),
    re_path(rf"^{REF}/tests/$", views.test_record, name="test_record"),
]
