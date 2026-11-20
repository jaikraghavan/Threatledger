from django.urls import path, re_path

from . import views

app_name = "risks"
REF = r"(?P<ref>R-\d{4,6})"

urlpatterns = [
    path("", views.RiskListView.as_view(), name="list"),
    path("new/", views.RiskCreateView.as_view(), name="create"),
    path("heatmap/", views.HeatmapView.as_view(), name="heatmap"),
    path("export/", views.export, name="export"),
    path("matrix/", views.MatrixSettingsView.as_view(), name="matrix"),
    path("acceptances/", views.AcceptanceListView.as_view(), name="acceptances"),
    path("acceptances/<int:pk>/decide/", views.acceptance_decide, name="acceptance_decide"),
    path("assets/", views.AssetListView.as_view(), name="asset_list"),
    path("assets/new/", views.AssetFormView.as_view(), name="asset_create"),
    path("assets/<int:pk>/", views.AssetDetailView.as_view(), name="asset_detail"),
    path("assets/<int:pk>/edit/", views.AssetFormView.as_view(), name="asset_edit"),
    re_path(rf"^{REF}/$", views.RiskDetailView.as_view(), name="detail"),
    re_path(rf"^{REF}/edit/$", views.RiskUpdateView.as_view(), name="edit"),
    re_path(rf"^{REF}/archive/$", views.risk_archive, name="archive"),
    re_path(rf"^{REF}/acceptance/$", views.acceptance_request, name="acceptance_request"),
    re_path(rf"^{REF}/techniques/search/$", views.technique_search, name="technique_search"),
    re_path(rf"^{REF}/techniques/add/$", views.technique_add, name="technique_add"),
    re_path(
        rf"^{REF}/techniques/(?P<link_id>\d+)/remove/$",
        views.technique_remove,
        name="technique_remove",
    ),
    re_path(
        rf"^{REF}/techniques/(?P<link_id>\d+)/remap/$",
        views.technique_remap,
        name="technique_remap",
    ),
    re_path(rf"^{REF}/controls/search/$", views.control_search, name="control_search"),
    re_path(rf"^{REF}/controls/add/$", views.control_add, name="control_add"),
    re_path(
        rf"^{REF}/controls/(?P<link_id>\d+)/remove/$", views.control_remove, name="control_remove"
    ),
]
