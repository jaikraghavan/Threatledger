from django.urls import path, re_path

from . import views

app_name = "frameworks"
CODE = r"(?P<code>[A-Za-z0-9][A-Za-z0-9_-]{1,39})"

urlpatterns = [
    path("", views.FrameworkListView.as_view(), name="list"),
    path("cross/", views.CrossFrameworkView.as_view(), name="cross"),
    path("import/", views.ImportView.as_view(), name="import"),
    re_path(rf"^{CODE}/$", views.FrameworkDetailView.as_view(), name="detail"),
    re_path(rf"^{CODE}/settings/$", views.framework_settings, name="settings"),
    re_path(
        rf"^{CODE}/requirements/(?P<pk>\d+)/$",
        views.RequirementDetailView.as_view(),
        name="requirement",
    ),
    re_path(
        rf"^{CODE}/requirements/(?P<pk>\d+)/controls/$",
        views.requirement_control_search,
        name="requirement_control_search",
    ),
    re_path(
        rf"^{CODE}/requirements/(?P<pk>\d+)/map/$", views.requirement_map, name="requirement_map"
    ),
    re_path(
        rf"^{CODE}/requirements/(?P<pk>\d+)/scope/$",
        views.requirement_scope,
        name="requirement_scope",
    ),
]
