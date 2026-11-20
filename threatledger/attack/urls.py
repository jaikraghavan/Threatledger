from django.urls import path, re_path

from . import views

app_name = "attack"
urlpatterns = [
    path("techniques/", views.TechniqueListView.as_view(), name="technique_list"),
    re_path(
        r"^techniques/(?P<attack_id>T\d{4}(?:\.\d{3})?)/$",
        views.TechniqueDetailView.as_view(),
        name="technique_detail",
    ),
    path("groups/", views.GroupListView.as_view(), name="group_list"),
    re_path(
        r"^groups/(?P<attack_id>G\d{4})/$", views.GroupDetailView.as_view(), name="group_detail"
    ),
    path("data/", views.AttackDataView.as_view(), name="data"),
]
