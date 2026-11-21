from django.urls import path, re_path

from . import views

app_name = "policies"
REF = r"(?P<ref>POL-\d{1,6})"

urlpatterns = [
    path("", views.policy_list, name="list"),
    path("new/", views.policy_form, name="create"),
    re_path(rf"^{REF}/$", views.policy_detail, name="detail"),
    re_path(rf"^{REF}/edit/$", views.policy_form, name="edit"),
    re_path(rf"^{REF}/revise/$", views.policy_revise, name="revise"),
    re_path(rf"^{REF}/review/$", views.policy_confirm_review, name="confirm_review"),
    re_path(rf"^{REF}/retire/$", views.policy_retire, name="retire"),
    re_path(rf"^{REF}/v(?P<number>\d+)/edit/$", views.version_edit, name="version_edit"),
    re_path(rf"^{REF}/v(?P<number>\d+)/decide/$", views.version_decide, name="version_decide"),
]
