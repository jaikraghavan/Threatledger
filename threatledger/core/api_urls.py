from django.urls import path

from . import api

app_name = "api"
urlpatterns = [path("me/", api.MeView.as_view(), name="me")]
