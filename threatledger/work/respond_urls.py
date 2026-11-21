from django.urls import path

from . import respond

app_name = "respond"

urlpatterns = [
    path("", respond.form, name="form"),
    path("start/", respond.start, name="start"),
]
