from django.urls import path

from . import views

app_name = "reporting"
urlpatterns = [path("board/", views.BoardReportView.as_view(), name="board")]
