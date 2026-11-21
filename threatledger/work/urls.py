from django.urls import path, re_path

from . import views

app_name = "work"
TREF = r"(?P<ref>T-\d{1,6})"
QREF = r"(?P<ref>Q-\d{1,6})"
AREF = r"(?P<ref>QA-\d{1,6})"

urlpatterns = [
    path("", views.my_work, name="mine"),
    path("approvals/", views.approvals, name="approvals"),
    path("approvals/evidence/<int:pk>/", views.evidence_review, name="evidence_review"),
    path("approvals/changes/<int:pk>/", views.change_decide, name="change_decide"),
    path("approvals/changes/<int:pk>/withdraw/", views.change_withdraw, name="change_withdraw"),
    path("board/", views.board, name="board"),
    path("tasks/", views.task_list, name="tasks"),
    path("tasks/new/", views.task_form, name="task_create"),
    re_path(rf"^tasks/{TREF}/$", views.task_detail, name="task"),
    re_path(rf"^tasks/{TREF}/edit/$", views.task_form, name="task_edit"),
    re_path(rf"^tasks/{TREF}/status/$", views.task_status, name="task_status"),
    path("comments/", views.comment_add, name="comment_add"),
    path("notifications/", views.notifications, name="notifications"),
    path("notifications/read/", views.notifications_read, name="notifications_read"),
    path("notifications/<int:pk>/", views.notification_open, name="notification_open"),
    path("preferences/", views.preferences, name="preferences"),
    path("questionnaires/", views.questionnaire_list, name="questionnaires"),
    path("questionnaires/new/", views.questionnaire_create, name="questionnaire_create"),
    re_path(rf"^questionnaires/{QREF}/$", views.questionnaire_detail, name="questionnaire"),
    re_path(rf"^answers/{AREF}/$", views.assignment_detail, name="assignment"),
    re_path(rf"^answers/{AREF}/review/$", views.assignment_review, name="assignment_review"),
    path("answers/file/<int:pk>/", views.answer_file, name="answer_file"),
]
