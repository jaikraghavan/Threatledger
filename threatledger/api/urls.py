from django.urls import path
from rest_framework.routers import SimpleRouter

from . import docs, views

app_name = "api"

router = SimpleRouter(trailing_slash=True)
router.register("risks", views.RiskViewSet, basename="risk")
router.register("controls", views.ControlViewSet, basename="control")
router.register("techniques", views.TechniqueViewSet, basename="technique")
router.register("audit-events", views.AuditEventViewSet, basename="audit-event")
router.register("audits", views.AuditViewSet, basename="audit")
router.register("findings", views.FindingViewSet, basename="finding")
router.register("exceptions", views.ExceptionViewSet, basename="exception")
router.register("policies", views.PolicyViewSet, basename="policy")
router.register("tasks", views.TaskViewSet, basename="task")

urlpatterns = [
    path("me/", views.MeView.as_view(), name="me"),
    path("frameworks/", views.FrameworkView.as_view(), name="frameworks"),
    path(
        "frameworks/<slug:code>/requirements/",
        views.FrameworkRequirementsView.as_view(),
        name="framework-requirements",
    ),
    path("coverage/", views.CoverageView.as_view(), name="coverage"),
    path("coverage/navigator/", views.NavigatorView.as_view(), name="navigator"),
    path("schema/", docs.SchemaView.as_view(), name="schema"),
    path("docs/", docs.DocsView.as_view(), name="docs"),
    *router.urls,
]
