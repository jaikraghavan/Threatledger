from __future__ import annotations

from typing import Any

from django.db.models import QuerySet
from django.views.generic import ListView

from threatledger.accounts.permissions import AccessControlMixin
from threatledger.accounts.roles import Cap

from .models import Action, AuditEvent


class AuditLogView(AccessControlMixin, ListView):
    tl_access = Cap.VIEW_AUDIT_LOG
    template_name = "audit/event_list.html"
    context_object_name = "events"
    paginate_by = 50

    def get_queryset(self) -> QuerySet[AuditEvent]:
        qs = AuditEvent.objects.select_related("actor").order_by("-id")
        action = self.request.GET.get("action")
        if action in Action.values:
            qs = qs.filter(action=action)
        actor = self.request.GET.get("actor", "").strip()
        if actor:
            qs = qs.filter(actor_label__icontains=actor)
        object_type = self.request.GET.get("object_type", "").strip()
        if object_type:
            qs = qs.filter(object_type=object_type)
        return qs

    def get_template_names(self) -> list[str]:
        if getattr(self.request, "htmx", False):
            return ["audit/_event_table.html"]
        return [self.template_name]

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        ctx = super().get_context_data(**kwargs)
        ctx["actions"] = Action.choices
        ctx["filters"] = {
            k: self.request.GET.get(k, "") for k in ("action", "actor", "object_type")
        }
        return ctx
