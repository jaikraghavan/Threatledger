from __future__ import annotations

from typing import Any

from django import template

from threatledger.accounts.permissions import can
from threatledger.accounts.roles import Cap

from ..services import comments_for

register = template.Library()


@register.inclusion_tag("work/_comments.html", takes_context=True)
def comments(context: dict[str, Any], obj: Any) -> dict[str, Any]:
    """Discussion thread for ``obj`` (``{% load work %}{% comments obj %}``)."""
    request = context["request"]
    return {
        "obj": obj,
        "target": obj._meta.label_lower,
        "comments": list(comments_for(obj)),
        "can_comment": can(request.user, Cap.COMMENT),
        "csrf_token": context.get("csrf_token"),
        "next": request.get_full_path(),
    }
