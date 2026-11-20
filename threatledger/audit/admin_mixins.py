"""Audit trail for changes made through the Django admin."""

from __future__ import annotations

from typing import Any

from django.contrib import admin
from django.db.models import Model, QuerySet
from django.http import HttpRequest

from .models import Action
from .services import diff, record, snapshot


class AuditedAdminMixin(admin.ModelAdmin):
    def save_model(self, request: HttpRequest, obj: Model, form: Any, change: bool) -> None:
        before = {}
        if change and obj.pk:
            original = type(obj)._default_manager.filter(pk=obj.pk).first()
            before = snapshot(original) if original else {}
        super().save_model(request, obj, form, change)
        after = snapshot(obj)
        if change:
            changes = diff(before, after)
            if changes:
                record(Action.UPDATE, obj, actor=request.user, changes=changes)
        else:
            record(Action.CREATE, obj, actor=request.user, changes=diff({}, after))

    def delete_model(self, request: HttpRequest, obj: Model) -> None:
        before = snapshot(obj)
        label, pk, text = obj._meta.label_lower, str(obj.pk), str(obj)
        super().delete_model(request, obj)
        record(
            Action.DELETE,
            actor=request.user,
            object_type=label,
            object_id=pk,
            object_repr=text,
            changes=diff(before, {}),
        )

    def delete_queryset(self, request: HttpRequest, queryset: QuerySet[Any]) -> None:
        for obj in queryset:
            self.delete_model(request, obj)
