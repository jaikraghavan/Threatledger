"""Read-only admin for ATT&CK data: it is owned by the importer, not edited by hand."""

from __future__ import annotations

from typing import Any

from django.contrib import admin
from django.http import HttpRequest

from .models import AttackRelease, Group, ImportRun, Mitigation, Software, Tactic, Technique


class ReadOnlyAdmin(admin.ModelAdmin):
    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False


@admin.register(Technique)
class TechniqueAdmin(ReadOnlyAdmin):
    list_display = ("attack_id", "name", "is_subtechnique", "is_revoked", "is_deprecated")
    list_filter = ("is_subtechnique", "is_revoked", "is_deprecated", "tactics")
    search_fields = ("attack_id", "name", "stix_id")


@admin.register(Tactic)
class TacticAdmin(ReadOnlyAdmin):
    list_display = ("order", "attack_id", "name", "shortname")


@admin.register(Group)
class GroupAdmin(ReadOnlyAdmin):
    list_display = ("attack_id", "name", "is_revoked", "is_deprecated")
    search_fields = ("attack_id", "name", "aliases_text")


@admin.register(Software)
class SoftwareAdmin(ReadOnlyAdmin):
    list_display = ("attack_id", "name", "kind", "is_revoked")
    list_filter = ("kind",)
    search_fields = ("attack_id", "name")


@admin.register(Mitigation)
class MitigationAdmin(ReadOnlyAdmin):
    list_display = ("attack_id", "name", "is_deprecated")
    search_fields = ("attack_id", "name")


@admin.register(AttackRelease)
class AttackReleaseAdmin(ReadOnlyAdmin):
    list_display = ("domain", "version", "imported_at", "imported_by", "sha256")


@admin.register(ImportRun)
class ImportRunAdmin(ReadOnlyAdmin):
    list_display = ("pk", "status", "requested_version", "release", "created_at", "finished_at")
    list_filter = ("status",)
