from django.contrib import admin

from threatledger.audit.admin_mixins import AuditedAdminMixin

from .models import Control, ControlMitigation, ControlTechnique


class ControlTechniqueInline(admin.TabularInline):
    model = ControlTechnique
    extra = 0
    autocomplete_fields = ("technique",)


class ControlMitigationInline(admin.TabularInline):
    model = ControlMitigation
    extra = 0
    autocomplete_fields = ("mitigation",)


@admin.register(Control)
class ControlAdmin(AuditedAdminMixin, admin.ModelAdmin):
    list_display = ("ref", "name", "status", "control_type", "owner", "effectiveness")
    list_filter = ("status", "control_type")
    search_fields = ("ref", "name")
    inlines = [ControlMitigationInline, ControlTechniqueInline]
