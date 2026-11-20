from django.contrib import admin

from threatledger.audit.admin_mixins import AuditedAdminMixin

from .models import Asset, Risk, RiskAcceptance, RiskMatrix, RiskScoreHistory


@admin.register(Risk)
class RiskAdmin(AuditedAdminMixin, admin.ModelAdmin):
    list_display = ("ref", "title", "status", "category", "owner", "business_unit")
    list_filter = ("status", "category", "business_unit")
    search_fields = ("ref", "title")
    readonly_fields = ("ref",)


@admin.register(Asset)
class AssetAdmin(AuditedAdminMixin, admin.ModelAdmin):
    list_display = ("name", "kind", "criticality", "data_classification", "contains_personal_data")
    list_filter = ("kind", "data_classification", "contains_personal_data")
    search_fields = ("name",)


@admin.register(RiskMatrix)
class RiskMatrixAdmin(AuditedAdminMixin, admin.ModelAdmin):
    list_display = ("organisation", "size", "low_max", "medium_max", "high_max")


@admin.register(RiskAcceptance)
class RiskAcceptanceAdmin(admin.ModelAdmin):
    list_display = ("risk", "status", "expires_on", "requested_by", "decided_by")
    list_filter = ("status",)


@admin.register(RiskScoreHistory)
class RiskScoreHistoryAdmin(admin.ModelAdmin):
    list_display = ("risk", "changed_at", "changed_by", "reason")

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
