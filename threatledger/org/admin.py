from django.contrib import admin

from threatledger.audit.admin_mixins import AuditedAdminMixin

from .models import BusinessUnit, Organisation


@admin.register(Organisation)
class OrganisationAdmin(AuditedAdminMixin, admin.ModelAdmin):
    list_display = ("name", "slug", "created_at")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(BusinessUnit)
class BusinessUnitAdmin(AuditedAdminMixin, admin.ModelAdmin):
    list_display = ("name", "code", "organisation", "parent")
    list_filter = ("organisation",)
