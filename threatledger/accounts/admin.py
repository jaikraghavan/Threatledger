from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from threatledger.audit.admin_mixins import AuditedAdminMixin

from .models import Membership, User


class MembershipInline(admin.TabularInline):
    model = Membership
    extra = 0
    filter_horizontal = ("business_units",)


@admin.register(User)
class UserAdmin(AuditedAdminMixin, BaseUserAdmin):
    inlines = [MembershipInline]
    list_display = ("username", "email", "first_name", "last_name", "is_active", "is_superuser")
    fieldsets = (*BaseUserAdmin.fieldsets, ("Security", {"fields": ("mfa_enabled",)}))  # type: ignore[misc]


@admin.register(Membership)
class MembershipAdmin(AuditedAdminMixin, admin.ModelAdmin):
    list_display = ("user", "organisation", "role")
    list_filter = ("role", "organisation")
    filter_horizontal = ("business_units",)
