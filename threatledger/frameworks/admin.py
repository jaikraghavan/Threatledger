from django.contrib import admin

from .models import ControlRequirement, Framework, Requirement, RequirementMapping


@admin.register(Framework)
class FrameworkAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "version", "content_level", "is_indicative")


@admin.register(Requirement)
class RequirementAdmin(admin.ModelAdmin):
    list_display = ("framework", "ref", "title", "is_domain")
    list_filter = ("framework", "is_domain")
    search_fields = ("ref", "title")


@admin.register(ControlRequirement)
class ControlRequirementAdmin(admin.ModelAdmin):
    list_display = ("control", "requirement", "source", "indicative")
    list_filter = ("source", "indicative")


@admin.register(RequirementMapping)
class RequirementMappingAdmin(admin.ModelAdmin):
    list_display = ("from_requirement", "relationship", "to_requirement", "indicative")
