"""Roles and capabilities: the single source of truth for who may do what.

Views, HTMX endpoints, templates and API permission classes all ask
``threatledger.accounts.permissions.can()``, which reads this matrix.
"""

from __future__ import annotations

from enum import StrEnum

from django.db import models


class Role(models.TextChoices):
    ADMIN = "admin", "Admin"
    RISK_MANAGER = "risk_manager", "Risk Manager"
    CONTROL_OWNER = "control_owner", "Control Owner"
    AUDITOR = "auditor", "Auditor (read-only)"
    VIEWER = "viewer", "Viewer"


class Cap(StrEnum):
    """Capabilities. Add new ones here and to ROLE_CAPABILITIES; tests enforce coverage."""

    # administration
    MANAGE_USERS = "manage_users"
    MANAGE_SETTINGS = "manage_settings"
    RUN_IMPORTS = "run_imports"
    # read
    VIEW_DASHBOARD = "view_dashboard"
    VIEW_RISKS = "view_risks"
    VIEW_CONTROLS = "view_controls"
    VIEW_FRAMEWORKS = "view_frameworks"
    VIEW_ATTACK = "view_attack"
    VIEW_EVIDENCE = "view_evidence"
    VIEW_AUDIT_LOG = "view_audit_log"
    EXPORT_DATA = "export_data"
    # write
    EDIT_RISKS = "edit_risks"
    APPROVE_ACCEPTANCE = "approve_acceptance"
    EDIT_ANY_CONTROL = "edit_any_control"
    EDIT_OWN_CONTROL = "edit_own_control"
    UPLOAD_EVIDENCE = "upload_evidence"
    EDIT_FRAMEWORKS = "edit_frameworks"
    EDIT_MAPPINGS = "edit_mappings"


_READ_ALL = {
    Cap.VIEW_DASHBOARD,
    Cap.VIEW_RISKS,
    Cap.VIEW_CONTROLS,
    Cap.VIEW_FRAMEWORKS,
    Cap.VIEW_ATTACK,
}
_READ_SENSITIVE = {Cap.VIEW_EVIDENCE, Cap.VIEW_AUDIT_LOG, Cap.EXPORT_DATA}

ROLE_CAPABILITIES: dict[Role, frozenset[Cap]] = {
    Role.ADMIN: frozenset(Cap),
    Role.RISK_MANAGER: frozenset(
        _READ_ALL
        | _READ_SENSITIVE
        | {
            Cap.EDIT_RISKS,
            Cap.APPROVE_ACCEPTANCE,
            Cap.EDIT_ANY_CONTROL,
            Cap.EDIT_OWN_CONTROL,
            Cap.UPLOAD_EVIDENCE,
            Cap.EDIT_FRAMEWORKS,
            Cap.EDIT_MAPPINGS,
        }
    ),
    Role.CONTROL_OWNER: frozenset(
        _READ_ALL | _READ_SENSITIVE | {Cap.EDIT_OWN_CONTROL, Cap.UPLOAD_EVIDENCE}
    ),
    Role.AUDITOR: frozenset(_READ_ALL | _READ_SENSITIVE),
    Role.VIEWER: frozenset(_READ_ALL),
}

# Capabilities that only apply to objects the user owns (checked against ``obj.owner_id``).
OWNERSHIP_SCOPED: frozenset[Cap] = frozenset({Cap.EDIT_OWN_CONTROL, Cap.UPLOAD_EVIDENCE})
