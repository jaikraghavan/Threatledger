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
    AUDITOR = "auditor", "Auditor"
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
    # governance (Phase 8)
    VIEW_POLICIES = "view_policies"
    VIEW_AUDITS = "view_audits"
    VIEW_FINDINGS = "view_findings"  # findings and exceptions
    MANAGE_AUDITS = "manage_audits"  # plan audits and campaigns, close audits
    PERFORM_AUDITS = "perform_audits"  # record auditor judgements in an audit
    RAISE_FINDINGS = "raise_findings"
    EDIT_FINDINGS = "edit_findings"
    UPDATE_OWN_FINDING = "update_own_finding"  # remediation updates by the finding owner
    REQUEST_EXCEPTION = "request_exception"
    APPROVE_EXCEPTION = "approve_exception"
    EDIT_POLICIES = "edit_policies"
    APPROVE_POLICIES = "approve_policies"
    # work management (Phase 9)
    VIEW_TASKS = "view_tasks"  # everyone always sees work assigned to them
    MANAGE_TASKS = "manage_tasks"  # create/assign tasks and questionnaires
    COMMENT = "comment"
    REVIEW_EVIDENCE = "review_evidence"  # four-eyes: never your own upload
    APPROVE_CONTROL_CHANGES = "approve_control_changes"
    # third-party risk (Phase 10)
    VIEW_VENDORS = "view_vendors"
    MANAGE_VENDORS = "manage_vendors"  # vendors, contracts, external assessment links
    # privacy & incidents (Phase 11)
    VIEW_PRIVACY = "view_privacy"
    MANAGE_PRIVACY = "manage_privacy"
    APPROVE_DPIA = "approve_dpia"  # never your own DPIA
    VIEW_INCIDENTS = "view_incidents"
    MANAGE_INCIDENTS = "manage_incidents"
    REPORT_INCIDENT = "report_incident"  # anyone can report a suspected incident


_READ_ALL = {
    Cap.VIEW_DASHBOARD,
    Cap.VIEW_RISKS,
    Cap.VIEW_CONTROLS,
    Cap.VIEW_FRAMEWORKS,
    Cap.VIEW_ATTACK,
    Cap.VIEW_POLICIES,
}
_READ_SENSITIVE = {
    Cap.VIEW_EVIDENCE,
    Cap.VIEW_AUDIT_LOG,
    Cap.EXPORT_DATA,
    Cap.VIEW_AUDITS,
    Cap.VIEW_FINDINGS,
    Cap.VIEW_TASKS,
    Cap.VIEW_VENDORS,
    Cap.VIEW_PRIVACY,
    Cap.VIEW_INCIDENTS,
}
# Auditors judge and report; they never change the controls, risks or policies they audit.
_EVERYONE = {Cap.REPORT_INCIDENT}
_AUDIT_WORK = {Cap.PERFORM_AUDITS, Cap.RAISE_FINDINGS, Cap.REVIEW_EVIDENCE, Cap.COMMENT}

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
            Cap.MANAGE_AUDITS,
            Cap.EDIT_FINDINGS,
            Cap.UPDATE_OWN_FINDING,
            Cap.REQUEST_EXCEPTION,
            Cap.APPROVE_EXCEPTION,
            Cap.EDIT_POLICIES,
            Cap.APPROVE_POLICIES,
            Cap.MANAGE_TASKS,
            Cap.APPROVE_CONTROL_CHANGES,
            Cap.MANAGE_VENDORS,
            Cap.MANAGE_PRIVACY,
            Cap.APPROVE_DPIA,
            Cap.MANAGE_INCIDENTS,
        }
        | _AUDIT_WORK
        | _EVERYONE
    ),
    Role.CONTROL_OWNER: frozenset(
        _READ_ALL
        | _READ_SENSITIVE
        | {
            Cap.EDIT_OWN_CONTROL,
            Cap.UPLOAD_EVIDENCE,
            Cap.UPDATE_OWN_FINDING,
            Cap.REQUEST_EXCEPTION,
            Cap.COMMENT,
        }
        | _EVERYONE
    ),
    Role.AUDITOR: frozenset(_READ_ALL | _READ_SENSITIVE | _AUDIT_WORK | _EVERYONE),
    Role.VIEWER: frozenset(_READ_ALL | _EVERYONE),
}

# Capabilities that only apply to objects the user owns (checked against ``obj.owner_id``).
OWNERSHIP_SCOPED: frozenset[Cap] = frozenset(
    {Cap.EDIT_OWN_CONTROL, Cap.UPLOAD_EVIDENCE, Cap.UPDATE_OWN_FINDING}
)
