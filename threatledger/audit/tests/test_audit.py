from __future__ import annotations

from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, connection, transaction
from django.test import Client
from django.urls import reverse

from threatledger.accounts.roles import Role
from threatledger.audit.models import GENESIS_HASH, Action, AuditEvent, AuditImmutableError
from threatledger.audit.services import diff, record, snapshot, verify_chain
from threatledger.core.context import RequestContext, reset_context, set_context
from threatledger.org.models import Organisation

pytestmark = pytest.mark.django_db


def test_record_builds_a_hash_chain(org):
    first = record(Action.CREATE, org)
    second = record(Action.UPDATE, org, changes={"name": ["Acme Ltd", "Acme plc"]})
    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.hash
    assert first.hash == first.compute_hash()
    assert verify_chain(AuditEvent.objects.order_by("id")) == []


def test_hash_survives_database_round_trip(org):
    record(
        Action.UPDATE, org, changes={"n": [1.5, {"nested": [1, "x"]}], "when": ["2026-01-01", None]}
    )
    reloaded = AuditEvent.objects.get()
    assert reloaded.compute_hash() == reloaded.hash


def test_record_uses_request_context(org, users):
    token = set_context(
        RequestContext(request_id="req-12345678", ip="203.0.113.9", user=users[Role.ADMIN])
    )
    try:
        event = record(Action.CREATE, org)
    finally:
        reset_context(token)
    assert event.actor == users[Role.ADMIN]
    assert event.actor_label == "admin"
    assert event.request_id == "req-12345678"
    assert event.ip == "203.0.113.9"
    assert event.object_type == "org.organisation"
    assert event.object_id == str(org.pk)


def test_system_event_has_no_actor(org):
    event = record(Action.SYSTEM, org)
    assert event.actor is None
    assert event.actor_label == ""


def test_update_via_save_is_refused(org):
    event = record(Action.CREATE, org)
    event.object_repr = "tampered"
    with pytest.raises(AuditImmutableError):
        event.save()


def test_delete_is_refused(org):
    event = record(Action.CREATE, org)
    with pytest.raises(AuditImmutableError):
        event.delete()
    with pytest.raises(AuditImmutableError):
        AuditEvent.objects.all().delete()
    with pytest.raises(AuditImmutableError):
        AuditEvent.objects.filter(pk=event.pk).update(object_repr="x")


def test_verify_detects_modified_content(org):
    events = [record(Action.CREATE, org), record(Action.UPDATE, org)]
    events[0].object_repr = "tampered in memory"
    problems = verify_chain(events)
    assert [p.event_id for p in problems] == [events[0].pk]
    assert "modified" in problems[0].reason


def test_verify_detects_removed_event(org):
    events = [record(Action.CREATE, org), record(Action.UPDATE, org), record(Action.DELETE, org)]
    problems = verify_chain([events[0], events[2]])
    assert [p.event_id for p in problems] == [events[2].pk]
    assert "broken link" in problems[0].reason


def test_audit_verify_command_ok(org):
    record(Action.CREATE, org)
    out = StringIO()
    call_command("audit_verify", stdout=out)
    assert "Audit chain OK (1 events)" in out.getvalue()


@pytest.mark.skipif(connection.vendor == "postgresql", reason="trigger blocks raw tampering")
def test_audit_verify_command_detects_raw_sql_tampering(org):
    event = record(Action.CREATE, org)
    with connection.cursor() as cursor:
        cursor.execute(
            "UPDATE audit_auditevent SET object_repr = %s WHERE id = %s", ["x", event.pk]
        )
    with pytest.raises(CommandError, match="INVALID"):
        call_command("audit_verify", stdout=StringIO(), stderr=StringIO())


@pytest.mark.postgres
@pytest.mark.skipif(connection.vendor != "postgresql", reason="PostgreSQL trigger")
@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE audit_auditevent SET object_repr = 'x'",
        "DELETE FROM audit_auditevent",
        "TRUNCATE audit_auditevent",
    ],
)
def test_postgres_trigger_blocks_raw_modification(org, sql):
    record(Action.CREATE, org)
    # The test runs inside a transaction holding deferred FK checks; PostgreSQL refuses
    # TRUNCATE while those are pending, before our trigger fires. Flush them first.
    with connection.cursor() as cursor:
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
    with (
        pytest.raises(DatabaseError, match="append-only"),
        transaction.atomic(),
        connection.cursor() as cursor,
    ):
        cursor.execute(sql)
    assert AuditEvent.objects.count() == 1


def test_snapshot_excludes_sensitive_fields(users):
    data = snapshot(users[Role.VIEWER])
    assert "password" not in data
    assert data["username"] == "viewer"


def test_diff_lists_only_changed_fields():
    assert diff({"a": 1, "b": 2}, {"a": 1, "b": 3, "c": 4}) == {"b": [2, 3], "c": [None, 4]}


def test_permission_denied_is_audited(client_for):
    response = client_for(Role.VIEWER).get(reverse("audit:list"))
    assert response.status_code == 403
    event = AuditEvent.objects.get(action=Action.PERMISSION_DENIED)
    assert event.actor_label == "viewer"
    assert event.object_repr == reverse("audit:list")
    assert event.changes["required"] == "view_audit_log"


@pytest.mark.parametrize(
    ("role", "status"),
    [
        (Role.ADMIN, 200),
        (Role.RISK_MANAGER, 200),
        (Role.CONTROL_OWNER, 200),
        (Role.AUDITOR, 200),
        (Role.VIEWER, 403),
    ],
)
def test_audit_log_access_by_role(client_for, role, status):
    assert client_for(role).get(reverse("audit:list")).status_code == status


def test_audit_log_filters_and_htmx_partial(client_for, org):
    record(Action.CREATE, org)
    record(Action.EXPORT, org)
    c = client_for(Role.AUDITOR)
    response = c.get(reverse("audit:list"), {"action": "export"}, HTTP_HX_REQUEST="true")
    assert response.status_code == 200
    assert response.templates[0].name == "audit/_event_table.html"
    assert [e.action for e in response.context["events"]] == ["export"]


def test_admin_changes_are_audited(make_user):
    superuser = make_user(role=None, username="root", is_superuser=True, is_staff=True)
    c = Client()
    c.force_login(superuser)
    response = c.post(
        reverse("admin:org_organisation_add"),
        {"name": "New Org", "slug": "new-org", "settings": "{}"},
    )
    assert response.status_code == 302, response.content
    org = Organisation.objects.get(slug="new-org")
    created = AuditEvent.objects.get(action=Action.CREATE, object_id=str(org.pk))
    assert created.changes["name"] == [None, "New Org"]

    c.post(
        reverse("admin:org_organisation_change", args=[org.pk]),
        {"name": "Renamed Org", "slug": "new-org", "settings": "{}"},
    )
    updated = AuditEvent.objects.get(action=Action.UPDATE, object_id=str(org.pk))
    assert updated.changes == {"name": ["New Org", "Renamed Org"]}

    c.post(reverse("admin:org_organisation_delete", args=[org.pk]), {"post": "yes"})
    assert AuditEvent.objects.filter(action=Action.DELETE, object_id=str(org.pk)).exists()


def test_audit_admin_is_read_only(make_user, org):
    superuser = make_user(role=None, username="root", is_superuser=True, is_staff=True)
    event = record(Action.CREATE, org)
    c = Client()
    c.force_login(superuser)
    assert c.get(reverse("admin:audit_auditevent_changelist")).status_code == 200
    assert c.get(reverse("admin:audit_auditevent_add")).status_code == 403
    assert (
        c.post(
            reverse("admin:audit_auditevent_delete", args=[event.pk]), {"post": "yes"}
        ).status_code
        == 403
    )
    assert AuditEvent.objects.filter(pk=event.pk).exists()
