"""Make the audit table append-only at the database level (PostgreSQL only).

UPDATE, DELETE and TRUNCATE raise an exception regardless of which client issues them. Other
backends (SQLite in local dev) rely on the model/queryset guards and the hash chain.
"""

from django.db import migrations

FORWARD = """
CREATE OR REPLACE FUNCTION audit_auditevent_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_auditevent is append-only (% blocked)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_auditevent_no_modify
    BEFORE UPDATE OR DELETE ON audit_auditevent
    FOR EACH ROW EXECUTE FUNCTION audit_auditevent_append_only();

CREATE TRIGGER audit_auditevent_no_truncate
    BEFORE TRUNCATE ON audit_auditevent
    FOR EACH STATEMENT EXECUTE FUNCTION audit_auditevent_append_only();
"""

REVERSE = """
DROP TRIGGER IF EXISTS audit_auditevent_no_truncate ON audit_auditevent;
DROP TRIGGER IF EXISTS audit_auditevent_no_modify ON audit_auditevent;
DROP FUNCTION IF EXISTS audit_auditevent_append_only();
"""


# params=None: static DDL, no interpolation. The plpgsql '%' format placeholder must reach
# PostgreSQL untouched (with params=() psycopg would treat it as a query parameter).
def forward(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(FORWARD, params=None)


def reverse(apps, schema_editor):
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(REVERSE, params=None)


class Migration(migrations.Migration):
    dependencies = [("audit", "0001_initial")]
    operations = [migrations.RunPython(forward, reverse)]
