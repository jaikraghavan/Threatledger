"""Trigram GIN indexes so ``name__icontains`` search stays fast (PostgreSQL only).

Django's ``icontains`` on PostgreSQL compiles to ``UPPER(col::text) LIKE UPPER(%s)``, so the
indexes are built on that expression. ``pg_trgm`` is a trusted extension (PG 13+), so the
database owner can create it. If it cannot be created, search still works, just unindexed.
"""

import logging

from django.db import migrations, transaction

logger = logging.getLogger(__name__)

INDEXES = [
    ("attack_technique_name_trgm", "attack_technique", 'UPPER("name"::text)'),
    ("attack_group_name_trgm", "attack_group", 'UPPER("name"::text)'),
    ("attack_group_aliases_trgm", "attack_group", 'UPPER("aliases_text"::text)'),
]


def forward(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    try:
        with transaction.atomic(using=schema_editor.connection.alias):
            schema_editor.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm", params=None)
    except Exception:  # insufficient privilege: keep working without the index
        logger.warning("pg_trgm unavailable; ATT&CK search will not use trigram indexes")
        return
    for name, table, expr in INDEXES:
        schema_editor.execute(
            f"CREATE INDEX IF NOT EXISTS {name} ON {table} USING gin ({expr} gin_trgm_ops)",
            params=None,
        )


def reverse(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        return
    for name, _, _ in INDEXES:
        schema_editor.execute(f"DROP INDEX IF EXISTS {name}", params=None)


class Migration(migrations.Migration):
    dependencies = [("attack", "0001_initial")]
    operations = [migrations.RunPython(forward, reverse)]
