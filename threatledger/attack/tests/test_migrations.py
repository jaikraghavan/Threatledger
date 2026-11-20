from __future__ import annotations

import pytest
from django.db import connection

pytestmark = [
    pytest.mark.django_db,
    pytest.mark.postgres,
    pytest.mark.skipif(connection.vendor != "postgresql", reason="PostgreSQL trigram indexes"),
]


def _scalar(sql: str):
    with connection.cursor() as cursor:
        cursor.execute(sql)
        return cursor.fetchone()[0]


def test_trigram_indexes_exist_when_pg_trgm_is_available():
    if not _scalar("SELECT count(*) FROM pg_available_extensions WHERE name = 'pg_trgm'"):
        pytest.skip("pg_trgm not shipped with this PostgreSQL build")
    names = {
        "attack_technique_name_trgm",
        "attack_group_name_trgm",
        "attack_group_aliases_trgm",
    }
    found = _scalar(
        "SELECT count(*) FROM pg_indexes WHERE indexname IN "
        "('attack_technique_name_trgm', 'attack_group_name_trgm', 'attack_group_aliases_trgm')"
    )
    assert found == len(names)
