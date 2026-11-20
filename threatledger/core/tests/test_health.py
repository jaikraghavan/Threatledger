from __future__ import annotations

from unittest import mock

import pytest
from django.urls import reverse

pytestmark = pytest.mark.django_db


def test_healthz_is_public_and_ok(client):
    response = client.get(reverse("core:healthz"))
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "no-cache" in response["Cache-Control"]


def test_readyz_ok(client):
    response = client.get(reverse("core:readyz"))
    assert response.status_code == 200
    assert response.json()["checks"] == {"database": "ok", "cache": "ok"}


def test_readyz_reports_failure_without_details(client):
    with mock.patch("threatledger.core.views.connection") as conn:
        conn.cursor.side_effect = RuntimeError("password=hunter2 host=db")
        response = client.get(reverse("core:readyz"))
    assert response.status_code == 503
    assert response.json()["checks"]["database"] == "fail"
    assert b"hunter2" not in response.content


def test_readyz_cache_failure(client):
    with mock.patch("threatledger.core.views.cache") as cache:
        cache.set.side_effect = ConnectionError("redis down")
        response = client.get(reverse("core:readyz"))
    assert response.status_code == 503
    assert response.json()["checks"]["cache"] == "fail"


def test_every_response_has_a_request_id(client):
    response = client.get(reverse("core:healthz"))
    assert len(response["X-Request-ID"]) == 32


def test_well_formed_upstream_request_id_is_kept(client):
    response = client.get(reverse("core:healthz"), HTTP_X_REQUEST_ID="abc-123-def-456")
    assert response["X-Request-ID"] == "abc-123-def-456"


def test_malformed_upstream_request_id_is_replaced(client):
    response = client.get(reverse("core:healthz"), HTTP_X_REQUEST_ID="<script>alert(1)</script>")
    assert response["X-Request-ID"] != "<script>alert(1)</script>"
