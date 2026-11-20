from __future__ import annotations

import json
import logging

import pytest
from django.test import RequestFactory, override_settings

from threatledger.core.context import (
    RequestContext,
    client_ip,
    normalise_ip,
    reset_context,
    set_context,
)
from threatledger.core.logging import (
    JsonFormatter,
    RequestContextFilter,
    SensitiveDataFilter,
    scrub,
)


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("login password=hunter2 ok", "hunter2"),
        ('{"password": "hunter2"}', "hunter2"),
        ("Authorization: Bearer abcdef1234567890", "abcdef1234567890"),
        ("token=abc123def456", "abc123def456"),
        ("postgres://app:s3cr3t@db:5432/x", "s3cr3t"),
        ("sessionid=xyz987654321; csrftoken=qwe123", "xyz987654321"),
        ("api_key: AKIA1234567890", "AKIA1234567890"),
    ],
)
def test_scrub_removes_secrets(text, secret):
    cleaned = scrub(text)
    assert secret not in cleaned
    assert "[REDACTED]" in cleaned


def test_scrub_keeps_ordinary_text():
    assert scrub("Risk R-0001 updated by admin") == "Risk R-0001 updated by admin"


def _record(msg: str, *args: object) -> logging.LogRecord:
    return logging.LogRecord("t", logging.INFO, __file__, 1, msg, args, None)


def test_filter_scrubs_formatted_args():
    record = _record("connecting with %s", "password=hunter2")
    SensitiveDataFilter().filter(record)
    assert "hunter2" not in record.getMessage()


def test_filter_scrubs_exception_text():
    try:
        raise ValueError("token=abcdef123456")
    except ValueError:
        import sys

        record = logging.LogRecord("t", logging.ERROR, __file__, 1, "boom", None, sys.exc_info())
    SensitiveDataFilter().filter(record)
    assert "abcdef123456" not in (record.exc_text or "")


def test_json_formatter_includes_request_context():
    token = set_context(RequestContext(request_id="rid-12345678"))
    try:
        record = _record("hello")
        RequestContextFilter().filter(record)
    finally:
        reset_context(token)
    payload = json.loads(JsonFormatter().format(record))
    assert payload["msg"] == "hello"
    assert payload["request_id"] == "rid-12345678"
    assert payload["level"] == "INFO"


rf = RequestFactory()


@override_settings(TRUST_X_FORWARDED_FOR=False)
def test_client_ip_ignores_forwarded_header_by_default():
    request = rf.get("/", REMOTE_ADDR="10.0.0.5", HTTP_X_FORWARDED_FOR="1.2.3.4")
    assert client_ip(request) == "10.0.0.5"


@override_settings(TRUST_X_FORWARDED_FOR=True)
def test_client_ip_uses_last_forwarded_hop_behind_proxy():
    request = rf.get("/", REMOTE_ADDR="172.18.0.4", HTTP_X_FORWARDED_FOR="6.6.6.6, 198.51.100.7")
    assert client_ip(request) == "198.51.100.7"


@override_settings(AUDIT_IP_MODE="truncated")
def test_ip_truncation():
    assert normalise_ip("203.0.113.77") == "203.0.113.0"
    assert normalise_ip("2001:db8:abcd:12::1") == "2001:db8:abcd::"


def test_invalid_ip_is_dropped():
    assert normalise_ip("not-an-ip") is None
    assert normalise_ip(None) is None
