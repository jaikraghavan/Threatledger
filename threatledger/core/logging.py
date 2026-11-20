"""Structured JSON logs with request ids, and a scrubber so secrets never reach log sinks."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

from .context import get_context

_SENSITIVE_KEYS = (
    r"password|passwd|secret|token|api[_-]?key|authorization|cookie|sessionid|csrftoken|otp"
)
_PATTERNS = [
    # Authorization header schemes first, so "Authorization: Bearer x" redacts x, not "Bearer"
    re.compile(r"(?i)(\b(?:bearer|token|basic)\s+)([A-Za-z0-9._~+/=-]{8,})"),
    # key=value / key: value / "key": "value"
    re.compile(
        rf"(?i)(\"?(?:{_SENSITIVE_KEYS})\"?\s*[:=]\s*\"?)(?!\[REDACTED\]|bearer\b|basic\b)([^\s\"&,;]+)"
    ),
    # credentials embedded in URLs: scheme://user:pass@host
    re.compile(r"(://[^:/\s@]+:)([^@\s]+)(@)"),
]
REDACTED = "[REDACTED]"


def scrub(text: str) -> str:
    for pattern in _PATTERNS:
        if pattern.groups == 3:
            text = pattern.sub(rf"\g<1>{REDACTED}\g<3>", text)
        else:
            text = pattern.sub(rf"\g<1>{REDACTED}", text)
    return text


class SensitiveDataFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        record.msg = scrub(message)
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = scrub(record.exc_text)
        return True


class RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        ctx = get_context()
        record.request_id = ctx.request_id
        record.user_id = getattr(ctx.user, "pk", None)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": getattr(record, "request_id", ""),
            "user_id": getattr(record, "user_id", None),
        }
        if record.exc_text:
            payload["exc"] = record.exc_text
        elif record.exc_info:
            payload["exc"] = scrub(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)
