"""Render ATT&CK description Markdown safely.

ATT&CK text is external input. Everything is HTML-escaped first; the only markup produced is
paragraphs, line breaks, inline code and links. Links must be http(s); links to ATT&CK
techniques/groups are rewritten to ThreatLedger's own pages. ``(Citation: …)`` markers are
removed (the reference list is not imported).
"""

from __future__ import annotations

import re

from django import template
from django.urls import reverse
from django.utils.html import escape
from django.utils.safestring import SafeString, mark_safe

register = template.Library()

_LINK = re.compile(r"\[([^\]\n]{1,300})\]\((https?://[^\s()<>\"']{1,500})\)")
_CITATION = re.compile(r"\s?\(Citation:[^)]{0,300}\)")
_CODE = re.compile(r"`([^`\n]{1,200})`")
_INTERNAL = [
    (re.compile(r"^https://attack\.mitre\.org/techniques/(T\d{4})(?:/(\d{3}))?/?$"), "technique"),
    (re.compile(r"^https://attack\.mitre\.org/groups/(G\d{4})/?$"), "group"),
]


def _internal_url(url: str) -> str | None:
    for pattern, kind in _INTERNAL:
        m = pattern.match(url)
        if not m:
            continue
        if kind == "technique":
            attack_id = m.group(1) + (f".{m.group(2)}" if m.group(2) else "")
            return reverse("attack:technique_detail", args=[attack_id])
        return reverse("attack:group_detail", args=[m.group(1)])
    return None


def _inline(text: str) -> str:
    return _CODE.sub(r"<code>\1</code>", escape(text))


def _link(label: str, url: str) -> str:
    internal = _internal_url(url)
    if internal:
        return (
            f'<a href="{escape(internal)}" class="text-brand-700 hover:underline">'
            f"{escape(label)}</a>"
        )
    return (
        f'<a href="{escape(url)}" class="text-brand-700 hover:underline" target="_blank" '
        f'rel="noopener noreferrer nofollow">{escape(label)}</a>'
    )


def render_attack_text(text: str | None) -> SafeString:
    if not text:
        return mark_safe("")  # nosec B308
    text = _CITATION.sub("", text)
    parts: list[str] = []
    pos = 0
    for m in _LINK.finditer(text):
        parts.append(_inline(text[pos : m.start()]))
        parts.append(_link(m.group(1), m.group(2)))
        pos = m.end()
    parts.append(_inline(text[pos:]))
    html = "".join(parts)
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", html) if p.strip()]
    body = "".join(f"<p>{p.replace(chr(10), '<br>')}</p>" for p in paragraphs)
    return mark_safe(body)  # noqa: S308 - every input fragment above is escaped  # nosec B308 B703


@register.filter(name="attack_text")
def attack_text(text: str | None) -> SafeString:
    return render_attack_text(text)


@register.filter(name="attack_plain")
def attack_plain(text: str | None) -> str:
    """Plain text (citations and link markup removed) for summaries/truncation."""
    if not text:
        return ""
    text = _CITATION.sub("", text)
    return _LINK.sub(r"\1", text)
