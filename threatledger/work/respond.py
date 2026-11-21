"""Public pages for external respondents (vendors) answering through a secret link.

Security model:
- The link carries a 256-bit random token in the query string (``?token=``); only its SHA-256
  is stored. Gunicorn's access log records paths without query strings and the log scrubber
  redacts ``token=`` values.
- The first request swaps the token for a server-side session entry and redirects to a clean
  URL, so the token does not stay in the address bar, history or Referer headers.
- Links expire, can be revoked, and only reach one assignment. Responses carry
  ``Referrer-Policy: no-referrer``, ``X-Robots-Tag: noindex`` and ``Cache-Control: no-store``.
- Requests are rate-limited per client IP; uploads use the same validation as evidence.
"""

from __future__ import annotations

from typing import Any

from django.contrib import messages
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render

from threatledger.accounts.permissions import PUBLIC, access
from threatledger.core.context import client_ip

from . import services

SESSION_KEY = "tl_respond_link"
WINDOW = 600  # seconds
LIMITS = {"start": 20, "form": 300}


def _limited(request: HttpRequest, bucket: str) -> bool:
    key = f"respond:{bucket}:{client_ip(request) or 'unknown'}"
    try:
        count = cache.incr(key)
    except ValueError:
        cache.set(key, 1, WINDOW)
        count = 1
    return count > LIMITS[bucket]


def _harden(response: HttpResponse) -> HttpResponse:
    response["Referrer-Policy"] = "no-referrer"
    response["X-Robots-Tag"] = "noindex, nofollow"
    response["Cache-Control"] = "no-store"
    return response


def _invalid(request: HttpRequest, status: int = 404) -> HttpResponse:
    return _harden(render(request, "respond/invalid.html", status=status))


@access(PUBLIC)
def start(request: HttpRequest) -> HttpResponse:
    if _limited(request, "start"):
        return _invalid(request, status=429)
    link = services.resolve_link(request.GET.get("token", ""))
    if link is None:
        return _invalid(request)
    request.session.cycle_key()
    request.session[SESSION_KEY] = link.pk
    return _harden(redirect("respond:form"))


@access(PUBLIC)
def form(request: HttpRequest) -> HttpResponse:
    if _limited(request, "form"):
        return _invalid(request, status=429)
    link = services.usable_link(request.session.get(SESSION_KEY))
    if link is None:
        return _invalid(request)
    a = link.assignment
    if request.method == "POST":
        if not a.editable_by_respondent:
            return _harden(redirect("respond:form"))
        errors: list[str] = []
        for question in a.questionnaire.questions.all():
            key = f"q{question.pk}"
            if key not in request.POST and f"{key}_file" not in request.FILES:
                continue
            try:
                services.save_external_answer(
                    link,
                    question,
                    value=request.POST.get(key, ""),
                    comment=request.POST.get(f"{key}_comment", ""),
                    evidence_url=request.POST.get(f"{key}_url", ""),
                    upload=request.FILES.get(f"{key}_file"),
                )
            except (ValidationError, services.WorkError) as exc:
                text = " ".join(getattr(exc, "messages", [str(exc)]))
                errors.append(f"{question.text[:60]}: {text}")
        for e in errors:
            messages.error(request, e)
        if not errors and request.POST.get("submit") == "1":
            try:
                services.submit_external(link)
            except services.WorkError as exc:
                messages.error(request, str(exc))
            else:
                messages.success(request, "Thank you: your answers were submitted.")
        elif not errors:
            messages.success(request, "Answers saved. You can come back with the same link.")
        return _harden(redirect("respond:form"))
    answers = {x.question_id: x for x in a.answers.all()}
    ctx: dict[str, Any] = {
        "a": a,
        "rows": [(q, answers.get(q.pk)) for q in a.questionnaire.questions.all()],
        "can_edit": a.editable_by_respondent,
        "missing": services.missing_answers(a) if a.editable_by_respondent else [],
        "expires_at": link.expires_at,
    }
    return _harden(render(request, "respond/form.html", ctx))
