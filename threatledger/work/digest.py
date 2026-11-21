"""Daily email digest: one email per person per day listing what is due, overdue or awaiting
them. Opt-out per user (``UserPreference.email_digest``)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.core.mail import send_mail
from django.db import IntegrityError, transaction
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.models import User
from threatledger.accounts.permissions import can, clear_role_cache

from .models import DigestLog, Notification, UserPreference

logger = logging.getLogger(__name__)
DUE_SOON_DAYS = 3


@dataclass
class Digest:
    lines: list[str] = field(default_factory=list)

    def add(self, text: str, path: str) -> None:
        self.lines.append(f"- {text}\n    {settings.SITE_URL.rstrip('/')}{path}")


def build_digest(user: Any) -> Digest:
    """Everything that needs ``user`` today (pure read; used by the job and by tests)."""
    from threatledger.accounts.roles import Cap
    from threatledger.controls.models import ChangeRequestStatus, ControlChangeRequest, Evidence
    from threatledger.findings.models import ExceptionStatus, Finding, FindingStatus
    from threatledger.findings.services import visible_exceptions
    from threatledger.policies.models import PolicyVersion, VersionStatus
    from threatledger.policies.services import policy_state, visible_policies

    from .models import OPEN_TASK_STATUSES, Assignment, AssignmentStatus, Task

    today = timezone.localdate()
    soon = today + timedelta(days=DUE_SOON_DAYS)
    d = Digest()
    for t in Task.objects.filter(
        assignees=user, status__in=OPEN_TASK_STATUSES, due_on__lte=soon
    ).order_by("due_on"):
        when = "OVERDUE" if t.due_on < today else f"due {t.due_on:%Y-%m-%d}"  # type: ignore[operator]
        d.add(f"Task {t.ref} {when}: {t.title}", reverse("work:task", args=[t.ref]))
    for f in Finding.objects.filter(
        owner=user,
        status__in=[FindingStatus.OPEN, FindingStatus.IN_PROGRESS],
        due_on__lte=soon,
    ).order_by("due_on"):
        when = "OVERDUE" if f.due_on < today else f"due {f.due_on:%Y-%m-%d}"  # type: ignore[operator]
        d.add(f"Finding {f.ref} {when}: {f.title}", reverse("findings:detail", args=[f.ref]))
    for a in Assignment.objects.filter(
        respondent=user,
        status__in=[AssignmentStatus.SENT, AssignmentStatus.IN_PROGRESS, AssignmentStatus.RETURNED],
    ).select_related("questionnaire"):
        when = f" (due {a.due_on:%Y-%m-%d})" if a.due_on else ""
        d.add(
            f"Questionnaire to answer{when}: {a.questionnaire.title}",
            reverse("work:assignment", args=[a.ref]),
        )
    approvals = 0
    if can(user, Cap.APPROVE_CONTROL_CHANGES):
        approvals += (
            ControlChangeRequest.objects.filter(status=ChangeRequestStatus.PENDING)
            .exclude(requested_by=user)
            .count()
        )
    if can(user, Cap.APPROVE_EXCEPTION):
        approvals += (
            visible_exceptions(user)
            .filter(status=ExceptionStatus.REQUESTED)
            .exclude(created_by=user)
            .count()
        )
    if can(user, Cap.APPROVE_POLICIES):
        approvals += (
            PolicyVersion.objects.filter(
                status=VersionStatus.IN_REVIEW, policy__in=visible_policies(user)
            )
            .exclude(author=user)
            .count()
        )
    if can(user, Cap.REVIEW_EVIDENCE):
        approvals += (
            Evidence.objects.filter(review_status="pending", archived_at__isnull=True)
            .exclude(uploaded_by=user)
            .count()
        )
    if approvals:
        d.add(f"{approvals} approval(s) or review(s) waiting for you", reverse("work:approvals"))
    from threatledger.vendors.models import Contract
    from threatledger.vendors.services import postures

    for c in Contract.objects.filter(entity__owner=user, terminated_on__isnull=True).select_related(
        "entity"
    ):
        if c.state == "notice_due":
            d.add(
                f"Contract {c.ref} with {c.entity.name}: give notice by "
                f"{c.notice_deadline:%Y-%m-%d}",
                reverse("vendors:detail", args=[c.entity.ref]),
            )
    from threatledger.vendors.models import Entity

    owned = list(Entity.objects.filter(owner=user, status__in=["active", "offboarding"]))
    for posture in postures(owned):
        if posture.reassess_overdue:
            d.add(
                f"Vendor {posture.entity.name} is due for reassessment",
                reverse("vendors:detail", args=[posture.entity.ref]),
            )
    for p in visible_policies(user).filter(owner=user, retired_at__isnull=True):
        state = policy_state(p)
        if state.status == "review_overdue":
            d.add(
                f"Policy {p.ref} review is overdue: {p.title}",
                reverse("policies:detail", args=[p.ref]),
            )
    return d


def send_digests() -> int:
    today = timezone.localdate()
    opted_out = set(
        UserPreference.objects.filter(email_digest=False).values_list("user_id", flat=True)
    )
    members = (
        User.objects.filter(is_active=True, memberships__isnull=False).exclude(email="").distinct()
    )
    sent = 0
    for user in members:
        if user.pk in opted_out or DigestLog.objects.filter(user=user, sent_on=today).exists():
            continue
        clear_role_cache(user)
        digest = build_digest(user)
        if not digest.lines:
            continue
        unread = Notification.objects.filter(recipient=user, read_at__isnull=True).count()
        try:
            with transaction.atomic():
                DigestLog.objects.create(user=user, sent_on=today, items=len(digest.lines))
                send_mail(
                    f"[ThreatLedger] {len(digest.lines)} item(s) need your attention",
                    f"Hello {user.get_short_name() or user.get_username()},\n\n"
                    + "\n".join(digest.lines)
                    + (f"\n\nYou also have {unread} unread notification(s)." if unread else "")
                    + "\n\nTurn this daily email off under Account → Notifications."
                    + "\n\n— ThreatLedger",
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                )
        except IntegrityError:  # another worker sent it already
            continue
        except Exception:
            logger.exception("digest email failed for user %s", user.pk)
            continue
        sent += 1
    return sent
