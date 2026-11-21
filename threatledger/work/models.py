"""Work management: tasks, comments, notifications and questionnaires (Phase 9)."""

from __future__ import annotations

import uuid
from typing import Any

from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.core.files.storage import Storage
from django.db import models
from django.utils import timezone

from threatledger.audits.models import Audit
from threatledger.controls.models import Control
from threatledger.core.models import TimeStampedModel
from threatledger.findings.models import Finding
from threatledger.org.models import BusinessUnit, Organisation
from threatledger.policies.models import Policy
from threatledger.risks.models import Risk


# ----------------------------------------------------------------------------- tasks
class TaskStatus(models.TextChoices):
    TODO = "todo", "To do"
    IN_PROGRESS = "in_progress", "In progress"
    BLOCKED = "blocked", "Blocked"
    DONE = "done", "Done"
    CANCELLED = "cancelled", "Cancelled"


OPEN_TASK_STATUSES = (TaskStatus.TODO, TaskStatus.IN_PROGRESS, TaskStatus.BLOCKED)


class Priority(models.TextChoices):
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"


class TaskRecurrence(models.TextChoices):
    NONE = "none", "One-off"
    WEEKLY = "weekly", "Weekly"
    MONTHLY = "monthly", "Monthly"
    QUARTERLY = "quarterly", "Quarterly"
    SEMIANNUAL = "semiannual", "Every 6 months"
    ANNUAL = "annual", "Annual"


# recurrence -> (days, months)
RECURRENCE_STEP = {
    "weekly": (7, 0),
    "monthly": (0, 1),
    "quarterly": (0, 3),
    "semiannual": (0, 6),
    "annual": (0, 12),
}


class Task(TimeStampedModel):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    ref = models.CharField(max_length=16, editable=False)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    status = models.CharField(
        max_length=16, choices=TaskStatus.choices, default=TaskStatus.TODO, db_index=True
    )
    priority = models.CharField(max_length=8, choices=Priority.choices, default=Priority.MEDIUM)
    due_on = models.DateField(null=True, blank=True)
    recurrence = models.CharField(
        max_length=16,
        choices=TaskRecurrence.choices,
        default=TaskRecurrence.NONE,
        help_text="Periodic checks: the next occurrence is created when this one is completed.",
    )
    assignees = models.ManyToManyField(
        settings.AUTH_USER_MODEL, blank=True, related_name="assigned_tasks"
    )
    business_unit = models.ForeignKey(
        BusinessUnit, null=True, blank=True, on_delete=models.PROTECT, related_name="tasks"
    )
    control = models.ForeignKey(
        Control, null=True, blank=True, on_delete=models.PROTECT, related_name="tasks"
    )
    risk = models.ForeignKey(
        Risk, null=True, blank=True, on_delete=models.PROTECT, related_name="tasks"
    )
    finding = models.ForeignKey(
        Finding, null=True, blank=True, on_delete=models.PROTECT, related_name="tasks"
    )
    policy = models.ForeignKey(
        Policy, null=True, blank=True, on_delete=models.PROTECT, related_name="tasks"
    )
    audit = models.ForeignKey(
        Audit, null=True, blank=True, on_delete=models.PROTECT, related_name="tasks"
    )
    requires_evidence = models.BooleanField(
        default=False,
        help_text="Completion needs a note, and new evidence on the linked control (if any).",
    )
    completion_note = models.TextField(blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    completed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    previous = models.OneToOneField(
        "self", null=True, blank=True, on_delete=models.PROTECT, related_name="next_occurrence"
    )

    class Meta:
        ordering = ["due_on", "id"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_task_ref"),
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.title}"

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_TASK_STATUSES

    @property
    def overdue(self) -> bool:
        return self.is_open and self.due_on is not None and self.due_on < timezone.localdate()

    @property
    def subject(self) -> Any:
        for name in ("control", "risk", "finding", "policy", "audit"):
            obj = getattr(self, name)
            if obj is not None:
                return obj
        return None


# ----------------------------------------------------------------------------- comments
class Comment(models.Model):
    """Append-only discussion on any governed object (risk, control, finding, …)."""

    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    content_type = models.ForeignKey(ContentType, on_delete=models.PROTECT, related_name="+")
    object_id = models.CharField(max_length=64)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+")
    body = models.TextField()
    mentions = models.ManyToManyField(settings.AUTH_USER_MODEL, blank=True, related_name="+")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["created_at", "id"]
        indexes = [models.Index(fields=["content_type", "object_id"])]

    def __str__(self) -> str:
        return f"Comment by {self.author} on {self.content_type.model} {self.object_id}"


# ----------------------------------------------------------------------------- notifications
class Notification(models.Model):
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notifications"
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    message = models.CharField(max_length=300)
    url = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [models.Index(fields=["recipient", "read_at"])]

    def __str__(self) -> str:
        return self.message


class UserPreference(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="tl_preference"
    )
    email_digest = models.BooleanField(
        default=True, help_text="A daily email when something is due, overdue or awaiting you."
    )

    def __str__(self) -> str:
        return f"Preferences of {self.user}"


class DigestLog(models.Model):
    """One digest per user per day (dedupe for the daily job)."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    sent_on = models.DateField()
    items = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "sent_on"], name="uniq_digest_per_day")
        ]

    def __str__(self) -> str:
        return f"Digest for {self.user} on {self.sent_on}"


# ----------------------------------------------------------------------------- questionnaires
class Questionnaire(TimeStampedModel):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    ref = models.CharField(max_length=16, editable=False)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    archived_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["ref"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_questionnaire_ref"),
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.title}"


class QuestionKind(models.TextChoices):
    YES_NO = "yes_no", "Yes / No / N/A"
    CHOICE = "choice", "Single choice"
    TEXT = "text", "Free text"


YES_NO_CHOICES = ["Yes", "No", "N/A"]


class Question(models.Model):
    questionnaire = models.ForeignKey(
        Questionnaire, on_delete=models.CASCADE, related_name="questions"
    )
    order = models.PositiveIntegerField(default=0)
    text = models.CharField(max_length=500)
    help_text = models.CharField(max_length=500, blank=True)
    kind = models.CharField(max_length=8, choices=QuestionKind.choices, default=QuestionKind.YES_NO)
    choices = models.JSONField(default=list, blank=True)
    required = models.BooleanField(default=True)
    evidence_required = models.BooleanField(
        default=False, help_text="The respondent must attach a file or link."
    )

    class Meta:
        ordering = ["order", "id"]

    def __str__(self) -> str:
        return self.text

    @property
    def options(self) -> list[str]:
        if self.kind == QuestionKind.YES_NO:
            return YES_NO_CHOICES
        return [str(c) for c in self.choices or []]


class AssignmentStatus(models.TextChoices):
    SENT = "sent", "Sent"
    IN_PROGRESS = "in_progress", "In progress"
    SUBMITTED = "submitted", "Submitted"
    RETURNED = "returned", "Returned for changes"
    ACCEPTED = "accepted", "Accepted"


class Assignment(TimeStampedModel):
    """A questionnaire sent to one respondent (any role: respondent mode)."""

    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="+")
    ref = models.CharField(max_length=16, editable=False)
    questionnaire = models.ForeignKey(
        Questionnaire, on_delete=models.PROTECT, related_name="assignments"
    )
    respondent = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="questionnaire_assignments",
    )
    # External respondents (Phase 10): a vendor contact answering through an access link.
    entity = models.ForeignKey(
        "vendors.Entity",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="assessments",
    )
    external_name = models.CharField(max_length=200, blank=True)
    external_email = models.EmailField(blank=True)
    control = models.ForeignKey(
        Control, null=True, blank=True, on_delete=models.PROTECT, related_name="questionnaires"
    )
    business_unit = models.ForeignKey(
        BusinessUnit, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    due_on = models.DateField(null=True, blank=True)
    message = models.TextField(blank=True)
    status = models.CharField(
        max_length=16, choices=AssignmentStatus.choices, default=AssignmentStatus.SENT
    )
    submitted_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_note = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        constraints = [
            models.UniqueConstraint(fields=["organisation", "ref"], name="uniq_assignment_ref"),
            models.CheckConstraint(
                condition=models.Q(respondent__isnull=False)
                | (models.Q(entity__isnull=False) & ~models.Q(external_email="")),
                name="assignment_has_respondent",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.ref} {self.questionnaire.title} → {self.respondent_label}"

    @property
    def is_external(self) -> bool:
        return self.respondent_id is None

    @property
    def respondent_label(self) -> str:
        if self.respondent_id is not None:
            return str(self.respondent)
        return f"{self.external_name or self.external_email} (external)"

    @property
    def editable_by_respondent(self) -> bool:
        return self.status in (
            AssignmentStatus.SENT,
            AssignmentStatus.IN_PROGRESS,
            AssignmentStatus.RETURNED,
        )

    @property
    def overdue(self) -> bool:
        return (
            self.editable_by_respondent
            and self.due_on is not None
            and self.due_on < timezone.localdate()
        )


def answer_path(instance: Answer, filename: str) -> str:
    """Random, extension-less storage name (user-supplied names never touch the filesystem)."""
    return f"{instance.assignment.organisation_id}/answers/{uuid.uuid4().hex}"


def answer_storage() -> Storage:
    from django.core.files.storage import storages

    return storages["evidence"]


class Answer(models.Model):
    assignment = models.ForeignKey(Assignment, on_delete=models.CASCADE, related_name="answers")
    question = models.ForeignKey(Question, on_delete=models.PROTECT, related_name="+")
    value = models.TextField(blank=True)
    comment = models.TextField(blank=True)
    evidence_url = models.URLField(max_length=1000, blank=True)
    file = models.FileField(
        upload_to=answer_path, storage=answer_storage, blank=True, max_length=200
    )
    original_filename = models.CharField(max_length=255, blank=True)
    content_type = models.CharField(max_length=100, blank=True)
    size = models.PositiveBigIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True)
    answered_at = models.DateTimeField(default=timezone.now)

    AUDIT_EXCLUDE = ("file",)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["assignment", "question"], name="uniq_answer"),
        ]

    def __str__(self) -> str:
        return f"{self.assignment.ref} · {self.question_id}"

    @property
    def has_evidence(self) -> bool:
        return bool(self.file) or bool(self.evidence_url)


class AccessLink(models.Model):
    """A secret, expiring link that lets an external respondent answer one assignment.

    Only a SHA-256 hash of the token is stored; the token is shown once when the link is made.
    """

    assignment = models.ForeignKey(Assignment, on_delete=models.CASCADE, related_name="links")
    token_hash = models.CharField(max_length=64, unique=True)
    prefix = models.CharField(max_length=8, help_text="First characters, to recognise the link.")
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    use_count = models.PositiveIntegerField(default=0)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+"
    )
    created_at = models.DateTimeField(default=timezone.now)

    AUDIT_EXCLUDE = ("token_hash",)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Link {self.prefix}… for {self.assignment.ref}"

    @property
    def is_usable(self) -> bool:
        return self.revoked_at is None and self.expires_at > timezone.now()
