"""Work-management rules: tasks, comments, questionnaires. All writes are audited."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from datetime import date, timedelta
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import UploadedFile
from django.db import models, transaction
from django.db.models import Q, QuerySet
from django.urls import reverse
from django.utils import timezone

from threatledger.accounts.models import User
from threatledger.accounts.permissions import business_unit_scope, can, current_organisation
from threatledger.accounts.roles import Cap
from threatledger.audit.models import Action
from threatledger.audit.services import diff, record, snapshot
from threatledger.core.dates import add_months
from threatledger.core.refs import next_ref

from .models import (
    OPEN_TASK_STATUSES,
    RECURRENCE_STEP,
    AccessLink,
    Answer,
    Assignment,
    AssignmentStatus,
    Comment,
    Notification,
    Question,
    QuestionKind,
    Questionnaire,
    Task,
    TaskRecurrence,
    TaskStatus,
    UserPreference,
)
from .notify import notify


class WorkError(ValueError):
    """A business rule was violated (shown to the user)."""


NOISE = ("updated_at", "created_at", "updated_by", "created_by")
TASK_FIELDS = (
    "title",
    "description",
    "priority",
    "due_on",
    "recurrence",
    "business_unit",
    "control",
    "risk",
    "finding",
    "policy",
    "audit",
    "requires_evidence",
)
LINK_FIELDS = ("control", "risk", "finding", "policy", "audit")


def _changes(before: dict[str, Any], obj: Any) -> dict[str, Any]:
    changes = diff(before, snapshot(obj))
    for noise in NOISE:
        changes.pop(noise, None)
    return changes


def _url(name: str, *args: Any) -> str:
    return reverse(name, args=args)


# ----------------------------------------------------------------------------- tasks
def visible_tasks(user: Any) -> QuerySet[Task]:
    """All tasks in scope for viewers of tasks; otherwise only the user's own."""
    org = current_organisation(user)
    if org is None:
        return Task.objects.none()
    qs = Task.objects.filter(organisation=org)
    if not can(user, Cap.VIEW_TASKS):
        return qs.filter(assignees=user)
    scope = business_unit_scope(user)
    if scope is not None:
        qs = qs.filter(
            Q(business_unit__isnull=True) | Q(business_unit_id__in=scope) | Q(assignees=user)
        ).distinct()
    return qs


def can_manage(user: Any) -> bool:
    return can(user, Cap.MANAGE_TASKS)


def is_assignee(user: Any, task: Task) -> bool:
    return task.assignees.filter(pk=user.pk).exists()


def can_progress(user: Any, task: Task) -> bool:
    return task.is_open and (can_manage(user) or is_assignee(user, task))


def _validate(
    user: Any, data: dict[str, Any], assignees: list[Any], *, check_scope: bool = True
) -> None:
    org = current_organisation(user)
    for name in LINK_FIELDS:
        obj = data.get(name)
        if obj is not None and obj.organisation_id != org.pk:
            raise WorkError(f"Unknown {name}.")
    members = set(User.objects.filter(memberships__organisation=org).values_list("pk", flat=True))
    if any(a.pk not in members for a in assignees):
        raise WorkError("Assignees must be members of the organisation.")
    bu = data.get("business_unit")
    scope = business_unit_scope(user) if check_scope else None
    if bu is not None and scope is not None and bu.pk not in scope:
        raise WorkError("This business unit is outside your scope.")


@transaction.atomic
def create_task(
    *, user: Any, data: dict[str, Any], assignees: Iterable[Any] = (), previous: Task | None = None
) -> Task:
    if not can_manage(user) and previous is None:
        raise WorkError("You cannot create tasks.")
    assignees = list(assignees)
    data = {k: v for k, v in data.items() if k in TASK_FIELDS}
    _validate(user, data, assignees, check_scope=previous is None)
    org = current_organisation(user)
    task = Task(organisation=org, previous=previous, created_by=user, updated_by=user, **data)
    task.ref = next_ref(Task, org, "T")
    task.full_clean(exclude=["organisation", "created_by", "updated_by", "previous"])
    task.save()
    task.assignees.set(assignees)
    changes = _changes({}, task)
    changes["assignees"] = [None, sorted(a.get_username() for a in assignees)]
    record(Action.CREATE, task, actor=user, changes=changes)
    notify(
        assignees,
        f"Task {task.ref} assigned to you: {task.title}",
        _url("work:task", task.ref),
        actor=user,
    )
    return task


@transaction.atomic
def update_task(
    task: Task, *, user: Any, data: dict[str, Any], assignees: Iterable[Any] | None = None
) -> Task:
    if not can_manage(user) or not task.is_open:
        raise WorkError("You cannot edit this task.")
    data = {k: v for k, v in data.items() if k in TASK_FIELDS}
    new_assignees = list(assignees) if assignees is not None else list(task.assignees.all())
    merged = {f: getattr(task, f) for f in (*LINK_FIELDS, "business_unit")} | data
    _validate(user, merged, new_assignees)
    before = snapshot(task)
    before_people = set(task.assignees.all())
    for key, value in data.items():
        setattr(task, key, value)
    task.updated_by = user
    task.full_clean(exclude=["organisation", "created_by", "updated_by", "previous"])
    task.save()
    changes = _changes(before, task)
    if assignees is not None and set(new_assignees) != before_people:
        task.assignees.set(new_assignees)
        changes["assignees"] = [
            sorted(a.get_username() for a in before_people),
            sorted(a.get_username() for a in new_assignees),
        ]
        notify(
            set(new_assignees) - before_people,
            f"Task {task.ref} assigned to you: {task.title}",
            _url("work:task", task.ref),
            actor=user,
        )
    if changes:
        record(Action.UPDATE, task, actor=user, changes=changes)
    return task


def next_due(task: Task) -> date:
    base = task.due_on or timezone.localdate()
    days, months = RECURRENCE_STEP[task.recurrence]
    return add_months(base, months) + timedelta(days=days)


@transaction.atomic
def set_task_status(task: Task, *, user: Any, status: str, note: str = "") -> Task:
    if status not in TaskStatus.values:
        raise WorkError("Unknown status.")
    if status == TaskStatus.CANCELLED:
        if not can_manage(user) or not task.is_open:
            raise WorkError("Only task managers can cancel open tasks.")
    elif task.status == TaskStatus.DONE and status in OPEN_TASK_STATUSES:
        if not can_manage(user):
            raise WorkError("Only task managers can reopen tasks.")
    elif not can_progress(user, task):
        raise WorkError("Only assignees or task managers can update this task.")
    if status == TaskStatus.DONE:
        _check_completion(task, note)
    before = snapshot(task)
    task.status = status
    task.updated_by = user
    if status == TaskStatus.DONE:
        task.completed_at, task.completed_by = timezone.now(), user
        task.completion_note = note.strip()
    elif status in OPEN_TASK_STATUSES:
        task.completed_at, task.completed_by = None, None
    task.save()
    record(Action.UPDATE, task, actor=user, changes=_changes(before, task))
    if status in (TaskStatus.DONE, TaskStatus.CANCELLED):
        _schedule_next(task, user)
    return task


def _check_completion(task: Task, note: str) -> None:
    if not task.requires_evidence:
        return
    if not note.strip():
        raise WorkError("This task needs a completion note describing the evidence.")
    control = task.control
    if control is not None:
        fresh = control.evidence.filter(
            archived_at__isnull=True, uploaded_at__gte=task.created_at
        ).exists()
        if not fresh:
            raise WorkError(
                f"Add evidence to {control.ref} first: this check requires new evidence."
            )


def _schedule_next(task: Task, user: Any) -> Task | None:
    if task.recurrence == TaskRecurrence.NONE or Task.objects.filter(previous=task).exists():
        return None
    data = {f: getattr(task, f) for f in TASK_FIELDS}
    data["due_on"] = next_due(task)
    return create_task(user=user, data=data, assignees=task.assignees.all(), previous=task)


# ----------------------------------------------------------------------------- comments
def _registry() -> dict[str, Callable[[Any], QuerySet[Any]]]:
    """Commentable model label -> function returning what ``user`` may see."""
    from threatledger.audits.services import visible_audits
    from threatledger.controls.services import visible_controls
    from threatledger.findings.services import visible_exceptions, visible_findings
    from threatledger.policies.services import visible_policies
    from threatledger.risks.services import visible_risks
    from threatledger.vendors.services import visible_entities

    return {
        "vendors.entity": visible_entities,
        "risks.risk": visible_risks,
        "controls.control": visible_controls,
        "findings.finding": visible_findings,
        "findings.securityexception": visible_exceptions,
        "audits.audit": visible_audits,
        "policies.policy": visible_policies,
        "work.task": visible_tasks,
    }


def commentable(user: Any, label: str, object_id: str) -> Any:
    visible = _registry().get(label)
    if visible is None:
        raise WorkError("Comments are not available here.")
    obj = visible(user).filter(pk=object_id).first()
    if obj is None:
        raise WorkError("Not found.")
    return obj


def comments_for(obj: Any) -> QuerySet[Comment]:
    ct = ContentType.objects.get_for_model(obj)
    return Comment.objects.filter(content_type=ct, object_id=str(obj.pk)).select_related("author")


MENTION_RE = re.compile(r"(?<![\w.])@([\w.+-]{2,150})")


def _people_to_tell(obj: Any) -> list[Any]:
    people = []
    for attr in ("owner", "lead_auditor", "respondent"):
        people.append(getattr(obj, attr, None))
    if isinstance(obj, Task):
        people.extend(obj.assignees.all())
    if hasattr(obj, "created_by"):
        people.append(obj.created_by)
    return people


def detail_url(obj: Any) -> str:
    label = obj._meta.label_lower
    names = {
        "risks.risk": "risks:detail",
        "controls.control": "controls:detail",
        "findings.finding": "findings:detail",
        "findings.securityexception": "findings:exception",
        "audits.audit": "audits:detail",
        "policies.policy": "policies:detail",
        "work.task": "work:task",
        "vendors.entity": "vendors:detail",
    }
    return _url(names[label], obj.ref) if label in names else ""


@transaction.atomic
def add_comment(obj: Any, *, user: Any, body: str) -> Comment:
    if not can(user, Cap.COMMENT):
        raise WorkError("You cannot comment.")
    body = body.strip()
    if not body:
        raise WorkError("Write a comment first.")
    if len(body) > 5000:
        raise WorkError("Comments are limited to 5,000 characters.")
    org = current_organisation(user)
    comment = Comment.objects.create(
        organisation=org,
        content_type=ContentType.objects.get_for_model(obj),
        object_id=str(obj.pk),
        author=user,
        body=body,
    )
    names = {m.lower() for m in MENTION_RE.findall(body)}
    mentioned = (
        list(
            User.objects.filter(
                memberships__organisation=org, is_active=True, username__in=names
            ).distinct()
        )
        if names
        else []
    )
    # Only people who can see the object are told about it.
    label = obj._meta.label_lower
    visible = _registry()[label]
    mentioned = [m for m in mentioned if visible(m).filter(pk=obj.pk).exists()]
    comment.mentions.set(mentioned)
    url = detail_url(obj)
    ref = getattr(obj, "ref", str(obj))
    notify(mentioned, f"{user} mentioned you on {ref}", url, actor=user)
    others = [p for p in _people_to_tell(obj) if p is not None and p not in mentioned]
    others = [p for p in others if visible(p).filter(pk=obj.pk).exists()]
    notify(others, f"{user} commented on {ref}", url, actor=user)
    record(
        Action.CREATE,
        comment,
        actor=user,
        object_repr=f"Comment on {ref}",
        changes={"on": [None, f"{label}:{obj.pk}"], "mentions": [None, sorted(names)]},
    )
    return comment


# ----------------------------------------------------------------------------- notifications
def mark_read(user: Any, ids: Iterable[int] | None = None) -> int:
    qs = Notification.objects.filter(recipient=user, read_at__isnull=True)
    if ids is not None:
        qs = qs.filter(pk__in=list(ids))
    return qs.update(read_at=timezone.now())


def preference(user: Any) -> UserPreference:
    pref, _ = UserPreference.objects.get_or_create(user=user)
    return pref


def set_preference(user: Any, *, email_digest: bool) -> UserPreference:
    pref = preference(user)
    if pref.email_digest != email_digest:
        pref.email_digest = email_digest
        pref.save()
        record(
            Action.UPDATE,
            pref,
            actor=user,
            changes={"email_digest": [not email_digest, email_digest]},
        )
    return pref


# ----------------------------------------------------------------------------- questionnaires
def visible_questionnaires(user: Any) -> QuerySet[Questionnaire]:
    org = current_organisation(user)
    if org is None or not can(user, Cap.VIEW_TASKS):
        return Questionnaire.objects.none()
    return Questionnaire.objects.filter(organisation=org)


def visible_assignments(user: Any) -> QuerySet[Assignment]:
    org = current_organisation(user)
    if org is None:
        return Assignment.objects.none()
    qs = Assignment.objects.filter(organisation=org)
    if not can(user, Cap.VIEW_TASKS):
        return qs.filter(respondent=user)
    scope = business_unit_scope(user)
    if scope is not None:
        qs = qs.filter(
            Q(business_unit__isnull=True) | Q(business_unit_id__in=scope) | Q(respondent=user)
        )
    return qs


@transaction.atomic
def create_questionnaire(
    *, user: Any, title: str, description: str = "", questions: Iterable[dict[str, Any]] = ()
) -> Questionnaire:
    if not can_manage(user):
        raise WorkError("You cannot create questionnaires.")
    org = current_organisation(user)
    q = Questionnaire(
        organisation=org, title=title.strip(), description=description, created_by=user
    )
    q.ref = next_ref(Questionnaire, org, "Q", width=3)
    q.full_clean(exclude=["organisation", "created_by", "updated_by"])
    q.save()
    for item in questions:
        add_question(q, user=user, data=item, audit=False)
    record(Action.CREATE, q, actor=user, changes={"questions": [None, q.questions.count()]})
    return q


def _check_question(data: dict[str, Any]) -> dict[str, Any]:
    kind = data.get("kind", QuestionKind.YES_NO)
    if kind not in QuestionKind.values:
        raise ValidationError({"kind": "Unknown question type."})
    choices = [str(c).strip() for c in data.get("choices") or [] if str(c).strip()]
    if kind == QuestionKind.CHOICE and len(choices) < 2:
        raise ValidationError({"choices": "Give at least two choices."})
    if not str(data.get("text", "")).strip():
        raise ValidationError({"text": "Write the question."})
    return {
        "text": str(data["text"]).strip()[:500],
        "help_text": str(data.get("help_text", "")).strip()[:500],
        "kind": kind,
        "choices": choices if kind == QuestionKind.CHOICE else [],
        "required": bool(data.get("required", True)),
        "evidence_required": bool(data.get("evidence_required", False)),
    }


@transaction.atomic
def add_question(
    q: Questionnaire, *, user: Any, data: dict[str, Any], audit: bool = True
) -> Question:
    if not can_manage(user) or q.archived_at:
        raise WorkError("You cannot change this questionnaire.")
    if q.assignments.exclude(status=AssignmentStatus.ACCEPTED).exists():
        raise WorkError("Questions cannot change while the questionnaire is out for answers.")
    order = (q.questions.aggregate(m=models.Max("order"))["m"] or 0) + 1
    question = Question.objects.create(questionnaire=q, order=order, **_check_question(data))
    if audit:
        record(Action.UPDATE, q, actor=user, changes={"question_added": [None, question.text]})
    return question


@transaction.atomic
def assign_questionnaire(
    q: Questionnaire, *, user: Any, respondents: Iterable[Any], data: dict[str, Any]
) -> list[Assignment]:
    if not can_manage(user) or q.archived_at:
        raise WorkError("You cannot send this questionnaire.")
    if not q.questions.exists():
        raise WorkError("Add questions first.")
    respondents = list(respondents)
    if not respondents:
        raise WorkError("Choose at least one respondent.")
    org = current_organisation(user)
    control = data.get("control")
    if control is not None and control.organisation_id != org.pk:
        raise WorkError("Unknown control.")
    out = []
    for person in respondents:
        a = Assignment(
            organisation=org,
            questionnaire=q,
            respondent=person,
            control=control,
            business_unit=data.get("business_unit"),
            due_on=data.get("due_on"),
            message=data.get("message", ""),
            created_by=user,
            updated_by=user,
        )
        a.ref = next_ref(Assignment, org, "QA")
        a.save()
        record(Action.CREATE, a, actor=user, changes={"respondent": [None, person.get_username()]})
        notify(
            [person],
            f"Questionnaire to answer: {q.title}",
            _url("work:assignment", a.ref),
            actor=user,
        )
        out.append(a)
    return out


@transaction.atomic
def save_answer(
    a: Assignment,
    question: Question,
    *,
    user: Any,
    value: str,
    comment: str = "",
    evidence_url: str = "",
    upload: UploadedFile | None = None,
) -> Answer:
    if a.respondent_id is None or a.respondent_id != user.pk:
        raise WorkError("Only the respondent can answer.")
    return _store_answer(a, question, value, comment, evidence_url, upload)


def _store_answer(
    a: Assignment,
    question: Question,
    value: str,
    comment: str,
    evidence_url: str,
    upload: UploadedFile | None,
) -> Answer:
    if not a.editable_by_respondent:
        raise WorkError("This questionnaire has been submitted.")
    if question.questionnaire_id != a.questionnaire_id:
        raise WorkError("Unknown question.")
    value = value.strip()
    if value and question.kind != QuestionKind.TEXT and value not in question.options:
        raise WorkError("Choose one of the options.")
    if evidence_url and not evidence_url.lower().startswith(("https://", "http://")):
        raise WorkError("Only http(s) links are allowed.")
    answer, _ = Answer.objects.get_or_create(assignment=a, question=question)
    answer.value, answer.comment = value[:5000], comment.strip()[:5000]
    answer.evidence_url = evidence_url.strip()[:1000]
    if upload is not None:
        from threatledger.controls.uploads import validate_upload

        checked = validate_upload(upload)
        answer.original_filename = checked.original_filename
        answer.content_type = checked.content_type
        answer.size, answer.sha256 = checked.size, checked.sha256
        answer.file.save(checked.original_filename, upload, save=False)
    answer.answered_at = timezone.now()
    answer.save()
    if a.status in (AssignmentStatus.SENT,):
        a.status = AssignmentStatus.IN_PROGRESS
        a.save(update_fields=["status", "updated_at"])
    return answer


def missing_answers(a: Assignment) -> list[Question]:
    answers = {x.question_id: x for x in a.answers.all()}
    missing = []
    for q in a.questionnaire.questions.all():
        ans = answers.get(q.pk)
        unanswered = q.required and (ans is None or not ans.value)
        no_evidence = q.evidence_required and (ans is None or not ans.has_evidence)
        if unanswered or no_evidence:
            missing.append(q)
    return missing


@transaction.atomic
def submit_assignment(a: Assignment, *, user: Any) -> Assignment:
    if a.respondent_id is None or a.respondent_id != user.pk or not a.editable_by_respondent:
        raise WorkError("You cannot submit this questionnaire.")
    return _submit(a, actor=user, who=str(user))


def _submit(a: Assignment, *, actor: Any, who: str) -> Assignment:
    if not a.editable_by_respondent:
        raise WorkError("This questionnaire has already been submitted.")
    missing = missing_answers(a)
    if missing:
        raise WorkError(
            f"{len(missing)} question(s) still need an answer or evidence: "
            + "; ".join(q.text[:60] for q in missing[:3])
        )
    before = a.status
    a.status, a.submitted_at = AssignmentStatus.SUBMITTED, timezone.now()
    a.save(update_fields=["status", "submitted_at", "updated_at"])
    record(
        Action.UPDATE,
        a,
        actor=actor,
        changes={
            "status": [before, a.status],
            "answers": [None, a.answers.count()],
            "by": [None, who],
        },
    )
    recipients = [a.created_by]
    if a.entity is not None:
        recipients.append(a.entity.owner)
    notify(
        recipients,
        f"{who} submitted {a.questionnaire.title} ({a.ref})",
        _url("work:assignment", a.ref),
        actor=actor,
    )
    return a


@transaction.atomic
def review_assignment(a: Assignment, *, user: Any, accept: bool, note: str = "") -> Assignment:
    if not can_manage(user):
        raise WorkError("You cannot review questionnaires.")
    if a.status != AssignmentStatus.SUBMITTED:
        raise WorkError("Only submitted questionnaires can be reviewed.")
    if a.respondent_id == user.pk:
        raise WorkError("Segregation of duties: you cannot review your own answers.")
    if not accept and not note.strip():
        raise WorkError("Explain what needs to change.")
    a.status = AssignmentStatus.ACCEPTED if accept else AssignmentStatus.RETURNED
    a.reviewed_by, a.reviewed_at, a.review_note = user, timezone.now(), note.strip()[:500]
    a.save()
    record(Action.UPDATE, a, actor=user, changes={"status": ["submitted", a.status]})
    notify(
        [a.respondent],
        f"{a.questionnaire.title} ({a.ref}) " + ("accepted" if accept else "returned for changes"),
        _url("work:assignment", a.ref),
        actor=user,
    )
    return a


# ----------------------------------------------------------------------------- scoring
def assessment_score(a: Assignment) -> float | None:
    """Share of "Yes" among Yes/No answers (N/A excluded). Derived, never stored."""
    yes = no = 0
    for ans in a.answers.all():
        if ans.question.kind != QuestionKind.YES_NO:
            continue
        if ans.value == "Yes":
            yes += 1
        elif ans.value == "No":
            no += 1
    return round(100 * yes / (yes + no), 1) if yes + no else None


# ----------------------------------------------------------------------------- external links
LINK_DAYS_MAX = 90


def _hash(token: str) -> str:
    import hashlib

    return hashlib.sha256(token.encode()).hexdigest()


@transaction.atomic
def send_external_assessment(
    entity: Any,
    *,
    user: Any,
    questionnaire: Questionnaire,
    name: str,
    email: str,
    due_on: date | None = None,
    days: int = 30,
    message: str = "",
) -> tuple[Assignment, str]:
    """Create an assignment for a vendor contact and return it with a one-time-shown link token."""
    if not can(user, Cap.MANAGE_VENDORS):
        raise WorkError("You cannot send vendor assessments.")
    org = current_organisation(user)
    if entity.organisation_id != org.pk or questionnaire.organisation_id != org.pk:
        raise WorkError("Unknown vendor or questionnaire.")
    if questionnaire.archived_at or not questionnaire.questions.exists():
        raise WorkError("Choose a questionnaire that has questions.")
    email = email.strip()
    from django.core.validators import validate_email

    try:
        validate_email(email)
    except ValidationError as exc:
        raise WorkError("Enter a valid contact email.") from exc
    a = Assignment(
        organisation=org,
        questionnaire=questionnaire,
        entity=entity,
        external_name=name.strip()[:200],
        external_email=email,
        business_unit=entity.business_unit,
        due_on=due_on,
        message=message,
        created_by=user,
        updated_by=user,
    )
    a.ref = next_ref(Assignment, org, "QA")
    a.full_clean(exclude=["organisation", "created_by", "updated_by"])
    a.save()
    record(
        Action.CREATE,
        a,
        actor=user,
        changes={"entity": [None, entity.ref], "external_email": [None, email]},
    )
    token = issue_link(a, user=user, days=days)
    return a, token


@transaction.atomic
def issue_link(a: Assignment, *, user: Any, days: int = 30) -> str:
    """Revoke any live link and create a new one. Returns the raw token (shown once)."""
    import secrets

    if not can(user, Cap.MANAGE_VENDORS):
        raise WorkError("You cannot manage vendor links.")
    if not a.is_external:
        raise WorkError("Links are only for external respondents.")
    if not 1 <= days <= LINK_DAYS_MAX:
        raise WorkError(f"Links last between 1 and {LINK_DAYS_MAX} days.")
    revoke_links(a, user=user, quiet=True)
    token = secrets.token_urlsafe(32)
    link = AccessLink.objects.create(
        assignment=a,
        token_hash=_hash(token),
        prefix=token[:6],
        expires_at=timezone.now() + timedelta(days=days),
        created_by=user,
    )
    record(
        Action.CREATE,
        link,
        actor=user,
        changes={"assignment": [None, a.ref], "expires_at": [None, link.expires_at.isoformat()]},
    )
    return token


@transaction.atomic
def revoke_links(a: Assignment, *, user: Any, quiet: bool = False) -> int:
    if not can(user, Cap.MANAGE_VENDORS):
        raise WorkError("You cannot manage vendor links.")
    live = a.links.filter(revoked_at__isnull=True, expires_at__gt=timezone.now())
    n = live.update(revoked_at=timezone.now())
    if n and not quiet:
        record(Action.UPDATE, a, actor=user, changes={"links_revoked": [None, n]})
    return n


def resolve_link(token: str) -> AccessLink | None:
    """The usable link for ``token`` (or None). Counts each successful use."""
    if not token or len(token) > 200:
        return None
    link = (
        AccessLink.objects.select_related("assignment__questionnaire", "assignment__entity")
        .filter(token_hash=_hash(token))
        .first()
    )
    if link is None or not link.is_usable:
        return None
    AccessLink.objects.filter(pk=link.pk).update(
        last_used_at=timezone.now(), use_count=models.F("use_count") + 1
    )
    return link


def usable_link(link_id: int | None) -> AccessLink | None:
    if link_id is None:
        return None
    link = (
        AccessLink.objects.select_related("assignment__questionnaire", "assignment__entity")
        .filter(pk=link_id)
        .first()
    )
    return link if link is not None and link.is_usable else None


@transaction.atomic
def save_external_answer(
    link: AccessLink,
    question: Question,
    *,
    value: str,
    comment: str = "",
    evidence_url: str = "",
    upload: UploadedFile | None = None,
) -> Answer:
    if not link.is_usable:
        raise WorkError("This link has expired or been revoked.")
    return _store_answer(link.assignment, question, value, comment, evidence_url, upload)


@transaction.atomic
def submit_external(link: AccessLink) -> Assignment:
    if not link.is_usable:
        raise WorkError("This link has expired or been revoked.")
    a = link.assignment
    return _submit(a, actor=None, who=f"{a.external_name or a.external_email} (external)")
