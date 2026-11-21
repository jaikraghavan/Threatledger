from __future__ import annotations

from typing import Any

from django.contrib import messages
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Q
from django.http import FileResponse, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.http import url_has_allowed_host_and_scheme

from threatledger.accounts.permissions import AUTHENTICATED, access, can
from threatledger.accounts.roles import Cap
from threatledger.controls import services as control_services
from threatledger.controls.models import (
    ChangeRequestStatus,
    ControlChangeRequest,
    Evidence,
    EvidenceReview,
)
from threatledger.controls.services import visible_controls
from threatledger.findings.models import ExceptionStatus, Finding, FindingStatus
from threatledger.findings.services import visible_exceptions, visible_findings
from threatledger.policies.models import PolicyVersion, VersionStatus
from threatledger.policies.services import visible_policies

from . import services
from .context import tabs
from .forms import (
    AssignForm,
    PreferenceForm,
    QuestionForm,
    QuestionnaireForm,
    TaskForm,
    TaskStatusForm,
)
from .models import (
    OPEN_TASK_STATUSES,
    Answer,
    Assignment,
    AssignmentStatus,
    Notification,
    TaskStatus,
)

STATUS_LABELS = dict(TaskStatus.choices)
BOARD_COLUMNS = [TaskStatus.TODO, TaskStatus.IN_PROGRESS, TaskStatus.BLOCKED, TaskStatus.DONE]


def _post_only(request: HttpRequest) -> None:
    if request.method != "POST":
        raise PermissionDenied("POST required")


def _safe_next(request: HttpRequest, fallback: str) -> str:
    target = request.POST.get("next") or request.GET.get("next") or ""
    if target and url_has_allowed_host_and_scheme(
        target, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return target
    return fallback


def _render(
    request: HttpRequest, template: str, ctx: dict[str, Any], tab: str = ""
) -> HttpResponse:
    ctx = {"tabs": tabs(request.user), "tab": tab, **ctx}
    return render(request, template, ctx)


def _apply_errors(form: Any, exc: Exception) -> None:
    if isinstance(exc, ValidationError) and hasattr(exc, "message_dict"):
        for field, errs in exc.message_dict.items():
            form.add_error(field if field in form.fields else None, errs)
    else:
        form.add_error(None, " ".join(getattr(exc, "messages", [str(exc)])))


# ----------------------------------------------------------------------------- my work
@access(AUTHENTICATED)
def my_work(request: HttpRequest) -> HttpResponse:
    user = request.user
    tasks = (
        services.visible_tasks(user)
        .filter(Q(assignees=user.pk), status__in=OPEN_TASK_STATUSES)
        .select_related("control", "risk", "finding")
        .order_by("due_on")
    )
    findings = (
        visible_findings(user)
        .filter(owner_id=user.pk, status__in=[FindingStatus.OPEN, FindingStatus.IN_PROGRESS])
        .order_by("due_on")
        if can(user, Cap.VIEW_FINDINGS)
        else Finding.objects.none()
    )
    assignments = (
        Assignment.objects.filter(respondent_id=user.pk)
        .exclude(status=AssignmentStatus.ACCEPTED)
        .select_related("questionnaire")
    )
    return _render(
        request,
        "work/my_work.html",
        {
            "tasks": tasks,
            "findings": findings,
            "assignments": assignments,
            "approvals": _approvals(user),
            "notifications": Notification.objects.filter(
                recipient_id=user.pk, read_at__isnull=True
            )[:10],
        },
        "mine",
    )


def _approvals(user: Any) -> dict[str, Any]:
    """What is waiting for this user's decision (never their own requests)."""
    out: dict[str, Any] = {}
    if can(user, Cap.APPROVE_CONTROL_CHANGES):
        out["changes"] = list(
            ControlChangeRequest.objects.filter(
                status=ChangeRequestStatus.PENDING, control__in=visible_controls(user)
            )
            .exclude(requested_by=user)
            .select_related("control", "requested_by")
        )
    if can(user, Cap.REVIEW_EVIDENCE):
        out["evidence"] = list(
            Evidence.objects.filter(
                review_status=EvidenceReview.PENDING,
                archived_at__isnull=True,
                control__in=visible_controls(user),
            )
            .exclude(uploaded_by=user)
            .select_related("control", "uploaded_by")
        )
    if can(user, Cap.APPROVE_EXCEPTION):
        out["exceptions"] = list(
            visible_exceptions(user)
            .filter(status=ExceptionStatus.REQUESTED)
            .exclude(created_by=user)
        )
    if can(user, Cap.APPROVE_POLICIES):
        out["policies"] = list(
            PolicyVersion.objects.filter(
                status=VersionStatus.IN_REVIEW, policy__in=visible_policies(user)
            )
            .exclude(author=user)
            .select_related("policy", "author")
        )
    if can(user, Cap.MANAGE_TASKS):
        out["questionnaires"] = list(
            services.visible_assignments(user)
            .filter(status=AssignmentStatus.SUBMITTED)
            .exclude(respondent=user)
            .select_related("questionnaire", "respondent")
        )
    out["total"] = sum(len(v) for v in out.values())
    return out


@access(AUTHENTICATED)
def approvals(request: HttpRequest) -> HttpResponse:
    data = _approvals(request.user)
    own_changes = ControlChangeRequest.objects.filter(
        requested_by_id=request.user.pk, status=ChangeRequestStatus.PENDING
    ).select_related("control")
    return _render(
        request, "work/approvals.html", {"a": data, "own_changes": own_changes}, "approvals"
    )


@access(Cap.REVIEW_EVIDENCE)
def evidence_review(request: HttpRequest, pk: int) -> HttpResponse:
    _post_only(request)
    evidence = get_object_or_404(
        Evidence.objects.select_related("control"),
        pk=pk,
        control__in=visible_controls(request.user),
    )
    try:
        control_services.review_evidence(
            evidence,
            user=request.user,
            accept=request.POST.get("decision") == "accept",
            note=request.POST.get("note", ""),
        )
    except control_services.ControlError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, f"Evidence “{evidence.title}” {evidence.review_status}.")
    return redirect(_safe_next(request, "/work/approvals/"))


@access(Cap.APPROVE_CONTROL_CHANGES)
def change_decide(request: HttpRequest, pk: int) -> HttpResponse:
    _post_only(request)
    cr = get_object_or_404(
        ControlChangeRequest.objects.select_related("control"),
        pk=pk,
        control__in=visible_controls(request.user),
    )
    try:
        control_services.decide_change(
            cr,
            user=request.user,
            approve=request.POST.get("decision") == "approve",
            note=request.POST.get("note", ""),
        )
    except control_services.ControlError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, f"{cr.control.ref} change {cr.status}.")
    return redirect("work:approvals")


@access(AUTHENTICATED)
def change_withdraw(request: HttpRequest, pk: int) -> HttpResponse:
    _post_only(request)
    cr = get_object_or_404(ControlChangeRequest, pk=pk, requested_by=request.user)
    try:
        control_services.withdraw_change(cr, user=request.user)
    except control_services.ControlError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, "Request withdrawn.")
    return redirect("work:approvals")


# ----------------------------------------------------------------------------- tasks
def _task(request: HttpRequest, ref: str) -> Any:
    return get_object_or_404(
        services.visible_tasks(request.user)
        .select_related(
            "control", "risk", "finding", "policy", "audit", "business_unit", "completed_by"
        )
        .prefetch_related("assignees"),
        ref__iexact=ref,
    )


@access(Cap.VIEW_TASKS)
def task_list(request: HttpRequest) -> HttpResponse:
    g = request.GET
    qs = services.visible_tasks(request.user).prefetch_related("assignees")
    status = g.get("status", "open")
    if status == "open":
        qs = qs.filter(status__in=OPEN_TASK_STATUSES)
    elif status in TaskStatus.values:
        qs = qs.filter(status=status)
    if g.get("mine") == "1":
        qs = qs.filter(Q(assignees=request.user.pk))
    return _render(
        request,
        "work/task_list.html",
        {
            "tasks": qs.order_by("due_on", "id")[:500],
            "status": status,
            "statuses": TaskStatus.choices,
            "mine": g.get("mine") == "1",
            "can_manage": services.can_manage(request.user),
        },
        "tasks",
    )


@access(Cap.VIEW_TASKS)
def board(request: HttpRequest) -> HttpResponse:
    from datetime import timedelta

    from django.utils import timezone

    qs = services.visible_tasks(request.user).prefetch_related("assignees")
    if request.GET.get("mine") == "1":
        qs = qs.filter(Q(assignees=request.user.pk))
    recent = timezone.now() - timedelta(days=14)
    qs = qs.filter(Q(status__in=OPEN_TASK_STATUSES) | Q(status="done", completed_at__gte=recent))
    tasks = list(qs.order_by("due_on", "id")[:400])
    columns = [
        (status, STATUS_LABELS[status], [t for t in tasks if t.status == status])
        for status in BOARD_COLUMNS
    ]
    return _render(
        request,
        "work/board.html",
        {
            "columns": columns,
            "mine": request.GET.get("mine") == "1",
            "can_manage": services.can_manage(request.user),
        },
        "board",
    )


@access(Cap.MANAGE_TASKS)
def task_form(request: HttpRequest, ref: str | None = None) -> HttpResponse:
    task = _task(request, ref) if ref else None
    if task is not None and not task.is_open:
        messages.error(request, "Closed tasks cannot be edited.")
        return redirect("work:task", task.ref)
    initial: dict[str, Any] = {}
    if task is None:
        if request.GET.get("control"):
            initial["control"] = (
                visible_controls(request.user).filter(ref__iexact=request.GET["control"]).first()
            )
        if request.GET.get("finding"):
            initial["finding"] = (
                visible_findings(request.user).filter(ref__iexact=request.GET["finding"]).first()
            )
    form = TaskForm(request.POST or None, instance=task, initial=initial, user=request.user)
    if request.method == "POST" and form.is_valid():
        data = dict(form.cleaned_data)
        assignees = data.pop("assignees")
        try:
            if task:
                task = services.update_task(task, user=request.user, data=data, assignees=assignees)
            else:
                task = services.create_task(user=request.user, data=data, assignees=assignees)
        except (ValidationError, services.WorkError) as exc:
            _apply_errors(form, exc)
        else:
            messages.success(request, f"Task {task.ref} saved.")
            return redirect("work:task", task.ref)
    return _render(request, "work/task_form.html", {"form": form, "task": task}, "tasks")


@access(AUTHENTICATED)
def task_detail(request: HttpRequest, ref: str) -> HttpResponse:
    task = _task(request, ref)
    user = request.user
    transitions: list[tuple[str, str]] = []
    if services.can_progress(user, task):
        transitions = [
            (s, STATUS_LABELS[s])
            for s in (TaskStatus.IN_PROGRESS, TaskStatus.BLOCKED, TaskStatus.DONE)
            if s != task.status
        ]
        if task.status != TaskStatus.TODO:
            transitions.insert(0, (TaskStatus.TODO, STATUS_LABELS[TaskStatus.TODO]))
    if services.can_manage(user) and task.is_open:
        transitions.append((TaskStatus.CANCELLED, STATUS_LABELS[TaskStatus.CANCELLED]))
    if services.can_manage(user) and not task.is_open:
        transitions.append((TaskStatus.TODO, "Reopen"))
    return _render(
        request,
        "work/task_detail.html",
        {
            "task": task,
            "transitions": transitions,
            "can_manage": services.can_manage(user),
            "next_occurrence": getattr(task, "next_occurrence", None),
        },
        "tasks",
    )


@access(AUTHENTICATED)
def task_status(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    task = _task(request, ref)
    form = TaskStatusForm(request.POST)
    if form.is_valid():
        try:
            services.set_task_status(
                task,
                user=request.user,
                status=form.cleaned_data["status"],
                note=form.cleaned_data["note"],
            )
        except services.WorkError as exc:
            messages.error(request, str(exc))
        else:
            messages.success(request, f"{task.ref} is now {task.get_status_display().lower()}.")
            nxt = type(task).objects.filter(previous=task).first()
            if nxt is not None and task.status == TaskStatus.DONE:
                messages.info(request, f"Next occurrence {nxt.ref} is due {nxt.due_on:%Y-%m-%d}.")
    return redirect(_safe_next(request, f"/work/tasks/{task.ref}/"))


# ----------------------------------------------------------------------------- comments
@access(Cap.COMMENT)
def comment_add(request: HttpRequest) -> HttpResponse:
    _post_only(request)
    label = request.POST.get("target", "")
    object_id = request.POST.get("object_id", "")
    fallback = "/"
    try:
        obj = services.commentable(request.user, label, object_id)
        fallback = services.detail_url(obj) or "/"
        services.add_comment(obj, user=request.user, body=request.POST.get("body", ""))
    except services.WorkError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, "Comment added.")
    return redirect(_safe_next(request, fallback) + "#comments")


# ----------------------------------------------------------------------------- notifications
@access(AUTHENTICATED)
def notifications(request: HttpRequest) -> HttpResponse:
    show_all = request.GET.get("all") == "1"
    qs = Notification.objects.filter(recipient_id=request.user.pk)
    if not show_all:
        qs = qs.filter(read_at__isnull=True)
    return _render(
        request,
        "work/notifications.html",
        {"notifications": qs.select_related("actor")[:200], "show_all": show_all},
        "",
    )


@access(AUTHENTICATED)
def notifications_read(request: HttpRequest) -> HttpResponse:
    _post_only(request)
    n = services.mark_read(request.user)
    messages.success(request, f"Marked {n} notification(s) as read.")
    return redirect("work:notifications")


@access(AUTHENTICATED)
def notification_open(request: HttpRequest, pk: int) -> HttpResponse:
    n = get_object_or_404(Notification, pk=pk, recipient=request.user)
    services.mark_read(request.user, [n.pk])
    target = n.url if n.url.startswith("/") and not n.url.startswith("//") else "/"
    return redirect(target)


@access(AUTHENTICATED)
def preferences(request: HttpRequest) -> HttpResponse:
    pref = services.preference(request.user)
    form = PreferenceForm(
        request.POST if request.method == "POST" else None,
        initial={"email_digest": pref.email_digest},
    )
    if request.method == "POST" and form.is_valid():
        services.set_preference(request.user, email_digest=form.cleaned_data["email_digest"])
        messages.success(request, "Notification preferences saved.")
        return redirect("work:preferences")
    return _render(request, "work/preferences.html", {"form": form}, "")


# ----------------------------------------------------------------------------- questionnaires
def _questionnaire(request: HttpRequest, ref: str) -> Any:
    return get_object_or_404(services.visible_questionnaires(request.user), ref__iexact=ref)


@access(Cap.VIEW_TASKS)
def questionnaire_list(request: HttpRequest) -> HttpResponse:
    return _render(
        request,
        "work/questionnaire_list.html",
        {
            "questionnaires": services.visible_questionnaires(request.user)
            .filter(archived_at__isnull=True)
            .prefetch_related("questions", "assignments"),
            "assignments": services.visible_assignments(request.user)
            .select_related("questionnaire", "respondent")
            .order_by("-created_at")[:100],
            "can_manage": services.can_manage(request.user),
        },
        "questionnaires",
    )


@access(Cap.MANAGE_TASKS)
def questionnaire_create(request: HttpRequest) -> HttpResponse:
    form = QuestionnaireForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            q = services.create_questionnaire(user=request.user, **form.cleaned_data)
        except (ValidationError, services.WorkError) as exc:
            _apply_errors(form, exc)
        else:
            return redirect("work:questionnaire", q.ref)
    return _render(request, "work/questionnaire_form.html", {"form": form}, "questionnaires")


@access(Cap.VIEW_TASKS)
def questionnaire_detail(request: HttpRequest, ref: str) -> HttpResponse:
    q = _questionnaire(request, ref)
    question_form = QuestionForm(prefix="q")
    assign_form = AssignForm(prefix="a", user=request.user)
    if request.method == "POST":
        if not services.can_manage(request.user):
            raise PermissionDenied("You cannot change questionnaires.")
        try:
            if request.POST.get("action") == "question":
                question_form = QuestionForm(request.POST, prefix="q")
                if question_form.is_valid():
                    services.add_question(
                        q, user=request.user, data=question_form.data_for_service()
                    )
                    messages.success(request, "Question added.")
                    return redirect("work:questionnaire", q.ref)
            elif request.POST.get("action") == "assign":
                assign_form = AssignForm(request.POST, prefix="a", user=request.user)
                if assign_form.is_valid():
                    data = dict(assign_form.cleaned_data)
                    people = data.pop("respondents")
                    sent = services.assign_questionnaire(
                        q, user=request.user, respondents=people, data=data
                    )
                    messages.success(request, f"Sent to {len(sent)} respondent(s).")
                    return redirect("work:questionnaire", q.ref)
        except (ValidationError, services.WorkError) as exc:
            target = question_form if request.POST.get("action") == "question" else assign_form
            _apply_errors(target, exc)
    return _render(
        request,
        "work/questionnaire_detail.html",
        {
            "q": q,
            "questions": q.questions.all(),
            "assignments": q.assignments.select_related("respondent"),
            "question_form": question_form,
            "assign_form": assign_form,
            "can_manage": services.can_manage(request.user),
            "locked": q.assignments.exclude(status=AssignmentStatus.ACCEPTED).exists(),
        },
        "questionnaires",
    )


def _assignment(request: HttpRequest, ref: str) -> Any:
    return get_object_or_404(
        services.visible_assignments(request.user).select_related(
            "questionnaire", "respondent", "control", "reviewed_by"
        ),
        ref__iexact=ref,
    )


@access(AUTHENTICATED)
def assignment_detail(request: HttpRequest, ref: str) -> HttpResponse:
    a = _assignment(request, ref)
    is_respondent = a.respondent_id == request.user.pk
    answers = {x.question_id: x for x in a.answers.all()}
    if request.method == "POST":
        if not is_respondent:
            raise PermissionDenied("Only the respondent can answer.")
        errors = []
        for question in a.questionnaire.questions.all():
            key = f"q{question.pk}"
            if key not in request.POST and f"{key}_file" not in request.FILES:
                continue
            try:
                services.save_answer(
                    a,
                    question,
                    user=request.user,
                    value=request.POST.get(key, ""),
                    comment=request.POST.get(f"{key}_comment", ""),
                    evidence_url=request.POST.get(f"{key}_url", ""),
                    upload=request.FILES.get(f"{key}_file"),
                )
            except (ValidationError, services.WorkError) as exc:
                errors.append(
                    f"{question.text[:60]}: {' '.join(getattr(exc, 'messages', [str(exc)]))}"
                )
        if errors:
            for e in errors:
                messages.error(request, e)
        elif request.POST.get("submit") == "1":
            try:
                services.submit_assignment(a, user=request.user)
            except services.WorkError as exc:
                messages.error(request, str(exc))
            else:
                messages.success(request, "Answers submitted for review.")
        else:
            messages.success(request, "Answers saved.")
        return redirect("work:assignment", a.ref)
    rows = [(q, answers.get(q.pk)) for q in a.questionnaire.questions.all()]
    return _render(
        request,
        "work/assignment_detail.html",
        {
            "a": a,
            "rows": rows,
            "is_respondent": is_respondent,
            "can_edit": is_respondent and a.editable_by_respondent,
            "can_review": services.can_manage(request.user)
            and not is_respondent
            and a.status == AssignmentStatus.SUBMITTED,
            "missing": services.missing_answers(a) if is_respondent else [],
        },
        "questionnaires",
    )


@access(Cap.MANAGE_TASKS)
def assignment_review(request: HttpRequest, ref: str) -> HttpResponse:
    _post_only(request)
    a = _assignment(request, ref)
    try:
        services.review_assignment(
            a,
            user=request.user,
            accept=request.POST.get("decision") == "accept",
            note=request.POST.get("note", ""),
        )
    except services.WorkError as exc:
        messages.error(request, str(exc))
    else:
        messages.success(request, f"{a.ref} {a.get_status_display().lower()}.")
    return redirect("work:assignment", a.ref)


@access(AUTHENTICATED)
def answer_file(request: HttpRequest, pk: int) -> FileResponse:
    answer = get_object_or_404(
        Answer.objects.select_related("assignment"),
        pk=pk,
        assignment__in=services.visible_assignments(request.user),
    )
    if not answer.file:
        raise PermissionDenied("No file.")
    from threatledger.audit.models import Action
    from threatledger.audit.services import record

    record(Action.EXPORT, answer, actor=request.user, object_repr=f"Answer file {answer.pk}")
    response = FileResponse(
        answer.file.open("rb"),
        as_attachment=True,
        filename=answer.original_filename or "answer",
        content_type=answer.content_type or "application/octet-stream",
    )
    response["X-Content-Type-Options"] = "nosniff"
    response["Content-Security-Policy"] = "default-src 'none'; sandbox"
    response["Cache-Control"] = "private, no-store"
    return response
