from __future__ import annotations

from datetime import timedelta

import pytest
from django.core import mail
from django.core.exceptions import ValidationError
from django.utils import timezone

from threatledger.accounts.models import Membership
from threatledger.accounts.permissions import clear_role_cache
from threatledger.accounts.roles import Role
from threatledger.audit.models import Action, AuditEvent
from threatledger.org.models import BusinessUnit, Organisation
from threatledger.risks import services
from threatledger.risks.models import Band, Risk, RiskAcceptance, RiskMatrix, RiskStatus, Treatment

from .helpers import (
    BASE_SCORES,
    make_control,
    make_risk,
    map_direct,
    map_mitigation,
    mitigation,
    technique,
)

pytestmark = pytest.mark.django_db


@pytest.fixture
def rm(users):
    return users[Role.RISK_MANAGER]


# ----------------------------------------------------------------------------- matrix & scoring
class TestMatrix:
    def test_default_bands_match_brief(self, org):
        m = RiskMatrix.for_org(org)
        assert [m.band(s) for s in (1, 4, 5, 9, 10, 15, 16, 25)] == [
            Band.LOW, Band.LOW, Band.MEDIUM, Band.MEDIUM, Band.HIGH, Band.HIGH, Band.CRITICAL, Band.CRITICAL
        ]  # fmt: skip
        assert m.band_range(Band.HIGH) == (10, 15)
        assert m.band_range(Band.CRITICAL) == (16, 25)

    def test_configurable_thresholds(self, org, users):
        m = services.update_matrix(
            RiskMatrix.for_org(org),
            user=users[Role.ADMIN],
            data={"low_max": 3, "medium_max": 8, "high_max": 12},
        )
        assert m.band(4) is Band.MEDIUM
        assert m.band(13) is Band.CRITICAL
        assert AuditEvent.objects.filter(
            object_type="risks.riskmatrix", action=Action.UPDATE
        ).exists()

    @pytest.mark.parametrize(
        "data",
        [
            {"low_max": 9, "medium_max": 5},
            {"high_max": 25},
            {"size": 2},
            {"likelihood_labels": ["a", "b"]},
        ],
    )
    def test_invalid_matrix_rejected(self, org, users, data):
        with pytest.raises(ValidationError):
            services.update_matrix(RiskMatrix.for_org(org), user=users[Role.ADMIN], data=data)

    def test_cannot_shrink_below_existing_scores(self, org, users, rm):
        make_risk(rm)
        with pytest.raises(ValidationError, match="Existing risks use scores up to 5"):
            services.update_matrix(
                RiskMatrix.for_org(org),
                user=users[Role.ADMIN],
                data={"size": 4, "likelihood_labels": list("abcd"), "impact_labels": list("abcd"),
                      "low_max": 3, "medium_max": 6, "high_max": 10},
            )  # fmt: skip

    def test_only_admin_changes_matrix(self, org, rm):
        with pytest.raises(services.RiskError):
            services.update_matrix(RiskMatrix.for_org(org), user=rm, data={"low_max": 3})


# ----------------------------------------------------------------------------- create / update
class TestRiskLifecycle:
    def test_create_assigns_sequential_refs_history_and_audit(self, rm):
        r1, r2 = make_risk(rm), make_risk(rm, title="Second")
        assert (r1.ref, r2.ref) == ("R-0001", "R-0002")
        assert r1.inherent.value == 20 and r1.residual.value == 8
        assert r1.score_history.get().reason == "Initial assessment"
        created = AuditEvent.objects.get(action=Action.CREATE, object_id=str(r1.pk))
        assert created.changes["title"] == [None, "Ransomware via phishing"]
        assert created.actor == rm

    @pytest.mark.parametrize(
        ("scores", "field"),
        [
            ({"inherent_likelihood": 6}, "inherent_likelihood"),
            ({"residual_impact": 0}, "residual_impact"),
            ({"residual_likelihood": 5, "residual_impact": 5}, "residual_impact"),  # 25 > 20
        ],
    )
    def test_score_validation(self, rm, scores, field):
        with pytest.raises(ValidationError) as exc:
            make_risk(rm, **scores)
        assert field in exc.value.message_dict

    def test_update_records_history_only_when_scores_change(self, rm):
        risk = make_risk(rm)
        services.update_risk(risk, user=rm, data={"title": "Renamed"})
        assert risk.score_history.count() == 1
        services.update_risk(
            risk, user=rm, data={"residual_likelihood": 1}, reason="EDR rolled out"
        )
        latest = risk.score_history.all()[0]
        assert risk.score_history.count() == 2
        assert (latest.residual_likelihood, latest.reason, latest.changed_by) == (
            1,
            "EDR rolled out",
            rm,
        )
        event = AuditEvent.objects.filter(action=Action.UPDATE, object_id=str(risk.pk))[0]
        assert event.changes["residual_likelihood"] == [2, 1]
        assert event.changes["reason"] == [None, "EDR rolled out"]

    def test_asset_changes_audited(self, org, rm):
        from threatledger.risks.models import Asset

        a = Asset.objects.create(organisation=org, name="CRM")
        risk = make_risk(rm)
        services.update_risk(risk, user=rm, data={}, assets=[a])
        event = AuditEvent.objects.filter(action=Action.UPDATE, object_id=str(risk.pk))[0]
        assert event.changes["assets"] == [[], ["CRM"]]

    def test_viewer_and_auditor_cannot_edit(self, users, rm):
        risk = make_risk(rm)
        for role in (Role.VIEWER, Role.AUDITOR, Role.CONTROL_OWNER):
            with pytest.raises(services.RiskError):
                services.update_risk(risk, user=users[role], data={"title": "x"})

    def test_archive_and_restore(self, rm):
        risk = make_risk(rm)
        services.archive_risk(risk, user=rm)
        assert not Risk.objects.live().filter(pk=risk.pk).exists()
        with pytest.raises(services.RiskError):
            services.update_risk(risk, user=rm, data={"title": "x"})
        services.restore_risk(risk, user=rm)
        assert Risk.objects.live().filter(pk=risk.pk).exists()


# ----------------------------------------------------------------------------- BU scoping
class TestBusinessUnitScope:
    @pytest.fixture
    def units(self, org):
        return BusinessUnit.objects.create(
            organisation=org, name="Retail"
        ), BusinessUnit.objects.create(organisation=org, name="Payments")

    def _scope(self, user, *units):
        Membership.objects.get(user=user).business_units.set(units)
        clear_role_cache(user)
        for attr in ("_tl_bu_scope_cache",):
            if hasattr(user, attr):
                delattr(user, attr)

    def test_scoped_user_sees_and_edits_only_their_units(self, users, rm, units):
        retail, payments = units
        admin = users[Role.ADMIN]
        r_retail = make_risk(admin, business_unit=retail)
        r_pay = make_risk(admin, business_unit=payments)
        self._scope(rm, retail)
        assert list(services.visible_risks(rm)) == [r_retail]
        assert services.can_edit_risk(rm, r_retail)
        assert not services.can_edit_risk(rm, r_pay)
        with pytest.raises(services.RiskError, match="scoped"):
            make_risk(rm, business_unit=payments)

    def test_admin_is_never_scoped(self, users, units):
        admin = users[Role.ADMIN]
        Membership.objects.get(user=admin).business_units.set([units[0]])
        make_risk(admin, business_unit=units[1])
        assert services.visible_risks(admin).count() == 1

    def test_other_organisation_invisible(self, rm):
        other = Organisation.objects.create(name="Other plc")
        Risk.objects.create(
            organisation=other, ref="R-0001", title="x", scenario="x", **BASE_SCORES
        )
        assert services.visible_risks(rm).count() == 0


# ----------------------------------------------------------------------------- techniques & controls
class TestMappings:
    def test_link_and_unlink_technique(self, rm):
        risk, t = make_risk(rm), technique("T1566")
        assert services.link_technique(risk, t, user=rm) is True
        assert services.link_technique(risk, t, user=rm) is False  # idempotent
        link = risk.technique_links.get()
        services.unlink_technique(risk, link, user=rm)
        actions = list(
            AuditEvent.objects.filter(object_id=str(risk.pk)).values_list("changes", flat=True)
        )
        assert any("technique_added" in c for c in actions)
        assert any("technique_removed" in c for c in actions)

    def test_cannot_link_revoked_technique(self, rm):
        with pytest.raises(services.RiskError, match="revoked or deprecated"):
            services.link_technique(make_risk(rm), technique("T1086", is_revoked=True), user=rm)

    def test_remap_revoked_technique(self, rm):
        new = technique("T1059.001")
        old = technique("T1086")
        risk = make_risk(rm)
        services.link_technique(risk, old, user=rm)
        old.is_revoked, old.revoked_by = True, new
        old.save()
        replacement = services.remap_revoked_technique(risk, risk.technique_links.get(), user=rm)
        assert replacement == new
        assert list(risk.techniques.all()) == [new]

    def test_remap_merges_when_replacement_already_linked(self, rm):
        new, old = technique("T1059.001"), technique("T1086")
        risk = make_risk(rm)
        services.link_technique(risk, old, user=rm)
        services.link_technique(risk, new, user=rm)
        old.is_revoked, old.revoked_by = True, new
        old.save()
        services.remap_revoked_technique(risk, risk.technique_links.get(technique=old), user=rm)
        assert list(risk.techniques.all()) == [new]

    def test_remap_requires_replacement(self, rm):
        t = technique("T1000")
        risk = make_risk(rm)
        services.link_technique(risk, t, user=rm)
        with pytest.raises(services.RiskError, match="No active replacement"):
            services.remap_revoked_technique(risk, risk.technique_links.get(), user=rm)

    def test_link_control_same_org_only(self, org, rm):
        risk = make_risk(rm)
        assert services.link_control(risk, make_control(org, "CTL-1"), user=rm)
        other = Organisation.objects.create(name="Other")
        with pytest.raises(services.RiskError):
            services.link_control(risk, make_control(other, "X"), user=rm)
        services.unlink_control(risk, risk.control_links.get(), user=rm)
        assert not risk.controls.exists()

    def test_suggestions_rank_by_techniques_addressed(self, org, rm):
        t1, t2 = technique("T1566"), technique("T1204")
        risk = make_risk(rm)
        services.link_technique(risk, t1, user=rm)
        services.link_technique(risk, t2, user=rm)
        email = make_control(org, "EMAIL", status="partial")
        aware = make_control(org, "AWARE", status="implemented")
        linked = make_control(org, "LINKED")
        map_direct(email, t1)
        map_mitigation(aware, mitigation("M1017", t1, t2))
        map_direct(linked, t1)
        services.link_control(risk, linked, user=rm)
        suggestions = services.suggested_controls(risk)
        assert [s.control.ref for s in suggestions] == ["AWARE", "EMAIL"]
        assert [t.attack_id for t in suggestions[0].techniques] == ["T1204", "T1566"]

    def test_uncovered_mitigations(self, org, rm):
        t = technique("T1566")
        risk = make_risk(rm)
        services.link_technique(risk, t, user=rm)
        m_done, m_open = mitigation("M1049", t), mitigation("M1054", t)
        map_mitigation(make_control(org, "AV"), m_done)
        assert [m.attack_id for m, _ in services.uncovered_mitigations(risk)] == [m_open.attack_id]
        assert services.uncovered_mitigations(make_risk(rm)) == []


# ----------------------------------------------------------------------------- acceptance
class TestAcceptance:
    def _request(self, risk, user, days=90):
        return services.request_acceptance(
            risk, user=user, justification="Legacy system, isolated network.",
            expires_on=timezone.localdate() + timedelta(days=days),
        )  # fmt: skip

    def test_approve_requires_different_person_and_sets_status(self, users, rm, make_user):
        risk = make_risk(rm)
        acc = self._request(risk, rm)
        with pytest.raises(services.RiskError, match="Segregation of duties"):
            services.decide_acceptance(acc, user=rm, approve=True)
        approver = make_user(Role.RISK_MANAGER, username="approver")
        services.decide_acceptance(acc, user=approver, approve=True, note="OK for 90 days")
        risk.refresh_from_db()
        acc.refresh_from_db()
        assert acc.status == RiskAcceptance.Status.APPROVED and acc.is_active
        assert (risk.status, risk.treatment) == (RiskStatus.ACCEPTED, Treatment.ACCEPT)
        with pytest.raises(services.RiskError, match="already been decided"):
            services.decide_acceptance(acc, user=users[Role.ADMIN], approve=False)

    def test_reject_leaves_risk_unchanged(self, users, rm):
        risk = make_risk(rm)
        services.decide_acceptance(self._request(risk, rm), user=users[Role.ADMIN], approve=False)
        risk.refresh_from_db()
        assert risk.status == RiskStatus.OPEN

    def test_validation(self, rm, users):
        risk = make_risk(rm)
        with pytest.raises(services.RiskError, match="future"):
            self._request(risk, rm, days=0)
        with pytest.raises(services.RiskError, match="within 3 years"):
            self._request(risk, rm, days=2000)
        self._request(risk, rm)
        with pytest.raises(services.RiskError, match="already pending"):
            self._request(risk, rm)
        with pytest.raises(services.RiskError):
            services.decide_acceptance(
                risk.acceptances.get(), user=users[Role.AUDITOR], approve=True
            )

    def test_expiry_reopens_risk(self, users, rm):
        risk = make_risk(rm)
        acc = self._request(risk, rm, days=10)
        services.decide_acceptance(acc, user=users[Role.ADMIN], approve=True)
        assert services.expire_acceptances(timezone.localdate() + timedelta(days=5)) == 0
        assert services.expire_acceptances(timezone.localdate() + timedelta(days=11)) == 1
        risk.refresh_from_db()
        acc.refresh_from_db()
        assert acc.status == RiskAcceptance.Status.EXPIRED
        assert risk.status == RiskStatus.OPEN
        assert AuditEvent.objects.filter(action=Action.SYSTEM, object_id=str(risk.pk)).exists()


# ----------------------------------------------------------------------------- reminders
class TestReminders:
    def test_digest_per_owner_once_a_week(self, rm, users):
        today = timezone.localdate()
        make_risk(rm, owner=rm, next_review_date=today + timedelta(days=3))
        make_risk(rm, owner=rm, title="Overdue one", next_review_date=today - timedelta(days=1))
        make_risk(rm, owner=rm, next_review_date=today + timedelta(days=60))  # outside window
        make_risk(rm, owner=rm, status=RiskStatus.CLOSED, next_review_date=today)
        make_risk(rm, owner=users[Role.AUDITOR], next_review_date=today)
        assert services.send_review_reminders(today) == 2
        assert len(mail.outbox) == 2
        mine = next(m for m in mail.outbox if m.to == [rm.email])
        assert "2 risk review(s) due" in mine.subject
        assert "OVERDUE" in mine.body and "Overdue one" in mine.body
        assert "http://localhost:8000/risks/R-0002/" in mine.body
        assert services.send_review_reminders(today + timedelta(days=1)) == 0  # not again so soon
        assert services.send_review_reminders(today + timedelta(days=8)) == 2

    def test_skips_owners_without_email(self, rm):
        rm.email = ""
        rm.save()
        make_risk(rm, owner=rm, next_review_date=timezone.localdate())
        assert services.send_review_reminders() == 0

    def test_daily_task_and_schedule_registration(self):
        from django_q.models import Schedule

        from threatledger.risks.schedules import ensure_schedules
        from threatledger.risks.tasks import daily

        ensure_schedules()
        ensure_schedules()
        assert Schedule.objects.filter(name="risk-register-daily").count() == 1
        assert daily() == "expired=0 reminder_emails=0"
