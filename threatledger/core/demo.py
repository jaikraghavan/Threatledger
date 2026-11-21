"""Demo data loader (data/demo/demo.yaml). Idempotent; everything goes through the services,
so the audit log, score history and segregation-of-duties rules apply as in real use."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from threatledger.accounts.models import User
from threatledger.attack.models import Technique
from threatledger.controls import services as control_services
from threatledger.controls.models import Control
from threatledger.org.models import BusinessUnit, Organisation

DEMO_FILE = Path(settings.BASE_DIR) / "data" / "demo" / "demo.yaml"


@dataclass
class DemoReport:
    assets: int = 0
    risks: int = 0
    technique_links: int = 0
    missing_techniques: set[str] = field(default_factory=set)
    acceptances: int = 0
    evidence: int = 0
    tests: int = 0
    audits: int = 0
    findings: int = 0
    exceptions: int = 0
    policies: int = 0


def _days(n: int | None) -> Any:
    return None if n is None else timezone.localdate() + timedelta(days=n)


@transaction.atomic
def seed_demo(org: Organisation, path: Path = DEMO_FILE) -> DemoReport:
    from threatledger.frameworks.services import seed_frameworks
    from threatledger.reporting.services import take_snapshots
    from threatledger.risks import services as risk_services
    from threatledger.risks.models import Asset, Risk, RiskAcceptance

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    report = DemoReport()
    users = {u.username: u for u in User.objects.all()}
    rm, admin = users["riskmanager"], users["admin"]
    if org.name in ("Demo Organisation", ""):
        org.name = data["organisation"]
        org.save(update_fields=["name"])
    bus = {}
    for name in data["business_units"]:
        bus[name], _ = BusinessUnit.objects.get_or_create(organisation=org, name=name)

    for name, kind, bu, crit, cls, pii in data["assets"]:
        _, created = Asset.objects.get_or_create(
            organisation=org,
            name=name,
            defaults={
                "kind": kind,
                "business_unit": bus[bu],
                "criticality": crit,
                "data_classification": cls,
                "contains_personal_data": pii,
                "owner": rm,
            },
        )
        report.assets += int(created)
    assets = {a.name: a for a in Asset.objects.filter(organisation=org)}

    control_services.seed_starter_controls(org, user=admin)
    seed_frameworks(org)
    controls = {c.ref: c for c in Control.objects.filter(organisation=org)}
    today = timezone.localdate()
    for ref, (status, eff, owner_name, tested_ago, result) in data["controls"].items():
        c = controls.get(ref)
        if c is None or c.last_tested_at is not None:  # already set up (idempotent)
            continue
        c.status, c.effectiveness = status, eff
        c.owner = users.get(owner_name) if owner_name else None
        c.save(update_fields=["status", "effectiveness", "owner", "updated_at"])
        if tested_ago is not None and result:
            control_services.record_test(
                c,
                user=admin,
                tested_on=today - timedelta(days=tested_ago),
                method="inspection",
                result=result,
                notes="Demo test record.",
            )
            report.tests += 1
    for ref, title, url, valid in data["evidence"]:
        c = controls.get(ref)
        if c and not c.evidence.filter(title=title).exists():
            control_services.add_link_evidence(
                c, user=admin, url=url, title=title, valid_until=_days(valid)
            )
            report.evidence += 1

    techniques = {t.attack_id: t for t in Technique.objects.active()}
    existing = set(Risk.objects.filter(organisation=org).values_list("title", flat=True))
    for item in data["risks"]:
        if item["title"] in existing:
            continue
        risk = risk_services.create_risk(
            user=rm,
            data={
                "title": item["title"],
                "scenario": item["scenario"],
                "category": item["category"],
                "business_unit": bus[item["bu"]],
                "owner": users.get(item["owner"], rm),
                "inherent_likelihood": item["inherent"][0],
                "inherent_impact": item["inherent"][1],
                "residual_likelihood": item["residual"][0],
                "residual_impact": item["residual"][1],
                "treatment": item["treatment"],
                "status": "open" if item["status"] == "accepted" else item["status"],
                "target_date": _days(item.get("target")),
                "next_review_date": _days(item.get("review")),
            },
            assets=[assets[a] for a in item["assets"]],
            reason="Demo data",
        )
        report.risks += 1
        for tid in item["techniques"]:
            if tid in techniques:
                risk_services.link_technique(risk, techniques[tid], user=rm)
                report.technique_links += 1
            else:
                report.missing_techniques.add(tid)
        for ref in item["controls"]:
            if ref in controls:
                risk_services.link_control(risk, controls[ref], user=rm)
        if item.get("acceptance"):
            state, justification, expires = item["acceptance"]
            acc = risk_services.request_acceptance(
                risk, user=rm, justification=justification, expires_on=_days(expires)
            )
            if state == "approved":
                risk_services.decide_acceptance(
                    acc, user=admin, approve=True, note="Approved at risk committee (demo)."
                )
            report.acceptances += int(isinstance(acc, RiskAcceptance))
    seed_governance(org, data, users, bus, controls, report)
    take_snapshots(org)
    return report


def seed_governance(
    org: Organisation,
    data: dict[str, Any],
    users: dict[str, User],
    bus: dict[str, BusinessUnit],
    controls: dict[str, Control],
    report: DemoReport,
) -> None:
    """Phase 8: sub-units, an audit in progress, a campaign, findings, exceptions, policies."""
    from threatledger.audits import services as audit_services
    from threatledger.audits.models import Audit, Campaign
    from threatledger.findings import services as finding_services
    from threatledger.findings.models import Finding, SecurityException
    from threatledger.frameworks.models import Framework, Requirement
    from threatledger.policies import services as policy_services
    from threatledger.policies.models import Policy

    rm, admin, auditor = users["riskmanager"], users["admin"], users.get("auditor", users["admin"])
    for name, parent in data.get("sub_units", []):
        BusinessUnit.objects.get_or_create(
            organisation=org, name=name, defaults={"parent": bus[parent]}
        )
    frameworks = {f.code: f for f in Framework.objects.all()}

    def requirement(fw: Framework, ref: str) -> Requirement | None:
        return Requirement.objects.filter(framework=fw, ref=ref).first()

    iso = frameworks.get("ISO27001-2022")
    for item in data.get("audits", []):
        fw = frameworks.get(item["framework"])
        if fw is None or Audit.objects.filter(organisation=org, name=item["name"]).exists():
            continue
        audit = audit_services.create_audit(
            user=rm,
            data={
                "name": item["name"],
                "framework": fw,
                "lead_auditor": users.get(item.get("lead", "")),
                "due_on": _days(item.get("due")),
                "scope_note": item.get("scope", ""),
            },
        )
        for ref, judgement, maturity, observation in item.get("judgements", []):
            req = requirement(fw, ref)
            if req is not None:
                audit_services.record_judgement(
                    audit,
                    req,
                    user=auditor,
                    judgement=judgement,
                    maturity=maturity,
                    observation=observation,
                )
        if item.get("accept_suggestions"):
            audit_services.accept_suggestions(audit, user=auditor)
        report.audits += 1
    for item in data.get("campaigns", []):
        fw = frameworks.get(item["framework"])
        if fw is None or Campaign.objects.filter(organisation=org, name=item["name"]).exists():
            continue
        audit_services.create_campaign(
            user=rm,
            perimeters=[bus[p] for p in item["perimeters"]],
            data={
                "name": item["name"],
                "framework": fw,
                "starts_on": _days(item["starts"]),
                "due_on": _days(item["due"]),
                "recurrence": item.get("recurrence", "none"),
                "baseline": item.get("baseline", ""),
            },
        )
        report.audits += len(item["perimeters"])

    iso_audit = Audit.objects.filter(organisation=org, framework=iso).first() if iso else None
    for title, severity, owner, due, status, link in data.get("findings", []):
        if Finding.objects.filter(organisation=org, title=title).exists():
            continue
        fdata: dict[str, Any] = {
            "title": title,
            "severity": severity,
            "owner": users.get(owner),
            "due_on": _days(due),
            "remediation": "",
        }
        if link in controls:
            fdata["control"] = controls[link]
        elif iso_audit is not None and iso is not None:
            fdata.update(audit=iso_audit, requirement=requirement(iso, link))
        finding = finding_services.create_finding(user=auditor, data=fdata)
        if status in ("in_progress", "resolved"):
            owner_user = finding.owner or rm
            finding_services.update_finding(
                finding, user=owner_user, data={"remediation": "Remediation under way (demo)."}
            )
            finding_services.set_finding_status(finding, user=owner_user, status="in_progress")
            if status == "resolved":
                finding_services.set_finding_status(finding, user=owner_user, status="resolved")
        report.findings += 1

    for title, ref, why, compensating, expires, approved in data.get("exceptions", []):
        if SecurityException.objects.filter(organisation=org, title=title).exists():
            continue
        requester = controls[ref].owner or rm if ref in controls else rm
        exc = finding_services.request_exception(
            user=requester,
            controls=[controls[ref]] if ref in controls else [],
            data={
                "title": title,
                "justification": why,
                "compensating_measures": compensating,
                "expires_on": _days(expires),
            },
        )
        if approved:
            approver = admin if requester != admin else rm
            finding_services.decide_exception(
                exc, user=approver, approve=True, note="Approved at risk committee (demo)."
            )
        report.exceptions += 1

    for item in data.get("policies", []):
        if Policy.objects.filter(organisation=org, title=item["title"]).exists():
            continue
        policy = policy_services.create_policy(
            user=rm,
            data={"title": item["title"], "kind": item["kind"], "owner": rm},
            body=item["body"].strip(),
            controls=[controls[c] for c in item.get("controls", []) if c in controls],
        )
        version = policy.versions.get()
        status = item.get("status", "draft")
        if status in ("published", "overdue", "in_review"):
            policy_services.submit_version(version, user=rm)
        if status in ("published", "overdue"):
            policy_services.decide_version(version, user=admin, approve=True)
            if status == "overdue":  # approved 13 months ago: the annual review is overdue
                version.decided_at = timezone.now() - timedelta(days=400)
                version.effective_on = timezone.localdate() - timedelta(days=400)
                version.save(update_fields=["decided_at", "effective_on"])
        report.policies += 1
