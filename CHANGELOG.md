# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Audits and campaigns:** compliance audits of a framework (optionally a baseline) for a business
  unit or the whole organisation. Auditors record a judgement, maturity (0–5), observation and
  evidence per requirement. The status derived from controls is suggested, kept with each judgement,
  and compared live, so disagreements are flagged. Workflow: planned → in progress → in review →
  closed (closed audits are frozen). Campaigns create one audit per perimeter and can recur
  quarterly, half-yearly or yearly. CSV export.
- **Findings:** severity, owner, due date (defaulted by severity), links to an audit requirement,
  control or risk; owners update remediation, and someone other than the owner verifies and closes.
- **Exceptions:** time-boxed (≤ 1 year) waivers of requirements or controls with compensating
  measures, approved by someone other than the requester, revocable, shown next to the derived
  status without changing it.
- **Policies:** policies, standards, procedures and guidelines with versions, approval by someone
  other than the author, supersession, periodic review dates and "reviewed, no changes".
- **Business-unit hierarchy:** admins manage nested units; scoping to a unit covers its sub-units.
- **Work management:** tasks and periodic checks (several assignees; links to a control, risk,
  finding, policy or audit; the next occurrence is created on completion; evidence-required checks
  need a note and new evidence on the linked control), a task board and list, and a "My work" page.
- **Questionnaires:** reusable templates (yes/no, choice, free text; required evidence) sent to any
  member (respondent mode), with validated private file or link evidence, submit, and review by
  someone other than the respondent.
- **Comments and @mentions** on risks, controls, findings, exceptions, audits, policies and tasks.
- **Notifications:** in-app centre with an unread badge, and a once-a-day email digest (opt-out).
- **Four-eyes workflow (optional, per organisation):** evidence review by someone other than the
  uploader, and approval of control owners' status changes before coverage and compliance change.
  One approvals queue for control changes, evidence, exceptions, policy versions and questionnaires.
- Tasks API (`/api/v1/tasks/`, PATCH `status` to complete).
- **Third-party risk:** vendors (tier, status, data access, ICT provider, substitutability, exit
  plan, LEI, external rating), services with supported functions, data locations and assets,
  contracts with notice deadlines and key clauses, links to risks and findings; posture by tier
  with derived assessment score, reassessment date (12/12/24/36 months by tier) and attention
  flags; contract-notice and reassessment items in the daily digest; vendors API.
- **External questionnaires:** vendors answer through a private, expiring, revocable link (token
  stored only as a hash, exchanged for a session, rate-limited); answers, uploads and review use
  the same rules as internal questionnaires.
- **DORA register of information** export (indicative Excel workbook: B_01.01, B_02.01, B_02.02,
  B_05.01, B_06.01).
- Dashboard governance KPIs; findings, exceptions and policies on control and requirement pages;
  API endpoints for audits, findings, exceptions and policies; demo data for all of the above.

### Changed
- **Roles:** the Auditor role is no longer read-only: auditors record audit judgements and raise
  findings, and still cannot change controls, risks or policies.
- **Licence:** ThreatLedger is now licensed under the GNU AGPL v3.0 or later (previously Apache-2.0;
  v0.1.0 remains available under Apache-2.0). Every page footer links to the source code, set with
  the new `SOURCE_CODE_URL` setting, as AGPL §13 requires for network use.

## [0.1.0] - 2026-11-21

First public release.

### Added
- **Foundation:** Django 5.2 app with role-based access (Admin, Risk Manager, Control Owner, Auditor,
  Viewer), deny-by-default views, business-unit scoping, an immutable hash-chained audit log, health
  checks, JSON logging with secret scrubbing, and a Docker Compose stack (PostgreSQL 16, Redis, worker,
  Caddy HTTPS) with generated secrets.
- **ATT&CK:** idempotent import of Enterprise ATT&CK STIX 2.1 (download or offline file). Revoked and
  deprecated objects are flagged with replacements and never deleted. Includes a technique browser,
  technique and group pages, and the v18+ detection-strategy model.
- **Risk register:** configurable matrix, inherent and residual heatmaps, score history, technique and
  control linking with live coverage, suggested controls, one-click remap of revoked techniques, risk
  acceptance with segregation of duties and expiry, review reminders, and CSV/Excel export safe against
  formula injection.
- **Controls & evidence:** control library, a 14-control starter set with indicative ATT&CK mitigation
  mappings, validated private evidence uploads, expiry alerts, and testing records.
- **Frameworks & compliance:** NIST SP 800-53 r5 (full text from OSCAL, with baselines), ISO/IEC
  27001:2022 Annex A, SOC 2 TSC, HIPAA Security Rule, CIS Controls v8 and India DPDP Act 2023. Adds a
  framework importer (JSON/YAML/CSV), derived requirement status, gap views, the cross-framework view,
  and CTID ATT&CK↔NIST mappings.
- **Coverage & reporting:** ATT&CK coverage matrix (risks, all, threat group or sector scope),
  Navigator layer 4.5 export, executive dashboard, printable board report, and daily trend snapshots.
- **API & hardening:** REST API v1 with hashed personal tokens, OpenAPI schema and self-hosted docs,
  rate limiting, strict CSP and security headers, idle and absolute session timeouts, account lockout,
  optional or role-enforced TOTP MFA with recovery codes, checksummed backup/restore, demo data
  (`seed_demo`) and a 1,000-risk performance check (`perf_check`).
- **Docs & tooling:** README with screenshots generated by `scripts/screenshots.py` (Playwright,
  dev-only), which also fails on browser console errors and CSP violations; SECURITY.md with a threat
  model, CONTRIBUTING.md.

[Unreleased]: https://github.com/jaikraghavan/Threatledger/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jaikraghavan/Threatledger/releases/tag/v0.1.0
