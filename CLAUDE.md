# ThreatLedger — notes for coding sessions

Threat-informed GRC platform: Risk → ATT&CK technique ← Control → Framework requirement.
The design lives in [PLAN.md](PLAN.md). Read it before changing models or scoring rules.

## Environment
- Python 3.12 and all dependencies are managed by **uv**. On this Mac uv lives at
  `~/Library/Python/3.9/bin/uv`, so run `export PATH="$HOME/Library/Python/3.9/bin:$PATH"` first.
- Local dev uses SQLite plus an in-memory cache, and Django-Q2 uses the ORM broker. CI runs tests on PostgreSQL 16.
- Docker is not installed locally yet, so the Docker build and the compose smoke test are verified in CI only.

## Commands
| Task | Command |
|---|---|
| Install deps | `make install` (`uv sync`) |
| Create `.env` with random key | `make env` |
| Build CSS (Tailwind standalone CLI, checksum-verified) | `make css`: source `assets/tailwind/app.css` → `static/css/app.css`. Keep the source out of `static/`, or prod `collectstatic` fails on `@import` |
| Dev server | `make run` → http://127.0.0.1:8000 |
| Seed org + one user per role | `make seed` (`SEED_PASSWORD=...` to set a shared password) |
| Background worker | `make worker` |
| Tests | `make test` · with coverage gate: `make cov` |
| Lint / format | `make lint` · `make fmt` |
| Types | `make typecheck` |
| Security | `make security` (bandit + pip-audit) |
| Everything CI runs (minus Docker) | `make check` |
| Verify audit hash chain | `uv run python manage.py audit_verify` |
| Full stack | `docker compose up -d --build`, then https://localhost |
| Import ATT&CK (latest / pinned / offline) | `uv run python manage.py import_attack` · `--version 20.1` · `--file bundle.json` (`--sha256`, `--allow-downgrade`, `--async`) |

## Conventions
- **Access control is deny-by-default.** Every view declares `tl_access` (`PUBLIC`, `AUTHENTICATED` or a
  `Cap`) via `AccessControlMixin`, `@access(...)`, or the DRF `HasCapability` permission. The test
  `tests/test_url_sweep.py` fails on any undeclared view, and new PUBLIC views must be added to its allowlist.
- **Roles → capabilities** are defined only in `threatledger/accounts/roles.py`. Check them with `can(user, Cap.X, obj)`,
  or `{% if user|can:"x" %}` in templates (`{% load tl %}`). `test_permissions.py::EXPECTED` mirrors the matrix,
  so update both together, deliberately.
- **Writes go through `services.py`** in each app. Services call `threatledger.audit.services.record()`;
  views and serializers never write audit events themselves. Use `snapshot()`/`diff()` for before/after values.
- **The audit log is immutable**: there are model and queryset guards, a Postgres trigger (migration
  `audit/0002`) and a hash chain. Never add UPDATE or DELETE paths. Users with history are deactivated, not deleted (FK is PROTECT).
- **Coverage, compliance % and scores are derived, never stored** (PLAN.md §4). Snapshots exist only for trends.
- **Secrets** come from env vars or `<NAME>_FILE`, via `config/settings/base.py:secret()`. Never hard-code them,
  and never log them (`core/logging.py` scrubs, but don't rely on it).
- **ATT&CK data is importer-owned** (`threatledger/attack`). Rows are matched by STIX id and never deleted. Revoked/deprecated
  objects are flagged and `Technique.revoked_by`/`replacement()` point to the successor. User mappings (risk/control ↔ technique)
  must live in *other* apps, FK to `Technique` with `on_delete=PROTECT`, and never in the `*Technique` link tables the importer re-syncs.
  Use `Technique.objects.active()` for anything user-facing. Tactic order comes from `Tactic.order` (the matrix), never hard-coded:
  v19+ replaced Defense Evasion with Stealth plus Defense Impairment.
- **Risk register** (`threatledger/risks`): always fetch risks/assets through `services.visible_risks(user)` /
  `visible_assets(user)` (org + business-unit scope) and check `services.can_edit_risk()`; never `Risk.objects` in views.
  Scores are `L × I` from `RiskMatrix` (per org); bands via `matrix.band(score)`; never store scores or bands.
  Score changes go through `update_risk()` which writes `RiskScoreHistory`. Exports must use `exports.neutralise()`.
- **Coverage** (`threatledger/coverage`): `engine.py` is pure; `selectors.coverage_for(technique_ids, org_id)` loads
  the graph (direct control↔technique + control↔mitigation↔technique). Use it everywhere coverage is shown.
- **Controls** (`threatledger/controls`): permissions via `services.can_edit/can_edit_fully/can_upload/can_map`;
  owners are limited to `services.OWNER_FIELDS`. Evidence uploads must go through `uploads.validate_upload()` and
  `services.add_file_evidence()`; never serve evidence from MEDIA_URL. Download only via `controls:evidence_download`.
  Recurring jobs are registered in `threatledger/core/schedules.py` (`JOBS`).
- **Frameworks** (`threatledger/frameworks`): requirement status is derived (`compliance.py`), never stored; use
  `services.framework_result(fw, org)` / `requirement_state()`. Seeds live in `data/frameworks/` and are rebuilt by
  `scripts/build_nist_80053.py` and `scripts/seeds/build_seeds.py` (never hand-edit the NIST JSON). Always quote refs
  in YAML. Starter-control requirement mappings live in `data/controls/starter.yaml` under `requirements:`.
  Commands: `seed_frameworks`, `import_framework <file> [--dry-run]`, `import_ctid_mappings [--attack-version|--file]`.
- **Reporting/coverage**: dashboard = `reporting.views.dashboard_context()`; KPIs and snapshots in
  `reporting/services.py` (snapshots are for trends only). Matrix/Navigator in `coverage/matrix.py`.
  Charts: include `partials/_chart.html` with `id`/`data` (series dict with `labels` + `datasets`) and load
  `vendor/chart-4.6.1.umd.min.js` in `{% block head_scripts %}`. Never add inline `<script>` or `style=`.
- **API** (`threatledger/api`): DRF views declare `tl_access` (GET) and `tl_write_access` (writes); writes call the
  same services as the UI. Tokens: `api.models.ApiToken.issue()`; never store or log raw tokens.
- **Security middleware**: CSP is strict. Never add `'unsafe-inline'`; `accounts/tests/test_security.py` scans all
  templates for inline script/style/handlers. MFA enforcement and idle timeout live in `accounts/middleware.py` (after
  MessageMiddleware). Lockout: django-axes (AUTHENTICATION_BACKENDS must keep Axes first).
- **Governance (Phase 8)**: `threatledger/audits` (Audit, Campaign, AuditResult; `scoring.py` is pure),
  `threatledger/findings` (Finding, SecurityException), `threatledger/policies` (Policy, PolicyVersion).
  Audit judgements are point-in-time records; the live status stays derived (`audit_rows()` compares
  them). Exceptions never alter derived status. Policy status/next review are derived (`policy_state()`).
  Segregation of duties: finding owners can't close their own finding; exception requesters and
  policy authors can't approve their own. Refs come from `core.refs.next_ref()` (A-, C-, F-, EX-, POL-).
  BU scope includes sub-units (`org.models.descendant_ids`).
- **Work (Phase 9)**: `threatledger/work` (Task, Comment, Notification, Questionnaire/Question/
  Assignment/Answer, UserPreference, DigestLog). Notify with `work.notify.notify(users, msg, url,
  actor=)` (lazy import from other apps); approvers via `users_with(org, Cap.X, bu_id)`. Comments
  via `{% load work %}{% comments obj %}`; add new commentable models to `services._registry()`.
  Org switches live in `Organisation.settings` (`org.workflow(key)`, `org.services.set_workflow`).
  `ControlChangeRequest` and evidence `review_status` live in `controls`; the control's status only
  changes on approval. Daily digest job: `work.tasks.daily`.
- **Vendors (Phase 10)**: `threatledger/vendors` (Entity, Solution, Contract; `postures()` derives
  score/reassessment/flags; `dora.py` builds the RoI workbook). External respondents are
  `work.Assignment` rows with `entity` + `external_email` and no `respondent`; access goes through
  `work.AccessLink` (hash only) and the PUBLIC views in `work/respond.py` (`/respond/`). Never put
  the raw token anywhere but the one-time link page/email; tokens travel as `?token=`.
- **Ops commands**: `backup`, `verify_backup`, `restore --force`, `seed_demo`, `perf_check --risks 1000`.
  Backups must run outside a DB transaction (tests use `django_db(transaction=True)`).
- Test helpers for risks/controls/techniques: `threatledger/risks/tests/helpers.py`.
- Test bundles: `threatledger/attack/tests/bundles.py` (`bundle_v1`/`bundle_v2`). Use `test_importer._load()` to load one in a fixture.
- Django admin is **superuser-only** break-glass. Everyday admin features belong in the app, behind `can()`.
- Settings: `config.settings.dev` (manage.py default), `.test` (pytest), `.prod` (wsgi/Docker; fails closed).
- Templates: Django + HTMX. HTMX partials are `_name.html`, chosen when `request.htmx`. Body sets the CSRF
  header for HTMX. Avoid inline `<script>` because a strict CSP arrives in Phase 7.
- Tests: pytest, fixtures in root `conftest.py` (`org`, `users`, `make_user`, `client_for(Role.X)`).
  Mark Postgres-only tests with `@pytest.mark.postgres` plus a vendor `skipif`.
- **Licence: AGPL-3.0-or-later** (v0.1.0 was Apache-2.0). Code adapted from CISO Assistant Community
  keeps intuitem's copyright notice and gets a NOTICE entry; never use its `enterprise/` directory.
  Framework libraries keep their own `copyright`/`provider` fields. Keep the footer source link
  (`SOURCE_CODE_URL`, AGPL §13). Roadmap to CISO Assistant parity: PLAN.md §12.
- Ruff line length is 100. Keep mypy clean. Ask before adding any dependency not listed in PLAN.md §10.
