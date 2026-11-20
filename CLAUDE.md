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
- Test bundles: `threatledger/attack/tests/bundles.py` (`bundle_v1`/`bundle_v2`). Use `test_importer._load()` to load one in a fixture.
- Django admin is **superuser-only** break-glass. Everyday admin features belong in the app, behind `can()`.
- Settings: `config.settings.dev` (manage.py default), `.test` (pytest), `.prod` (wsgi/Docker; fails closed).
- Templates: Django + HTMX. HTMX partials are `_name.html`, chosen when `request.htmx`. Body sets the CSRF
  header for HTMX. Avoid inline `<script>` because a strict CSP arrives in Phase 7.
- Tests: pytest, fixtures in root `conftest.py` (`org`, `users`, `make_user`, `client_for(Role.X)`).
  Mark Postgres-only tests with `@pytest.mark.postgres` plus a vendor `skipif`.
- Ruff line length is 100. Keep mypy clean. Ask before adding any dependency not listed in PLAN.md §10.
