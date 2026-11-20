# Contributing to ThreatLedger

Thanks for helping. Bug reports, framework content, mappings, docs and code are all welcome.

## Ground rules

- Be kind; assume good intent.
- **Security issues go to [SECURITY.md](SECURITY.md)**, not public issues.
- Do not contribute copyrighted framework text (ISO, AICPA, CIS, etc.) unless you hold the right to
  license it under Apache-2.0. Identifiers and short paraphrased titles are fine.
- Mappings you contribute are reviewed as *indicative*; cite your source in the PR.

## Development setup

```sh
# Python 3.12 and uv (https://docs.astral.sh/uv/) are required; Docker is optional.
make install        # creates .venv with all dependencies
make env            # writes .env with a random secret key
make run            # builds CSS, migrates, serves http://127.0.0.1:8000
uv run python manage.py seed_demo   # optional demo data (import ATT&CK first for technique links)
```

## Before you open a pull request

```sh
make check          # ruff (lint + format), mypy, pytest with ≥80 % coverage, bandit, pip-audit
```

If you change the UI, regenerate the README screenshots with `SCREENSHOT_PASSWORD=… make screenshots`
against a demo instance. The script also fails on browser console errors and CSP violations.

CI also runs the whole suite on PostgreSQL 16, builds the Docker image, scans it with Trivy and
smoke-tests `docker compose up` end to end.

## Conventions (summary; see [CLAUDE.md](CLAUDE.md) for details)

- **Every view declares `tl_access`** (a capability, `AUTHENTICATED` or a reviewed `PUBLIC`).
  The URL-sweep test fails otherwise.
- **Writes go through `services.py`**, which records audit events. Views and serializers never write
  models directly.
- **Derived values are never stored**: risk scores and bands, technique coverage, requirement status
  and compliance %.
- **No inline `<script>`, `style=` or event handlers** in templates (strict CSP; tests enforce it).
  Behaviour goes in `static/js/app.js`; chart data goes in `json_script` blocks.
- Add tests for every change; keep query counts bounded (`django_assert_max_num_queries`).
- New dependencies need a short justification in the PR.

## Commit messages

Imperative subject (≤ 72 chars), blank line, then *why* the change is needed. Reference issues with
`Fixes #123`.

## Licence

By contributing you agree that your contributions are licensed under the Apache License 2.0.
