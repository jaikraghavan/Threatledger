# Security policy

ThreatLedger stores some of an organisation's most sensitive information: its weaknesses, its
risk acceptances and its audit evidence. This document covers how to report vulnerabilities,
which versions are supported, and how the application protects itself.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

- Use GitHub's **private vulnerability reporting** on this repository
  (*Security → Report a vulnerability*).
- Include affected version or commit, steps to reproduce, impact, and any proof of concept.
- We aim to acknowledge reports within **3 working days** and to agree a fix and disclosure
  timeline within **14 days**. Critical issues are fixed first; we credit reporters unless they
  prefer otherwise.

Please test only against your own installation. Do not access other people's data or degrade
anyone's service.

## Supported versions

| Version | Supported |
|---|---|
| `main` / latest release | ✅ |
| older releases | ❌ (upgrade; migrations are forward-only) |

## Deployment checklist

- Run behind the bundled Caddy reverse proxy (TLS, HSTS) or an equivalent. Never expose gunicorn directly.
- Set `DOMAIN` so Caddy obtains a real certificate; keep `SECURE_SSL_REDIRECT` on.
- Keep the generated `secrets` Docker volume private and back it up separately from data backups.
- Enforce MFA for privileged roles: `MFA_REQUIRED_ROLES=admin,risk_manager`.
- Give the Django **admin** (superuser) account only to break-glass operators; daily administration
  happens in the app with role-based permissions.
- Schedule `manage.py backup` and test `manage.py restore` on a separate instance.
- Run `manage.py audit_verify` periodically; investigate any failure.
- Watch Dependabot / `pip-audit` / Trivy results from CI.

## Threat model (summary)

**Assets:** risk register and acceptances, control status, evidence files, audit log,
credentials/tokens, framework mappings.

**Actors:** anonymous internet users; authenticated users of each role (who may be curious or
malicious within their role); a compromised user account or API token; a malicious file uploader;
an operator with database access; a compromised upstream data source (ATT&CK/CTID).

| Threat (STRIDE) | Mitigation |
|---|---|
| **Spoofing:** credential stuffing, phishing | Argon2 hashing, 12-char minimum + common-password checks, lockout after 5 failures per username+IP (django-axes), optional/enforceable TOTP MFA with single-use recovery codes, idle (30 min) and absolute (8 h) session timeouts, session key rotation on login |
| **Spoofing:** stolen API token | Tokens are random 256-bit secrets, stored only as SHA-256, prefix lookup with constant-time compare, expiry (≤ 1 year), revocation, per-user rate limits, act only with the owner's role |
| **Tampering:** audit log edits | Append-only model/queryset guards, PostgreSQL trigger blocking UPDATE/DELETE/TRUNCATE, SHA-256 hash chain verified by `audit_verify` |
| **Tampering:** CSRF | Django CSRF on every form and HTMX request (token in `hx-headers`), SameSite cookies |
| **Tampering:** malicious data import | ATT&CK/CTID downloads only from allowlisted HTTPS URLs (re-checked after redirects), size caps, SHA-256 recorded; framework files validated before any write; YAML parsed with `safe_load` |
| **Repudiation** | Every write goes through a service that records actor, IP (proxy-aware), request ID and before/after values |
| **Information disclosure:** broken access control | Single capability matrix, deny-by-default (`tl_access` required on every view, enforced by a URL-sweep test), object-level checks (owners, business-unit scope), API uses the same checks |
| **Information disclosure:** evidence files | Extension allowlist plus content sniffing (no HTML/SVG/macros), random storage names outside the web root, permission-checked downloads served as attachments with `nosniff` and `CSP: sandbox`, every download audited |
| **Information disclosure:** XSS | Template auto-escaping, ATT&CK Markdown rendered by an escaping allowlist renderer, strict CSP (`script-src 'self'`, `style-src 'self'`, no inline scripts/styles: enforced by tests), HTMX `allowEval` off |
| **Information disclosure:** spreadsheet formula injection | Every exported text cell is neutralised; Excel cells are written as explicit strings |
| **Information disclosure:** logs | JSON logs with request IDs; a scrubber redacts passwords, tokens, cookies and URL credentials |
| **Denial of service** | Rate limits on the API, upload size caps (Caddy 30 MB, app 25 MB), bounded query counts per page (tested), import size caps |
| **Elevation of privilege** | Django admin is superuser-only; control owners can change only operational fields of their own controls; segregation of duties on risk acceptance; non-root, read-only containers with all capabilities dropped |
| **Supply chain** | Pinned, hashed lockfile; GitHub Actions pinned by commit SHA; vendored JS pinned with checksums; pip-audit, bandit and Trivy in CI; PostgreSQL client installed from PGDG with a pinned key fingerprint |

**Out of scope / residual risks:** a malicious superuser or database administrator can destroy data
(the hash chain makes audit tampering *detectable*, not impossible); seeded framework content and
mappings are indicative, not legal advice; backups contain sensitive data and must be protected by
whoever stores them.
