# ThreatLedger

Open-source, threat-informed GRC platform. It links a risk register to MITRE ATT&CK techniques,
security controls and compliance framework requirements, so that changing one control updates threat
coverage, risk views and compliance percentages everywhere that control applies.

> **Status:** early development (Phase 1 of 7: foundation). The full README, with screenshots,
> configuration reference, architecture and a "How to use this for GRC" guide, arrives with Phase 7.
> See [PLAN.md](PLAN.md) for the roadmap.

## Quick start (Docker)

Requires only Docker with the Compose plugin.

```sh
git clone <this repo> threatledger && cd threatledger
docker compose up -d --build
docker compose exec web python manage.py createsuperuser
# or demo users, one per role:
docker compose exec web python manage.py seed --allow-production
```

Open https://localhost. Caddy uses its internal CA for `localhost`, so your browser will warn
until you trust it. To use a public name with automatic Let's Encrypt certificates, set `DOMAIN=your.host`
in `.env`.

Secrets (Django key, Postgres and Redis passwords) are generated on first start into the
`secrets` Docker volume and are never written to the repository.

## Load MITRE ATT&CK

```sh
docker compose exec web python manage.py import_attack                 # latest Enterprise release
docker compose exec web python manage.py import_attack --version 20.1  # pin a version
# air-gapped: download enterprise-attack-<ver>.json from github.com/mitre-attack/attack-stix-data
docker compose cp enterprise-attack-20.1.json web:/tmp/b.json
docker compose exec web python manage.py import_attack --file /tmp/b.json --sha256 <expected>
```

Admins can also start an import from **ATT&CK data** in the app, which runs on the background worker.
Re-importing is safe and idempotent. Techniques MITRE revokes are kept and flagged, with a pointer to
their replacement, so your mappings never break. Importing an older version over a newer one is refused
unless you pass `--allow-downgrade`.

## Local development

```sh
make install   # uv sync (installs Python 3.12 + deps)
make env       # .env with a random secret key
make run       # builds CSS, migrates, runs http://127.0.0.1:8000
make seed      # demo org + users
make check     # lint, types, tests with coverage gate, security scans
```

## Licence

Apache-2.0. See [LICENSE](LICENSE).
# Threatledger
