# syntax=docker/dockerfile:1.7
ARG PYTHON_IMAGE=python:3.12-slim-bookworm

# ---------------------------------------------------------------- CSS (Tailwind standalone CLI; no Node.js)
FROM debian:bookworm-slim AS css
ARG TAILWIND_VERSION=4.1.11
ARG TARGETARCH
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) arch=x64;   sum=64805b84af4292e043ea6f86d242f191c0ac75359c1a498455dfe6c642afdbab ;; \
      arm64) arch=arm64; sum=0409aa4222969f47fa6f4160fe5387e79bf7269e7afe0e8b22f7532c98e1d314 ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/v${TAILWIND_VERSION}/tailwindcss-linux-${arch}"; \
    echo "${sum}  /usr/local/bin/tailwindcss" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/tailwindcss
WORKDIR /src
COPY assets assets
COPY templates templates
COPY threatledger threatledger
RUN tailwindcss -i assets/tailwind/app.css -o static/css/app.css --minify

# ---------------------------------------------------------------- Python dependencies
FROM ${PYTHON_IMAGE} AS builder
COPY --from=ghcr.io/astral-sh/uv:0.13.9 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# ---------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    DJANGO_SETTINGS_MODULE=config.settings.prod \
    STATIC_ROOT=/app/staticfiles \
    MEDIA_ROOT=/srv/media \
    BACKUP_DIR=/srv/backups

# PostgreSQL 16 client tools (pg_dump/pg_restore must match the server major version) from
# the official PGDG repository; the signing key's fingerprint is pinned and checked.
ARG PGDG_KEY_FPR=B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg; \
    curl -fsSL -o /tmp/pgdg.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc; \
    fpr="$(gpg --show-keys --with-colons /tmp/pgdg.asc | awk -F: '/^fpr:/ {print $10; exit}')"; \
    test "$fpr" = "$PGDG_KEY_FPR"; \
    gpg --dearmor -o /usr/share/keyrings/pgdg.gpg /tmp/pgdg.asc; \
    echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" > /etc/apt/sources.list.d/pgdg.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends postgresql-client-16; \
    apt-get purge -y curl gnupg; apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/* /tmp/pgdg.asc /root/.gnupg

# /srv/secrets is 0711: postgres/redis (other uids) may open their known password files but
# cannot list the directory; the Django key file itself is 0600 (see deploy/init_secrets.py).
RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid app --no-create-home --home-dir /app --shell /usr/sbin/nologin app \
 && mkdir -p /srv/media /srv/secrets /srv/backups \
 && chown app:app /srv/media /srv/secrets /srv/backups \
 && chmod 0750 /srv/media /srv/backups \
 && chmod 0711 /srv/secrets

COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=root:root . .
COPY --from=css --chown=root:root /src/static/css/app.css static/css/app.css

# collectstatic needs settings to load; a throwaway random key is generated for this step only.
RUN DJANGO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')" \
    DJANGO_ALLOWED_HOSTS=build \
    python manage.py collectstatic --noinput \
 && chmod 0755 deploy/entrypoint.sh

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"]
ENTRYPOINT ["/app/deploy/entrypoint.sh"]
CMD ["web"]
