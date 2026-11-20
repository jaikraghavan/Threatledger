#!/bin/sh
# Container entrypoint. Roles: web | worker | init-secrets | manage <args> | <any command>
set -eu

wait_for_database() {
  python - <<'PY'
import sys
import time

import django

django.setup()
from django.db import connection

for attempt in range(60):
    try:
        connection.ensure_connection()
        sys.exit(0)
    except Exception:
        time.sleep(1)
print("database not reachable after 60s", file=sys.stderr)
sys.exit(1)
PY
}

case "${1:-web}" in
  web)
    wait_for_database
    if [ "${RUN_MIGRATIONS:-1}" = "1" ]; then
      python manage.py migrate --noinput
    fi
    exec gunicorn config.wsgi:application \
      --bind 0.0.0.0:8000 \
      --workers "${GUNICORN_WORKERS:-3}" \
      --timeout "${GUNICORN_TIMEOUT:-60}" \
      --worker-tmp-dir /dev/shm \
      --access-logfile - \
      --access-logformat '{"remote":"%(h)s","method":"%(m)s","path":"%(U)s","status":%(s)s,"bytes":%(B)s,"ms":%(M)s,"request_id":"%({x-request-id}i)s"}'
    ;;
  worker)
    wait_for_database
    exec python manage.py qcluster
    ;;
  init-secrets)
    exec python deploy/init_secrets.py
    ;;
  manage)
    shift
    exec python manage.py "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
