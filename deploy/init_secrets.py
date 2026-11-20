"""Generate deployment secrets on first start (docker compose ``init`` service).

Writes random values into the ``secrets`` volume only if they do not exist yet, so restarts
and upgrades keep the same keys. Nothing is printed. To rotate a secret, delete its file and
restart (rotating the Postgres password also needs ``ALTER ROLE``; see README).
"""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

SECRETS_DIR = Path(os.environ.get("SECRETS_DIR", "/srv/secrets"))


def write_once(name: str, value: str, mode: int) -> bool:
    path = SECRETS_DIR / name
    if path.exists():
        return False
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(value)
    os.chmod(path, mode)  # umask-independent
    return True


def main() -> int:
    if not SECRETS_DIR.is_dir():
        print(f"{SECRETS_DIR} is not a directory", file=sys.stderr)
        return 1
    created = []
    # Read only by the app (uid 10001).
    if write_once("django_secret_key", secrets.token_urlsafe(64), 0o600):
        created.append("django_secret_key")
    # Read by the postgres/redis containers too, which run as different uids. The volume is
    # mounted only into this stack's containers.
    if write_once("postgres_password", secrets.token_urlsafe(32), 0o644):
        created.append("postgres_password")
    redis_password = secrets.token_urlsafe(32)
    if write_once("redis_password", redis_password, 0o644):
        created.append("redis_password")
    else:
        redis_password = (SECRETS_DIR / "redis_password").read_text(encoding="utf-8").strip()
    if write_once("redis.conf", f"requirepass {redis_password}\nprotected-mode yes\n", 0o644):
        created.append("redis.conf")
    print(f"secrets: created {', '.join(created)}" if created else "secrets: already present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
