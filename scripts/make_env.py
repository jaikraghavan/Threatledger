"""Create .env from .env.example with a random DJANGO_SECRET_KEY. Never overwrites."""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    target = ROOT / ".env"
    if target.exists():
        print(".env already exists; leaving it alone")
        return 0
    lines = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    key = secrets.token_urlsafe(64)
    out = [
        f"DJANGO_SECRET_KEY={key}" if line.startswith("DJANGO_SECRET_KEY=") else line
        for line in lines
    ]
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out) + "\n")
    print("wrote .env (mode 600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
