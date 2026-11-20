"""Test settings. SQLite by default; set DATABASE_URL to run against PostgreSQL (CI does)."""

import os

from django.core.management.utils import get_random_secret_key

from .base import *  # noqa: F403
from .base import BASE_DIR, REST_FRAMEWORK, env

DEBUG = False
SECRET_KEY = get_random_secret_key()
ALLOWED_HOSTS = ["testserver", "localhost"]

if os.environ.get("DATABASE_URL"):
    DATABASES = {"default": env.db_url("DATABASE_URL")}
else:
    DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
Q_CLUSTER = {
    "name": "threatledger-test",
    "orm": "default",
    "sync": True,
    "timeout": 60,
    "retry": 120,
}
WHITENOISE_AUTOREFRESH = True

# Fast hashing keeps the suite quick. Test-only; production uses Argon2.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
MEDIA_ROOT = BASE_DIR / ".test-media"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.InMemoryStorage"},
    "evidence": {"BACKEND": "django.core.files.storage.InMemoryStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}
LOGGING = {"version": 1, "disable_existing_loggers": False}

REST_FRAMEWORK = {
    **REST_FRAMEWORK,
    "DEFAULT_THROTTLE_RATES": {"anon": "1000/minute", "user": "10000/minute"},
}
BACKUP_DIR = BASE_DIR / ".test-backups"
