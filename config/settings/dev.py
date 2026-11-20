"""Local development. Never use in production."""

import logging

from django.core.management.utils import get_random_secret_key

from .base import *  # noqa: F403
from .base import env, secret

DEBUG = env.bool("DJANGO_DEBUG", default=True)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])

_key = secret("DJANGO_SECRET_KEY")
if not _key:
    # A random per-process key: sessions reset on restart. Run `make env` to persist one.
    logging.getLogger(__name__).warning("DJANGO_SECRET_KEY not set; using an ephemeral key")
    _key = get_random_secret_key()
SECRET_KEY = _key

EMAIL_BACKEND = env.str("EMAIL_BACKEND", default="django.core.mail.backends.console.EmailBackend")
WHITENOISE_AUTOREFRESH = True
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "evidence": STORAGES["evidence"],  # noqa: F405
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}
