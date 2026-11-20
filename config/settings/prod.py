"""Production. Fails closed: missing secrets or hosts stop the process at startup."""

from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F403
from .base import env, secret

DEBUG = False

_key = secret("DJANGO_SECRET_KEY")
if not _key or len(_key) < 50:
    raise ImproperlyConfigured(
        "DJANGO_SECRET_KEY (or DJANGO_SECRET_KEY_FILE) must be set to a value of 50+ characters."
    )
SECRET_KEY = _key

ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=[])
if not ALLOWED_HOSTS:
    raise ImproperlyConfigured("DJANGO_ALLOWED_HOSTS must be set in production.")

# TLS terminates at Caddy, which sets X-Forwarded-Proto.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = env.bool("SECURE_SSL_REDIRECT", default=True)
SECURE_REDIRECT_EXEMPT = [r"^healthz$", r"^readyz$"]  # container healthchecks use plain HTTP
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = env.int("SECURE_HSTS_SECONDS", default=31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env.bool("SECURE_HSTS_INCLUDE_SUBDOMAINS", default=True)
SECURE_HSTS_PRELOAD = env.bool("SECURE_HSTS_PRELOAD", default=False)
# HSTS preload submits the domain to browser preload lists, which is very hard to undo, so it
# is a deliberate opt-in per deployment. Only that one check is silenced, only while it is off.
SILENCED_SYSTEM_CHECKS = [] if SECURE_HSTS_PRELOAD else ["security.W021"]
TRUST_X_FORWARDED_FOR = env.bool("TRUST_X_FORWARDED_FOR", default=True)
