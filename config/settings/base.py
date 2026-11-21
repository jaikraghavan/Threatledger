"""Shared settings. Environment-specific modules (dev, test, prod) import from here.

Every secret is read from the environment (or from a ``<NAME>_FILE`` path, which is how the
docker-compose stack hands over generated secrets). Nothing secret is hard-coded.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import quote

import environ

BASE_DIR = Path(__file__).resolve().parent.parent.parent

env = environ.Env()
if (BASE_DIR / ".env").is_file():
    environ.Env.read_env(BASE_DIR / ".env")


def secret(name: str, default: str | None = None) -> str | None:
    """Return a secret from ``$NAME`` or the file named by ``$NAME_FILE``."""
    value = os.environ.get(name)
    if value:
        return value
    path = os.environ.get(f"{name}_FILE")
    if path and Path(path).is_file():
        return Path(path).read_text(encoding="utf-8").strip()
    return default


# ------------------------------------------------------------------ core
DEBUG = env.bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS: list[str] = env.list("DJANGO_ALLOWED_HOSTS", default=[])
CSRF_TRUSTED_ORIGINS: list[str] = env.list("DJANGO_CSRF_TRUSTED_ORIGINS", default=[])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "drf_spectacular",
    "django_htmx",
    "axes",
    "django_otp",
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_static",
    "django_q",
    "threatledger.core",
    "threatledger.org",
    "threatledger.accounts",
    "threatledger.audit",
    "threatledger.attack",
    "threatledger.controls",
    "threatledger.coverage",
    "threatledger.risks",
    "threatledger.frameworks",
    "threatledger.reporting",
    "threatledger.audits",
    "threatledger.findings",
    "threatledger.policies",
    "threatledger.work",
    "threatledger.vendors",
    "threatledger.privacy",
    "threatledger.incidents",
    "threatledger.api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "threatledger.core.middleware.RequestContextMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_otp.middleware.OTPMiddleware",
    "threatledger.core.middleware.UserContextMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "threatledger.accounts.middleware.IdleTimeoutMiddleware",
    "threatledger.accounts.middleware.MfaEnforcementMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "threatledger.core.middleware.SecurityHeadersMiddleware",
    "csp.middleware.CSPMiddleware",
    "django_htmx.middleware.HtmxMiddleware",
    "axes.middleware.AxesMiddleware",  # must be last (django-axes docs)
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "threatledger.core.context_processors.navigation",
            ],
        },
    },
]


# ------------------------------------------------------------------ database
def _database_url() -> str:
    """DATABASE_URL wins; otherwise build one from POSTGRES_* parts (compose stack)."""
    url = secret("DATABASE_URL")
    if url:
        return url
    host = os.environ.get("POSTGRES_HOST")
    if host:
        user = quote(os.environ.get("POSTGRES_USER", "threatledger"), safe="")
        password = quote(secret("POSTGRES_PASSWORD", "") or "", safe="")
        name = os.environ.get("POSTGRES_DB", "threatledger")
        port = os.environ.get("POSTGRES_PORT", "5432")
        return f"postgres://{user}:{password}@{host}:{port}/{name}"
    return f"sqlite:///{BASE_DIR / 'db.sqlite3'}"


DATABASES = {"default": env.db_url_config(_database_url())}
DATABASES["default"]["CONN_MAX_AGE"] = env.int("DB_CONN_MAX_AGE", default=60)
DATABASES["default"]["CONN_HEALTH_CHECKS"] = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


def _redis_url() -> str | None:
    url = secret("REDIS_URL")
    if url:
        return url
    host = os.environ.get("REDIS_HOST")
    if host:
        password = quote(secret("REDIS_PASSWORD", "") or "", safe="")
        auth = f":{password}@" if password else ""
        return f"redis://{auth}{host}:{os.environ.get('REDIS_PORT', '6379')}/0"
    return None


REDIS_URL = _redis_url()

if REDIS_URL:
    CACHES = {
        "default": {"BACKEND": "django.core.cache.backends.redis.RedisCache", "LOCATION": REDIS_URL}
    }
else:
    CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

# ------------------------------------------------------------------ background jobs (Django-Q2)
Q_CLUSTER: dict[str, object] = {
    "name": "threatledger",
    "workers": env.int("Q_WORKERS", default=2),
    "timeout": 1800,  # ATT&CK import can take several minutes
    "retry": 2100,  # must exceed timeout
    "max_attempts": 2,
    "catch_up": False,
    "label": "Background tasks",
}
if REDIS_URL:
    Q_CLUSTER["redis"] = REDIS_URL
else:
    Q_CLUSTER["orm"] = "default"

# ------------------------------------------------------------------ auth
AUTH_USER_MODEL = "accounts.User"
AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",  # lockout check first
    "django.contrib.auth.backends.ModelBackend",
]
LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "core:home"
LOGOUT_REDIRECT_URL = "accounts:login"

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ------------------------------------------------------------------ sessions & cookies
SESSION_COOKIE_AGE = env.int("SESSION_COOKIE_AGE", default=8 * 60 * 60)  # absolute lifetime
# Sign out after this many seconds without a request (0 disables).
SESSION_IDLE_TIMEOUT = env.int("SESSION_IDLE_TIMEOUT", default=30 * 60)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"

# ------------------------------------------------------------------ i18n
LANGUAGE_CODE = "en-gb"
TIME_ZONE = env.str("TIME_ZONE", default="UTC")
USE_I18N = True
USE_TZ = True

# ------------------------------------------------------------------ static & media
STATIC_URL = "/static/"
STATIC_ROOT = Path(env.str("STATIC_ROOT", default=str(BASE_DIR / "staticfiles")))
STATICFILES_DIRS = [BASE_DIR / "static"]
# Evidence lives here. It is NOT served by whitenoise/Caddy: only via permission-checked views.
MEDIA_ROOT = Path(env.str("MEDIA_ROOT", default=str(BASE_DIR / "media")))
EVIDENCE_ROOT = Path(env.str("EVIDENCE_ROOT", default=str(MEDIA_ROOT / "evidence")))
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    # Private: no base_url, never served directly; downloads go through a permission check.
    "evidence": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {"location": EVIDENCE_ROOT, "base_url": None, "file_permissions_mode": 0o640},
    },
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}
EVIDENCE_MAX_BYTES = env.int("EVIDENCE_MAX_BYTES", default=25 * 1024 * 1024)
# Uploads above this are streamed to a temp file instead of held in memory.
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024
DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024

# ------------------------------------------------------------------ REST framework
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "threatledger.api.authentication.ApiTokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": env.str("API_THROTTLE_ANON", default="30/hour"),
        "user": env.str("API_THROTTLE_USER", default="2000/hour"),
    },
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PERMISSION_CLASSES": [
        "threatledger.accounts.permissions.HasCapability",
    ],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
}

SPECTACULAR_SETTINGS = {
    "TITLE": "ThreatLedger API",
    "DESCRIPTION": "Threat-informed GRC: risks, ATT&CK coverage, controls and compliance. "
    "Authenticate with `Authorization: Bearer <token>` (create tokens under Account → API tokens).",
    "VERSION": "1",
    "SERVE_INCLUDE_SCHEMA": False,
    "SERVE_PERMISSIONS": ["rest_framework.permissions.IsAuthenticated"],
    "COMPONENT_SPLIT_REQUEST": True,
}

# ------------------------------------------------------------------ security headers
# Strict CSP: no inline scripts or styles anywhere (tests enforce this on templates).
CONTENT_SECURITY_POLICY = {
    "DIRECTIVES": {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "img-src": ["'self'", "data:"],
        "font-src": ["'self'"],
        "connect-src": ["'self'"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
        "frame-ancestors": ["'none'"],
    }
}
PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"

# ------------------------------------------------------------------ account lockout (django-axes)
AXES_ENABLED = env.bool("AXES_ENABLED", default=True)
AXES_FAILURE_LIMIT = env.int("AXES_FAILURE_LIMIT", default=5)
AXES_COOLOFF_TIME = env.int("AXES_COOLOFF_MINUTES", default=15) / 60  # hours
AXES_LOCKOUT_PARAMETERS = [["username", "ip_address"]]
AXES_RESET_ON_SUCCESS = True
AXES_LOCKOUT_TEMPLATE = "registration/locked_out.html"
AXES_CLIENT_IP_CALLABLE = "threatledger.core.context.axes_client_ip"
AXES_SENSITIVE_PARAMETERS = ["password", "otp_token", "token"]

# ------------------------------------------------------------------ MFA (django-otp, TOTP)
# Roles that must enrol in MFA before using the app (e.g. "admin,risk_manager"). Empty = optional.
MFA_REQUIRED_ROLES = env.list("MFA_REQUIRED_ROLES", default=[])
OTP_TOTP_ISSUER = env.str("OTP_TOTP_ISSUER", default="ThreatLedger")

# ------------------------------------------------------------------ backups
BACKUP_DIR = Path(env.str("BACKUP_DIR", default=str(BASE_DIR / "backups")))

# ------------------------------------------------------------------ audit
# "full" keeps the client IP (useful for investigations); "truncated" drops the last
# octet (IPv4) or the last 80 bits (IPv6) for privacy-sensitive deployments.
AUDIT_IP_MODE = env.str("AUDIT_IP_MODE", default="full")
# Only trust X-Forwarded-For when running behind our own reverse proxy (Caddy).
TRUST_X_FORWARDED_FOR = env.bool("TRUST_X_FORWARDED_FOR", default=False)

# ------------------------------------------------------------------ email
EMAIL_BACKEND = env.str("EMAIL_BACKEND", default="django.core.mail.backends.smtp.EmailBackend")
EMAIL_HOST = env.str("EMAIL_HOST", default="localhost")
EMAIL_PORT = env.int("EMAIL_PORT", default=587)
EMAIL_HOST_USER = env.str("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = secret("EMAIL_HOST_PASSWORD", "") or ""
EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS", default=True)
DEFAULT_FROM_EMAIL = env.str("DEFAULT_FROM_EMAIL", default="threatledger@localhost")
# Absolute base URL used in emails (no trailing slash).
SITE_URL = env.str("SITE_URL", default="http://localhost:8000")

# ------------------------------------------------------------------ logging
LOG_LEVEL = env.str("LOG_LEVEL", default="INFO")
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "request_context": {"()": "threatledger.core.logging.RequestContextFilter"},
        "scrub": {"()": "threatledger.core.logging.SensitiveDataFilter"},
    },
    "formatters": {
        "json": {"()": "threatledger.core.logging.JsonFormatter"},
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "filters": ["request_context", "scrub"],
        },
    },
    "root": {"handlers": ["console"], "level": LOG_LEVEL},
    "loggers": {
        "django.db.backends": {"level": "WARNING"},
        "django.security": {"level": "INFO"},
    },
}

# ------------------------------------------------------------------ ATT&CK
ATTACK_MAX_BUNDLE_BYTES = env.int("ATTACK_MAX_BUNDLE_BYTES", default=200 * 1024 * 1024)

# ------------------------------------------------------------------ app
THREATLEDGER_VERSION = "0.1.0"
# AGPL-3.0 §13: users interacting over a network must be offered the Corresponding Source.
# If you run a modified version, point this at the source of *your* version.
SOURCE_CODE_URL = env.str("SOURCE_CODE_URL", default="https://github.com/jaikraghavan/Threatledger")
