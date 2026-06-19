"""
Llavero base settings — shared by dev and production.
All environment-specific values live in dev.py or production.py.
"""

from pathlib import Path

from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

INSTALLED_APPS = [
    # Django internals — no built-in admin; operator model replaces auth.User
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.staticfiles",
    "django.contrib.postgres",  # ArrayField, native-type support
    # Llavero apps
    "apps.common",
    "apps.operators",
    "apps.inventory",
    "apps.relationships",
    "apps.vault",
    "apps.audit",
    "apps.backup",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "llavero.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
            ],
        },
    },
]

WSGI_APPLICATION = "llavero.wsgi.application"

# ---------------------------------------------------------------------------
# Database — PostgreSQL, scram-sha-256 auth configured in pg_hba.conf
# ---------------------------------------------------------------------------

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": config("DB_NAME", default="llavero"),
        "USER": config("DB_USER", default="llavero"),
        "PASSWORD": config("DB_PASSWORD"),
        "HOST": config("DB_HOST", default="127.0.0.1"),
        "PORT": config("DB_PORT", default="5432"),
        "OPTIONS": {
            # Enforce TLS on the DB connection in production via ssl=require.
            # Dev accepts the default (no TLS to localhost).
            "sslmode": config("DB_SSLMODE", default="prefer"),
        },
        "CONN_MAX_AGE": 60,
    }
}

# Django internal tables (migrations, sessions) use BigAutoField.
# Our domain models declare id = UUIDField(primary_key=True) explicitly (P1-T2).
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---------------------------------------------------------------------------
# Sessions — DB-backed; token hash stored, never the raw token (P1-T4)
# ---------------------------------------------------------------------------

SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"

# ---------------------------------------------------------------------------
# Internationalisation
# ---------------------------------------------------------------------------

LANGUAGE_CODE = "es-do"
TIME_ZONE = "America/Santo_Domingo"
USE_I18N = True
USE_TZ = True

# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "static_collected"
STATICFILES_DIRS = [BASE_DIR / "static"]

# ---------------------------------------------------------------------------
# Security spine constants (Phase 1)
# These are referenced by the crypto layer; never change without a migration.
# ---------------------------------------------------------------------------

LLAVERO_ARGON2_SCHEME_VERSION = 1
LLAVERO_NACL_SCHEME_VERSION = 1

# Vault second factor (Annex A 5.2, Annex G 4): "tpm" on the hardened server,
# "keyfile" as the fallback. The keyfile MUST live off the backup path with
# owner-only permissions; it holds the second factor only, never the MK.
LLAVERO_SECOND_FACTOR_MODE = config("SECOND_FACTOR_MODE", default="keyfile")
LLAVERO_KEYFILE_PATH = config("KEYFILE_PATH", default="")

# Idle auto-lock: seconds of inactivity before the MK is wiped from memory.
LLAVERO_IDLE_LOCK_SECONDS = config("IDLE_LOCK_SECONDS", default=900, cast=int)

# Step-up reauth window for bulk/export actions (~2 min, open point Annex D 10).
LLAVERO_STEPUP_WINDOW_SECONDS = config("STEPUP_WINDOW_SECONDS", default=120, cast=int)

# Session handover — hybrid B+C chosen config (Annex D 8).
LLAVERO_HANDOVER_IDLE_YIELD_SECONDS = config("HANDOVER_IDLE_YIELD_SECONDS", default=120, cast=int)
LLAVERO_HANDOVER_GRACE_SECONDS = config("HANDOVER_GRACE_SECONDS", default=300, cast=int)
LLAVERO_HANDOVER_EXTEND_SECONDS = config("HANDOVER_EXTEND_SECONDS", default=600, cast=int)
LLAVERO_HANDOVER_RELEASE_LOCK_SECONDS = config("HANDOVER_RELEASE_LOCK_SECONDS", default=5, cast=int)

# ---------------------------------------------------------------------------
# Backup (Phase 2, Annex H)
# ---------------------------------------------------------------------------

# Path where backup.sh writes its JSON result after every run.
LLAVERO_BACKUP_STATUS_PATH = config("BACKUP_STATUS_PATH", default="")

# Local directory holding the encrypted archive files (*.age).
LLAVERO_BACKUP_ARCHIVE_DIR = config(
    "BACKUP_ARCHIVE_DIR", default="/var/backups/llavero/archive"
)

# Hours after which a backup is considered overdue (default: 24 h + 2 h grace).
LLAVERO_BACKUP_OVERDUE_HOURS = config("BACKUP_OVERDUE_HOURS", default=26, cast=int)
