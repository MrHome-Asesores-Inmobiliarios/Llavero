"""
Production settings — runs behind the internal nginx reverse proxy.
All values come from environment variables; nothing is hardcoded.
"""

from decouple import config

from .base import *  # noqa: F401, F403

SECRET_KEY = config("SECRET_KEY")

DEBUG = False

ALLOWED_HOSTS = config("ALLOWED_HOSTS", cast=lambda v: [h.strip() for h in v.split(",")])

# ---------------------------------------------------------------------------
# Security headers (proxy sets X-Forwarded-Proto = https)
# ---------------------------------------------------------------------------

USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = "DENY"

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_AGE = 43200  # 12 h hard maximum
CSRF_COOKIE_SECURE = True

# ---------------------------------------------------------------------------
# Logging — structured, no secret material, shipped to the separate host
# ---------------------------------------------------------------------------

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "format": (
                '{"time":"%(asctime)s","level":"%(levelname)s",'
                '"logger":"%(name)s","msg":%(message)s}'
            ),
        },
    },
    "handlers": {
        "file": {
            "class": "logging.handlers.WatchedFileHandler",
            "filename": config("LOG_FILE", default="/var/log/llavero/app.log"),
            "formatter": "json",
        },
    },
    "root": {
        "handlers": ["file"],
        "level": "WARNING",
    },
    "loggers": {
        "django": {
            "handlers": ["file"],
            "level": "WARNING",
            "propagate": False,
        },
        "django.db.backends": {
            "handlers": ["file"],
            "level": "ERROR",
            "propagate": False,
        },
        "llavero": {
            "handlers": ["file"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
