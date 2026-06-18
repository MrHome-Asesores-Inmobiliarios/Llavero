"""
Development settings — not for production.
Reads .env from the project root via python-decouple.
"""

from decouple import config

from .base import *  # noqa: F401, F403

SECRET_KEY = config(
    "SECRET_KEY",
    default="dev-insecure-key-change-before-any-production-use",
)

DEBUG = True

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]"]

# Relax session cookie for plain HTTP on localhost
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# Verbose logging to console — never log secret material
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        # Silence django.db.backends to avoid any chance of query params
        # (which could include secret material) appearing in logs.
        "django.db.backends": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}
