"""
P1-T1 scaffold smoke tests.
Verify settings load, URL routing works, and no secret material is reachable
from the settings module itself.
"""

from django.conf import settings
from django.test import TestCase


class SettingsTest(TestCase):
    def test_debug_is_bool(self):
        assert isinstance(settings.DEBUG, bool)

    def test_secret_key_not_blank(self):
        assert settings.SECRET_KEY

    def test_database_engine_is_postgresql(self):
        assert settings.DATABASES["default"]["ENGINE"] == "django.db.backends.postgresql"

    def test_session_cookie_httponly(self):
        assert settings.SESSION_COOKIE_HTTPONLY is True

    def test_session_cookie_samesite(self):
        assert settings.SESSION_COOKIE_SAMESITE == "Strict"

    def test_idle_lock_seconds_positive(self):
        assert settings.LLAVERO_IDLE_LOCK_SECONDS > 0

    def test_stepup_window_seconds_positive(self):
        assert settings.LLAVERO_STEPUP_WINDOW_SECONDS > 0

    def test_no_django_admin_in_installed_apps(self):
        # We intentionally omit Django's built-in admin (replaced in P1-T15).
        assert "django.contrib.admin" not in settings.INSTALLED_APPS

    def test_no_django_auth_in_installed_apps(self):
        # Django's built-in User model is replaced by our operator model (P1-T2).
        assert "django.contrib.auth" not in settings.INSTALLED_APPS


class HealthEndpointTest(TestCase):
    def test_health_returns_200(self):
        response = self.client.get("/health/")
        assert response.status_code == 200
        assert response.content == b"ok"
