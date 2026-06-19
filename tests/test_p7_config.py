"""P7-T4: Reauth window + idle auto-lock alignment assertions.

Verifies that the LLAVERO_ settings governing session lifecycle are within
the allowed ranges specified in Annex D 10 and that the handover grace period
is long enough to fit a full step-up window.
"""

import pytest
from django.conf import settings


@pytest.mark.django_db
class TestLlaveroSettingsAlignment:
    """Annex D 10 bounds — these are static assertions, no DB needed.

    Marked django_db so Django's settings fixture is fully initialised.
    """

    def test_stepup_window_lower_bound(self):
        assert settings.LLAVERO_STEPUP_WINDOW_SECONDS >= 60, (
            f"LLAVERO_STEPUP_WINDOW_SECONDS={settings.LLAVERO_STEPUP_WINDOW_SECONDS} "
            f"is below the 60-second minimum (Annex D 10)"
        )

    def test_stepup_window_upper_bound(self):
        assert settings.LLAVERO_STEPUP_WINDOW_SECONDS <= 300, (
            f"LLAVERO_STEPUP_WINDOW_SECONDS={settings.LLAVERO_STEPUP_WINDOW_SECONDS} "
            f"exceeds the 300-second maximum (Annex D 10)"
        )

    def test_idle_lock_lower_bound(self):
        assert settings.LLAVERO_IDLE_LOCK_SECONDS >= 300, (
            f"LLAVERO_IDLE_LOCK_SECONDS={settings.LLAVERO_IDLE_LOCK_SECONDS} "
            f"is below the 300-second minimum"
        )

    def test_idle_lock_upper_bound(self):
        assert settings.LLAVERO_IDLE_LOCK_SECONDS <= 3600, (
            f"LLAVERO_IDLE_LOCK_SECONDS={settings.LLAVERO_IDLE_LOCK_SECONDS} "
            f"exceeds the 3600-second maximum"
        )

    def test_handover_grace_fits_stepup_window(self):
        """The step-up reauth window must fit inside the handover grace period.

        If LLAVERO_HANDOVER_GRACE_SECONDS < LLAVERO_STEPUP_WINDOW_SECONDS an
        Administrator cannot complete a step-up challenge before the handover
        auto-transfers.
        """
        assert settings.LLAVERO_HANDOVER_GRACE_SECONDS >= settings.LLAVERO_STEPUP_WINDOW_SECONDS, (
            f"LLAVERO_HANDOVER_GRACE_SECONDS={settings.LLAVERO_HANDOVER_GRACE_SECONDS} "
            f"is less than LLAVERO_STEPUP_WINDOW_SECONDS={settings.LLAVERO_STEPUP_WINDOW_SECONDS}. "
            f"The step-up window must fit inside the handover grace period."
        )

    def test_handover_release_lock_is_5(self):
        actual = settings.LLAVERO_HANDOVER_RELEASE_LOCK_SECONDS
        assert actual == 5, (
            f"LLAVERO_HANDOVER_RELEASE_LOCK_SECONDS={actual} "
            f"must be exactly 5 (Annex D 8, handover docstring)"
        )
