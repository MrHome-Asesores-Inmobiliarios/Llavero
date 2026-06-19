"""P7-T3: Handover countdown polish tests.

Verifies that:
- color_state() returns "normal" / "amber" / "red" at the correct thresholds.
- is_release_locked() returns True for the first 5 seconds of the grace period.
"""

import pytest

from apps.operators.handover import color_state, is_release_locked

# ---------------------------------------------------------------------------
# color_state() thresholds
# ---------------------------------------------------------------------------


class TestColorState:
    def test_normal_above_60(self):
        assert color_state(61) == "normal"

    def test_normal_at_60(self):
        # Boundary: exactly 60 is still "normal" (< 60 triggers amber)
        assert color_state(60) == "normal"

    def test_amber_just_below_60(self):
        assert color_state(59.9) == "amber"

    def test_amber_at_30(self):
        assert color_state(30) == "amber"

    def test_amber_at_20(self):
        # Boundary: exactly 20 is still "amber" (< 20 triggers red)
        assert color_state(20) == "amber"

    def test_red_just_below_20(self):
        assert color_state(19.9) == "red"

    def test_red_at_10(self):
        assert color_state(10) == "red"

    def test_red_at_zero(self):
        assert color_state(0) == "red"

    def test_red_negative(self):
        # Overshoot: already expired, still red
        assert color_state(-1) == "red"

    def test_large_value_is_normal(self):
        assert color_state(300) == "normal"

    def test_exactly_59_is_amber(self):
        assert color_state(59) == "amber"

    def test_exactly_19_is_red(self):
        assert color_state(19) == "red"


# ---------------------------------------------------------------------------
# is_release_locked() — first 5 seconds of grace period
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestIsReleaseLocked:
    """is_release_locked reads settings.LLAVERO_HANDOVER_RELEASE_LOCK_SECONDS (default 5)."""

    def test_locked_at_zero_elapsed(self):
        assert is_release_locked(0.0) is True

    def test_locked_at_one_second(self):
        assert is_release_locked(1.0) is True

    def test_locked_at_four_point_nine(self):
        assert is_release_locked(4.9) is True

    def test_boundary_at_exactly_5(self):
        # grace_elapsed_seconds == release_lock_seconds: NOT locked (>= not <)
        assert is_release_locked(5.0) is False

    def test_unlocked_after_5(self):
        assert is_release_locked(5.1) is False

    def test_unlocked_well_after_5(self):
        assert is_release_locked(60.0) is False


# ---------------------------------------------------------------------------
# Integration: color_state + is_release_locked describe the full countdown bar
# ---------------------------------------------------------------------------


class TestCountdownBarCombined:
    """The countdown bar is: color from color_state, lock from is_release_locked.

    At t=0 grace elapsed, 300 s remaining: normal colour, release locked.
    At t=5 grace elapsed, 295 s remaining: normal colour, release unlocked.
    At t=241 grace elapsed, 59 s remaining: amber, release unlocked.
    At t=281 grace elapsed, 19 s remaining: red, release unlocked.
    """

    def test_start_of_grace(self):
        assert color_state(300) == "normal"
        assert is_release_locked(0) is True

    def test_just_after_lock_expires(self):
        assert color_state(295) == "normal"
        assert is_release_locked(5) is False

    def test_amber_zone(self):
        assert color_state(59) == "amber"
        assert is_release_locked(241) is False

    def test_red_zone(self):
        assert color_state(19) == "red"
        assert is_release_locked(281) is False
