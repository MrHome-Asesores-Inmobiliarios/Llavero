"""P1-T17 acceptance + security-property tests (Annex D 6).

Brief acceptance criteria:
- reveal prompts every time (per-action, no caching)
- a windowed action reuses one step-up within the window, then re-prompts
- idle timeout wipes the MK and forces a full unlock next
"""

import pytest

from apps.operators import sessions, stepup
from apps.operators.models import Operator
from apps.operators.stepup import StepUp, StepUpRequired
from apps.vault.memory import MasterKeyLocked

MK = bytes(range(32))


@pytest.fixture
def admin(db):
    return Operator.objects.create(
        username="admin", display_name="Admin", role=Operator.Role.ADMINISTRATOR, password_hash="x"
    )


@pytest.fixture(autouse=True)
def _restore_holder():
    yield
    sessions.configure_holder()  # reset to a real-clock, locked holder


def _stepup(window=120.0):
    clock = {"t": 0.0}
    su = StepUp(window_seconds=window, clock=lambda: clock["t"])
    return su, clock


# --- per-action: reveal prompts every time --------------------------------


def test_reveal_requires_fresh_step_up_every_time():
    su, _ = _stepup()
    su.authorize(stepup.REVEAL, fresh_factor=True)  # ok with a fresh factor
    # Immediately after, a reveal without a fresh factor still prompts (no cache).
    with pytest.raises(StepUpRequired):
        su.authorize(stepup.REVEAL, fresh_factor=False)


@pytest.mark.parametrize(
    "action",
    [stepup.REVEAL, stepup.SECRET_CREATE, stepup.SECRET_ROTATE, stepup.CHECKPOINT_CREATE],
)
def test_per_action_never_caches(action):
    su, _ = _stepup()
    su.authorize(action, fresh_factor=True)
    with pytest.raises(StepUpRequired):
        su.authorize(action, fresh_factor=False)


# --- windowed: reuse within the window, then re-prompt --------------------


def test_windowed_reuses_one_step_up_then_reprompts():
    su, clock = _stepup(window=120.0)
    su.authorize(stepup.EXPORT, fresh_factor=True)  # opens the window
    clock["t"] = 60.0
    su.authorize(stepup.EXPORT, fresh_factor=False)  # within window: reused
    clock["t"] = 121.0  # window elapsed
    with pytest.raises(StepUpRequired):
        su.authorize(stepup.EXPORT, fresh_factor=False)


def test_windowed_step_up_covers_a_burst_of_admin_actions():
    su, clock = _stepup(window=120.0)
    su.authorize(stepup.OPERATOR_MANAGE, fresh_factor=True)  # one step-up...
    clock["t"] = 30.0
    su.authorize(stepup.PARAMETER_CHANGE, fresh_factor=False)  # ...covers the burst
    su.authorize(stepup.EXPORT, fresh_factor=False)


def test_per_action_step_up_does_not_open_a_window():
    su, _ = _stepup()
    su.authorize(stepup.REVEAL, fresh_factor=True)  # per-action, no window
    with pytest.raises(StepUpRequired):
        su.authorize(stepup.EXPORT, fresh_factor=False)


def test_unknown_action_rejected():
    su, _ = _stepup()
    with pytest.raises(ValueError):
        su.authorize("definitely_not_an_action", fresh_factor=True)


# --- idle auto-lock wipes the MK and forces a full unlock -----------------


@pytest.mark.django_db
def test_idle_autolock_wipes_mk_and_forces_full_unlock(admin):
    clock = {"t": 0.0}
    sessions.configure_holder(idle_seconds=60, clock=lambda: clock["t"])
    sessions.establish_session(operator=admin, ip="127.0.0.1", mk=bytearray(MK))
    assert sessions.is_vault_unlocked()
    assert sessions.current_master_key() == MK

    clock["t"] = 61.0  # idle window elapsed
    assert sessions.enforce_idle() is True  # MK wiped
    assert not sessions.is_vault_unlocked()
    with pytest.raises(MasterKeyLocked):
        sessions.current_master_key()  # nothing to decrypt with until full unlock

    # A full unlock (re-login with the MK) restores access.
    sessions.establish_session(operator=admin, ip="127.0.0.1", mk=bytearray(MK))
    assert sessions.current_master_key() == MK


@pytest.mark.django_db
def test_activity_postpones_idle(admin):
    clock = {"t": 0.0}
    sessions.configure_holder(idle_seconds=60, clock=lambda: clock["t"])
    sessions.establish_session(operator=admin, ip="127.0.0.1", mk=bytearray(MK))
    clock["t"] = 50.0
    sessions.touch()  # activity resets the idle clock
    clock["t"] = 100.0  # 50s since the touch (< 60)
    assert not sessions.enforce_idle()
    assert sessions.is_vault_unlocked()
