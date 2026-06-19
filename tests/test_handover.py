"""P1-T18 acceptance + security-property tests (Annex D 8 chosen config; C 4.3b).

Brief acceptance criteria:
- the state machine moves pending -> granted / denied / expired / cancelled
- on auto-transfer the outgoing MK is wiped and work is saved as a draft
- the incoming admin unlocks with their own credentials
"""

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.operators import handover, sessions
from apps.operators.handover import HandoverError
from apps.operators.models import Operator, SessionRequestState
from apps.operators.sessions import current_master_key, is_vault_unlocked
from apps.vault.memory import MasterKeyLocked

MK_A = bytes(range(32))
MK_B = bytes(range(32, 64))
State = SessionRequestState


@pytest.fixture
def admin_a(db):
    return Operator.objects.create(
        username="a", display_name="A", role=Operator.Role.ADMINISTRATOR, password_hash="x"
    )


@pytest.fixture
def admin_b(db):
    return Operator.objects.create(
        username="b", display_name="B", role=Operator.Role.ADMINISTRATOR, password_hash="x"
    )


@pytest.fixture(autouse=True)
def _lock_after():
    yield
    sessions.lock_vault()


@pytest.fixture
def active_a(admin_a):
    session, _ = sessions.establish_session(operator=admin_a, ip="127.0.0.1", mk=bytearray(MK_A))
    return session


# --- state machine transitions --------------------------------------------


@pytest.mark.django_db
def test_request_creates_pending(active_a, admin_b):
    req = handover.request_access(requested_by=admin_b, current_session=active_a)
    assert req.state == State.PENDING
    assert req.expires_at > req.requested_at


@pytest.mark.django_db
def test_cannot_request_own_session(active_a, admin_a):
    with pytest.raises(HandoverError):
        handover.request_access(requested_by=admin_a, current_session=active_a)


@pytest.mark.django_db
def test_one_pending_request_at_a_time(active_a, admin_b):
    handover.request_access(requested_by=admin_b, current_session=active_a)
    with pytest.raises(HandoverError):
        handover.request_access(requested_by=admin_b, current_session=active_a)


@pytest.mark.django_db
def test_deny(active_a, admin_a, admin_b):
    req = handover.request_access(requested_by=admin_b, current_session=active_a)
    handover.deny(req, by=admin_a)
    req.refresh_from_db()
    assert req.state == State.DENIED
    assert req.resolved_by_id == admin_a.id


@pytest.mark.django_db
def test_cancel_by_requester(active_a, admin_a, admin_b):
    req = handover.request_access(requested_by=admin_b, current_session=active_a)
    with pytest.raises(HandoverError):
        handover.cancel(req, by=admin_a)  # only the requester may cancel
    handover.cancel(req, by=admin_b)
    req.refresh_from_db()
    assert req.state == State.CANCELLED


@pytest.mark.django_db
def test_expired_when_active_session_ended(active_a, admin_b):
    req = handover.request_access(requested_by=admin_b, current_session=active_a)
    active_a.revoke()  # A logs out before resolving
    handover.tick(req)
    req.refresh_from_db()
    assert req.state == State.EXPIRED


# --- release now + the 5 s lock -------------------------------------------


@pytest.mark.django_db
def test_release_is_locked_for_the_first_5s(active_a, admin_a, admin_b):
    req = handover.request_access(requested_by=admin_b, current_session=active_a)
    with pytest.raises(HandoverError):
        handover.release_now(req, by=admin_a, now=req.requested_at + timedelta(seconds=2))


@pytest.mark.django_db
def test_release_now_grants_wipes_mk_and_saves_draft(active_a, admin_a, admin_b):
    assert is_vault_unlocked()  # A holds the MK
    req = handover.request_access(requested_by=admin_b, current_session=active_a)
    saved = []
    handover.release_now(
        req,
        by=admin_a,
        now=req.requested_at + timedelta(seconds=6),
        draft_saver=lambda: saved.append(1),
    )
    req.refresh_from_db()
    assert req.state == State.GRANTED
    assert saved == [1]  # outgoing work saved as a draft
    assert not is_vault_unlocked()  # outgoing MK wiped
    with pytest.raises(MasterKeyLocked):
        current_master_key()
    active_a.refresh_from_db()
    assert active_a.revoked_at is not None


@pytest.mark.django_db
def test_only_active_admin_can_release(active_a, admin_b):
    req = handover.request_access(requested_by=admin_b, current_session=active_a)
    with pytest.raises(HandoverError):
        handover.release_now(req, by=admin_b, now=req.requested_at + timedelta(seconds=6))


# --- auto-transfer: idle 120 s and grace countdown ------------------------


@pytest.mark.django_db
def test_idle_auto_yield_after_120s(active_a, admin_a, admin_b):
    req = handover.request_access(requested_by=admin_b, current_session=active_a)
    # A has been idle for 121 s.
    active_a.last_activity_at = timezone.now() - timedelta(seconds=121)
    active_a.save(update_fields=["last_activity_at"])
    saved = []
    handover.tick(req, draft_saver=lambda: saved.append(1))
    req.refresh_from_db()
    assert req.state == State.GRANTED
    assert req.resolved_by is None  # system auto-transfer
    assert saved == [1]
    assert not is_vault_unlocked()


@pytest.mark.django_db
def test_grace_countdown_auto_transfers_at_zero(active_a, admin_b):
    req = handover.request_access(requested_by=admin_b, current_session=active_a)
    handover.tick(req, now=req.expires_at + timedelta(seconds=1))
    req.refresh_from_db()
    assert req.state == State.GRANTED
    assert not is_vault_unlocked()


@pytest.mark.django_db
def test_extend_pushes_the_grace_deadline(active_a, admin_a, admin_b):
    req = handover.request_access(requested_by=admin_b, current_session=active_a)
    before = req.expires_at
    handover.extend(req, by=admin_a)
    req.refresh_from_db()
    assert (req.expires_at - before).total_seconds() == 600
    # Just past the ORIGINAL deadline, with A still active (not idle): the extend
    # means no auto-transfer yet — neither grace (extended) nor idle (active).
    at = before + timedelta(seconds=1)
    active_a.last_activity_at = at  # A is actively working
    active_a.save(update_fields=["last_activity_at"])
    handover.tick(req, now=at)
    req.refresh_from_db()
    assert req.state == State.PENDING


# --- handover never transfers the key -------------------------------------


@pytest.mark.django_db
def test_incoming_admin_unlocks_with_own_credentials(active_a, admin_a, admin_b):
    req = handover.request_access(requested_by=admin_b, current_session=active_a)
    handover.release_now(req, by=admin_a, now=req.requested_at + timedelta(seconds=6))
    # No key was transferred: the vault is locked until B unlocks with their own MK.
    assert not is_vault_unlocked()
    sessions.establish_session(operator=admin_b, ip="127.0.0.2", mk=bytearray(MK_B))
    assert is_vault_unlocked()
    assert current_master_key() == MK_B  # B's own key, not A's
