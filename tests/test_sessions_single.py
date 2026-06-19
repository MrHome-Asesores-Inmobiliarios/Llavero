"""P1-T16 acceptance + security-property tests (Annex D 2, 8; Annex C 4.3).

Brief acceptance criteria:
- two concurrent privileged sessions are impossible (race test)
- the Viewer session holds no MK and a forced reveal has nothing to decrypt with

A new login is advisory-lock guarded and revokes any prior active session. The
in-process master-key holder is unlocked only for an Administrator session; a
Viewer session leaves it locked (keyless by construction).
"""

import threading

import pytest
from django.db import connection, connections

from apps.operators import sessions
from apps.operators.models import Operator, OperatorSession
from apps.operators.sessions import SessionError, current_master_key, is_vault_unlocked
from apps.vault.memory import MasterKeyLocked

MK = bytes(range(32))


@pytest.fixture
def admin(db):
    return Operator.objects.create(
        username="admin", display_name="Admin", role=Operator.Role.ADMINISTRATOR, password_hash="x"
    )


@pytest.fixture
def viewer(db):
    return Operator.objects.create(
        username="viewer", display_name="Viewer", role=Operator.Role.VIEWER, password_hash="x"
    )


@pytest.fixture(autouse=True)
def _lock_vault_after():
    # Keep the process-global holder from leaking the MK across tests.
    yield
    sessions.lock_vault()


# --- a new login revokes the prior; only the token hash is stored ----------


@pytest.mark.django_db
def test_new_login_revokes_prior_session(admin):
    s1, t1 = sessions.establish_session(operator=admin, ip="127.0.0.1", mk=bytearray(MK))
    s2, t2 = sessions.establish_session(operator=admin, ip="127.0.0.2", mk=bytearray(MK))
    s1.refresh_from_db()
    assert s1.revoked_at is not None  # prior revoked
    assert s2.revoked_at is None
    assert OperatorSession.objects.filter(revoked_at__isnull=True).count() == 1
    # Only the token hash is stored, never the raw token.
    assert s2.token_hash != t2
    assert t1 != t2


# --- keyless Viewer --------------------------------------------------------


@pytest.mark.django_db
def test_viewer_session_holds_no_master_key(viewer):
    sessions.establish_session(operator=viewer, ip="127.0.0.1")
    assert not is_vault_unlocked()
    # A forced reveal path has nothing to decrypt with.
    with pytest.raises(MasterKeyLocked):
        current_master_key()


@pytest.mark.django_db
def test_admin_session_holds_master_key(admin):
    sessions.establish_session(operator=admin, ip="127.0.0.1", mk=bytearray(MK))
    assert is_vault_unlocked()
    assert current_master_key() == MK


@pytest.mark.django_db
def test_viewer_login_wipes_a_prior_admin_master_key(admin, viewer):
    sessions.establish_session(operator=admin, ip="127.0.0.1", mk=bytearray(MK))
    assert is_vault_unlocked()
    # A Viewer logging in supersedes the admin session AND wipes the MK.
    sessions.establish_session(operator=viewer, ip="127.0.0.2")
    assert not is_vault_unlocked()
    with pytest.raises(MasterKeyLocked):
        current_master_key()


@pytest.mark.django_db
def test_admin_session_without_mk_is_refused(admin):
    with pytest.raises(SessionError):
        sessions.establish_session(operator=admin, ip="127.0.0.1")  # no mk supplied


@pytest.mark.django_db
def test_logout_revokes_and_wipes(admin):
    s, _ = sessions.establish_session(operator=admin, ip="127.0.0.1", mk=bytearray(MK))
    sessions.logout(s)
    s.refresh_from_db()
    assert s.revoked_at is not None
    assert not is_vault_unlocked()


# --- concurrency: two privileged sessions cannot both be active -----------


@pytest.mark.django_db(transaction=True)
def test_concurrent_logins_leave_one_active_session():
    # Several operators logging in at once must never leave two active sessions:
    # the advisory lock + revoke-prior serialise it.
    ops = [
        Operator.objects.create(
            username=f"a{i}",
            display_name=f"A{i}",
            role=Operator.Role.ADMINISTRATOR,
            password_hash="x",
        )
        for i in range(6)
    ]
    errors = []

    def worker(op):
        try:
            sessions.establish_session(operator=op, ip="127.0.0.1", mk=bytearray(MK))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=worker, args=(op,)) for op in ops]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    try:
        assert not errors, errors
        # Exactly one active session survives, no matter the interleaving.
        assert OperatorSession.objects.filter(revoked_at__isnull=True).count() == 1
        assert OperatorSession.objects.count() == 6
    finally:
        sessions.lock_vault()
        OperatorSession.objects.all().delete()
        connection.close()
