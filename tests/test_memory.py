"""P1-T8 acceptance + security-property tests (Annex A 6, 7; Annex G 2).

Brief acceptance criteria:
- the buffer is zeroed after lock / idle / logout (asserted via a test hook)
- core dumps are off
- the MK never enters a Django session, cache, or log

Model A: the MK lives in mlock'd, zeroizable memory for the session; idle
auto-lock wipes it. We assert zeroization by reading the raw buffer through a
test-only snapshot hook, and assert the holder cannot be serialised (which is
how Django sessions/caches would persist it).
"""

import copy
import json
import os
import pickle
import uuid

import pytest

from apps.vault import crypto
from apps.vault.memory import (
    KeyBufferCleared,
    MasterKeyHolder,
    MasterKeyLocked,
    SecureBuffer,
    disable_core_dumps,
)

MK = bytes(range(32))  # includes 0x00..0x1f; distinct, non-trivial
ZEROS = b"\x00" * 32


# --- SecureBuffer ---------------------------------------------------------


def test_secure_buffer_round_trips_then_zeroizes_on_clear():
    buf = SecureBuffer(MK)
    assert buf.get() == MK
    buf.clear()
    assert buf.raw_snapshot() == ZEROS  # memory actually zeroed
    with pytest.raises(KeyBufferCleared):
        buf.get()


def test_secure_buffer_clear_is_idempotent():
    buf = SecureBuffer(MK)
    buf.clear()
    buf.clear()  # must not raise or unzero
    assert buf.raw_snapshot() == ZEROS


def test_secure_buffer_context_manager_clears_on_exit():
    with SecureBuffer(MK) as buf:
        assert buf.get() == MK
    assert buf.raw_snapshot() == ZEROS
    with pytest.raises(KeyBufferCleared):
        buf.get()


def test_secure_buffer_repr_does_not_leak_contents():
    buf = SecureBuffer(MK)
    text = repr(buf)
    assert MK.hex() not in text
    assert "SecureBuffer" in text
    buf.clear()


def test_secure_buffer_is_not_picklable():
    # Django sessions/caches persist via pickle; a key buffer must refuse.
    buf = SecureBuffer(MK)
    with pytest.raises((TypeError, pickle.PicklingError)):
        pickle.dumps(buf)
    buf.clear()


def test_secure_buffer_is_not_copyable():
    buf = SecureBuffer(MK)
    with pytest.raises(TypeError):
        copy.copy(buf)
    with pytest.raises(TypeError):
        copy.deepcopy(buf)
    buf.clear()


def test_secure_buffer_records_mlock_status_as_bool():
    buf = SecureBuffer(MK)
    # mlock/VirtualLock is best-effort; we only require the status be tracked.
    assert isinstance(buf.locked_in_ram, bool)
    buf.clear()


# --- MasterKeyHolder (Model A session vault) ------------------------------


def _holder(idle=100.0):
    clock = {"t": 0.0}
    h = MasterKeyHolder(idle_seconds=idle, clock=lambda: clock["t"])
    return h, clock


def test_holder_starts_locked():
    h, _ = _holder()
    assert not h.is_unlocked()
    with pytest.raises(MasterKeyLocked):
        h.get_master_key()


def test_holder_unlock_then_get():
    h, _ = _holder()
    h.unlock(bytearray(MK))
    assert h.is_unlocked()
    assert h.get_master_key() == MK


def test_holder_lock_zeroizes_buffer_and_blocks_access():
    h, _ = _holder()
    h.unlock(bytearray(MK))
    buf = h._buf  # capture to inspect after lock
    h.lock()
    assert not h.is_unlocked()
    assert buf.raw_snapshot() == ZEROS
    with pytest.raises(MasterKeyLocked):
        h.get_master_key()


def test_holder_idle_auto_lock_wipes_mk():
    h, clock = _holder(idle=60.0)
    h.unlock(bytearray(MK))
    buf = h._buf
    clock["t"] = 60.0  # reach the idle threshold
    assert not h.is_unlocked()
    with pytest.raises(MasterKeyLocked):
        h.get_master_key()
    assert buf.raw_snapshot() == ZEROS  # wiped, not merely flagged


def test_holder_use_postpones_idle():
    h, clock = _holder(idle=60.0)
    h.unlock(bytearray(MK))
    clock["t"] = 30.0
    assert h.get_master_key() == MK  # using the key touches activity
    clock["t"] = 80.0  # only 50s since last use (< 60)
    assert h.is_unlocked()
    assert h.get_master_key() == MK


def test_holder_enforce_idle_locks_when_expired():
    h, clock = _holder(idle=60.0)
    h.unlock(bytearray(MK))
    buf = h._buf
    clock["t"] = 61.0
    assert h.enforce_idle() is True  # now locked
    assert buf.raw_snapshot() == ZEROS


def test_holder_relock_on_new_unlock_clears_prior_key():
    h, _ = _holder()
    h.unlock(bytearray(MK))
    first = h._buf
    h.unlock(bytearray(b"\x01" * 32))
    assert first.raw_snapshot() == ZEROS
    assert h.get_master_key() == b"\x01" * 32


def test_holder_wipes_caller_bytearray_on_unlock():
    h, _ = _holder()
    mk = bytearray(MK)
    h.unlock(mk)
    # The caller's mutable copy is wiped; only the secured buffer retains it.
    assert bytes(mk) == ZEROS
    assert h.get_master_key() == MK


def test_holder_is_not_picklable_or_json_serialisable():
    h, _ = _holder()
    h.unlock(bytearray(MK))
    with pytest.raises((TypeError, pickle.PicklingError)):
        pickle.dumps(h)
    with pytest.raises(TypeError):
        json.dumps(h)
    h.lock()


# --- integration: the in-memory MK decrypts a sealed secret ---------------


def test_holder_master_key_decrypts_sealed_secret():
    h, _ = _holder()
    h.unlock(bytearray(crypto.generate_master_key()))
    owner_id = uuid.uuid4()
    row = crypto.seal(
        h.get_master_key(),
        owner_type="account",
        owner_id=owner_id,
        kind="password",
        plaintext=b"hunter2",
    )
    out = crypto.open_sealed(
        h.get_master_key(),
        owner_type="account",
        owner_id=owner_id,
        kind="password",
        ciphertext=row["ciphertext"],
        nonce=row["nonce"],
        dek_wrapped=row["dek_wrapped"],
        dek_nonce=row["dek_nonce"],
        aad_context=row["aad_context"],
    )
    assert out == b"hunter2"
    h.lock()


# --- core dumps -----------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="RLIMIT_CORE is POSIX-only")
def test_disable_core_dumps_sets_rlimit_zero():
    import resource

    assert disable_core_dumps() is True
    soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    assert soft == 0 and hard == 0


@pytest.mark.skipif(os.name == "posix", reason="Windows has no RLIMIT_CORE")
def test_disable_core_dumps_is_noop_off_posix():
    # systemd LimitCORE=0 is the authoritative control in production (Linux).
    assert disable_core_dumps() is False
