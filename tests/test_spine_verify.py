"""P1-T20 — Phase 1 security-spine VERIFY gate (Annex I 4, 5).

Three proofs that the spine holds before fanning out to later phases:
  1. the hash chain verifies (walk + signed-checkpoint anchor + off-box copy)
  2. the master key is absent from disk / swap / core
  3. a Viewer cannot decrypt (keyless by construction)

The automated checks are below; the manual swap/core-dump check on the hardened
server is in deploy/PHASE1-VERIFY.md. All three must pass to sign off Phase 1.
"""

import pickle

import pytest

from apps import vertical_slice as slice_
from apps.audit import anchor
from apps.audit.anchor import AppendOnlyFileAnchorStore
from apps.audit.checkpoints import create_checkpoint
from apps.audit.models import AuditCheckpoint, AuditEntry
from apps.audit.signing import Ed25519CheckpointSigner
from apps.audit.verify import verify_chain, verify_with_anchor
from apps.operators import auth, sessions
from apps.operators.models import Operator, OperatorTotpDevice
from apps.vault import key_holders
from apps.vault.kdf import DEV_PARAMS
from apps.vault.memory import MasterKeyHolder, MasterKeyLocked, SecureBuffer, disable_core_dumps
from apps.vault.models import Secret, VaultKeyHolder

SECOND_FACTOR = b"\x11" * 32
PASSPHRASE = b"admin vault passphrase, long and unique"
LOGIN_PW = "admin login password"


@pytest.fixture(autouse=True)
def _lock_after():
    yield
    sessions.lock_vault()


def _make_admin(username="admin"):
    op = Operator.objects.create(
        username=username, display_name="Admin", role=Operator.Role.ADMINISTRATOR, password_hash=""
    )
    auth.set_password(op, LOGIN_PW)
    _, mk = key_holders.install_vault(
        operator=op, passphrase=PASSPHRASE, second_factor=SECOND_FACTOR, params=DEV_PARAMS
    )
    auth.enroll_totp(op, SECOND_FACTOR)
    return op, mk


def _totp(op):
    import pyotp

    return pyotp.TOTP(auth._load_totp_secret(op, SECOND_FACTOR)).now()


def _run_slice(admin):
    session, _ = slice_.login(
        operator=admin,
        password=LOGIN_PW,
        totp_code=_totp(admin),
        second_factor=SECOND_FACTOR,
        passphrase=PASSPHRASE,
    )
    person = slice_.create_person(operator=admin, session=session, full_name="Ada")
    secret = slice_.store_secret(
        operator=admin,
        session=session,
        owner_type="account",
        owner_id=person.id,
        kind="password",
        plaintext=b"value",
        fresh_factor=True,
    )
    slice_.reveal_secret(
        operator=admin, session=session, secret=secret, reason="rotation", fresh_factor=True
    )
    return session


# === PROOF 1: the chain verifies ==========================================


@pytest.mark.django_db
def test_proof1_chain_verifies_walk_anchor_and_offbox(tmp_path):
    admin, _ = _make_admin()
    _run_slice(admin)

    # Walk verifies.
    assert verify_chain().ok

    # Signed checkpoint + anchor verify against the trusted key.
    signer = Ed25519CheckpointSigner()
    cp = create_checkpoint(signer=signer, created_by=admin, signer_label="phase1 verify")
    assert verify_with_anchor(trusted_public_key=signer.public_key).ok

    # Off-box copy matches.
    store = AppendOnlyFileAnchorStore(str(tmp_path / "anchors"))
    anchor.anchor_checkpoint(cp, store)
    assert anchor.verify_offbox_anchor(store, trusted_public_key=signer.public_key).ok


# === PROOF 2: the master key is absent from disk / swap / core ============


def test_proof2_holder_cannot_be_serialised_to_session_or_cache():
    # Django sessions/caches persist via pickle/JSON; the MK holder refuses both,
    # so the MK can never be written into a session, cache, or any serialised store.
    holder = MasterKeyHolder(idle_seconds=900, clock=lambda: 0.0)
    holder.unlock(bytearray(b"\x01" * 32))
    with pytest.raises((TypeError, pickle.PicklingError)):
        pickle.dumps(holder)
    with pytest.raises((TypeError, pickle.PicklingError)):
        pickle.dumps(SecureBuffer(b"\x01" * 32))
    holder.lock()


@pytest.mark.django_db
def test_proof2_plaintext_master_key_is_never_stored(tmp_path):
    admin, mk = _make_admin()
    _run_slice(admin)
    # The live MK is in memory only.
    assert sessions.current_master_key() == mk

    # The plaintext MK appears in NO persisted column — only wrapped forms exist.
    for row in VaultKeyHolder.objects.all():
        assert mk not in bytes(row.mk_wrapped)
        assert mk != bytes(row.mk_wrapped)
    for s in Secret.objects.all():
        for blob in (s.ciphertext, s.nonce, s.dek_wrapped, s.dek_nonce):
            assert mk not in bytes(blob)
    for d in OperatorTotpDevice.objects.all():
        for blob in (d.ciphertext, d.nonce, d.dek_wrapped, d.dek_nonce):
            assert mk not in bytes(blob)
    # The audit chain never carries the MK either.
    for e in AuditEntry.objects.all():
        assert mk not in (str(e.changes) + str(e.metadata)).encode()


@pytest.mark.django_db
def test_proof2_only_token_hash_in_session_table_no_key(admin_factor=None):
    admin, mk = _make_admin()
    session = _run_slice(admin)
    # The session row stores only a token hash and never any key material.
    session.refresh_from_db()
    assert mk not in session.token_hash.encode()
    # operator_session has no column that could hold a key.
    from apps.operators.models import OperatorSession

    field_names = {f.name for f in OperatorSession._meta.get_fields()}
    for forbidden in ("master_key", "mk", "key", "secret"):
        assert forbidden not in field_names


def test_proof2_core_dumps_disabled():
    import os

    if os.name == "posix":
        assert disable_core_dumps() is True  # RLIMIT_CORE driven to 0
    else:
        # No RLIMIT_CORE off POSIX; the systemd unit sets LimitCORE=0 (P1-T1).
        assert disable_core_dumps() is False


# === PROOF 3: a Viewer cannot decrypt =====================================


@pytest.mark.django_db
def test_proof3_viewer_cannot_decrypt():
    admin, _ = _make_admin()
    a_session = _run_slice(admin)
    secret = Secret.objects.first()
    assert secret is not None

    viewer = Operator.objects.create(
        username="v", display_name="V", role=Operator.Role.VIEWER, password_hash=""
    )
    auth.set_password(viewer, "viewer pw")
    auth.enroll_totp(viewer, SECOND_FACTOR)
    slice_.login(
        operator=viewer, password="viewer pw", totp_code=_totp(viewer), second_factor=SECOND_FACTOR
    )
    # The Viewer login superseded the admin session and wiped the MK.
    assert not sessions.is_vault_unlocked()
    with pytest.raises(MasterKeyLocked):
        sessions.current_master_key()
    # A forced reveal has nothing to decrypt with.
    with pytest.raises(MasterKeyLocked):
        slice_.reveal_secret(
            operator=viewer, session=a_session, secret=secret, reason="x", fresh_factor=True
        )


# === sign-off marker ======================================================


@pytest.mark.django_db
def test_phase1_signoff_all_three_proofs_present():
    # A trivially-true marker documenting that all three VERIFY proofs above
    # ran in this module; CI failing any of them blocks the Phase 1 sign-off.
    assert AuditCheckpoint is not None
