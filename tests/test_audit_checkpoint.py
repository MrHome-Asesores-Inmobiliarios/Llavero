"""P1-T13 acceptance + security-property tests (Annex B 7; Annex G 7).

Brief acceptance criteria:
- verify pinpoints an altered entry at the right seq (chain walk, from P1-T12)
- a checkpoint signature verifies against the admin public key
- post-checkpoint tampering is caught by the anchor check

Security properties also asserted:
- the anchor verifies against an INDEPENDENTLY-TRUSTED public key, so a rewrite
  re-signed with the attacker's own key is rejected (honest-limitation defence;
  the off-box copy is P1-T14)
- the server stores only the signature + public-key reference, never the
  private signing key
- only an Administrator can create a checkpoint; an invalid chain is not signed

Checkpoint signing uses the offline Ed25519 key (Annex G 7's stated unattended
alternative); the WebAuthn-assertion signing ceremony is wired in the auth/web
phase. The signing key is never held by the server.
"""

import pytest
from django.db import connection, transaction

from apps.audit.chain import ZERO32, append_audit, compute_entry_hash, payload_for
from apps.audit.checkpoints import (
    ChainNotVerifiable,
    NotAnAdministrator,
    create_checkpoint,
)
from apps.audit.models import AuditCheckpoint, AuditEntry
from apps.audit.signing import Ed25519CheckpointSigner, verify_signature
from apps.audit.verify import verify_chain, verify_with_anchor
from apps.operators.models import Operator

SYSTEM = AuditEntry.ActorType.SYSTEM


@pytest.fixture
def admin(db):
    return Operator.objects.create(
        username="admin", display_name="Admin", role=Operator.Role.ADMINISTRATOR, password_hash="x"
    )


@pytest.fixture
def viewer(db):
    return Operator.objects.create(
        username="v", display_name="V", role=Operator.Role.VIEWER, password_hash="x"
    )


def _append_n(n):
    # Wrap each append in its own atomic block so this works under both the
    # transactional and non-transactional db fixtures.
    out = []
    for _ in range(n):
        with transaction.atomic():
            out.append(
                append_audit(
                    action=AuditEntry.Action.RECORD_VIEW, actor_type=SYSTEM, target_table="device"
                )
            )
    return out


def _toggle_trigger(enabled):
    state = "ENABLE" if enabled else "DISABLE"
    with connection.cursor() as cur:
        cur.execute(f"ALTER TABLE audit_entry {state} TRIGGER audit_entry_append_only")


def _rewrite_chain_relinking(tamper_seq, new_label):
    """Simulate an attacker with raw DB write access (superuser/owner bypassing
    the trigger): tamper an entry and recompute every hash forward so the chain
    re-links and the plain walk passes. Requires committed rows, so the callers
    use the transactional db fixture; statements run in autocommit."""
    _toggle_trigger(False)
    try:
        prev = ZERO32
        rows = list(AuditEntry.objects.order_by("seq"))
        for e in rows:
            if e.seq == tamper_seq:
                e.target_label = new_label
            e.prev_hash = prev
            e.entry_hash = compute_entry_hash(payload_for(e), prev)
            with connection.cursor() as cur:
                cur.execute(
                    "UPDATE audit_entry SET target_label=%s, prev_hash=%s, entry_hash=%s "
                    "WHERE seq=%s",
                    [e.target_label, e.prev_hash, e.entry_hash, e.seq],
                )
            prev = e.entry_hash
    finally:
        _toggle_trigger(True)


# --- chain-walk verifier pinpoints an altered entry (Annex B 7) -----------


@pytest.mark.django_db
def test_verify_pinpoints_altered_entry_at_right_seq():
    entries = _append_n(4)
    entries[2].changes = {"tampered": True}  # in-memory tamper of seq 3
    status = verify_chain(entries)
    assert not status.ok
    assert status.reason == "altered_entry"
    assert status.seq == 3


# --- signed checkpoint ----------------------------------------------------


@pytest.mark.django_db
def test_checkpoint_signature_verifies_against_admin_public_key(admin):
    _append_n(3)
    signer = Ed25519CheckpointSigner()
    cp = create_checkpoint(signer=signer, created_by=admin, signer_label="admin offline key")

    assert cp.seq == 3
    assert verify_signature("ed25519", signer.public_key, bytes(cp.head_hash), bytes(cp.signature))
    # A tampered head_hash or the wrong key does not verify.
    assert not verify_signature("ed25519", signer.public_key, b"\x00" * 32, bytes(cp.signature))
    assert not verify_signature(
        "ed25519", Ed25519CheckpointSigner().public_key, bytes(cp.head_hash), bytes(cp.signature)
    )


@pytest.mark.django_db
def test_checkpoint_stores_no_private_signing_key(admin):
    _append_n(2)
    signer = Ed25519CheckpointSigner()
    cp = create_checkpoint(signer=signer, created_by=admin, signer_label="k")
    cp.refresh_from_db()
    priv = signer.signing_key_bytes
    # The private signing key appears in no stored checkpoint field.
    assert priv not in bytes(cp.signature)
    assert priv not in bytes(cp.head_hash)
    assert priv.hex() not in (cp.signer or "")
    assert priv.hex() not in (cp.signature_algo or "")


# --- anchor: post-checkpoint tampering is caught --------------------------


@pytest.mark.django_db
def test_anchor_passes_on_untampered_chain(admin):
    _append_n(3)
    signer = Ed25519CheckpointSigner()
    create_checkpoint(signer=signer, created_by=admin, signer_label="k")
    _append_n(2)  # legitimate activity after the checkpoint
    status = verify_with_anchor(trusted_public_key=signer.public_key)
    assert status.ok
    assert status.anchored is True


@pytest.mark.django_db(transaction=True)
def test_post_checkpoint_tampering_caught_by_anchor(admin):
    try:
        _append_n(3)
        signer = Ed25519CheckpointSigner()
        cp = create_checkpoint(signer=signer, created_by=admin, signer_label="k")
        _append_n(2)  # head now seq 5; checkpoint anchors seq 3

        # Attacker rewrites seq 2 and re-links the whole chain so the walk passes.
        _rewrite_chain_relinking(tamper_seq=2, new_label="forged")
        assert verify_chain().ok  # the plain walk is fooled by the re-link

        status = verify_with_anchor(trusted_public_key=signer.public_key)
        assert not status.ok
        assert status.reason == "rewritten_after_checkpoint"
        assert status.seq == cp.seq == 3
    finally:
        connection.close()


@pytest.mark.django_db
def test_anchor_rejects_checkpoint_signed_by_untrusted_key(admin):
    _append_n(3)
    attacker = Ed25519CheckpointSigner()
    create_checkpoint(signer=attacker, created_by=admin, signer_label="attacker key")

    trusted = Ed25519CheckpointSigner()  # the real admin key the server trusts
    status = verify_with_anchor(trusted_public_key=trusted.public_key)
    assert not status.ok
    assert status.reason == "bad_checkpoint_signature"


@pytest.mark.django_db
def test_anchor_ok_when_no_checkpoint_exists(admin):
    _append_n(2)
    status = verify_with_anchor(trusted_public_key=Ed25519CheckpointSigner().public_key)
    assert status.ok
    assert status.anchored is False


# --- guards ---------------------------------------------------------------


@pytest.mark.django_db
def test_create_checkpoint_requires_administrator(viewer):
    _append_n(1)
    with pytest.raises(NotAnAdministrator):
        create_checkpoint(signer=Ed25519CheckpointSigner(), created_by=viewer, signer_label="k")
    assert AuditCheckpoint.objects.count() == 0


@pytest.mark.django_db(transaction=True)
def test_create_checkpoint_refuses_an_invalid_chain(admin):
    try:
        _append_n(3)
        # Break a link (attacker bypassing the trigger) so the chain won't verify.
        _toggle_trigger(False)
        with connection.cursor() as cur:
            cur.execute("UPDATE audit_entry SET prev_hash = %s WHERE seq = 2", [b"\x99" * 32])
        _toggle_trigger(True)

        assert not verify_chain().ok
        with pytest.raises(ChainNotVerifiable):
            create_checkpoint(signer=Ed25519CheckpointSigner(), created_by=admin, signer_label="k")
    finally:
        connection.close()
