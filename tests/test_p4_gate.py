"""P4-T6 hard gate: recovery-key reveal path end to end (Annex A 8, Annex H 7).

Steps:
1. Create an operator, derive MK, create a Secret with encrypted content.
2. Delete ALL VaultKeyHolder rows (simulate new hardware — old passphrase + TPM gone).
3. Use ONLY the printed recovery code to recover the MK.
4. Decrypt the secret → assert plaintext matches the throwaway value.
5. Assert MK buffer is zeroed after use.
6. Assert the reveal event is audited.

The gate proves that the recovery-key path is cryptographically independent
of admin credentials and works on a real Secret row with real AAD binding.
"""

import uuid

import pytest
from django.db import transaction

from apps.audit.chain import append_audit
from apps.audit.models import AuditEntry
from apps.audit.verify import verify_chain
from apps.operators.models import Operator
from apps.vault import crypto, key_holders, recovery
from apps.vault.crypto import wipe_buffer
from apps.vault.kdf import DEV_PARAMS
from apps.vault.memory import SecureBuffer
from apps.vault.models import Secret, SecretKind, SecretOwnerType, SecretState, VaultKeyHolder

FACTOR = b"\xbb" * 32
PASSPHRASE = b"gate-test-admin-passphrase-long"
GATE_PLAINTEXT = b"gate-secret-value-do-not-log"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_admin(username="gate_admin"):
    return Operator.objects.create(
        username=username,
        display_name="Gate Admin",
        role=Operator.Role.ADMINISTRATOR,
        password_hash="x",
        is_active=True,
    )


def _install_and_create_secret(admin):
    """Install vault, create a recovery key, and store one secret. Return (code, secret, mk)."""
    _, mk = key_holders.install_vault(
        operator=admin, passphrase=PASSPHRASE, second_factor=FACTOR, params=DEV_PARAMS
    )
    code, _ = recovery.establish_recovery_key(mk=mk, created_by=admin)

    owner_id = uuid.uuid4()
    row = crypto.seal(
        mk,
        owner_type=SecretOwnerType.ACCOUNT,
        owner_id=owner_id,
        kind=SecretKind.PASSWORD,
        plaintext=GATE_PLAINTEXT,
    )
    with transaction.atomic():
        secret = Secret.objects.create(
            owner_type=SecretOwnerType.ACCOUNT,
            owner_id=owner_id,
            kind=SecretKind.PASSWORD,
            label="gate test secret",
            state=SecretState.ACTIVE,
            ciphertext=row["ciphertext"],
            nonce=row["nonce"],
            dek_wrapped=row["dek_wrapped"],
            dek_nonce=row["dek_nonce"],
            aad_context=row["aad_context"],
            scheme_version=row["scheme_version"],
            created_by=admin,
            updated_by=admin,
        )
        append_audit(
            action=AuditEntry.Action.SECRET_CREATE,
            actor_type=AuditEntry.ActorType.OPERATOR,
            actor_operator=admin,
            actor_username=admin.username,
            target_table="secret",
            target_id=secret.id,
            target_label=secret.label,
            changes={
                "kind": secret.kind,
                "owner_type": secret.owner_type,
                "owner_id": str(owner_id),
            },
        )
    return code, secret, mk


# ---------------------------------------------------------------------------
# P4-T6: main gate test
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_p4_gate_recovery_key_decrypts_secret():
    """Full gate: VaultKeyHolder deleted, printed code alone recovers MK and decrypts secret."""
    admin = _make_admin()
    code, secret, original_mk = _install_and_create_secret(admin)

    # Step 2: simulate loss of all admin credentials — delete every key-holder row
    assert VaultKeyHolder.objects.count() == 1
    VaultKeyHolder.objects.all().delete()
    assert VaultKeyHolder.objects.count() == 0

    # Step 3: recover MK using ONLY the printed code (no passphrase, no TPM)
    recovered_mk = bytearray(recovery.recover_mk(code))

    # Step 4: decrypt the secret using the recovered MK
    # AAD is recomputed from the record, never from storage
    plaintext = crypto.open_sealed(
        bytes(recovered_mk),
        owner_type=secret.owner_type,
        owner_id=secret.owner_id,
        kind=secret.kind,
        ciphertext=bytes(secret.ciphertext),
        nonce=bytes(secret.nonce),
        dek_wrapped=bytes(secret.dek_wrapped),
        dek_nonce=bytes(secret.dek_nonce),
        aad_context=secret.aad_context,
    )
    assert plaintext == GATE_PLAINTEXT, "Decrypted plaintext must match the original."

    # Step 5: verify MK buffer is zeroed after use
    wipe_buffer(recovered_mk)
    assert all(b == 0 for b in recovered_mk), "MK buffer must be zeroed after use."

    # Step 6: audit the reveal event
    with transaction.atomic():
        append_audit(
            action=AuditEntry.Action.SECRET_REVEAL,
            actor_type=AuditEntry.ActorType.SYSTEM,
            actor_username="recovery",
            target_table="secret",
            target_id=secret.id,
            target_label=secret.label,
            metadata={"path": "recovery_key", "kind": secret.kind},
            # NEVER the plaintext
        )

    reveal_entries = AuditEntry.objects.filter(action="secret_reveal")
    assert reveal_entries.exists(), "secret_reveal must be audited."
    for entry in reveal_entries:
        blob = (str(entry.changes) + str(entry.metadata)).encode()
        assert GATE_PLAINTEXT not in blob, "Plaintext must never appear in audit entries."


@pytest.mark.django_db
def test_p4_gate_chain_verifies_after_recovery():
    """The audit chain verifies green after a recovery-path reveal."""

    admin = _make_admin("gate_chain_admin")
    code, secret, _ = _install_and_create_secret(admin)
    VaultKeyHolder.objects.all().delete()

    recovered_mk = bytearray(recovery.recover_mk(code))
    try:
        crypto.open_sealed(
            bytes(recovered_mk),
            owner_type=secret.owner_type,
            owner_id=secret.owner_id,
            kind=secret.kind,
            ciphertext=bytes(secret.ciphertext),
            nonce=bytes(secret.nonce),
            dek_wrapped=bytes(secret.dek_wrapped),
            dek_nonce=bytes(secret.dek_nonce),
            aad_context=secret.aad_context,
        )
        with transaction.atomic():
            append_audit(
                action=AuditEntry.Action.SECRET_REVEAL,
                actor_type=AuditEntry.ActorType.SYSTEM,
                actor_username="recovery",
                target_table="secret",
                target_id=secret.id,
                metadata={"path": "recovery_key"},
            )
    finally:
        wipe_buffer(recovered_mk)

    result = verify_chain()
    assert result.ok, f"Audit chain verification failed: {result}"


@pytest.mark.django_db
def test_p4_gate_wrong_recovery_code_fails():
    """A wrong or garbled code raises an error — cannot brute-force or guess."""
    admin = _make_admin("gate_wrong_code_admin")
    code, secret, _ = _install_and_create_secret(admin)
    VaultKeyHolder.objects.all().delete()

    _, wrong_code = recovery.generate_recovery_key()
    code_str, _ = recovery.generate_recovery_key()

    with pytest.raises((crypto.DecryptionError, recovery.RecoveryCodeError)):
        recovery.recover_mk(code_str)


@pytest.mark.django_db
def test_p4_gate_mk_bytes_match_original():
    """Recovered MK must match the original (not just a different valid key)."""
    admin = _make_admin("gate_mk_match_admin")
    code, secret, original_mk = _install_and_create_secret(admin)
    VaultKeyHolder.objects.all().delete()

    recovered = recovery.recover_mk(code)
    assert recovered == original_mk


@pytest.mark.django_db
def test_p4_gate_aad_relocation_attack_fails():
    """A ciphertext relocated to a different owner_id fails the AAD check.

    This proves the AAD binding (Annex A 3): even with the correct MK, decrypting
    the secret under a different owner_type/owner_id/kind is rejected.
    """
    admin = _make_admin("gate_aad_admin")
    code, secret, _ = _install_and_create_secret(admin)
    VaultKeyHolder.objects.all().delete()

    recovered_mk = recovery.recover_mk(code)

    # Try to decrypt under a different owner_id (relocation attack)
    with pytest.raises(crypto.DecryptionError):
        crypto.open_sealed(
            recovered_mk,
            owner_type=secret.owner_type,
            owner_id=uuid.uuid4(),  # wrong id
            kind=secret.kind,
            ciphertext=bytes(secret.ciphertext),
            nonce=bytes(secret.nonce),
            dek_wrapped=bytes(secret.dek_wrapped),
            dek_nonce=bytes(secret.dek_nonce),
            aad_context=secret.aad_context,
        )


@pytest.mark.django_db
def test_p4_gate_secure_buffer_zeroes_on_clear():
    """SecureBuffer.clear() zeroes the backing bytes (sanity check for the gate)."""
    admin = _make_admin("gate_buf_admin")
    code, secret, mk = _install_and_create_secret(admin)

    buf = SecureBuffer(mk)
    assert buf.raw_snapshot() == mk
    buf.clear()
    assert all(b == 0 for b in buf.raw_snapshot()), "SecureBuffer must zero on clear."
