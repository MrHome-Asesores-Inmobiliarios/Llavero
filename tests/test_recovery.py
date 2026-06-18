"""P1-T10 acceptance + security-property tests (Annex A 8).

Brief acceptance criteria:
- the recovery key alone unwraps the MK
- the print/store procedure is documented (deploy/README.md)

Security properties also asserted:
- recovery is independent of admin credentials (works with every key holder gone)
- the recovery code round-trips through messy formatting; a transcription error
  is caught by a checksum
- establishing a new recovery key invalidates the prior one
- MK rotation (P1-T9) invalidates the stale recovery wrap until re-established
"""

import pytest

from apps.operators.models import Operator
from apps.vault import crypto, key_holders, recovery
from apps.vault.kdf import DEV_PARAMS
from apps.vault.models import VaultKeyHolder, VaultRecoveryKey

FACTOR = b"\x11" * 32
PASS_A = b"admin-A-passphrase-quite-long"
PASS_B = b"admin-B-passphrase-quite-long"


@pytest.fixture
def admin(db):
    return Operator.objects.create(
        username="a", display_name="A", role=Operator.Role.ADMINISTRATOR, password_hash="x"
    )


@pytest.fixture
def admin_b(db):
    return Operator.objects.create(
        username="b", display_name="B", role=Operator.Role.ADMINISTRATOR, password_hash="x"
    )


# --- pure recovery-key crypto ---------------------------------------------


def test_generate_recovery_key_is_256bit_and_printable():
    code, key = recovery.generate_recovery_key()
    assert len(key) == 32
    assert isinstance(code, str)
    assert "-" in code  # grouped for transcription
    assert code == code.upper()


def test_recovery_key_alone_unwraps_mk():
    mk = crypto.generate_master_key()
    code, key = recovery.generate_recovery_key()
    wrapped, nonce = recovery.wrap_mk(mk, key)
    assert recovery.unwrap_mk(code, wrapped, nonce) == mk


def test_recovery_code_round_trips_through_messy_formatting():
    code, key = recovery.generate_recovery_key()
    messy = "  " + code.lower().replace("-", " ") + "  "
    assert recovery.decode_recovery_code(messy) == key


def test_transcription_error_caught_by_checksum():
    code, _ = recovery.generate_recovery_key()
    chars = list(code.replace("-", ""))
    chars[0] = "A" if chars[0] != "A" else "B"  # flip one in-alphabet char
    with pytest.raises(recovery.RecoveryCodeError):
        recovery.decode_recovery_code("".join(chars))


def test_invalid_characters_rejected():
    with pytest.raises(recovery.RecoveryCodeError):
        recovery.decode_recovery_code("0018-OIOI")  # 0/1/8/9 not in base32 alphabet


def test_wrong_recovery_key_fails_unwrap():
    mk = crypto.generate_master_key()
    _, key1 = recovery.generate_recovery_key()
    wrapped, nonce = recovery.wrap_mk(mk, key1)
    code2, _ = recovery.generate_recovery_key()
    with pytest.raises(crypto.DecryptionError):
        recovery.unwrap_mk(code2, wrapped, nonce)


def test_fingerprint_is_stable_and_does_not_reveal_the_key():
    code, key = recovery.generate_recovery_key()
    fpr = recovery.fingerprint(key)
    assert recovery.fingerprint(key) == fpr
    assert key.hex() not in fpr
    _, key2 = recovery.generate_recovery_key()
    assert recovery.fingerprint(key2) != fpr


# --- service + model ------------------------------------------------------


def _install(admin):
    _, mk = key_holders.install_vault(
        operator=admin, passphrase=PASS_A, second_factor=FACTOR, params=DEV_PARAMS
    )
    return mk


@pytest.mark.django_db
def test_establish_and_recover(admin):
    mk = _install(admin)
    code, row = recovery.establish_recovery_key(mk=mk, created_by=admin)
    assert VaultRecoveryKey.objects.count() == 1
    assert row.fingerprint  # non-secret id stored
    assert recovery.recover_mk(code) == mk


@pytest.mark.django_db
def test_recovery_independent_of_admin_credentials(admin):
    mk = _install(admin)
    code, _ = recovery.establish_recovery_key(mk=mk, created_by=admin)
    # Simulate every admin credential lost: delete all key-holder rows.
    VaultKeyHolder.objects.all().delete()
    # The printed key alone still recovers the MK.
    assert recovery.recover_mk(code) == mk


@pytest.mark.django_db
def test_establishing_again_invalidates_the_prior_code(admin):
    mk = _install(admin)
    code1, _ = recovery.establish_recovery_key(mk=mk, created_by=admin)
    code2, _ = recovery.establish_recovery_key(mk=mk, created_by=admin)
    assert VaultRecoveryKey.objects.count() == 1  # single active wrap
    assert recovery.recover_mk(code2) == mk
    with pytest.raises(crypto.DecryptionError):
        recovery.recover_mk(code1)


@pytest.mark.django_db
def test_recover_without_a_recovery_row_raises(admin):
    with pytest.raises(recovery.NoRecoveryKey):
        recovery.recover_mk("AAAA-BBBB-CCCC")


@pytest.mark.django_db
def test_the_stored_row_holds_no_recovery_key_or_mk(admin):
    mk = _install(admin)
    code, row = recovery.establish_recovery_key(mk=mk, created_by=admin)
    row.refresh_from_db()
    key = recovery.decode_recovery_code(code)
    # Neither the recovery key nor the MK appears in the stored wrap/fingerprint.
    assert key not in bytes(row.rk_wrapped)
    assert mk not in bytes(row.rk_wrapped)
    assert key.hex() not in row.fingerprint


# --- rotation invalidates the stale recovery wrap (P1-T9 integration) ------


@pytest.mark.django_db
def test_rotation_invalidates_recovery_until_reestablished(admin, admin_b):
    _, mk_old = key_holders.install_vault(
        operator=admin, passphrase=PASS_A, second_factor=FACTOR, params=DEV_PARAMS
    )
    key_holders.enroll_admin(
        mk=mk_old,
        newcomer=admin_b,
        passphrase=PASS_B,
        second_factor=FACTOR,
        params=DEV_PARAMS,
        enrolled_by=admin,
    )
    code_old, _ = recovery.establish_recovery_key(mk=mk_old, created_by=admin)

    holder_a = VaultKeyHolder.objects.get(operator=admin)
    kwk_a = key_holders.derive_holder_kwk(holder_a, PASS_A, FACTOR)
    new_mk = key_holders.remove_admin_and_rotate(
        removed_operator=admin_b, old_mk=mk_old, remaining_kwks={admin.id: kwk_a}
    )

    # The stale wrap (pointing at the old MK) is removed by rotation.
    assert VaultRecoveryKey.objects.count() == 0
    with pytest.raises(recovery.NoRecoveryKey):
        recovery.recover_mk(code_old)

    # A new recovery key must be established for the new MK.
    code_new, _ = recovery.establish_recovery_key(mk=new_mk, created_by=admin)
    assert recovery.recover_mk(code_new) == new_mk
