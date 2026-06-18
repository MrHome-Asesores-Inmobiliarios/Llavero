"""P1-T9 acceptance + security-property tests (Annex A 13).

Brief acceptance criteria:
- both admins unlock the same MK via their own rows
- after removal + rotation the removed row no longer derives a working MK, and
  all secrets still decrypt for the remaining admin

Security properties also asserted:
- only Administrators may hold a wrapped MK (keyless Viewer)
- rotation is atomic (a partial rotation rolls back)
- the old MK cannot decrypt secrets after rotation (re-wrapped DEKs)
- the second factor itself is never stored on the holder row
"""

import uuid

import pytest

from apps.operators.models import Operator
from apps.vault import crypto, key_holders
from apps.vault.kdf import DEV_PARAMS
from apps.vault.key_holders import KeyRotationError, NotAnAdministrator
from apps.vault.models import Secret, VaultKeyHolder

FACTOR = b"\x11" * 32
PASS_A = b"admin-A-passphrase-quite-long"
PASS_B = b"admin-B-passphrase-quite-long"


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


@pytest.fixture
def viewer(db):
    return Operator.objects.create(
        username="v", display_name="V", role=Operator.Role.VIEWER, password_hash="x"
    )


def _seal_secret(mk, operator, owner_id, kind="password", plaintext=b"pw"):
    row = crypto.seal(mk, owner_type="account", owner_id=owner_id, kind=kind, plaintext=plaintext)
    return Secret.objects.create(
        owner_type=Secret.OwnerType.ACCOUNT,
        owner_id=owner_id,
        kind=kind,
        aad_context=row["aad_context"],
        ciphertext=row["ciphertext"],
        nonce=row["nonce"],
        dek_wrapped=row["dek_wrapped"],
        dek_nonce=row["dek_nonce"],
        scheme_version=row["scheme_version"],
        created_by=operator,
        updated_by=operator,
    )


def _open(mk, secret):
    return crypto.open_sealed(
        mk,
        owner_type=secret.owner_type,
        owner_id=secret.owner_id,
        kind=secret.kind,
        ciphertext=bytes(secret.ciphertext),
        nonce=bytes(secret.nonce),
        dek_wrapped=bytes(secret.dek_wrapped),
        dek_nonce=bytes(secret.dek_nonce),
        aad_context=secret.aad_context,
    )


# --- install + per-admin unlock -------------------------------------------


@pytest.mark.django_db
def test_install_creates_holder_and_unlocks(admin_a):
    holder, mk = key_holders.install_vault(
        operator=admin_a, passphrase=PASS_A, second_factor=FACTOR, params=DEV_PARAMS
    )
    assert VaultKeyHolder.objects.filter(operator=admin_a).exists()
    again = key_holders.unlock_with_holder(admin_a, PASS_A, FACTOR)
    assert again == mk


@pytest.mark.django_db
def test_both_admins_unlock_the_same_mk(admin_a, admin_b):
    _, mk = key_holders.install_vault(
        operator=admin_a, passphrase=PASS_A, second_factor=FACTOR, params=DEV_PARAMS
    )
    key_holders.enroll_admin(
        mk=mk,
        newcomer=admin_b,
        passphrase=PASS_B,
        second_factor=FACTOR,
        params=DEV_PARAMS,
        enrolled_by=admin_a,
    )
    mk_a = key_holders.unlock_with_holder(admin_a, PASS_A, FACTOR)
    mk_b = key_holders.unlock_with_holder(admin_b, PASS_B, FACTOR)
    assert mk_a == mk == mk_b  # one MK, two independent wraps


@pytest.mark.django_db
def test_unlock_wrong_passphrase_fails(admin_a):
    key_holders.install_vault(
        operator=admin_a, passphrase=PASS_A, second_factor=FACTOR, params=DEV_PARAMS
    )
    with pytest.raises(crypto.DecryptionError):
        key_holders.unlock_with_holder(admin_a, b"wrong", FACTOR)


# --- keyless Viewer -------------------------------------------------------


@pytest.mark.django_db
def test_install_rejects_viewer(viewer):
    with pytest.raises(NotAnAdministrator):
        key_holders.install_vault(
            operator=viewer, passphrase=PASS_A, second_factor=FACTOR, params=DEV_PARAMS
        )
    assert not VaultKeyHolder.objects.filter(operator=viewer).exists()


@pytest.mark.django_db
def test_enroll_rejects_viewer(admin_a, viewer):
    _, mk = key_holders.install_vault(
        operator=admin_a, passphrase=PASS_A, second_factor=FACTOR, params=DEV_PARAMS
    )
    with pytest.raises(NotAnAdministrator):
        key_holders.enroll_admin(
            mk=mk,
            newcomer=viewer,
            passphrase=PASS_B,
            second_factor=FACTOR,
            params=DEV_PARAMS,
            enrolled_by=admin_a,
        )
    assert not VaultKeyHolder.objects.filter(operator=viewer).exists()


@pytest.mark.django_db
def test_holder_does_not_store_the_second_factor(admin_a):
    holder, _ = key_holders.install_vault(
        operator=admin_a,
        passphrase=PASS_A,
        second_factor=FACTOR,
        params=DEV_PARAMS,
        second_factor_ref="dev-keyfile-1",
    )
    holder.refresh_from_db()
    assert holder.second_factor_ref == "dev-keyfile-1"
    assert FACTOR not in bytes(holder.mk_wrapped)
    assert FACTOR not in bytes(holder.kdf_salt)


# --- removal + MK rotation ------------------------------------------------


@pytest.mark.django_db
def test_removal_and_rotation_invalidates_removed_and_keeps_secrets(admin_a, admin_b):
    _, mk_old = key_holders.install_vault(
        operator=admin_a, passphrase=PASS_A, second_factor=FACTOR, params=DEV_PARAMS
    )
    key_holders.enroll_admin(
        mk=mk_old,
        newcomer=admin_b,
        passphrase=PASS_B,
        second_factor=FACTOR,
        params=DEV_PARAMS,
        enrolled_by=admin_a,
    )
    secrets = [
        _seal_secret(mk_old, admin_a, uuid.uuid4(), plaintext=f"pw{i}".encode()) for i in range(3)
    ]

    # The remaining admin (A) supplies their own KWK for the re-wrap.
    holder_a = VaultKeyHolder.objects.get(operator=admin_a)
    kwk_a = key_holders.derive_holder_kwk(holder_a, PASS_A, FACTOR)

    new_mk = key_holders.remove_admin_and_rotate(
        removed_operator=admin_b,
        old_mk=mk_old,
        remaining_kwks={admin_a.id: kwk_a},
    )
    assert new_mk != mk_old

    # B's row is gone; B can no longer unlock.
    assert not VaultKeyHolder.objects.filter(operator=admin_b).exists()
    with pytest.raises(VaultKeyHolder.DoesNotExist):
        key_holders.unlock_with_holder(admin_b, PASS_B, FACTOR)

    # A unlocks and gets the NEW MK, and every secret still decrypts.
    mk_a = key_holders.unlock_with_holder(admin_a, PASS_A, FACTOR)
    assert mk_a == new_mk
    for s in secrets:
        s.refresh_from_db()
        assert _open(new_mk, s) in (b"pw0", b"pw1", b"pw2")

    # The OLD MK can no longer decrypt the live (re-wrapped) secrets.
    for s in secrets:
        with pytest.raises(crypto.DecryptionError):
            _open(mk_old, s)


@pytest.mark.django_db
def test_rotation_is_atomic_when_a_remaining_admin_lacks_kwk(admin_a, admin_b):
    _, mk_old = key_holders.install_vault(
        operator=admin_a, passphrase=PASS_A, second_factor=FACTOR, params=DEV_PARAMS
    )
    key_holders.enroll_admin(
        mk=mk_old,
        newcomer=admin_b,
        passphrase=PASS_B,
        second_factor=FACTOR,
        params=DEV_PARAMS,
        enrolled_by=admin_a,
    )
    secret = _seal_secret(mk_old, admin_a, uuid.uuid4(), plaintext=b"keepme")
    original_wrapped = bytes(secret.dek_wrapped)

    # Remove A but supply NO KWK for the remaining admin B -> must refuse + roll back.
    with pytest.raises(KeyRotationError):
        key_holders.remove_admin_and_rotate(
            removed_operator=admin_a,
            old_mk=mk_old,
            remaining_kwks={},
        )

    # Nothing changed: B's row still present, secret DEK untouched, old MK works.
    assert VaultKeyHolder.objects.filter(operator=admin_b).exists()
    assert VaultKeyHolder.objects.filter(operator=admin_a).exists()
    secret.refresh_from_db()
    assert bytes(secret.dek_wrapped) == original_wrapped
    assert _open(mk_old, secret) == b"keepme"


# --- crypto-level re-wrap -------------------------------------------------


@pytest.mark.django_db
def test_rewrap_dek_moves_dek_to_new_mk(admin_a):
    mk_old = crypto.generate_master_key()
    mk_new = crypto.generate_master_key()
    owner_id = uuid.uuid4()
    row = crypto.seal(
        mk_old, owner_type="account", owner_id=owner_id, kind="password", plaintext=b"x"
    )
    new_wrapped, new_nonce = crypto.rewrap_dek(mk_old, mk_new, row["dek_wrapped"], row["dek_nonce"])
    aad_kwargs = dict(owner_type="account", owner_id=owner_id, kind="password")
    # New MK + re-wrapped DEK decrypts; old wrapping no longer valid under new MK.
    assert (
        crypto.open_sealed(
            mk_new,
            ciphertext=row["ciphertext"],
            nonce=row["nonce"],
            dek_wrapped=new_wrapped,
            dek_nonce=new_nonce,
            **aad_kwargs,
        )
        == b"x"
    )
    with pytest.raises(crypto.DecryptionError):
        crypto.open_sealed(
            mk_old,
            ciphertext=row["ciphertext"],
            nonce=row["nonce"],
            dek_wrapped=new_wrapped,
            dek_nonce=new_nonce,
            **aad_kwargs,
        )
