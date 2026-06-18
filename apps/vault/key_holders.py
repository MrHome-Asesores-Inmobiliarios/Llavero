"""Per-administrator key wrapping, enrollment, removal + MK rotation (Annex A 13).

There is a single vault master key (MK). It is wrapped once per Administrator
under that admin's KWK (derived from their passphrase + the server second
factor). Operations here never store the plaintext MK and wipe KWK
intermediates.

Keyless Viewer: only Administrators may hold a wrapped MK. install/enroll
reject non-admins, so a Viewer can never obtain a row and therefore can never
unlock the MK.

Auditing: enroll/remove/rotate are sensitive (operator_change / parameter_change
in Annex B). The audit chain is P1-T11/T12; once it exists these calls must
emit audit entries in the same transaction as the change.
"""

from django.db import transaction

from apps.operators.models import Operator
from apps.vault import crypto
from apps.vault.kdf import Argon2Params, generate_salt
from apps.vault.models import Secret, VaultKeyHolder


class NotAnAdministrator(Exception):
    """Refused: only Administrators may hold a wrapped master key."""


class KeyRotationError(Exception):
    """Rotation could not complete safely (e.g. a remaining admin has no KWK)."""


def _require_admin(operator: Operator) -> None:
    if operator.role != Operator.Role.ADMINISTRATOR:
        raise NotAnAdministrator(
            f"operator {operator.username!r} is not an Administrator; "
            "Viewers never hold the master key"
        )


def _params_of(holder: VaultKeyHolder) -> Argon2Params:
    return Argon2Params(
        memory_kib=holder.kdf_memory,
        iterations=holder.kdf_iterations,
        parallelism=holder.kdf_parallelism,
        scheme_version=holder.scheme_version,
    )


def derive_holder_kwk(holder: VaultKeyHolder, passphrase: bytes, second_factor: bytes) -> bytes:
    """Recompute an admin's KWK from their stored salt/params + credentials."""
    return crypto.derive_kwk(passphrase, bytes(holder.kdf_salt), _params_of(holder), second_factor)


def install_vault(
    *,
    operator: Operator,
    passphrase: bytes,
    second_factor: bytes,
    params: Argon2Params,
    second_factor_ref: str = "",
) -> tuple[VaultKeyHolder, bytes]:
    """Install-time: generate the MK and write the first Administrator's row.

    Returns (holder, mk). The caller must immediately secure ``mk`` in a
    MasterKeyHolder (P1-T8); it is the only plaintext copy and is not stored.
    """
    _require_admin(operator)
    salt = generate_salt()
    kwk = bytearray(crypto.derive_kwk(passphrase, salt, params, second_factor))
    try:
        mk = crypto.generate_master_key()
        mk_wrapped, mk_nonce = crypto.wrap_master_key(mk, bytes(kwk))
    finally:
        crypto.wipe_buffer(kwk)
    holder = VaultKeyHolder.objects.create(
        operator=operator,
        kdf_salt=salt,
        kdf_memory=params.memory_kib,
        kdf_iterations=params.iterations,
        kdf_parallelism=params.parallelism,
        scheme_version=params.scheme_version,
        mk_wrapped=mk_wrapped,
        mk_nonce=mk_nonce,
        second_factor_ref=second_factor_ref,
        created_by=operator,
    )
    return holder, mk


def unlock_with_holder(operator: Operator, passphrase: bytes, second_factor: bytes) -> bytes:
    """Unlock the MK via this operator's own row. Raises DecryptionError on a
    wrong passphrase/factor, VaultKeyHolder.DoesNotExist if there is no row."""
    holder = VaultKeyHolder.objects.get(operator=operator)
    kwk = bytearray(derive_holder_kwk(holder, passphrase, second_factor))
    try:
        return crypto.unwrap_master_key(
            bytes(holder.mk_wrapped), bytes(holder.mk_nonce), bytes(kwk)
        )
    finally:
        crypto.wipe_buffer(kwk)


def enroll_admin(
    *,
    mk: bytes,
    newcomer: Operator,
    passphrase: bytes,
    second_factor: bytes,
    params: Argon2Params,
    enrolled_by: Operator,
    second_factor_ref: str = "",
) -> VaultKeyHolder:
    """An existing admin (holding ``mk`` in memory) wraps it under the newcomer's
    KWK and writes their row. The newcomer never sees the raw MK (Annex A 13)."""
    _require_admin(newcomer)
    salt = generate_salt()
    kwk = bytearray(crypto.derive_kwk(passphrase, salt, params, second_factor))
    try:
        mk_wrapped, mk_nonce = crypto.wrap_master_key(mk, bytes(kwk))
    finally:
        crypto.wipe_buffer(kwk)
    return VaultKeyHolder.objects.create(
        operator=newcomer,
        kdf_salt=salt,
        kdf_memory=params.memory_kib,
        kdf_iterations=params.iterations,
        kdf_parallelism=params.parallelism,
        scheme_version=params.scheme_version,
        mk_wrapped=mk_wrapped,
        mk_nonce=mk_nonce,
        second_factor_ref=second_factor_ref,
        created_by=enrolled_by,
    )


def remove_admin_and_rotate(
    *,
    removed_operator: Operator,
    old_mk: bytes,
    remaining_kwks: dict,
) -> bytes:
    """Remove an Administrator and rotate the MK (Annex A 13).

    In one transaction: delete the removed admin's row, generate a new MK,
    re-wrap every secret's DEK from the old MK to the new MK, and re-wrap the
    new MK for each remaining admin using the supplied KWKs. Returns the new MK
    (the caller re-secures it in their MasterKeyHolder after commit).

    ``remaining_kwks`` maps each remaining admin's operator id -> their KWK
    bytes. A remaining admin without a supplied KWK cannot be re-wrapped (only
    they can compute their KWK), so rotation refuses rather than orphaning them
    — they must re-enroll instead.

    Why rotate: a removed admin who kept a copy of the old wrapped MK plus their
    passphrase could otherwise still derive the old MK. After rotation the live
    DEKs are wrapped under the new MK, so the old MK no longer decrypts anything.
    """
    new_mk = crypto.generate_master_key()
    with transaction.atomic():
        VaultKeyHolder.objects.filter(operator=removed_operator).delete()

        for secret in Secret.objects.select_for_update():
            new_wrapped, new_nonce = crypto.rewrap_dek(
                old_mk, new_mk, bytes(secret.dek_wrapped), bytes(secret.dek_nonce)
            )
            secret.dek_wrapped = new_wrapped
            secret.dek_nonce = new_nonce
            secret.save(update_fields=["dek_wrapped", "dek_nonce", "updated_at"])

        for holder in VaultKeyHolder.objects.select_for_update():
            kwk = remaining_kwks.get(holder.operator_id)
            if kwk is None:
                raise KeyRotationError(
                    f"no KWK supplied for remaining admin {holder.operator_id}; "
                    "that admin must re-enroll after rotation"
                )
            mk_wrapped, mk_nonce = crypto.wrap_master_key(new_mk, bytes(kwk))
            holder.mk_wrapped = mk_wrapped
            holder.mk_nonce = mk_nonce
            holder.save(update_fields=["mk_wrapped", "mk_nonce"])

        # NOTE (P1-T10): the independent printed-recovery-key wrap of the MK
        # must also be re-wrapped here once it exists, or recovery would still
        # point at the old MK.

    return new_mk
