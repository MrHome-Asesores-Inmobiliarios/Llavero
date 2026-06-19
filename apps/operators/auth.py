"""Operator authentication (Annex D 1, 2; Annex C 4.1, 4.2; Prelim 6).

Login = operator password (Argon2id *login* hash, entirely separate from the
vault master key) + a second factor (WebAuthn platform authenticator preferred,
pyotp TOTP fallback). Login is fully local and never depends on Microsoft 365.

Role routing: an Administrator login proceeds to the vault-unlock path (it will
derive and hold the MK, P1-T9/T16); a Viewer login never unlocks the MK — the
Viewer session is keyless by construction (Annex D 2).

WebAuthn: the server stores only the credential public key + a monotonically
increasing sign_count; a non-increasing sign_count is rejected as a replay/clone.

No secret, password, seed, or key is ever logged here.
"""

from dataclasses import dataclass

import nacl.encoding
import nacl.hash
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from apps.operators.models import Operator, OperatorTotpDevice, OperatorWebAuthnCredential
from apps.vault import crypto

# Login password hashing — a distinct Argon2id use from the vault KWK. These are
# auth credentials, calibrated for login latency, never the master key.
_password_hasher = PasswordHasher()

_LOGIN_TOTP_LABEL = b"llavero-login-totp"


class ReplayDetected(Exception):
    """WebAuthn sign_count did not increase — a replay or cloned authenticator."""


@dataclass(frozen=True)
class AuthResult:
    operator: Operator
    role: str
    requires_vault_unlock: bool


# --- password (Argon2id login hash) ---------------------------------------


def hash_password(raw_password: str) -> str:
    return _password_hasher.hash(raw_password)


def set_password(operator: Operator, raw_password: str, *, save: bool = True) -> None:
    operator.password_hash = hash_password(raw_password)
    if save:
        operator.save(update_fields=["password_hash", "updated_at"])


def check_password(operator: Operator, raw_password: str) -> bool:
    """Verify the login password, transparently rehashing if params changed."""
    try:
        _password_hasher.verify(operator.password_hash, raw_password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    if _password_hasher.check_needs_rehash(operator.password_hash):
        set_password(operator, raw_password)
    return True


# --- TOTP fallback (pyotp), seed encrypted under the login key -------------


def _login_key(second_factor: bytes) -> bytes:
    """Login-secrets key derived from the server second factor (not the MK)."""
    return nacl.hash.blake2b(
        second_factor,
        key=_LOGIN_TOTP_LABEL,
        digest_size=crypto.KEY_BYTES,
        encoder=nacl.encoding.RawEncoder,
    )


def _totp_aad(operator: Operator) -> bytes:
    return crypto.build_aad("operator_totp", operator.id, "totp")


def enroll_totp(
    operator: Operator, second_factor: bytes, *, issuer: str = "Llavero"
) -> tuple[str, str]:
    """Generate a TOTP seed for the operator, store it encrypted, and return
    (seed_base32, provisioning_uri) to show ONCE for enrolment."""
    seed = pyotp.random_base32()
    login_key = bytearray(_login_key(second_factor))
    try:
        row = crypto.encrypt_secret(bytes(login_key), seed.encode("ascii"), _totp_aad(operator))
    finally:
        crypto.wipe_buffer(login_key)
    OperatorTotpDevice.objects.update_or_create(
        operator=operator,
        defaults=dict(
            ciphertext=row["ciphertext"],
            nonce=row["nonce"],
            dek_wrapped=row["dek_wrapped"],
            dek_nonce=row["dek_nonce"],
            confirmed=False,
        ),
    )
    uri = pyotp.TOTP(seed).provisioning_uri(name=operator.username, issuer_name=issuer)
    return seed, uri


def _load_totp_secret(operator: Operator, second_factor: bytes) -> str:
    device = OperatorTotpDevice.objects.get(operator=operator)
    login_key = bytearray(_login_key(second_factor))
    try:
        seed = crypto.decrypt_secret(
            bytes(login_key),
            ciphertext=bytes(device.ciphertext),
            nonce=bytes(device.nonce),
            dek_wrapped=bytes(device.dek_wrapped),
            dek_nonce=bytes(device.dek_nonce),
            aad=_totp_aad(operator),
        )
    finally:
        crypto.wipe_buffer(login_key)
    return seed.decode("ascii")


def verify_totp(operator: Operator, code: str, second_factor: bytes) -> bool:
    """Verify a TOTP code (±1 step for clock skew). Confirms the device on first
    successful use."""
    try:
        seed = _load_totp_secret(operator, second_factor)
    except (OperatorTotpDevice.DoesNotExist, crypto.DecryptionError):
        # No enrolled device, or a wrong/absent server second factor: the code
        # cannot be verified, so the factor fails (never crashes the login).
        return False
    if not pyotp.TOTP(seed).verify(code, valid_window=1):
        return False
    OperatorTotpDevice.objects.filter(operator=operator, confirmed=False).update(confirmed=True)
    return True


# --- WebAuthn second factor (py_webauthn) ---------------------------------


def check_and_update_sign_count(
    credential: OperatorWebAuthnCredential, new_sign_count: int
) -> None:
    """Enforce the WebAuthn replay rule and persist the new counter.

    If either counter is non-zero, the new sign_count must strictly increase; a
    non-increase signals a replayed assertion or a cloned authenticator and is
    rejected. (Both zero means the authenticator has no counter — accepted, with
    no counter-based replay protection possible.)
    """
    stored = credential.sign_count
    if (new_sign_count or stored) and new_sign_count <= stored:
        raise ReplayDetected(f"WebAuthn sign_count did not increase ({new_sign_count} <= {stored})")
    credential.sign_count = new_sign_count
    credential.save(update_fields=["sign_count", "last_used_at"])


def verify_webauthn_authentication(
    credential: OperatorWebAuthnCredential,
    *,
    credential_response,
    expected_challenge: bytes,
    expected_rp_id: str,
    expected_origin: str,
    require_user_verification: bool = True,
) -> None:
    """Verify a WebAuthn assertion against the stored public key and apply the
    sign_count replay rule. Raises on invalid assertion or replay."""
    from django.utils import timezone
    from webauthn import verify_authentication_response

    verified = verify_authentication_response(
        credential=credential_response,
        expected_challenge=expected_challenge,
        expected_rp_id=expected_rp_id,
        expected_origin=expected_origin,
        credential_public_key=bytes(credential.public_key),
        credential_current_sign_count=credential.sign_count,
        require_user_verification=require_user_verification,
    )
    credential.last_used_at = timezone.now()
    check_and_update_sign_count(credential, verified.new_sign_count)


# --- login orchestration / role routing -----------------------------------


def login_outcome(operator: Operator) -> AuthResult:
    """Route a *successfully authenticated* operator.

    An Administrator proceeds to vault unlock (will hold the MK); a Viewer does
    not (keyless session). The caller has already verified password + a second
    factor before calling this.
    """
    if not operator.is_active:
        raise PermissionError("operator is not active")
    requires_unlock = operator.role == Operator.Role.ADMINISTRATOR
    return AuthResult(operator=operator, role=operator.role, requires_vault_unlock=requires_unlock)
