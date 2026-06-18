"""Printed recovery key — independent wrap of the master key (Annex A 8).

A high-entropy (256-bit) recovery key is generated at install, wraps the MK
independently of any administrator credential, and is **printed once and stored
in the safe**. It is the anti-lockout path: if every admin passphrase and the
second factor are lost, the printed key alone recovers the MK.

What is stored vs printed:
- Stored (DB, ``vault_recovery_key``): only the *wrapped* MK + nonce and a
  non-secret fingerprint. Never the recovery key itself.
- Printed (shown to the admin once): the recovery code. It is never persisted
  by the application and never logged.

Encoding: base32 (alphabet A-Z2-7, transcription-friendly) of the 32-byte key
plus a 2-byte BLAKE2b checksum, grouped in fours. The checksum turns a
mistyped code into a clear error instead of a confusing decryption failure.

Crypto: the recovery key is high-entropy, so no Argon2id is needed. A
domain-separated BLAKE2b keyed hash derives the 32-byte wrapping key, and the
MK is wrapped with XChaCha20-Poly1305 (reusing apps.vault.crypto). All
libsodium via PyNaCl.

Rotation: MK rotation (P1-T9) invalidates this wrap (it points at the old MK)
and a new recovery key must be established and re-printed.

The full recovery PATH is validated end to end at the P4-T6 gate; here we
exercise the wrap/unwrap so the mechanism is proven early (Annex A 8).
"""

import base64
import binascii

import nacl.encoding
import nacl.hash

from apps.vault import crypto

RECOVERY_KEY_BYTES = 32
_CHECKSUM_BYTES = 2
_GROUP = 4

# Domain-separation labels (BLAKE2b keys) so recovery derivations never collide
# with the per-admin KWK or with each other.
_KWK_LABEL = b"llavero-recovery-kwk"
_CSUM_LABEL = b"llavero-rec-csum"
_FPR_LABEL = b"llavero-recovery-fpr"


class RecoveryCodeError(Exception):
    """The recovery code is malformed or fails its checksum (e.g. a typo)."""


class NoRecoveryKey(Exception):
    """No recovery wrap is stored (never established, or invalidated by rotation)."""


def _b2(data: bytes, *, label: bytes, size: int) -> bytes:
    return nacl.hash.blake2b(data, key=label, digest_size=size, encoder=nacl.encoding.RawEncoder)


def _checksum(key: bytes) -> bytes:
    # BLAKE2b min digest is 16; take the first 2 bytes for a short checksum.
    return _b2(key, label=_CSUM_LABEL, size=16)[:_CHECKSUM_BYTES]


def _encode(key: bytes) -> str:
    raw = key + _checksum(key)
    b32 = base64.b32encode(raw).decode("ascii").rstrip("=")
    return "-".join(b32[i : i + _GROUP] for i in range(0, len(b32), _GROUP))


def decode_recovery_code(code: str) -> bytes:
    """Decode + checksum-verify a (possibly messily typed) recovery code."""
    cleaned = "".join(code.split()).replace("-", "").upper()
    if not cleaned:
        raise RecoveryCodeError("empty recovery code")
    try:
        raw = base64.b32decode(cleaned + "=" * (-len(cleaned) % 8), casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise RecoveryCodeError("recovery code has invalid characters") from exc
    if len(raw) != RECOVERY_KEY_BYTES + _CHECKSUM_BYTES:
        raise RecoveryCodeError("recovery code is the wrong length")
    key, checksum = raw[:RECOVERY_KEY_BYTES], raw[RECOVERY_KEY_BYTES:]
    if checksum != _checksum(key):
        raise RecoveryCodeError("recovery code checksum mismatch (transcription error?)")
    return key


def generate_recovery_key() -> tuple[str, bytes]:
    """Return (printable_code, key_bytes). The code is shown once and printed."""
    import nacl.bindings as sodium

    key = sodium.randombytes(RECOVERY_KEY_BYTES)
    return _encode(key), key


def _recovery_wrapping_key(key: bytes) -> bytes:
    return _b2(key, label=_KWK_LABEL, size=crypto.KEY_BYTES)


def fingerprint(key: bytes) -> str:
    """Non-secret identifier of a recovery key (one-way; safe to store/show)."""
    return _b2(key, label=_FPR_LABEL, size=16).hex()


def wrap_mk(mk: bytes, recovery_key: bytes) -> tuple[bytes, bytes]:
    """Wrap the MK under the recovery key. Returns (rk_wrapped, rk_nonce)."""
    rkwk = bytearray(_recovery_wrapping_key(recovery_key))
    try:
        return crypto.wrap_master_key(mk, bytes(rkwk))
    finally:
        crypto.wipe_buffer(rkwk)


def unwrap_mk(recovery_code: str, rk_wrapped: bytes, rk_nonce: bytes) -> bytes:
    """Recover the MK from the printed code + stored wrap. Raises
    RecoveryCodeError (bad code) or crypto.DecryptionError (wrong key)."""
    key = bytearray(decode_recovery_code(recovery_code))
    try:
        rkwk = bytearray(_recovery_wrapping_key(bytes(key)))
    finally:
        crypto.wipe_buffer(key)
    try:
        return crypto.unwrap_master_key(rk_wrapped, rk_nonce, bytes(rkwk))
    finally:
        crypto.wipe_buffer(rkwk)


# --- model-backed service -------------------------------------------------


def establish_recovery_key(*, mk: bytes, created_by) -> tuple[str, object]:
    """Generate a new recovery key, wrap the MK, and store the wrap.

    Returns (printable_code, VaultRecoveryKey). The code is shown to the admin
    ONCE to print and store in the safe; it is never persisted or logged. Any
    prior recovery wrap is replaced (single active recovery key).
    """
    from django.conf import settings
    from django.db import transaction

    from apps.vault.models import VaultRecoveryKey

    code, key = generate_recovery_key()
    rk_wrapped, rk_nonce = wrap_mk(mk, key)
    fpr = fingerprint(key)
    with transaction.atomic():
        VaultRecoveryKey.objects.all().delete()
        row = VaultRecoveryKey.objects.create(
            rk_wrapped=rk_wrapped,
            rk_nonce=rk_nonce,
            fingerprint=fpr,
            scheme_version=settings.LLAVERO_NACL_SCHEME_VERSION,
            created_by=created_by,
        )
    return code, row


def recover_mk(recovery_code: str) -> bytes:
    """Recover the MK using the printed code and the stored wrap.

    Independent of admin credentials. Raises NoRecoveryKey if none is stored.
    """
    from apps.vault.models import VaultRecoveryKey

    row = VaultRecoveryKey.objects.order_by("-created_at").first()
    if row is None:
        raise NoRecoveryKey("no recovery key is established")
    return unwrap_mk(recovery_code, bytes(row.rk_wrapped), bytes(row.rk_nonce))
