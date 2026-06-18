"""Envelope encryption (Annex A 3, 4, 11; Annex C 4.9).

Key hierarchy (Annex A 4)::

    passphrase ──Argon2id (kdf.derive_raw_key)──▶ base key material
    KWK = BLAKE2b(base, key=second_factor)        # combine w/ out-of-DB factor
    MK  (256-bit, generated once)  wrapped under KWK   (XChaCha20-Poly1305)
    DEK (one per secret)           wrapped under MK    (XChaCha20-Poly1305)
    ciphertext = XChaCha20-Poly1305(plaintext, AAD, DEK)

AAD binds each ciphertext to the record it belongs to
(``owner_type:owner_id:kind``). Moving a ciphertext or its wrapped DEK to a
different record changes the AAD, so the Poly1305 tag check fails — a ciphertext
cannot be relocated (Annex A 3).

Cryptographic choices (no invented crypto — Annex A, libsodium via PyNaCl):
- AEAD: XChaCha20-Poly1305 IETF, 24-byte random nonce, 256-bit key, 128-bit tag.
- KWK combiner: libsodium BLAKE2b *keyed* hash. PyNaCl 1.5 exposes no HKDF/
  crypto_kdf, and the Annex §11 reference combines the Argon2id output with the
  second factor using libsodium BLAKE2b. Using the second factor as the BLAKE2b
  key is the canonical libsodium pattern and keeps us on the pinned stack
  (PyNaCl + argon2-cffi; pulling in `cryptography` for HKDF would break that).

Security boundaries:
- This module NEVER logs secrets, keys, or passphrases.
- The MK is passed in as bytes. Holding it in mlock'd / memzero'd memory with
  idle auto-lock is P1-T8; this module only performs the crypto operations.
- The real second factor (TPM 2.0 seal / keyfile) is provided by P1-T7; here it
  is an opaque input.
- The per-secret DEK is generated in a mutable buffer and best-effort wiped
  after use; Python cannot guarantee zeroization of immutable copies, so the
  durable guarantee also rides on P1-T8's protected memory.
"""

import nacl.bindings as sodium
import nacl.encoding
import nacl.exceptions
import nacl.hash

KEY_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES  # 32
NONCE_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24
MIN_SECOND_FACTOR_BYTES = 16


class DecryptionError(Exception):
    """Authenticated decryption failed (tamper, wrong key, or wrong AAD).

    Carries no secret material. Callers treat this as a hard rejection.
    """


def wipe_buffer(buf: bytearray) -> None:
    """Best-effort zeroisation of a mutable key buffer (see module note).

    Durable, guaranteed wiping of long-lived key material is P1-T8 (mlock +
    sodium_memzero); this overwrites short-lived intermediates in place.
    """
    for i in range(len(buf)):
        buf[i] = 0


def generate_master_key() -> bytes:
    """A fresh 256-bit master key (generated once at install, Annex A 4)."""
    return sodium.randombytes(KEY_BYTES)


def derive_kwk(passphrase: bytes, salt: bytes, params, second_factor: bytes) -> bytes:
    """Derive the Key Wrapping Key from passphrase + out-of-database factor.

    ``params`` is an ``apps.vault.kdf.Argon2Params``. The Argon2id step is the
    slow, memory-hard work; the result is combined with the second factor via a
    BLAKE2b keyed hash. Never stored — recomputed at each unlock.
    """
    if len(second_factor) < MIN_SECOND_FACTOR_BYTES:
        raise ValueError("second factor is too short to be a real key")
    # Imported lazily to avoid any import cycle and to keep this module's import
    # cheap for callers that only need the AEAD helpers.
    from apps.vault.kdf import derive_raw_key

    base = bytearray(derive_raw_key(passphrase, salt, params))
    try:
        return nacl.hash.blake2b(
            bytes(base),
            key=second_factor,
            digest_size=KEY_BYTES,
            encoder=nacl.encoding.RawEncoder,
        )
    finally:
        wipe_buffer(base)


def _aead_encrypt(plaintext: bytes, aad: bytes, key: bytes) -> tuple[bytes, bytes]:
    nonce = sodium.randombytes(NONCE_BYTES)
    ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return ciphertext, nonce


def _aead_decrypt(ciphertext: bytes, aad: bytes, nonce: bytes, key: bytes) -> bytes:
    try:
        return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)
    except (nacl.exceptions.CryptoError, ValueError) as exc:
        # Re-raise without echoing any inputs (no secret material in the message).
        raise DecryptionError("authenticated decryption failed") from exc


def wrap_master_key(mk: bytes, kwk: bytes) -> tuple[bytes, bytes]:
    """Encrypt the MK under the KWK. Returns (mk_wrapped, mk_nonce)."""
    return _aead_encrypt(mk, b"", kwk)


def unwrap_master_key(mk_wrapped: bytes, mk_nonce: bytes, kwk: bytes) -> bytes:
    """Decrypt the wrapped MK. Raises DecryptionError if the KWK is wrong
    (wrong passphrase or wrong/absent second factor)."""
    return _aead_decrypt(mk_wrapped, b"", mk_nonce, kwk)


def build_aad(owner_type: str, owner_id, kind: str) -> bytes:
    """Canonical associated data binding a secret to its record (Annex A 3).

    Stored as ``Secret.aad_context`` and recomputed from the record's
    authoritative identity at decrypt time, so a ciphertext cannot be moved to
    a different owner without the tag failing.
    """
    return f"{owner_type}:{owner_id}:{kind}".encode()


def encrypt_secret(mk: bytes, plaintext: bytes, aad: bytes) -> dict:
    """Encrypt one secret: fresh DEK, AEAD over plaintext bound to ``aad``, then
    wrap the DEK under the MK. Returns the storable fields only."""
    dek = bytearray(sodium.randombytes(KEY_BYTES))
    try:
        ciphertext, nonce = _aead_encrypt(plaintext, aad, bytes(dek))
        dek_wrapped, dek_nonce = _aead_encrypt(bytes(dek), b"", mk)
    finally:
        wipe_buffer(dek)
    return {
        "ciphertext": ciphertext,
        "nonce": nonce,
        "dek_wrapped": dek_wrapped,
        "dek_nonce": dek_nonce,
    }


def decrypt_secret(
    mk: bytes,
    *,
    ciphertext: bytes,
    nonce: bytes,
    dek_wrapped: bytes,
    dek_nonce: bytes,
    aad: bytes,
) -> bytes:
    """Unwrap the DEK with the MK, then decrypt the ciphertext bound to ``aad``.

    Raises DecryptionError on any tamper, wrong MK, or AAD mismatch.
    """
    dek = bytearray(_aead_decrypt(dek_wrapped, b"", dek_nonce, mk))
    try:
        return _aead_decrypt(ciphertext, aad, nonce, bytes(dek))
    finally:
        wipe_buffer(dek)


# --- record-shaped layer (maps to the Secret storage fields) --------------
# Pure functions (no ORM): persistence and the audited reveal flow are P4.


def seal(mk: bytes, *, owner_type: str, owner_id, kind: str, plaintext: bytes) -> dict:
    """Encrypt ``plaintext`` for a record, returning all storable Secret fields.

    The AAD is derived from the record identity and recorded as ``aad_context``;
    ``scheme_version`` is stamped from settings so future scheme upgrades can be
    detected per row (Annex A 9, Annex C 4.9).
    """
    from django.conf import settings

    aad = build_aad(owner_type, owner_id, kind)
    row = encrypt_secret(mk, plaintext, aad)
    row["aad_context"] = aad.decode()
    row["scheme_version"] = settings.LLAVERO_NACL_SCHEME_VERSION
    return row


def open_sealed(
    mk: bytes,
    *,
    owner_type: str,
    owner_id,
    kind: str,
    ciphertext: bytes,
    nonce: bytes,
    dek_wrapped: bytes,
    dek_nonce: bytes,
    aad_context: str | None = None,
) -> bytes:
    """Decrypt a stored secret, rebuilding the AAD from the record identity.

    The AAD is recomputed from ``owner_type``/``owner_id``/``kind`` rather than
    trusted from storage, so a ciphertext relocated to another record fails. If
    a stored ``aad_context`` is supplied it must match the recomputed value.
    """
    aad = build_aad(owner_type, owner_id, kind)
    if aad_context is not None and aad_context.encode() != aad:
        raise DecryptionError("aad_context does not match the record identity")
    return decrypt_secret(
        mk,
        ciphertext=ciphertext,
        nonce=nonce,
        dek_wrapped=dek_wrapped,
        dek_nonce=dek_nonce,
        aad=aad,
    )
