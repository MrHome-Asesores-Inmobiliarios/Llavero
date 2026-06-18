"""Vault second factor (Annex A 5.2; Annex G 4).

The second factor is a 256-bit secret that lives OUTSIDE the database and its
backups. It is combined with the Argon2id output to form the KWK (see
``apps.vault.crypto.derive_kwk``), so a stolen database backup — even with the
passphrase — cannot derive the master key.

Two providers:

- ``TPMSecondFactor`` (recommended, Annex G 4): the secret is sealed to the
  server TPM 2.0 and can only be unsealed on that machine. The seal/unseal is a
  subprocess to the platform's tpm2 tooling and is finalised on the hardened
  server (P0-T6); here the seam is injectable and defaults to raising rather
  than silently degrading.
- ``KeyfileSecondFactor`` (fallback): a 256-bit keyfile with owner-only
  permissions, kept off the backup path. Portable, therefore slightly weaker.

Anti-lockout: a dead TPM or a lost keyfile is recovered via the printed
recovery key (Annex A 8, P1-T10) — an independent wrap of the MK. That is the
reason hardware-binding the factor is safe.

This module never logs the factor, the passphrase, or the MK, and never writes
the MK to disk. The keyfile holds only the second factor, never the MK.
"""

import os
from abc import ABC, abstractmethod
from collections.abc import Callable

import nacl.bindings as sodium

from apps.vault import crypto

SECOND_FACTOR_BYTES = 32  # 256-bit


class SecondFactorUnavailable(Exception):
    """The second factor could not be obtained (missing keyfile, no TPM, etc.).

    Always raised loudly rather than returning a weak/empty secret, so a
    misconfiguration can never silently weaken the KWK.
    """


class SecondFactorProvider(ABC):
    @abstractmethod
    def get_secret(self) -> bytes:
        """Return the 256-bit factor, or raise SecondFactorUnavailable."""


class KeyfileSecondFactor(SecondFactorProvider):
    """Keyfile fallback: a 256-bit secret on disk, kept off the backup path."""

    def __init__(self, path: str):
        self.path = path

    @classmethod
    def provision(cls, path: str) -> "KeyfileSecondFactor":
        """Generate a fresh 256-bit keyfile with owner-only permissions."""
        secret = sodium.randombytes(SECOND_FACTOR_BYTES)
        # Create with 0o600 from the start so the bytes are never briefly
        # world-readable. O_BINARY (Windows only; 0 on POSIX) prevents text-mode
        # newline translation from corrupting a keyfile that contains 0x0A.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o600)
        try:
            os.write(fd, secret)
        finally:
            os.close(fd)
        try:
            os.chmod(path, 0o600)  # enforce on POSIX; best-effort elsewhere
        except OSError:
            pass
        return cls(path)

    def get_secret(self) -> bytes:
        try:
            with open(self.path, "rb") as fh:
                secret = fh.read()
        except OSError as exc:
            raise SecondFactorUnavailable(f"keyfile not readable at {self.path}") from exc
        if len(secret) != SECOND_FACTOR_BYTES:
            raise SecondFactorUnavailable("keyfile is not a 256-bit secret")
        return secret


def _tpm_unavailable(*_args, **_kwargs):
    raise SecondFactorUnavailable(
        "TPM sealing is not wired here; finalise on the hardened server (P0-T6) "
        "or use the keyfile fallback"
    )


class TPMSecondFactor(SecondFactorProvider):
    """TPM 2.0-sealed second factor.

    The sealed blob is bound to the server TPM and is useless off that machine,
    so it may live in the database/on disk. The actual seal/unseal is injected:
    on the server it shells out to tpm2 tooling (see deploy/README.md); in tests
    a fake seam exercises the contract. With no seam it raises.
    """

    def __init__(self, sealed_blob: bytes, unseal_fn: Callable[[bytes], bytes] | None = None):
        self.sealed_blob = sealed_blob
        self._unseal_fn = unseal_fn or _tpm_unavailable

    @classmethod
    def provision(
        cls,
        *,
        seal_fn: Callable[[bytes], bytes] | None = None,
        unseal_fn: Callable[[bytes], bytes] | None = None,
    ) -> "TPMSecondFactor":
        seal = seal_fn or _tpm_unavailable
        secret = bytearray(sodium.randombytes(SECOND_FACTOR_BYTES))
        try:
            blob = seal(bytes(secret))
        finally:
            crypto.wipe_buffer(secret)
        return cls(blob, unseal_fn=unseal_fn)

    def get_secret(self) -> bytes:
        secret = self._unseal_fn(self.sealed_blob)
        if len(secret) != SECOND_FACTOR_BYTES:
            raise SecondFactorUnavailable("unsealed secret has the wrong length")
        return secret


def load_second_factor() -> SecondFactorProvider:
    """Select the configured provider (Annex G 4: TPM preferred, keyfile fallback)."""
    from django.conf import settings

    mode = getattr(settings, "LLAVERO_SECOND_FACTOR_MODE", "keyfile")
    if mode == "keyfile":
        path = getattr(settings, "LLAVERO_KEYFILE_PATH", "")
        if not path:
            raise SecondFactorUnavailable("LLAVERO_KEYFILE_PATH is not set")
        return KeyfileSecondFactor(path)
    if mode == "tpm":
        # The server wiring constructs TPMSecondFactor with the stored blob and
        # the real unseal seam; it is intentionally not auto-wired on dev.
        raise SecondFactorUnavailable("TPM provider must be wired on the server (P0-T6)")
    raise SecondFactorUnavailable(f"unknown second factor mode: {mode!r}")


def unlock_master_key(
    provider: SecondFactorProvider,
    passphrase: bytes,
    salt: bytes,
    params,
    mk_wrapped: bytes,
    mk_nonce: bytes,
) -> bytes:
    """Unlock flow (Annex A 5.3): passphrase + factor -> KWK -> unwrap MK.

    Raises SecondFactorUnavailable if the factor is missing, or
    DecryptionError if the passphrase/factor is wrong. Intermediate key
    material (the factor and the KWK) is wiped; the returned MK's protected
    lifetime is managed by P1-T8.
    """
    secret = bytearray(provider.get_secret())
    try:
        kwk = bytearray(crypto.derive_kwk(passphrase, salt, params, bytes(secret)))
    finally:
        crypto.wipe_buffer(secret)
    try:
        return crypto.unwrap_master_key(mk_wrapped, mk_nonce, bytes(kwk))
    finally:
        crypto.wipe_buffer(kwk)
