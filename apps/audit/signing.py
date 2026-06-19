"""Checkpoint signing keys (Annex B 7; Annex G 7).

A signed checkpoint is the defence against a full chain rewrite: the head hash
is signed with a key the database/server process does NOT hold, and verification
uses only the public key.

Production signer: the Administrator WebAuthn credential — the head hash is the
authenticator challenge, the private key never leaves the authenticator, and the
server stores only the public key (in operator_webauthn_credential) and the
signed assertion. That ceremony is interactive (hardware + browser) and is wired
in the auth/web phase.

Unattended alternative (Annex G 7), implemented and tested here: an offline
Ed25519 key (PyNaCl). The private signing key is kept offline with the recovery
material; the server stores only the public key + signature.

This module is pure crypto (no DB, no chain dependency) so the verifier and the
checkpoint creator can both import it without cycles.
"""

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


class SignatureError(Exception):
    """Unsupported or malformed checkpoint signature."""


class Ed25519CheckpointSigner:
    """Offline Ed25519 signer (Annex G 7 unattended alternative).

    Constructed wherever signing happens (offline, or in an admin action) — the
    private key is never persisted to the database. ``signing_key_bytes`` is
    exposed only so the offline key can be stored with the recovery material.
    """

    algo = "ed25519"

    def __init__(self, signing_key: bytes | None = None):
        self._sk = SigningKey(signing_key) if signing_key else SigningKey.generate()
        self.public_key = bytes(self._sk.verify_key)

    @property
    def signing_key_bytes(self) -> bytes:
        return bytes(self._sk)

    def sign(self, message: bytes) -> bytes:
        """Detached 64-byte signature over ``message`` (the chain head hash)."""
        return self._sk.sign(message).signature


def verify_signature(algo: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a checkpoint signature against a trusted public key.

    The caller supplies the public key it independently trusts (the enrolled
    admin credential or the configured offline key) — never one taken from the
    checkpoint row, which an attacker could replace.
    """
    if algo == "ed25519":
        try:
            VerifyKey(public_key).verify(message, signature)
            return True
        except BadSignatureError:
            return False
    if algo == "webauthn":
        raise SignatureError(
            "WebAuthn checkpoint verification is wired in the auth/web phase "
            "(py_webauthn assertion over the head-hash challenge)"
        )
    raise SignatureError(f"unsupported checkpoint signature algo: {algo!r}")
