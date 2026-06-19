"""Single active session + keyless Viewer (Annex D 2, 8; Annex C 4.3).

One active session at a time, system-wide: a new login is serialised by a
constant advisory lock and revokes any prior active session, so two privileged
sessions can never be active at once.

Keyless Viewer (the strongest part of the model, Annex D 2): the in-process
master-key holder is unlocked only for an Administrator session. A Viewer
session leaves it locked, so a Viewer — even if fully compromised — has no key
to decrypt with. It is a cryptographic fact, not just a permission check.

Only the session token's hash is stored, never the token. Logging of
login/logout/revoke into the audit chain is wired with the login view (the
P1-T19 slice).
"""

import hashlib
import secrets
import threading
import time

import nacl.encoding
import nacl.hash
from django.db import connection, transaction
from django.utils import timezone

from apps.operators.models import Operator, OperatorSession
from apps.operators.stepup import StepUp
from apps.vault.memory import MasterKeyHolder

# Constant advisory-lock key (signed 64-bit) serialising logins across
# connections, so two logins cannot race into two active sessions.
LOGIN_LOCK_KEY = int.from_bytes(
    nacl.hash.blake2b(b"llavero-login", digest_size=8, encoder=nacl.encoding.RawEncoder),
    "big",
    signed=True,
)

# Process-global holder for the single privileged session's master key, plus a
# lock guarding in-memory holder access across threads. ``_stepup`` is the
# step-up state for the current privileged session (reset on each login).
_holder_instance: MasterKeyHolder | None = None
_stepup_instance: StepUp | None = None
_holder_clock = time.monotonic
_HOLDER_LOCK = threading.Lock()


class SessionError(Exception):
    """The session could not be established as requested."""


def _holder() -> MasterKeyHolder:
    global _holder_instance
    if _holder_instance is None:
        _holder_instance = MasterKeyHolder(clock=_holder_clock)
    return _holder_instance


def configure_holder(*, idle_seconds=None, clock=None) -> None:
    """(Re)create the master-key holder, e.g. at startup or in tests.

    Wipes any current MK first. ``clock`` lets tests drive idle auto-lock.
    """
    global _holder_instance, _holder_clock
    with _HOLDER_LOCK:
        if _holder_instance is not None:
            _holder_instance.lock()
        _holder_clock = clock or time.monotonic
        _holder_instance = MasterKeyHolder(idle_seconds=idle_seconds, clock=_holder_clock)


def current_step_up() -> StepUp:
    """The step-up state for the active privileged session."""
    global _stepup_instance
    if _stepup_instance is None:
        _stepup_instance = StepUp()
    return _stepup_instance


def touch() -> None:
    """Record activity, postponing idle auto-lock."""
    with _HOLDER_LOCK:
        _holder().touch()


def enforce_idle() -> bool:
    """Wipe the MK if the idle window elapsed. Returns True if now locked."""
    with _HOLDER_LOCK:
        return _holder().enforce_idle()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def establish_session(*, operator: Operator, ip: str, mk: bytearray | bytes | None = None):
    """Log a session in: revoke any prior active session and create a new one.

    For an Administrator, ``mk`` (the already-unlocked master key from P1-T9) is
    taken into the in-process holder. For a Viewer, the holder is locked — the
    session is keyless. Returns (OperatorSession, raw_token); only the token's
    hash is persisted.
    """
    if not operator.is_active:
        raise SessionError("operator is not active")
    if operator.role == Operator.Role.ADMINISTRATOR and mk is None:
        raise SessionError("an Administrator session requires the unlocked master key")

    token = _new_token()
    with _HOLDER_LOCK:
        with transaction.atomic():
            # Serialise logins so the revoke+create is atomic across connections.
            with connection.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%s)", [LOGIN_LOCK_KEY])
            OperatorSession.objects.filter(revoked_at__isnull=True).update(
                revoked_at=timezone.now()
            )
            session = OperatorSession.objects.create(
                operator=operator, token_hash=_hash_token(token), ip=ip
            )

        global _stepup_instance
        _stepup_instance = StepUp()  # fresh step-up state per session
        holder = _holder()
        if operator.role == Operator.Role.ADMINISTRATOR:
            holder.unlock(bytearray(mk))
        else:
            holder.lock()  # keyless Viewer: never holds the MK
    return session, token


def logout(session: OperatorSession) -> None:
    """Revoke a session and wipe the master key from memory."""
    with _HOLDER_LOCK:
        session.revoke()
        _holder().lock()


def lock_vault() -> None:
    """Wipe the master key (idle auto-lock / shutdown)."""
    with _HOLDER_LOCK:
        _holder().lock()


def is_vault_unlocked() -> bool:
    return _holder().is_unlocked()


def current_master_key() -> bytes:
    """The active privileged session's master key.

    Raises MasterKeyLocked if the vault is locked — which is always the case for
    a Viewer session, so a forced reveal has nothing to decrypt with.
    """
    return _holder().get_master_key()
