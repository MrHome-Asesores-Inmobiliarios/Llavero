"""Session handover — hybrid B+C state machine (Annex D 8 chosen config; C 4.3b).

When admin B wants in while admin A is active, B raises a SessionRequest. The
request resolves through: pending -> granted / denied / expired / cancelled.

Triggers (whichever fires first wins):
- **Release now** — A hands over immediately (disabled for the first 5 s so it
  cannot be dismissed reflexively).
- **Deny** — A refuses.
- **Idle auto-yield (120 s)** — A inactive for 120 s hands over early.
- **Grace countdown (300 s, + 600 s per extend)** — hard ceiling; at 0 it
  auto-transfers.
- **Cancel** — B withdraws the request.
- **Expired** — A's session ended on its own before resolution; nothing to hand
  over.

Handover NEVER transfers the master key (Annex D 8): on grant the outgoing
session is revoked, its MK is wiped, and in-progress work is saved as a draft.
The incoming admin then unlocks with their OWN passphrase + second factor
(per-administrator wrapping, Annex A 13) — a separate login, not a key transfer.

The depleting-bar UI (amber <60 s, red <20 s, release locked first 5 s) is the
web phase; this module owns the state + timing.
"""

from datetime import timedelta

from django.conf import settings
from django.db import connection, transaction
from django.utils import timezone

from apps.operators import sessions
from apps.operators.models import Operator, SessionRequest, SessionRequestState

State = SessionRequestState


class HandoverError(Exception):
    """An invalid handover transition or guard violation."""


def _cfg():
    return (
        settings.LLAVERO_HANDOVER_IDLE_YIELD_SECONDS,
        settings.LLAVERO_HANDOVER_GRACE_SECONDS,
        settings.LLAVERO_HANDOVER_EXTEND_SECONDS,
        settings.LLAVERO_HANDOVER_RELEASE_LOCK_SECONDS,
    )


def request_access(*, requested_by: Operator, current_session, now=None) -> SessionRequest:
    """B requests access to the active session A. One pending request at a time."""
    now = now or timezone.now()
    _, grace, _, _ = _cfg()
    if requested_by.id == current_session.operator_id:
        raise HandoverError("cannot request access to your own session")
    with transaction.atomic():
        with connection.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", [sessions.LOGIN_LOCK_KEY])
        if SessionRequest.objects.filter(
            current_session=current_session, state=State.PENDING
        ).exists():
            raise HandoverError("a request is already pending for this session")
        return SessionRequest.objects.create(
            requested_by=requested_by,
            current_session=current_session,
            state=State.PENDING,
            expires_at=now + timedelta(seconds=grace),
        )


def _ensure_pending(request: SessionRequest) -> None:
    if request.state != State.PENDING:
        raise HandoverError(f"request is {request.state}, not pending")


def _resolve(request, *, state, by, now):
    request.state = state
    request.resolved_at = now
    request.resolved_by = by
    request.save(update_fields=["state", "resolved_at", "resolved_by"])


def _grant(request, *, by, now, draft_saver):
    """Hand over WITHOUT transferring the key: revoke the outgoing session, wipe
    the MK, save outgoing work as a draft, then mark the request granted."""
    request.current_session.revoke()
    sessions.lock_vault()  # the outgoing MK is wiped; never handed to B
    if draft_saver is not None:
        draft_saver()  # in-progress work preserved as a draft (Phase 3 UI)
    _resolve(request, state=State.GRANTED, by=by, now=now)


def release_now(request, *, by: Operator, now=None, draft_saver=None) -> SessionRequest:
    now = now or timezone.now()
    _ensure_pending(request)
    _, _, _, release_lock = _cfg()
    if (now - request.requested_at).total_seconds() < release_lock:
        raise HandoverError(f"release is locked for the first {release_lock}s")
    if by.id != request.current_session.operator_id:
        raise HandoverError("only the active admin can release the session")
    _grant(request, by=by, now=now, draft_saver=draft_saver)
    return request


def deny(request, *, by: Operator, now=None) -> SessionRequest:
    now = now or timezone.now()
    _ensure_pending(request)
    if by.id != request.current_session.operator_id:
        raise HandoverError("only the active admin can deny the request")
    _resolve(request, state=State.DENIED, by=by, now=now)
    return request


def cancel(request, *, by: Operator, now=None) -> SessionRequest:
    now = now or timezone.now()
    _ensure_pending(request)
    if by.id != request.requested_by_id:
        raise HandoverError("only the requester can cancel the request")
    _resolve(request, state=State.CANCELLED, by=by, now=now)
    return request


def extend(request, *, by: Operator, now=None) -> SessionRequest:
    now = now or timezone.now()
    _ensure_pending(request)
    if by.id != request.current_session.operator_id:
        raise HandoverError("only the active admin can extend the grace period")
    _, _, extend_seconds, _ = _cfg()
    request.expires_at = request.expires_at + timedelta(seconds=extend_seconds)
    request.save(update_fields=["expires_at"])
    return request


def tick(request, *, now=None, draft_saver=None) -> SessionRequest:
    """System tick: auto-transfer on idle (120 s) or grace expiry, or mark the
    request expired if the active session has already ended."""
    now = now or timezone.now()
    if request.state != State.PENDING:
        return request
    session = request.current_session
    session.refresh_from_db()
    if session.revoked_at is not None:
        # A's session ended on its own — nothing to hand over.
        _resolve(request, state=State.EXPIRED, by=None, now=now)
        return request
    idle_yield, _, _, _ = _cfg()
    idle_elapsed = (now - session.last_activity_at).total_seconds()
    if idle_elapsed >= idle_yield or now >= request.expires_at:
        _grant(request, by=None, now=now, draft_saver=draft_saver)  # auto-transfer
    return request
