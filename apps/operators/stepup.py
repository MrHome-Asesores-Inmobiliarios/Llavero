"""Step-up reauthentication policy (Annex D 6).

A step-up is a fresh second-factor check on top of an already-open Administrator
session, so a walked-away-from but still-unlocked session cannot perform the
most damaging actions without a deliberate human present.

Two policies:
- **Per-action, no caching:** reveal a secret, create or rotate a secret, create
  a signed checkpoint. Each prompts every time.
- **Windowed (~2 min):** export, operator management, parameter changes. One
  step-up covers a short burst of related admin work, then it re-prompts.

This module decides *whether* a fresh factor is required; the actual WebAuthn/
TOTP verification is P1-T15. Idle auto-lock (which wipes the MK) is the
MasterKeyHolder's job (P1-T8), enforced via apps.operators.sessions.
"""

import time

from django.conf import settings

# Per-action (no caching)
REVEAL = "reveal"
SECRET_CREATE = "secret_create"
SECRET_ROTATE = "secret_rotate"
CHECKPOINT_CREATE = "checkpoint_create"
# Windowed
EXPORT = "export"
OPERATOR_MANAGE = "operator_manage"
PARAMETER_CHANGE = "parameter_change"

PER_ACTION = frozenset({REVEAL, SECRET_CREATE, SECRET_ROTATE, CHECKPOINT_CREATE})
WINDOWED = frozenset({EXPORT, OPERATOR_MANAGE, PARAMETER_CHANGE})


class StepUpRequired(Exception):
    """A fresh second-factor step-up is required for this action."""


class StepUp:
    """Per-session step-up state. A fresh StepUp is created on each login."""

    def __init__(self, *, window_seconds=None, clock=time.monotonic):
        if window_seconds is None:
            window_seconds = settings.LLAVERO_STEPUP_WINDOW_SECONDS
        self._window = float(window_seconds)
        self._clock = clock
        self._windowed_until = None

    def authorize(self, action: str, *, fresh_factor: bool) -> None:
        """Authorize an action, or raise StepUpRequired.

        ``fresh_factor`` is True iff a second factor was just re-verified for
        this request.
        """
        if action in PER_ACTION:
            # Never cached: every per-action call needs a fresh factor.
            if not fresh_factor:
                raise StepUpRequired(f"{action} requires a fresh step-up every time")
            return
        if action in WINDOWED:
            now = self._clock()
            if self._windowed_until is not None and now < self._windowed_until:
                return  # within the window: one step-up covers the burst
            if not fresh_factor:
                raise StepUpRequired(f"{action} requires a step-up")
            self._windowed_until = now + self._window
            return
        raise ValueError(f"unknown step-up action: {action!r}")

    def reset(self) -> None:
        self._windowed_until = None
