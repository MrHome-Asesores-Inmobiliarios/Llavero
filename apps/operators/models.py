"""Operator identity models (Annex C 4.1, 4.2).

An Operator is one of the 1-2 people who log in (roles Administrator and
Viewer). It is the subject of authentication and is never conflated with a
Person (the subject of inventoried data).

``password_hash`` holds the Argon2id *login* hash, which is entirely separate
from the vault master key (Annex A). The hashing logic is built in P1-T15;
here the column simply exists.

Session tables (operator_session, session_request) are P1-T4, not this task.

Enums are module-level TextChoices (so Meta CHECK constraints can reference
``.values``) and aliased onto each model for ergonomic access, e.g.
``Operator.Role.ADMINISTRATOR``.
"""

import uuid

from django.db import models
from django.utils import timezone

from apps.common.models import UUIDModel


class OperatorRole(models.TextChoices):
    ADMINISTRATOR = "administrator", "Administrator"
    VIEWER = "viewer", "Viewer"


class Operator(models.Model):
    Role = OperatorRole

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.TextField(unique=True)
    display_name = models.TextField()
    role = models.TextField(choices=OperatorRole.choices)
    # Argon2id login hash, separate from the vault master key (Annex A).
    password_hash = models.TextField()
    is_active = models.BooleanField(default=True)
    last_login_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "operator"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(role__in=OperatorRole.values),
                name="operator_role_valid",
            ),
        ]

    def __str__(self):
        return f"{self.username} ({self.role})"


class OperatorWebAuthnCredential(models.Model):
    """A registered WebAuthn authenticator for an operator.

    The server stores only the public key and credential id; the private key
    never leaves the authenticator (Annex G 7). ``sign_count`` backs replay
    protection, enforced in P1-T15.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    operator = models.ForeignKey(
        Operator,
        on_delete=models.PROTECT,
        related_name="webauthn_credentials",
    )
    credential_id = models.BinaryField()
    public_key = models.BinaryField()
    sign_count = models.BigIntegerField(default=0)
    label = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "operator_webauthn_credential"
        constraints = [
            models.UniqueConstraint(
                fields=["credential_id"],
                name="operator_webauthn_credential_id_unique",
            ),
        ]


class OperatorSession(UUIDModel):
    """Backs the single-active-session rule (Annex C 4.3, Annex D 2).

    Security: only ``token_hash`` is stored, never the session token itself.
    The hashing happens in P1-T16; this table holds the hash column only.
    ``last_activity_at`` drives the idle auto-lock (P1-T17); ``revoked_at`` is
    set when a new privileged login supersedes this session.
    """

    operator = models.ForeignKey(
        Operator,
        on_delete=models.PROTECT,
        related_name="sessions",
    )
    # Hash of the session token, NEVER the token (Annex C 4.3).
    token_hash = models.TextField()
    ip = models.GenericIPAddressField()
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity_at = models.DateTimeField(default=timezone.now)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "operator_session"
        indexes = [
            models.Index(fields=["operator", "revoked_at"], name="operator_session_active_idx"),
        ]

    @property
    def is_active(self):
        return self.revoked_at is None

    def revoke(self, when=None):
        """Revoke this session (set on a new login). Never deletes the row."""
        self.revoked_at = when or timezone.now()
        self.save(update_fields=["revoked_at"])

    def touch(self, when=None):
        """Record activity to push back the idle auto-lock clock."""
        self.last_activity_at = when or timezone.now()
        self.save(update_fields=["last_activity_at"])


class SessionRequestState(models.TextChoices):
    PENDING = "pending", "Pending"
    GRANTED = "granted", "Granted"
    DENIED = "denied", "Denied"
    EXPIRED = "expired", "Expired"
    CANCELLED = "cancelled", "Cancelled"


class SessionRequest(UUIDModel):
    """Backs session handover logistics (Annex C 4.3b, Annex D 8).

    An operator asks an active session to yield; the state machine moves
    pending -> granted/denied/expired/cancelled. The key is never transferred
    by this flow (handover wipes the outgoing MK and the incoming admin
    unlocks with their own credentials).
    """

    State = SessionRequestState

    requested_by = models.ForeignKey(
        Operator,
        on_delete=models.PROTECT,
        related_name="session_requests",
    )
    current_session = models.ForeignKey(
        OperatorSession,
        on_delete=models.PROTECT,
        related_name="requests",
    )
    state = models.TextField(
        choices=SessionRequestState.choices, default=SessionRequestState.PENDING
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        Operator,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
    )

    class Meta:
        db_table = "session_request"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(state__in=SessionRequestState.values),
                name="session_request_state_valid",
            ),
        ]
