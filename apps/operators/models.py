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
