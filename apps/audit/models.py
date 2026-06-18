"""Hash-chained, append-only audit log schema (Annex B 3, 4, 6).

This task (P1-T11) defines the schema and append-only enforcement. The hash
chain itself (computing entry_hash under an advisory lock, in the same
transaction as the change) is P1-T12; verification and signed checkpoints are
P1-T13.

Append-only is enforced two ways (apps/audit/migrations/0002):
- a BEFORE UPDATE OR DELETE trigger that raises on both audit tables, and
- database role grants: the app role has INSERT/SELECT only (production
  two-role setup; see deploy/README.md).

No secret leakage (Annex B 1, 6): there is deliberately no ciphertext/plaintext
column. ``changes``/``metadata`` are jsonb for redacted, non-sensitive diffs
only — never the plaintext, never the full ciphertext bytes.

``seq`` is a manually assigned bigint PK (NOT a DB sequence): it must be
gap-free, which P1-T12 guarantees by assigning it under an advisory lock. A DB
sequence could leave gaps on rollback.
"""

import uuid

from django.db import models


class ActorType(models.TextChoices):
    OPERATOR = "operator", "Operator"
    SYSTEM = "system", "System"


class AuditAction(models.TextChoices):
    # Entity lifecycle
    CREATE = "create", "Create"
    UPDATE = "update", "Update"
    STATE_CHANGE = "state_change", "State change"
    # Relationships
    RELATIONSHIP_CREATE = "relationship_create", "Relationship create"
    RELATIONSHIP_END = "relationship_end", "Relationship end"
    # Secrets
    SECRET_CREATE = "secret_create", "Secret create"
    SECRET_ROTATE = "secret_rotate", "Secret rotate"
    SECRET_REVEAL = "secret_reveal", "Secret reveal"
    SECRET_STATE_CHANGE = "secret_state_change", "Secret state change"
    # Authentication
    LOGIN_SUCCESS = "login_success", "Login success"
    LOGIN_FAILURE = "login_failure", "Login failure"
    LOGOUT = "logout", "Logout"
    VAULT_UNLOCK = "vault_unlock", "Vault unlock"
    VAULT_LOCK = "vault_lock", "Vault lock"
    SESSION_REVOKE = "session_revoke", "Session revoke"
    REAUTH = "reauth", "Re-auth"
    # Configuration
    FIELD_DEFINITION_CHANGE = "field_definition_change", "Field definition change"
    OPERATOR_CHANGE = "operator_change", "Operator change"
    PARAMETER_CHANGE = "parameter_change", "Parameter change"
    # Data egress
    EXPORT = "export", "Export"
    # Read access
    RECORD_VIEW = "record_view", "Record view"
    LIST_VIEW = "list_view", "List view"
    SEARCH = "search", "Search"
    # Integrity
    CHAIN_VERIFY = "chain_verify", "Chain verify"
    CHECKPOINT_CREATED = "checkpoint_created", "Checkpoint created"


class AuditEntry(models.Model):
    ActorType = ActorType
    Action = AuditAction

    seq = models.BigIntegerField(primary_key=True)  # assigned under the append lock (P1-T12)
    id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    occurred_at = models.DateTimeField()
    recorded_at = models.DateTimeField(auto_now_add=True)
    actor_type = models.TextField(choices=ActorType.choices)
    actor_operator = models.ForeignKey(
        "operators.Operator",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
        db_column="actor_operator_id",
    )
    actor_username = models.TextField(blank=True, default="")  # snapshot
    session = models.ForeignKey(
        "operators.OperatorSession",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
        db_column="session_id",
    )
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    action = models.TextField(choices=AuditAction.choices)
    target_table = models.TextField(blank=True, default="")
    target_id = models.UUIDField(null=True, blank=True)
    target_label = models.TextField(blank=True, default="")
    changes = models.JSONField(default=dict)  # redacted before/after diff
    metadata = models.JSONField(default=dict)  # extra context (e.g. reveal reason)
    prev_hash = models.BinaryField()
    entry_hash = models.BinaryField()
    hash_algo = models.TextField(default="blake2b-256")
    scheme_version = models.IntegerField(default=1)

    class Meta:
        db_table = "audit_entry"
        indexes = [
            models.Index(fields=["target_table", "target_id"], name="audit_target_idx"),
            models.Index(fields=["action"], name="audit_action_idx"),
            models.Index(fields=["occurred_at"], name="audit_occurred_idx"),
        ]
        constraints = [
            models.UniqueConstraint(fields=["entry_hash"], name="audit_entry_hash_unique"),
            models.CheckConstraint(
                condition=models.Q(actor_type__in=ActorType.values),
                name="audit_actor_type_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(action__in=AuditAction.values),
                name="audit_action_valid",
            ),
        ]

    def __str__(self):
        return f"#{self.seq} {self.action} {self.target_table}:{self.target_id}"


class AuditCheckpoint(models.Model):
    """A signed reference to the chain head (Annex B 4.2, 7).

    Created as a complete, signed row in a single INSERT (P1-T13); never
    updated, so it is append-only like audit_entry.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    seq = models.BigIntegerField()  # head seq at checkpoint time
    head_hash = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        "operators.Operator",
        on_delete=models.PROTECT,
        related_name="+",
    )
    signature = models.BinaryField(null=True, blank=True)  # over head_hash (P1-T13)
    signer = models.TextField(blank=True, default="")
    external_anchor_ref = models.TextField(blank=True, default="")

    class Meta:
        db_table = "audit_checkpoint"

    def __str__(self):
        return f"checkpoint @seq {self.seq}"
