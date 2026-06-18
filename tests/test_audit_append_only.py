"""P1-T11 acceptance + security-property tests (Annex B 4, 5; Annex G 5).

Brief acceptance criteria:
- UPDATE/DELETE on audit_entry as the app role fails by both grant and trigger
- INSERT/SELECT work

Mechanisms:
- A BEFORE UPDATE OR DELETE trigger raises on both audit tables. This fires for
  every role (including the owner), so it is tested directly here.
- The app role is granted INSERT/SELECT only. In dev the single owner role is
  unaffected by grants (the trigger is the dev safeguard), so the grant *model*
  is proven with a probe role via has_table_privilege; the production two-role
  setup is in deploy/README.md / deploy/audit-roles.sql.
"""

import os
import uuid
from datetime import UTC, datetime

import pytest
from django.db import DatabaseError, connection, transaction

from apps.audit.models import AuditCheckpoint, AuditEntry
from apps.operators.models import Operator

ZERO32 = b"\x00" * 32


@pytest.fixture
def admin_operator(db):
    return Operator.objects.create(
        username="admin", display_name="Admin", role=Operator.Role.ADMINISTRATOR, password_hash="x"
    )


def _entry(seq, **kw):
    defaults = dict(
        seq=seq,
        occurred_at=datetime.now(UTC),
        actor_type=AuditEntry.ActorType.SYSTEM,
        action=AuditEntry.Action.CHECKPOINT_CREATED,
        target_table="",
        prev_hash=ZERO32,
        entry_hash=os.urandom(32),
        hash_algo="blake2b-256",
    )
    defaults.update(kw)
    return AuditEntry.objects.create(**defaults)


# --- INSERT / SELECT work -------------------------------------------------


@pytest.mark.django_db
def test_insert_and_select_work():
    e = _entry(1)
    assert AuditEntry.objects.get(seq=1).id == e.id
    assert isinstance(e.id, uuid.UUID)


# --- UPDATE / DELETE blocked by the trigger -------------------------------


@pytest.mark.django_db
def test_update_blocked_by_trigger_orm():
    _entry(1)
    with pytest.raises(DatabaseError):
        with transaction.atomic():
            AuditEntry.objects.filter(seq=1).update(target_label="tampered")


@pytest.mark.django_db
def test_update_blocked_by_trigger_raw_sql():
    _entry(1)
    with pytest.raises(DatabaseError):
        with transaction.atomic(), connection.cursor() as cur:
            cur.execute("UPDATE audit_entry SET action = 'create' WHERE seq = 1")


@pytest.mark.django_db
def test_delete_blocked_by_trigger_orm():
    _entry(1)
    with pytest.raises(DatabaseError):
        with transaction.atomic():
            AuditEntry.objects.filter(seq=1).delete()
    # The row survives the blocked delete.
    assert AuditEntry.objects.filter(seq=1).exists()


@pytest.mark.django_db
def test_delete_blocked_by_trigger_raw_sql():
    _entry(1)
    with pytest.raises(DatabaseError):
        with transaction.atomic(), connection.cursor() as cur:
            cur.execute("DELETE FROM audit_entry WHERE seq = 1")


@pytest.mark.django_db
def test_checkpoint_table_is_also_append_only(admin_operator):
    cp = AuditCheckpoint.objects.create(
        seq=1, head_hash=os.urandom(32), created_by=admin_operator, signer="test"
    )
    with pytest.raises(DatabaseError):
        with transaction.atomic():
            AuditCheckpoint.objects.filter(pk=cp.pk).update(signer="x")
    with pytest.raises(DatabaseError):
        with transaction.atomic():
            AuditCheckpoint.objects.filter(pk=cp.pk).delete()


# --- grant model: an app role gets INSERT/SELECT only ---------------------


@pytest.mark.django_db
def test_app_role_grant_model_has_no_update_or_delete():
    # Prove the production grant model: a role granted INSERT/SELECT on the
    # audit tables must NOT thereby gain UPDATE/DELETE. Uses a NOLOGIN probe
    # role created in-transaction (rolled back at test end).
    with connection.cursor() as cur:
        cur.execute("CREATE ROLE llavero_app_probe NOLOGIN")
        cur.execute("GRANT INSERT, SELECT ON audit_entry TO llavero_app_probe")
        expectations = {"INSERT": True, "SELECT": True, "UPDATE": False, "DELETE": False}
        for priv, expected in expectations.items():
            cur.execute(
                "SELECT has_table_privilege('llavero_app_probe', 'audit_entry', %s)", [priv]
            )
            assert cur.fetchone()[0] is expected, f"{priv} privilege mismatch"


@pytest.mark.django_db
def test_public_cannot_update_or_delete_audit_tables():
    # The migration REVOKEs UPDATE/DELETE from PUBLIC. A fresh NOLOGIN role with
    # no explicit grants (so it has only PUBLIC privileges) must not be able to
    # UPDATE/DELETE the audit tables.
    with connection.cursor() as cur:
        cur.execute("CREATE ROLE llavero_public_probe NOLOGIN")
        for priv in ("UPDATE", "DELETE"):
            cur.execute(
                "SELECT has_table_privilege('llavero_public_probe', 'audit_entry', %s)", [priv]
            )
            assert cur.fetchone()[0] is False


# --- no secret leakage at the schema level --------------------------------


def test_audit_entry_has_no_secret_columns():
    # The audit schema cannot hold secret material: there is no ciphertext /
    # plaintext / value column. Diffs live in redacted jsonb (changes/metadata).
    names = {f.name for f in AuditEntry._meta.get_fields()}
    for forbidden in ("ciphertext", "plaintext", "value", "secret", "password", "mk"):
        assert forbidden not in names
    assert "changes" in names and "metadata" in names
