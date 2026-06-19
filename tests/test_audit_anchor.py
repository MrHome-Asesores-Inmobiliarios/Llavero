"""P1-T14 acceptance + security-property tests (Annex G 7; Annex B 2).

Brief acceptance criteria:
- a checkpoint lands on the separate host
- the app role cannot overwrite or delete it there

The separate host (P0-T9) does not exist yet, so these run against a local
write-once stand-in (AppendOnlyFileAnchorStore): each checkpoint is a read-only,
write-once file. The real off-box target (append-only syslog / WORM on the
separate host) enforces no-modify/no-delete at the OS level.

Value of the off-box copy: it is the independent reference that catches an
attacker who rewrites BOTH the DB chain and the DB checkpoint row.
"""

import os

import pytest
from django.db import connection

from apps.audit import anchor
from apps.audit.anchor import AnchorImmutable, AppendOnlyFileAnchorStore
from apps.audit.chain import append_audit
from apps.audit.checkpoints import create_checkpoint
from apps.audit.models import AuditEntry
from apps.audit.signing import Ed25519CheckpointSigner
from apps.operators.models import Operator

SYSTEM = AuditEntry.ActorType.SYSTEM


@pytest.fixture
def admin(db):
    return Operator.objects.create(
        username="admin", display_name="Admin", role=Operator.Role.ADMINISTRATOR, password_hash="x"
    )


def _append_n(n):
    from django.db import transaction

    for _ in range(n):
        with transaction.atomic():
            append_audit(action=AuditEntry.Action.RECORD_VIEW, actor_type=SYSTEM, target_table="d")


# --- the store stand-in (no DB needed) ------------------------------------


def test_record_lands_and_reads_back(tmp_path):
    store = AppendOnlyFileAnchorStore(str(tmp_path / "anchors"))
    store.append({"id": "a", "seq": 1, "head_hash": "aa"})
    store.append({"id": "b", "seq": 2, "head_hash": "bb"})
    records = store.read_all()
    assert [r["seq"] for r in records] == [1, 2]  # ordered by seq
    assert records[0]["head_hash"] == "aa"


def test_records_are_write_once(tmp_path):
    store = AppendOnlyFileAnchorStore(str(tmp_path / "anchors"))
    store.append({"id": "a", "seq": 1, "head_hash": "aa"})
    # Re-anchoring the same checkpoint (same seq+id) is refused: append-only.
    with pytest.raises(AnchorImmutable):
        store.append({"id": "a", "seq": 1, "head_hash": "TAMPERED"})
    assert store.read_all()[0]["head_hash"] == "aa"


@pytest.mark.skipif(
    os.name != "posix", reason="read-only-file overwrite block is clearest on POSIX"
)
def test_written_record_file_is_read_only(tmp_path):
    store = AppendOnlyFileAnchorStore(str(tmp_path / "anchors"))
    store.append({"id": "a", "seq": 1, "head_hash": "aa"})
    path = store._path_for(seq=1, record_id="a")
    mode = os.stat(path).st_mode & 0o777
    assert mode & 0o222 == 0  # no write bits -> cannot be overwritten in place
    with pytest.raises(PermissionError):
        open(path, "w").close()


def test_store_exposes_no_modify_or_delete_api():
    store = AppendOnlyFileAnchorStore.__new__(AppendOnlyFileAnchorStore)
    for forbidden in ("delete", "remove", "overwrite", "update", "truncate", "clear"):
        assert not hasattr(store, forbidden)


# --- anchoring a real checkpoint ------------------------------------------


@pytest.mark.django_db
def test_checkpoint_lands_on_anchor(admin, tmp_path):
    _append_n(3)
    signer = Ed25519CheckpointSigner()
    cp = create_checkpoint(signer=signer, created_by=admin, signer_label="k")

    store = AppendOnlyFileAnchorStore(str(tmp_path / "anchors"))
    anchor.anchor_checkpoint(cp, store)

    records = store.read_all()
    assert len(records) == 1
    assert records[0]["seq"] == cp.seq
    assert records[0]["head_hash"] == bytes(cp.head_hash).hex()
    assert records[0]["signature"] == bytes(cp.signature).hex()


@pytest.mark.django_db
def test_verify_offbox_anchor_ok(admin, tmp_path):
    _append_n(2)
    signer = Ed25519CheckpointSigner()
    cp = create_checkpoint(signer=signer, created_by=admin, signer_label="k")
    store = AppendOnlyFileAnchorStore(str(tmp_path / "anchors"))
    anchor.anchor_checkpoint(cp, store)

    status = anchor.verify_offbox_anchor(store, trusted_public_key=signer.public_key)
    assert status.ok
    assert status.anchored is True


@pytest.mark.django_db
def test_verify_detects_missing_anchor(admin, tmp_path):
    _append_n(2)
    signer = Ed25519CheckpointSigner()
    create_checkpoint(signer=signer, created_by=admin, signer_label="k")
    store = AppendOnlyFileAnchorStore(str(tmp_path / "anchors"))  # nothing anchored

    status = anchor.verify_offbox_anchor(store, trusted_public_key=signer.public_key)
    assert not status.ok
    assert status.reason == "not_anchored"


@pytest.mark.django_db(transaction=True)
def test_offbox_anchor_detects_db_checkpoint_tamper(admin, tmp_path):
    try:
        _append_n(2)
        signer = Ed25519CheckpointSigner()
        cp = create_checkpoint(signer=signer, created_by=admin, signer_label="k")
        store = AppendOnlyFileAnchorStore(str(tmp_path / "anchors"))
        anchor.anchor_checkpoint(cp, store)

        # Attacker rewrites the DB checkpoint row (bypassing the trigger). The
        # off-box copy is immutable, so the mismatch is detected.
        with connection.cursor() as cur:
            cur.execute("ALTER TABLE audit_checkpoint DISABLE TRIGGER audit_checkpoint_append_only")
        with connection.cursor() as cur:
            cur.execute(
                "UPDATE audit_checkpoint SET head_hash = %s WHERE id = %s",
                [b"\x77" * 32, str(cp.id)],
            )
        with connection.cursor() as cur:
            cur.execute("ALTER TABLE audit_checkpoint ENABLE TRIGGER audit_checkpoint_append_only")

        status = anchor.verify_offbox_anchor(store, trusted_public_key=signer.public_key)
        assert not status.ok
        assert status.reason == "db_checkpoint_tampered"
    finally:
        connection.close()
