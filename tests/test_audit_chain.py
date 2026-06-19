"""P1-T12 acceptance + security-property tests (Annex B 3, 5, 7).

Brief acceptance criteria:
- concurrent operator + monitoring writes under load produce a gap-free linear chain
- verify passes
- forcing the audit insert to fail rolls back the data change too

Plus: genesis shape, hash linking, length-prefix anti-ambiguity, tamper
detection (altered entry / broken link / gap), and the same-transaction
guarantee in both directions.
"""

import threading
import uuid

import pytest
from django.db import IntegrityError, connection, connections, transaction

from apps.audit import chain
from apps.audit.chain import AuditTransactionRequired, append_audit
from apps.audit.models import AuditEntry
from apps.audit.verify import verify_chain
from apps.inventory.models import Person
from apps.operators.models import Operator

ZERO32 = b"\x00" * 32
SYSTEM = AuditEntry.ActorType.SYSTEM
OPERATOR = AuditEntry.ActorType.OPERATOR


@pytest.fixture
def admin(db):
    return Operator.objects.create(
        username="admin", display_name="Admin", role=Operator.Role.ADMINISTRATOR, password_hash="x"
    )


def _append(**kw):
    kw.setdefault("action", AuditEntry.Action.RECORD_VIEW)
    kw.setdefault("actor_type", SYSTEM)
    kw.setdefault("target_table", "device")
    return append_audit(**kw)


# --- genesis + linking ----------------------------------------------------


@pytest.mark.django_db
def test_genesis_entry_shape():
    e = _append()
    assert e.seq == 1
    assert bytes(e.prev_hash) == ZERO32
    assert len(bytes(e.entry_hash)) == 32
    assert e.hash_algo == "blake2b-256"


@pytest.mark.django_db
def test_chain_links_and_increments():
    e1 = _append()
    e2 = _append()
    e3 = _append()
    assert [e1.seq, e2.seq, e3.seq] == [1, 2, 3]
    assert bytes(e2.prev_hash) == bytes(e1.entry_hash)
    assert bytes(e3.prev_hash) == bytes(e2.entry_hash)


@pytest.mark.django_db
def test_verify_passes_on_valid_chain(admin):
    for _ in range(5):
        _append(actor_type=OPERATOR, actor_operator=admin, action=AuditEntry.Action.RECORD_VIEW)
    status = verify_chain()
    assert status.ok
    assert status.head_seq == 5


# --- canonicalization -----------------------------------------------------


def test_length_prefix_prevents_field_ambiguity():
    base = dict(
        seq=1,
        occurred_at_iso="t",
        actor_type="system",
        actor_operator_id=None,
        session_id=None,
        source_ip=None,
        action="x",
        target_id=None,
        target_label="",
        changes={},
        metadata={},
    )
    p1 = chain._payload(actor_username="ab", target_table="c", **base)
    p2 = chain._payload(actor_username="a", target_table="bc", **base)
    # Without length-prefixing, "ab"+"c" and "a"+"bc" would collide.
    assert p1 != p2


@pytest.mark.django_db
def test_stored_entry_hash_recomputes_from_canonical_payload():
    e = _append(
        actor_type=OPERATOR,
        target_table="account",
        target_id=uuid.uuid4(),
        changes={"b": 2, "a": 1},
    )
    recomputed = chain.compute_entry_hash(chain.payload_for(e), bytes(e.prev_hash))
    assert recomputed == bytes(e.entry_hash)


# --- tamper detection -----------------------------------------------------


@pytest.mark.django_db
def test_verify_detects_altered_entry_and_pinpoints_seq():
    entries = [_append() for _ in range(4)]
    # Tamper the in-memory copy of seq 3 (as an attacker who bypassed the
    # trigger would tamper the row); verify must catch it at seq 3.
    entries[2].target_label = "tampered"
    status = verify_chain(entries)
    assert not status.ok
    assert status.reason == "altered_entry"
    assert status.seq == 3


@pytest.mark.django_db
def test_verify_detects_broken_link():
    entries = [_append() for _ in range(3)]
    entries[1].prev_hash = b"\x99" * 32  # link no longer points at seq 1's hash
    status = verify_chain(entries)
    assert not status.ok
    assert status.reason == "broken_link"
    assert status.seq == 2


@pytest.mark.django_db
def test_verify_detects_gap_or_reorder():
    entries = [_append() for _ in range(3)]
    dropped = [entries[0], entries[2]]  # seq 1 then 3 -> gap at the 2nd position
    status = verify_chain(dropped)
    assert not status.ok
    assert status.reason == "gap_or_reorder"
    assert status.seq == 3


# --- same-transaction guarantee (both directions) -------------------------


@pytest.mark.django_db
def test_audit_insert_failure_rolls_back_the_data_change(admin, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("forced audit failure")

    monkeypatch.setattr(chain, "compute_entry_hash", boom)
    with pytest.raises(RuntimeError):
        with transaction.atomic():
            Person.objects.create(full_name="Rollback Me", created_by=admin, updated_by=admin)
            append_audit(
                action=AuditEntry.Action.CREATE,
                actor_type=OPERATOR,
                actor_operator=admin,
                target_table="person",
            )
    # The data change rolled back with the failed audit insert.
    assert not Person.objects.filter(full_name="Rollback Me").exists()


@pytest.mark.django_db
def test_data_change_failure_rolls_back_the_audit_entry(admin):
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            entry = append_audit(
                action=AuditEntry.Action.CREATE,
                actor_type=OPERATOR,
                actor_operator=admin,
                target_table="person",
            )
            seq = entry.seq
            # Force a data error AFTER the audit insert (invalid enum -> CHECK).
            Person.objects.create(
                full_name="Nope", state="bogus", created_by=admin, updated_by=admin
            )
    # No orphan audit entry for a change that did not happen.
    assert not AuditEntry.objects.filter(seq=seq).exists()


@pytest.mark.django_db(transaction=True)
def test_append_requires_an_open_transaction():
    # Outside a transaction the advisory lock would auto-release and the audit
    # row would commit orphaned from its data change, so append_audit refuses.
    try:
        with pytest.raises(AuditTransactionRequired):
            append_audit(action=AuditEntry.Action.RECORD_VIEW, actor_type=SYSTEM)
        assert AuditEntry.objects.count() == 0
    finally:
        connection.close()  # teardown TRUNCATE (bypasses the trigger) resets rows


# --- concurrency: gap-free linear chain under load ------------------------


@pytest.mark.django_db(transaction=True)
def test_concurrent_writers_produce_gap_free_linear_chain():
    n_threads = 4
    per_thread = 25
    errors = []

    def worker(actor_type):
        try:
            for _ in range(per_thread):
                with transaction.atomic():
                    append_audit(
                        action=AuditEntry.Action.RECORD_VIEW,
                        actor_type=actor_type,
                        target_table="device",
                    )
        except Exception as exc:  # noqa: BLE001 - surface any thread error to the assert
            errors.append(exc)
        finally:
            connections.close_all()

    # One "monitoring" (system) writer + several "operator" writers, concurrently.
    threads = [
        threading.Thread(target=worker, args=(SYSTEM if i == 0 else OPERATOR,))
        for i in range(n_threads)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    try:
        assert not errors, errors
        total = n_threads * per_thread
        seqs = list(AuditEntry.objects.order_by("seq").values_list("seq", flat=True))
        # Exactly 1..N: gap-free, no duplicates, strictly linear.
        assert seqs == list(range(1, total + 1))
        assert verify_chain().ok
    finally:
        connection.close()  # teardown TRUNCATE (bypasses the trigger) resets rows
