"""Hash-chain construction and the append path (Annex B 3, 5, 7).

entry_hash = BLAKE2b-256( canonical_payload || prev_hash ), where the payload is
a length-prefixed concatenation of a fixed, ordered field list and prev_hash is
appended as raw bytes. The genesis entry has seq=1 and prev_hash = 32 zero bytes.

``append_audit`` serialises appends with a constant advisory lock so seq stays
gap-free and every prev_hash points at the true head, and MUST run inside the
same transaction as the data change it records (either both commit or both roll
back). A single canonicalisation function (``payload_for``) is used by both the
append path and the verifier, so there is no representation mismatch.

This module records only non-secret facts; callers must never pass secret
plaintext in ``changes``/``metadata`` (Annex B 1, 6).
"""

import json
import uuid
from datetime import UTC

import nacl.encoding
import nacl.hash
from django.db import connection
from django.utils import timezone

from apps.audit.models import AuditEntry

ZERO32 = b"\x00" * 32

# Stable, per-purpose signed 64-bit advisory-lock key derived from a label, so
# audit appends serialise without colliding with any other advisory lock.
AUDIT_LOCK_KEY = int.from_bytes(
    nacl.hash.blake2b(b"llavero-audit-append", digest_size=8, encoder=nacl.encoding.RawEncoder),
    "big",
    signed=True,
)


class AuditTransactionRequired(Exception):
    """append_audit must run inside the same transaction as the data change."""


def _lp(value) -> bytes:
    """Length-prefix: 4-byte big-endian length + UTF-8 bytes (None -> empty)."""
    b = b"" if value is None else str(value).encode("utf-8")
    return len(b).to_bytes(4, "big") + b


def _canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _iso(dt) -> str:
    return dt.astimezone(UTC).isoformat()


def _payload(
    *,
    seq,
    occurred_at_iso,
    actor_type,
    actor_operator_id,
    actor_username,
    session_id,
    source_ip,
    action,
    target_table,
    target_id,
    target_label,
    changes,
    metadata,
) -> bytes:
    return b"".join(
        _lp(v)
        for v in (
            seq,
            occurred_at_iso,
            actor_type,
            actor_operator_id,
            actor_username,
            session_id,
            source_ip,
            action,
            target_table,
            target_id,
            target_label,
            _canonical_json(changes),
            _canonical_json(metadata),
        )
    )


def payload_for(entry: AuditEntry) -> bytes:
    """Canonical payload for an entry (used by both append and verify)."""
    return _payload(
        seq=entry.seq,
        occurred_at_iso=_iso(entry.occurred_at),
        actor_type=entry.actor_type,
        actor_operator_id=entry.actor_operator_id,
        actor_username=entry.actor_username,
        session_id=entry.session_id,
        source_ip=entry.source_ip,
        action=entry.action,
        target_table=entry.target_table,
        target_id=entry.target_id,
        target_label=entry.target_label,
        changes=entry.changes,
        metadata=entry.metadata,
    )


def compute_entry_hash(payload: bytes, prev_hash: bytes) -> bytes:
    """BLAKE2b-256 over payload || prev_hash (libsodium crypto_generichash)."""
    return nacl.hash.blake2b(payload + prev_hash, digest_size=32, encoder=nacl.encoding.RawEncoder)


def append_audit(
    *,
    action,
    actor_type,
    occurred_at=None,
    actor_operator=None,
    actor_username="",
    session=None,
    source_ip=None,
    target_table="",
    target_id=None,
    target_label="",
    changes=None,
    metadata=None,
    hash_algo="blake2b-256",
    scheme_version=1,
) -> AuditEntry:
    """Append one entry to the chain, in the caller's transaction.

    Call inside ``transaction.atomic()`` together with the data change being
    recorded. Raises AuditTransactionRequired otherwise.
    """
    if not connection.in_atomic_block:
        raise AuditTransactionRequired(
            "append_audit must be called inside a transaction.atomic() block, "
            "in the same transaction as the data change"
        )

    occurred_at = occurred_at or timezone.now()
    if target_id is not None and not isinstance(target_id, uuid.UUID):
        target_id = uuid.UUID(str(target_id))  # canonical form, stable on reload
    changes = {} if changes is None else changes
    metadata = {} if metadata is None else metadata

    # Serialise appends: gap-free seq and a true prev_hash even under concurrent
    # operator + monitoring writers. The xact lock releases at transaction end.
    with connection.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", [AUDIT_LOCK_KEY])

    head = AuditEntry.objects.order_by("-seq").first()
    prev_hash = bytes(head.entry_hash) if head else ZERO32
    seq = (head.seq + 1) if head else 1

    entry = AuditEntry(
        seq=seq,
        occurred_at=occurred_at,
        actor_type=actor_type,
        actor_operator=actor_operator,
        actor_username=actor_username,
        session=session,
        source_ip=source_ip,
        action=action,
        target_table=target_table,
        target_id=target_id,
        target_label=target_label,
        changes=changes,
        metadata=metadata,
        prev_hash=prev_hash,
        hash_algo=hash_algo,
        scheme_version=scheme_version,
    )
    entry.entry_hash = compute_entry_hash(payload_for(entry), prev_hash)
    entry.save(force_insert=True)
    return entry
