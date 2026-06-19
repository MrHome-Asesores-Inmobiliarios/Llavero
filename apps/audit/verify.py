"""Chain-walk verification (Annex B 7).

Iterates entries in seq order and confirms, for each: the seq is gap-free, the
prev_hash links to the previous entry's hash, and entry_hash recomputes from the
canonical payload. The first failure pinpoints the earliest tampered, reordered,
or corrupted entry.

The signed-checkpoint anchor check (catching a full-rewrite by someone who can
rewrite the whole chain) is layered on in P1-T13.
"""

from dataclasses import dataclass

from apps.audit.chain import ZERO32, compute_entry_hash, payload_for
from apps.audit.models import AuditEntry


@dataclass(frozen=True)
class ChainStatus:
    ok: bool
    reason: str | None = None
    seq: int | None = None
    head_seq: int = 0
    head_hash: bytes = ZERO32


def verify_chain(entries=None) -> ChainStatus:
    """Walk the chain. ``entries`` defaults to all entries ordered by seq;
    an explicit iterable may be passed (e.g. to verify a tampered copy)."""
    if entries is None:
        entries = AuditEntry.objects.order_by("seq").iterator()

    prev = ZERO32
    expected_seq = 1
    head_seq = 0
    for e in entries:
        if e.seq != expected_seq:
            return ChainStatus(False, "gap_or_reorder", e.seq, head_seq, prev)
        if bytes(e.prev_hash) != prev:
            return ChainStatus(False, "broken_link", e.seq, head_seq, prev)
        if compute_entry_hash(payload_for(e), bytes(e.prev_hash)) != bytes(e.entry_hash):
            return ChainStatus(False, "altered_entry", e.seq, head_seq, prev)
        prev = bytes(e.entry_hash)
        head_seq = e.seq
        expected_seq += 1

    return ChainStatus(True, head_seq=head_seq, head_hash=prev)
