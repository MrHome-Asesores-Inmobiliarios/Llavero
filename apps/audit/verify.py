"""Chain-walk verification (Annex B 7).

Iterates entries in seq order and confirms, for each: the seq is gap-free, the
prev_hash links to the previous entry's hash, and entry_hash recomputes from the
canonical payload. The first failure pinpoints the earliest tampered, reordered,
or corrupted entry.

The signed-checkpoint anchor check (catching a full-rewrite by someone who can
rewrite the whole chain) is layered on in P1-T13.
"""

from dataclasses import dataclass

from apps.audit import signing
from apps.audit.chain import ZERO32, compute_entry_hash, payload_for
from apps.audit.models import AuditCheckpoint, AuditEntry


@dataclass(frozen=True)
class ChainStatus:
    ok: bool
    reason: str | None = None
    seq: int | None = None
    head_seq: int = 0
    head_hash: bytes = ZERO32


@dataclass(frozen=True)
class AnchorStatus:
    ok: bool
    reason: str | None = None
    seq: int | None = None
    anchored: bool = False
    chain_head_seq: int = 0


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


def verify_with_anchor(*, trusted_public_key: bytes, algo: str | None = None) -> AnchorStatus:
    """Walk the chain, then check it against the latest signed checkpoint.

    ``trusted_public_key`` is the key the caller independently trusts (the
    enrolled admin credential or the configured offline key) — NOT one read from
    the checkpoint, which an attacker could replace. A valid-walking chain whose
    entry at the checkpoint seq no longer matches the signed head hash was
    rewritten after the checkpoint.
    """
    chain = verify_chain()
    if not chain.ok:
        return AnchorStatus(
            False, chain.reason, chain.seq, anchored=False, chain_head_seq=chain.head_seq
        )

    checkpoint = AuditCheckpoint.objects.exclude(signature=None).order_by("-seq").first()
    if checkpoint is None:
        return AnchorStatus(True, anchored=False, chain_head_seq=chain.head_seq)

    if not signing.verify_signature(
        algo or checkpoint.signature_algo,
        trusted_public_key,
        bytes(checkpoint.head_hash),
        bytes(checkpoint.signature),
    ):
        return AnchorStatus(
            False,
            "bad_checkpoint_signature",
            checkpoint.seq,
            anchored=True,
            chain_head_seq=chain.head_seq,
        )

    anchored_entry = AuditEntry.objects.filter(seq=checkpoint.seq).first()
    if anchored_entry is None or bytes(anchored_entry.entry_hash) != bytes(checkpoint.head_hash):
        return AnchorStatus(
            False,
            "rewritten_after_checkpoint",
            checkpoint.seq,
            anchored=True,
            chain_head_seq=chain.head_seq,
        )

    return AnchorStatus(True, anchored=True, chain_head_seq=chain.head_seq)
