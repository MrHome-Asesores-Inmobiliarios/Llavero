"""Post-restore verification — the P2-T6 gate logic (Annex H 8, 9).

After a dump is restored into an isolated environment, three things must hold
before the restore is trusted (Annex H 9):

  1. the database loads,
  2. the audit chain verifies and matches the off-box signed checkpoint, and
  3. a secret decrypts through the **recovery-key path** (no admin passphrase,
     no TPM/keyfile second factor — the new-hardware DR scenario, Annex H 7).

This module is the reusable verification both the automated gate proof
(``tests/test_restore_dry_run.py``) and the operational drill
(``manage.py restore_verify`` / ``deploy/backup/restore.sh``) call, so the
dry run and the quarterly drills check exactly the same properties.

Annex H 8 note on lag: a daily dump restores a chain head that is *behind* the
latest off-box checkpoint by up to a day. That lag is expected and must be
**visible, not a silent gap** — ``verify_restore`` reports it explicitly as the
``behind`` state with a numeric ``lag``, distinct from a tamper failure.

Security boundaries: this module recovers the master key only into a mutable
buffer that is wiped in ``finally``; it never returns, logs, or persists the MK,
the recovery code, or any secret plaintext. The recovery drill returns only the
decrypted *length*, which confirms a successful round trip without exposing the
value.
"""

from dataclasses import dataclass

from apps.audit.anchor import verify_offbox_anchor
from apps.audit.verify import verify_chain, verify_with_anchor
from apps.vault import crypto, recovery


@dataclass(frozen=True)
class RestoreReport:
    """Structured outcome of a post-restore verification (no secret material)."""

    chain_ok: bool
    chain_reason: str | None
    restored_head_seq: int
    anchor_ok: bool
    # one of: unanchored_check, current, behind, ahead, no_checkpoint, tampered, chain_invalid
    anchor_state: str
    anchor_reason: str | None
    offbox_head_seq: int | None
    lag: int | None  # offbox_head_seq - restored_head_seq (positive == restored is behind)

    @property
    def loads(self) -> bool:
        """The restored DB is structurally sound enough to walk the chain."""
        return self.chain_ok

    @property
    def trustworthy(self) -> bool:
        """Safe to trust: chain verified and the anchor was not tampered.

        A ``behind`` (daily-dump lag) or ``ahead`` state is still trustworthy —
        the lag is reported for the operator to see, it is not a failure.
        """
        return self.chain_ok and self.anchor_ok


def verify_restore(*, trusted_public_key: bytes | None = None, anchor_store=None) -> RestoreReport:
    """Verify a freshly restored database (Annex H 8).

    ``trusted_public_key`` is the checkpoint-signing public key the operator
    independently trusts — the offline key kept with the recovery material, NEVER
    one read from the restored checkpoint row (which a tampered dump could carry).
    ``anchor_store`` is the append-only off-box store on the separate host; when
    supplied, the restored head is compared against the latest off-box checkpoint
    so daily-dump lag is surfaced.
    """
    chain = verify_chain()
    if not chain.ok:
        return RestoreReport(
            chain_ok=False,
            chain_reason=chain.reason,
            restored_head_seq=chain.head_seq,
            anchor_ok=False,
            anchor_state="chain_invalid",
            anchor_reason=chain.reason,
            offbox_head_seq=None,
            lag=None,
        )

    restored_head = chain.head_seq

    # No trust anchor available: the walk passed, but we cannot prove the restored
    # head matches an independently-signed checkpoint. Report it as a partial check.
    if trusted_public_key is None:
        return RestoreReport(
            chain_ok=True,
            chain_reason=None,
            restored_head_seq=restored_head,
            anchor_ok=True,
            anchor_state="unanchored_check",
            anchor_reason=None,
            offbox_head_seq=None,
            lag=None,
        )

    # 1) The restored DB checkpoint must be authentic under the offline key.
    db_anchor = verify_with_anchor(trusted_public_key=trusted_public_key)
    if not db_anchor.ok:
        return RestoreReport(
            chain_ok=True,
            chain_reason=None,
            restored_head_seq=restored_head,
            anchor_ok=False,
            anchor_state="tampered",
            anchor_reason=db_anchor.reason,
            offbox_head_seq=None,
            lag=None,
        )
    if not db_anchor.anchored:
        return RestoreReport(
            chain_ok=True,
            chain_reason=None,
            restored_head_seq=restored_head,
            anchor_ok=True,
            anchor_state="no_checkpoint",
            anchor_reason=None,
            offbox_head_seq=None,
            lag=None,
        )

    # 2) Cross-check the immutable off-box copy and compute the daily-dump lag.
    offbox_head: int | None = None
    lag: int | None = None
    state = "current"
    if anchor_store is not None:
        offbox = verify_offbox_anchor(anchor_store, trusted_public_key=trusted_public_key)
        if not offbox.ok:
            return RestoreReport(
                chain_ok=True,
                chain_reason=None,
                restored_head_seq=restored_head,
                anchor_ok=False,
                anchor_state="tampered",
                anchor_reason=offbox.reason,
                offbox_head_seq=None,
                lag=None,
            )
        seqs = [r["seq"] for r in anchor_store.read_all()]
        if seqs:
            offbox_head = max(seqs)
            lag = offbox_head - restored_head
            if lag > 0:
                state = "behind"  # expected for a daily dump (Annex H 8): visible, not a gap
            elif lag < 0:
                state = "ahead"  # restored newer than any anchor — surface for attention
            else:
                state = "current"

    return RestoreReport(
        chain_ok=True,
        chain_reason=None,
        restored_head_seq=restored_head,
        anchor_ok=True,
        anchor_state=state,
        anchor_reason=None,
        offbox_head_seq=offbox_head,
        lag=lag,
    )


def recovery_decrypt_drill(*, recovery_code: str, secret) -> int:
    """Prove a secret decrypts through the recovery-key path (Annex H 7, 9).

    Recovers the MK from the printed code **alone** — independent of any admin
    passphrase or the TPM/keyfile second factor — decrypts ``secret``, confirms
    the AEAD round trip, then wipes the MK and the plaintext.

    Returns the plaintext LENGTH only. The value itself is never returned,
    logged, or persisted. Raises on any failure (bad code, wrong key, tamper,
    AAD mismatch), so a caller can treat a return as proof of recovery.
    """
    mk = bytearray(recovery.recover_mk(recovery_code))
    try:
        plaintext = bytearray(
            crypto.open_sealed(
                bytes(mk),
                owner_type=secret.owner_type,
                owner_id=secret.owner_id,
                kind=secret.kind,
                ciphertext=bytes(secret.ciphertext),
                nonce=bytes(secret.nonce),
                dek_wrapped=bytes(secret.dek_wrapped),
                dek_nonce=bytes(secret.dek_nonce),
                aad_context=secret.aad_context,
            )
        )
        try:
            return len(plaintext)
        finally:
            crypto.wipe_buffer(plaintext)
    finally:
        crypto.wipe_buffer(mk)
