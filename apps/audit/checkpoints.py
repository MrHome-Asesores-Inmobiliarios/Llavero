"""Signed checkpoint creation (Annex B 7; Annex G 7).

A checkpoint records the current chain head (seq, head_hash) and a signature
over the head hash, produced by a signer whose private key the server does not
hold. Only Administrators may create checkpoints, and only over a chain that
currently verifies.

The checkpoint is inserted as one complete row, so audit_checkpoint stays
append-only (the BEFORE UPDATE/DELETE trigger from P1-T11 forbids edits).
Copying the signed checkpoint to an append-only off-box store is P1-T14.
"""

from apps.audit.models import AuditCheckpoint
from apps.audit.verify import verify_chain
from apps.operators.models import Operator


class NotAnAdministrator(Exception):
    """Only Administrators may create checkpoints."""


class ChainNotVerifiable(Exception):
    """Refused: the chain does not currently verify, so it must not be signed."""


def create_checkpoint(
    *, signer, created_by: Operator, signer_label: str, external_anchor_ref: str = ""
) -> AuditCheckpoint:
    """Sign the current chain head and store a checkpoint row.

    ``signer`` exposes ``algo``, ``public_key`` and ``sign(message)``. The head
    hash is signed; the server stores the signature + algo + a signer label, and
    trusts the public key independently at verification time (P1-T14 / config).
    """
    if created_by.role != Operator.Role.ADMINISTRATOR:
        raise NotAnAdministrator("only Administrators may create checkpoints")

    status = verify_chain()
    if not status.ok:
        raise ChainNotVerifiable(
            f"refusing to sign an invalid chain: {status.reason} at seq {status.seq}"
        )
    if status.head_seq == 0:
        raise ChainNotVerifiable("refusing to checkpoint an empty chain")

    signature = signer.sign(status.head_hash)
    return AuditCheckpoint.objects.create(
        seq=status.head_seq,
        head_hash=status.head_hash,
        signature=signature,
        signature_algo=signer.algo,
        signer=signer_label,
        created_by=created_by,
        external_anchor_ref=external_anchor_ref,
    )
