"""Off-box checkpoint anchoring (Annex G 7; Annex B 2).

Each signed checkpoint is copied to a separate internal host in an append-only
store the app can write to but cannot modify or delete. Together with the
periodic printed copy in the safe, that gives two independent copies the
database process cannot rewrite — which is what defeats an attacker who can
rewrite both the DB chain and the DB checkpoint row.

The separate host (P0-T9) does not exist yet, so the working implementation
here is ``AppendOnlyFileAnchorStore``, a local write-once stand-in (one
read-only file per checkpoint). The production store (append-only syslog to the
separate host, or a WORM / ``chattr +a`` location) enforces no-modify/no-delete
at the OS level and plugs in behind the same AnchorStore interface.
"""

import glob
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass

from apps.audit import signing
from apps.audit.models import AuditCheckpoint


class AnchorImmutable(Exception):
    """Refused: an anchor record already exists (the store is append-only)."""


class AnchorStore(ABC):
    @abstractmethod
    def append(self, record: dict) -> None:
        """Write one record. Must never overwrite or delete an existing one."""

    @abstractmethod
    def read_all(self) -> list[dict]:
        """All records, ordered by seq."""


class AppendOnlyFileAnchorStore(AnchorStore):
    """Local write-once stand-in: one read-only file per checkpoint.

    Deliberately exposes no modify/delete operation. Re-anchoring an existing
    record is refused (AnchorImmutable), and each file is made read-only so it
    cannot be overwritten in place. Durable no-delete is an OS/host property of
    the real separate-host store (P0-T9).
    """

    def __init__(self, directory: str):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)

    def _path_for(self, *, seq: int, record_id: str) -> str:
        # Zero-padded seq keeps lexical order == seq order.
        return os.path.join(self.directory, f"{seq:020d}-{record_id}.json")

    def append(self, record: dict) -> None:
        path = self._path_for(seq=record["seq"], record_id=record["id"])
        if os.path.exists(path):
            raise AnchorImmutable(f"anchor record for seq {record['seq']} already exists")
        data = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o400)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        try:
            os.chmod(path, 0o400)  # read-only: no in-place overwrite
        except OSError:
            pass

    def read_all(self) -> list[dict]:
        records = []
        for path in sorted(glob.glob(os.path.join(self.directory, "*.json"))):
            with open(path, "rb") as fh:
                records.append(json.loads(fh.read()))
        return records


@dataclass(frozen=True)
class AnchorVerification:
    ok: bool
    reason: str | None = None
    seq: int | None = None
    anchored: bool = False


def checkpoint_to_record(checkpoint: AuditCheckpoint) -> dict:
    """Serialise a checkpoint to a self-verifying off-box record (no secrets)."""
    return {
        "id": str(checkpoint.id),
        "seq": checkpoint.seq,
        "head_hash": bytes(checkpoint.head_hash).hex(),
        "signature": bytes(checkpoint.signature).hex(),
        "signature_algo": checkpoint.signature_algo,
        "signer": checkpoint.signer,
        "created_at": checkpoint.created_at.isoformat(),
    }


def anchor_checkpoint(checkpoint: AuditCheckpoint, store: AnchorStore) -> dict:
    """Copy a signed checkpoint to the append-only off-box store."""
    record = checkpoint_to_record(checkpoint)
    store.append(record)
    return record


def verify_offbox_anchor(store: AnchorStore, *, trusted_public_key: bytes) -> AnchorVerification:
    """Confirm the latest DB checkpoint matches its immutable off-box copy.

    Catches tampering with the DB checkpoint row: the off-box record is the
    independent reference. Signature is verified against the trusted public key.
    """
    checkpoint = AuditCheckpoint.objects.exclude(signature=None).order_by("-seq").first()
    if checkpoint is None:
        return AnchorVerification(True, anchored=False)

    by_seq = {r["seq"]: r for r in store.read_all()}
    record = by_seq.get(checkpoint.seq)
    if record is None:
        return AnchorVerification(False, "not_anchored", checkpoint.seq)

    if (
        record["head_hash"] != bytes(checkpoint.head_hash).hex()
        or record["signature"] != bytes(checkpoint.signature).hex()
    ):
        return AnchorVerification(False, "db_checkpoint_tampered", checkpoint.seq)

    if not signing.verify_signature(
        record["signature_algo"],
        trusted_public_key,
        bytes.fromhex(record["head_hash"]),
        bytes.fromhex(record["signature"]),
    ):
        return AnchorVerification(False, "bad_signature", checkpoint.seq)

    return AnchorVerification(True, anchored=True, seq=checkpoint.seq)
