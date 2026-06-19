"""P2-T6 GATE — first restore dry run (Annex H 8, 9; Annex I).

This is one half of the hard gate (with P4-T6) that must pass before any real
secret is loaded. It proves, on throwaway data, the three things Annex H 9
requires of a restore:

  1. the database **loads** — a full dump is captured, the live data is wiped
     (the "old machine is gone"), and every security table is restored;
  2. the audit **chain verifies** on the restored data and matches the off-box
     signed checkpoint under an independently-trusted offline key, with any
     daily-dump lag surfaced visibly (not as a silent gap); and
  3. a secret **decrypts through the recovery-key path** — from restored bytes
     plus the printed recovery code alone, with no admin passphrase and no
     TPM/keyfile second factor (the new-hardware DR scenario, Annex H 7).

Security properties also asserted, because a subtle error here is expensive:
  - the recovery path is the SOLE input (works with every key holder deleted);
  - the master key is recovered into a buffer that is wiped, and never appears
    in the backup artifact (only wrapped/ciphertext forms are dumped);
  - AAD binding survives the restore (a relocated ciphertext still fails);
  - the restored chain stays tamper-evident, and trust is anchored on the
    caller's offline key — never on a value read from the restored row;
  - a Viewer remains keyless after a restore.

Modelling note: the security claim this gate owns is "the persisted bytes are
sufficient and correct to re-walk the chain, match the signed checkpoint, and
recover a secret via the printed key — with no live key material." That is
proven faithfully in-process by dumping every security table to bytes, wiping
the database, and reloading. The full ``pg_dump | age`` → isolated-cluster
restore is the host-level drill in ``deploy/backup/RESTORE-DRILL.md``; an
availability-gated real-``pg_dump`` archive check is included below.
"""

import base64
import json
import os
import shutil
import subprocess
import uuid

import pytest
from django.db import connection, transaction

from apps.audit import anchor
from apps.audit.anchor import AppendOnlyFileAnchorStore
from apps.audit.chain import append_audit
from apps.audit.checkpoints import create_checkpoint
from apps.audit.models import AuditCheckpoint, AuditEntry
from apps.audit.signing import Ed25519CheckpointSigner, verify_signature
from apps.audit.verify import verify_chain
from apps.backup.restore_verify import recovery_decrypt_drill, verify_restore
from apps.operators.models import Operator
from apps.vault import crypto, key_holders, recovery
from apps.vault.kdf import DEV_PARAMS
from apps.vault.models import Secret, VaultKeyHolder, VaultRecoveryKey

SECOND_FACTOR = b"\x11" * 32
PASSPHRASE = b"admin vault passphrase, long and unique"
THROWAWAY_PLAINTEXT = b"throwaway-dry-run-secret-value"  # never a real secret (hard gate)
SYSTEM = AuditEntry.ActorType.SYSTEM

# Restore order matters: parents before children (FK PROTECT). The disaster wipe
# runs in reverse, with the audit append-only triggers disabled for the DELETE.
_MODELS_PARENT_FIRST = [
    Operator,
    VaultKeyHolder,
    Secret,
    VaultRecoveryKey,
    AuditEntry,
    AuditCheckpoint,
]
_AUDIT_TRIGGERS = [
    ("audit_entry", "audit_entry_append_only"),
    ("audit_checkpoint", "audit_checkpoint_append_only"),
]


# ── dump / disaster / restore helpers ──────────────────────────────────────


def _dump_model(model) -> list[dict]:
    """Capture every row of a model as plain field->value dicts (bytes for blobs).

    Uses attnames, so FKs are captured as ``<name>_id`` — exactly what a logical
    dump preserves and what the model constructor accepts on restore.
    """
    rows = []
    for obj in model.objects.all():
        row = {}
        for f in model._meta.concrete_fields:
            val = getattr(obj, f.attname)
            if isinstance(val, memoryview):
                val = bytes(val)
            row[f.attname] = val
        rows.append(row)
    return rows


def _dump_all() -> dict:
    """The 'backup': every security table captured at this instant."""
    return {m.__name__: _dump_model(m) for m in _MODELS_PARENT_FIRST}


def _wipe_all() -> None:
    """The 'disaster': clear every table. Audit triggers block DELETE, so they
    are disabled around the audit-table wipe (modelling total disk loss)."""
    for table, trig in _AUDIT_TRIGGERS:
        with connection.cursor() as cur:
            cur.execute(f"ALTER TABLE {table} DISABLE TRIGGER {trig}")
    try:
        for model in reversed(_MODELS_PARENT_FIRST):
            model.objects.all().delete()
    finally:
        for table, trig in _AUDIT_TRIGGERS:
            with connection.cursor() as cur:
                cur.execute(f"ALTER TABLE {table} ENABLE TRIGGER {trig}")


def _restore_all(dump: dict) -> None:
    """The 'restore': reload every row byte-for-byte. INSERT is allowed by the
    append-only trigger (it fires only on UPDATE/DELETE), so no toggling here."""
    for model in _MODELS_PARENT_FIRST:
        for row in dump[model.__name__]:
            obj = model(**row)
            obj.save(force_insert=True)


def _serialize_artifact(dump: dict) -> bytes:
    """Render the dump to on-disk-artifact bytes (base64 for binary columns),
    modelling the unencrypted pg_dump output that ``age`` would then encrypt."""

    def _enc(v):
        if isinstance(v, bytes | bytearray | memoryview):
            return {"__b64__": base64.b64encode(bytes(v)).decode("ascii")}
        if isinstance(v, uuid.UUID):
            return str(v)
        return v

    plain = {
        name: [{k: _enc(v) for k, v in r.items()} for r in rows] for name, rows in dump.items()
    }
    return json.dumps(plain, default=str, sort_keys=True).encode("utf-8")


# ── state seeding ───────────────────────────────────────────────────────────


def _make_admin(username="admin"):
    op = Operator.objects.create(
        username=username, display_name="Admin", role=Operator.Role.ADMINISTRATOR, password_hash="x"
    )
    _, mk = key_holders.install_vault(
        operator=op, passphrase=PASSPHRASE, second_factor=SECOND_FACTOR, params=DEV_PARAMS
    )
    return op, mk


def _store_secret(mk, admin, *, owner_id=None, plaintext=THROWAWAY_PLAINTEXT):
    owner_id = owner_id or uuid.uuid4()
    row = crypto.seal(
        mk, owner_type="account", owner_id=owner_id, kind="password", plaintext=plaintext
    )
    return Secret.objects.create(
        owner_type="account",
        owner_id=owner_id,
        kind="password",
        label="dry-run",
        created_by=admin,
        updated_by=admin,
        **row,
    )


def _append(n):
    for _ in range(n):
        with transaction.atomic():
            append_audit(action=AuditEntry.Action.RECORD_VIEW, actor_type=SYSTEM, target_table="d")


# ════════════════════════════════════════════════════════════════════════════
# THE GATE: dump → wipe → restore, then prove all three Annex H 9 properties.
# ════════════════════════════════════════════════════════════════════════════


@pytest.mark.django_db(transaction=True)
def test_restore_dry_run_full_gate(tmp_path):
    try:
        # ---- build a realistic "production" state -------------------------
        admin, mk = _make_admin()
        secret = _store_secret(mk, admin)
        code, _ = recovery.establish_recovery_key(mk=mk, created_by=admin)

        signer = Ed25519CheckpointSigner()  # the offline key (kept with recovery material)
        offline_pub = signer.public_key
        store = AppendOnlyFileAnchorStore(str(tmp_path / "offbox"))  # the separate host

        _append(3)
        cp1 = create_checkpoint(signer=signer, created_by=admin, signer_label="dry-run")
        anchor.anchor_checkpoint(cp1, store)

        # ---- take the daily dump NOW (chain head == seq 3) ----------------
        dump = _dump_all()

        # ---- the off-box host keeps anchoring AFTER the dump (RPO lag) ----
        _append(2)
        cp2 = create_checkpoint(signer=signer, created_by=admin, signer_label="dry-run-later")
        anchor.anchor_checkpoint(cp2, store)
        assert cp2.seq == 5

        # ---- DISASTER: the machine is gone --------------------------------
        _wipe_all()
        assert AuditEntry.objects.count() == 0
        assert Secret.objects.count() == 0
        assert VaultKeyHolder.objects.count() == 0
        with pytest.raises(recovery.NoRecoveryKey):
            recovery.recover_mk(code)

        # ===================================================================
        # PROOF 1 — the database LOADS.
        # ===================================================================
        _restore_all(dump)
        assert Operator.objects.count() == 1
        assert Secret.objects.count() == 1
        assert VaultKeyHolder.objects.count() == 1
        assert VaultRecoveryKey.objects.count() == 1
        assert AuditEntry.objects.count() == 3  # the dump was a prefix (head seq 3)

        # ===================================================================
        # PROOF 2 — the chain VERIFIES and matches the off-box checkpoint,
        # with the daily-dump lag VISIBLE (Annex H 8), under the offline key.
        # ===================================================================
        report = verify_restore(trusted_public_key=offline_pub, anchor_store=store)
        assert report.loads is True
        assert report.chain_ok is True
        assert report.restored_head_seq == 3
        assert report.trustworthy is True
        assert report.anchor_state == "behind"  # restored head behind the latest anchor
        assert report.offbox_head_seq == 5
        assert report.lag == 2  # exactly the entries appended after the dump — not a silent gap

        # ===================================================================
        # PROOF 3 — a secret decrypts through the RECOVERY-KEY path, with
        # every admin key holder gone (new hardware, old factors lost).
        # ===================================================================
        VaultKeyHolder.objects.all().delete()  # old passphrases + TPM/keyfile are gone
        assert VaultKeyHolder.objects.count() == 0

        recovered = bytearray(recovery.recover_mk(code))  # printed code is the SOLE input
        try:
            assert bytes(recovered) == mk  # the same MK comes back
            plaintext = crypto.open_sealed(
                bytes(recovered),
                owner_type=secret.owner_type,
                owner_id=secret.owner_id,
                kind=secret.kind,
                ciphertext=bytes(Secret.objects.get(id=secret.id).ciphertext),
                nonce=bytes(Secret.objects.get(id=secret.id).nonce),
                dek_wrapped=bytes(Secret.objects.get(id=secret.id).dek_wrapped),
                dek_nonce=bytes(Secret.objects.get(id=secret.id).dek_nonce),
                aad_context=Secret.objects.get(id=secret.id).aad_context,
            )
            assert plaintext == THROWAWAY_PLAINTEXT
        finally:
            crypto.wipe_buffer(recovered)
        assert bytes(recovered) == b"\x00" * 32  # MK buffer wiped after use
    finally:
        connection.close()


# ── recovery-key path is the sole input (no passphrase, no second factor) ────


@pytest.mark.django_db
def test_recovery_path_uses_no_passphrase_or_second_factor():
    admin, mk = _make_admin()
    secret = _store_secret(mk, admin)
    code, _ = recovery.establish_recovery_key(mk=mk, created_by=admin)

    # New hardware: the only admin's key holder is gone with the old machine.
    VaultKeyHolder.objects.all().delete()
    with pytest.raises(VaultKeyHolder.DoesNotExist):
        key_holders.unlock_with_holder(admin, PASSPHRASE, SECOND_FACTOR)

    # The printed code alone recovers the MK and decrypts the secret — the
    # drill returns only the LENGTH, never the value.
    assert recovery_decrypt_drill(recovery_code=code, secret=secret) == len(THROWAWAY_PLAINTEXT)

    # A wrong/mistyped code cannot recover anything.
    with pytest.raises((recovery.RecoveryCodeError, crypto.DecryptionError)):
        recovery_decrypt_drill(recovery_code="AAAA-BBBB-CCCC-DDDD", secret=secret)


# ── the recovery drill returns no plaintext ─────────────────────────────────


@pytest.mark.django_db
def test_recovery_drill_returns_only_length_never_value():
    admin, mk = _make_admin()
    secret = _store_secret(mk, admin, plaintext=b"sixteen-byte-pw!")
    code, _ = recovery.establish_recovery_key(mk=mk, created_by=admin)
    result = recovery_decrypt_drill(recovery_code=code, secret=secret)
    assert result == 16
    assert isinstance(result, int)  # an int length, not bytes — no value escapes


# ── AAD binding survives the restore ────────────────────────────────────────


@pytest.mark.django_db
def test_restored_secret_keeps_aad_binding():
    admin, mk = _make_admin()
    secret = _store_secret(mk, admin)

    # Restoring preserves the exact ciphertext/nonce/DEK bytes; the AAD is
    # recomputed from the record identity at decrypt time. A ciphertext relocated
    # to a different owner_id (a tampered restore) must fail the AEAD tag check.
    with pytest.raises(crypto.DecryptionError):
        crypto.open_sealed(
            mk,
            owner_type=secret.owner_type,
            owner_id=uuid.uuid4(),  # relocated to a different record
            kind=secret.kind,
            ciphertext=bytes(secret.ciphertext),
            nonce=bytes(secret.nonce),
            dek_wrapped=bytes(secret.dek_wrapped),
            dek_nonce=bytes(secret.dek_nonce),
            aad_context=None,
        )


# ── the restored chain stays tamper-evident ─────────────────────────────────


@pytest.mark.django_db
def test_restored_chain_is_tamper_evident():
    _make_admin()
    _append(4)
    assert verify_chain().ok

    # Model a dump that was tampered before restore: flip one entry's stored
    # hash. The walk catches it at that seq (it never silently accepts it).
    entries = list(AuditEntry.objects.order_by("seq"))
    entries[2].entry_hash = bytes(entries[2].entry_hash)[:-1] + b"\x00"
    status = verify_chain(entries=entries)
    assert not status.ok
    assert status.reason in ("altered_entry", "broken_link")
    assert status.seq == entries[2].seq


# ── trust is anchored on the offline key, never on the restored row ──────────


def test_offline_key_anchors_trust_not_the_restored_checkpoint():
    signer = Ed25519CheckpointSigner()
    head = b"\x42" * 32
    sig = signer.sign(head)

    # Genuine head verifies under the independently-held offline public key.
    assert verify_signature("ed25519", signer.public_key, head, sig) is True

    # A head tampered in the dump fails — the signature does not cover it.
    tampered = b"\x99" * 32
    assert verify_signature("ed25519", signer.public_key, tampered, sig) is False

    # A different key (an attacker substituting their own) cannot vouch for it.
    attacker = Ed25519CheckpointSigner()
    assert verify_signature("ed25519", attacker.public_key, head, sig) is False


# ── the backup artifact carries no plaintext and no master key ───────────────


@pytest.mark.django_db
def test_backup_artifact_has_no_plaintext_or_master_key():
    admin, mk = _make_admin()
    _store_secret(mk, admin)
    recovery.establish_recovery_key(mk=mk, created_by=admin)
    _append(2)

    artifact = _serialize_artifact(_dump_all())

    # Even the *unencrypted* dump exposes no plaintext and no master key: the DB
    # holds only wrapped/ciphertext forms (Annex H 2). Check raw and base64 forms.
    assert THROWAWAY_PLAINTEXT not in artifact
    assert base64.b64encode(THROWAWAY_PLAINTEXT) not in artifact
    assert mk not in artifact
    assert base64.b64encode(mk) not in artifact


# ── a Viewer stays keyless across a restore ──────────────────────────────────


@pytest.mark.django_db
def test_keyless_viewer_survives_restore():
    admin, mk = _make_admin()
    viewer = Operator.objects.create(
        username="v", display_name="V", role=Operator.Role.VIEWER, password_hash="x"
    )
    dump = _dump_all()
    # The dump (and therefore any restore) contains a key holder only for the
    # admin — never for the Viewer, which is what makes a Viewer cryptographically
    # keyless (Annex D 2). Restoring cannot conjure one.
    holder_ops = {r["operator_id"] for r in dump["VaultKeyHolder"]}
    assert admin.id in holder_ops
    assert viewer.id not in holder_ops


# ── the operational verification surface (the drill command) ─────────────────


@pytest.mark.django_db
def test_restore_verify_command_reports_clean_restore(tmp_path, capsys):
    admin, mk = _make_admin()
    _store_secret(mk, admin)  # a secret in the DB for realism (no drill in this test)
    recovery.establish_recovery_key(mk=mk, created_by=admin)
    signer = Ed25519CheckpointSigner()
    store_dir = tmp_path / "offbox"
    store = AppendOnlyFileAnchorStore(str(store_dir))
    _append(2)
    cp = create_checkpoint(signer=signer, created_by=admin, signer_label="drill")
    anchor.anchor_checkpoint(cp, store)

    key_file = tmp_path / "offline.pub"
    key_file.write_text(signer.public_key.hex())

    from django.core.management import call_command

    call_command(
        "restore_verify",
        "--trusted-key-file",
        str(key_file),
        "--anchor-dir",
        str(store_dir),
        "--json",
    )
    out = json.loads(capsys.readouterr().out)
    assert out["chain_ok"] is True
    assert out["trustworthy"] is True
    assert out["restored_head_seq"] == 2
    assert out["anchor_state"] == "current"


# ── (optional) a REAL pg_dump produces a loadable archive ────────────────────


def _resolve_pg_tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    # Common Windows install path used by the dev box (PostgreSQL 18).
    candidate = rf"C:\Program Files\PostgreSQL\18\bin\{name}.exe"
    return candidate if os.path.exists(candidate) else None


@pytest.mark.django_db
def test_real_pg_dump_artifact_is_loadable(tmp_path):
    """If pg_dump/pg_restore are available, prove the actual dump command emits a
    structurally loadable archive that contains the security tables. Skipped when
    the client tools are absent (the full restore is the host drill)."""
    pg_dump = _resolve_pg_tool("pg_dump")
    pg_restore = _resolve_pg_tool("pg_restore")
    if not pg_dump or not pg_restore:
        pytest.skip("pg_dump/pg_restore not available; full restore is the host drill")

    admin, mk = _make_admin()
    _store_secret(mk, admin)
    _append(1)

    db = connection.settings_dict
    env = dict(os.environ, PGPASSWORD=db["PASSWORD"] or "")
    archive = tmp_path / "llavero_test.dump"

    dump_cmd = [
        pg_dump,
        "-Fc",
        "-h",
        db["HOST"] or "127.0.0.1",
        "-p",
        str(db["PORT"] or "5432"),
        "-U",
        db["USER"],
        "-d",
        connection.settings_dict["NAME"],  # the test database
        "-f",
        str(archive),
    ]
    # Trusted inputs only: a resolved tool path + Django DB settings, no shell.
    proc = subprocess.run(dump_cmd, env=env, capture_output=True, text=True)  # noqa: S603
    assert proc.returncode == 0, proc.stderr
    assert archive.exists() and archive.stat().st_size > 0

    # pg_restore --list parses the archive TOC — it succeeds only on a valid,
    # loadable dump — and the security tables must be present.
    listing = subprocess.run(  # noqa: S603
        [pg_restore, "--list", str(archive)], env=env, capture_output=True, text=True
    )
    assert listing.returncode == 0, listing.stderr
    toc = listing.stdout
    for table in ("audit_entry", "secret", "vault_key_holder", "vault_recovery_key"):
        assert table in toc, f"{table} missing from the dump TOC"
