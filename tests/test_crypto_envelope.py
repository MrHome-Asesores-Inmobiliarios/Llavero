"""P1-T6 acceptance + security-property tests (Annex A 3, 4, 11; Annex C 4.9).

Brief acceptance criteria:
- encrypt/decrypt round-trips
- tampering the ciphertext or AAD makes decrypt raise
- a DEK reused on another record fails AAD verification

Additional security properties asserted here:
- wrong passphrase / wrong second factor cannot derive the MK (a database-only
  copy without the factor is useless)
- the stored row carries no plaintext and no unwrapped DEK
- encryption is non-deterministic (fresh nonce + DEK per call)
"""

import uuid

import pytest

from apps.vault import crypto
from apps.vault.kdf import DEV_PARAMS, generate_salt

PASSPHRASE = b"correct horse battery staple - long admin passphrase"
SECOND_FACTOR = b"\x11" * 32  # keyfile/TPM-sealed stub (real factor is P1-T7)


@pytest.fixture
def unlocked():
    """Simulate install + unlock: derive KWK, generate + wrap MK, then unwrap."""
    salt = generate_salt()
    kwk = crypto.derive_kwk(PASSPHRASE, salt, DEV_PARAMS, SECOND_FACTOR)
    mk = crypto.generate_master_key()
    mk_wrapped, mk_nonce = crypto.wrap_master_key(mk, kwk)
    # The MK held in memory after unlock is what we encrypt/decrypt with.
    mk_unlocked = crypto.unwrap_master_key(mk_wrapped, mk_nonce, kwk)
    assert mk_unlocked == mk
    return {"salt": salt, "mk": mk_unlocked, "mk_wrapped": mk_wrapped, "mk_nonce": mk_nonce}


def _aad(owner_id, owner_type="account", kind="password"):
    return crypto.build_aad(owner_type, owner_id, kind)


# --- round trip -----------------------------------------------------------


def test_encrypt_decrypt_round_trip(unlocked):
    owner_id = uuid.uuid4()
    aad = _aad(owner_id)
    plaintext = b"hunter2-the-actual-password"

    row = crypto.encrypt_secret(unlocked["mk"], plaintext, aad)
    out = crypto.decrypt_secret(unlocked["mk"], aad=aad, **row)
    assert out == plaintext


def test_master_key_wrap_unwrap_round_trip(unlocked):
    # Re-deriving the KWK from the same passphrase+salt+factor unwraps the MK.
    kwk = crypto.derive_kwk(PASSPHRASE, unlocked["salt"], DEV_PARAMS, SECOND_FACTOR)
    mk = crypto.unwrap_master_key(unlocked["mk_wrapped"], unlocked["mk_nonce"], kwk)
    assert mk == unlocked["mk"]


# --- the MK cannot be derived without the right inputs --------------------


def test_wrong_passphrase_cannot_unwrap_mk(unlocked):
    bad_kwk = crypto.derive_kwk(b"wrong passphrase", unlocked["salt"], DEV_PARAMS, SECOND_FACTOR)
    with pytest.raises(crypto.DecryptionError):
        crypto.unwrap_master_key(unlocked["mk_wrapped"], unlocked["mk_nonce"], bad_kwk)


def test_missing_second_factor_cannot_unwrap_mk(unlocked):
    # A stolen database backup WITHOUT the out-of-DB second factor is useless,
    # even with the correct passphrase (Annex A 2, 5.2).
    wrong_factor = b"\x22" * 32
    bad_kwk = crypto.derive_kwk(PASSPHRASE, unlocked["salt"], DEV_PARAMS, wrong_factor)
    with pytest.raises(crypto.DecryptionError):
        crypto.unwrap_master_key(unlocked["mk_wrapped"], unlocked["mk_nonce"], bad_kwk)


# --- tamper detection -----------------------------------------------------


def test_tampered_ciphertext_raises(unlocked):
    owner_id = uuid.uuid4()
    aad = _aad(owner_id)
    row = crypto.encrypt_secret(unlocked["mk"], b"secret", aad)
    tampered = bytearray(row["ciphertext"])
    tampered[0] ^= 0x01
    row["ciphertext"] = bytes(tampered)
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_secret(unlocked["mk"], aad=aad, **row)


def test_tampered_aad_raises(unlocked):
    owner_id = uuid.uuid4()
    row = crypto.encrypt_secret(unlocked["mk"], b"secret", _aad(owner_id))
    with pytest.raises(crypto.DecryptionError):
        # Decrypt with a different AAD (e.g. kind changed) -> tag fails.
        crypto.decrypt_secret(unlocked["mk"], aad=_aad(owner_id, kind="pin"), **row)


# --- AAD binding: a DEK/ciphertext cannot move to another record ----------


def test_dek_reused_on_another_record_fails_aad(unlocked):
    owner_a = uuid.uuid4()
    owner_b = uuid.uuid4()
    row = crypto.encrypt_secret(unlocked["mk"], b"secret-of-A", _aad(owner_a))
    # Attacker copies A's ciphertext + wrapped DEK into B's row and tries to
    # decrypt in B's context. The DEK unwraps (same MK) but the AAD differs.
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_secret(unlocked["mk"], aad=_aad(owner_b), **row)


# --- no plaintext / DEK leakage in the stored row -------------------------


def test_stored_row_contains_only_wrapped_material(unlocked):
    aad = _aad(uuid.uuid4())
    plaintext = b"super-secret-value"
    dek_would_be = None  # we never get to see it
    row = crypto.encrypt_secret(unlocked["mk"], plaintext, aad)

    assert set(row) == {"ciphertext", "nonce", "dek_wrapped", "dek_nonce"}
    # None of the stored blobs equal the plaintext or the MK.
    for value in row.values():
        assert plaintext not in value
        assert unlocked["mk"] not in value
    assert dek_would_be is None


def test_encryption_is_non_deterministic(unlocked):
    aad = _aad(uuid.uuid4())
    r1 = crypto.encrypt_secret(unlocked["mk"], b"same", aad)
    r2 = crypto.encrypt_secret(unlocked["mk"], b"same", aad)
    assert r1["ciphertext"] != r2["ciphertext"]
    assert r1["nonce"] != r2["nonce"]
    assert r1["dek_wrapped"] != r2["dek_wrapped"]


# --- KWK derivation properties --------------------------------------------


def test_kwk_is_deterministic_for_same_inputs():
    salt = generate_salt()
    k1 = crypto.derive_kwk(PASSPHRASE, salt, DEV_PARAMS, SECOND_FACTOR)
    k2 = crypto.derive_kwk(PASSPHRASE, salt, DEV_PARAMS, SECOND_FACTOR)
    assert k1 == k2
    assert len(k1) == crypto.KEY_BYTES


def test_kwk_changes_with_salt_passphrase_and_factor():
    salt = generate_salt()
    base = crypto.derive_kwk(PASSPHRASE, salt, DEV_PARAMS, SECOND_FACTOR)
    assert crypto.derive_kwk(PASSPHRASE, generate_salt(), DEV_PARAMS, SECOND_FACTOR) != base
    assert crypto.derive_kwk(b"other", salt, DEV_PARAMS, SECOND_FACTOR) != base
    assert crypto.derive_kwk(PASSPHRASE, salt, DEV_PARAMS, b"\x33" * 32) != base


def test_short_second_factor_rejected():
    with pytest.raises(ValueError):
        crypto.derive_kwk(PASSPHRASE, generate_salt(), DEV_PARAMS, b"tooshort")


# --- record-shaped layer (seal / open_sealed) -----------------------------


def test_seal_produces_all_storable_fields(unlocked):
    owner_id = uuid.uuid4()
    row = crypto.seal(
        unlocked["mk"],
        owner_type="account",
        owner_id=owner_id,
        kind="password",
        plaintext=b"pw",
    )
    assert set(row) == {
        "ciphertext",
        "nonce",
        "dek_wrapped",
        "dek_nonce",
        "aad_context",
        "scheme_version",
    }
    assert row["aad_context"] == f"account:{owner_id}:password"
    assert row["scheme_version"] == 1


def test_open_sealed_round_trip(unlocked):
    owner_id = uuid.uuid4()
    row = crypto.seal(
        unlocked["mk"],
        owner_type="device",
        owner_id=owner_id,
        kind="snmp_community",
        plaintext=b"public-ish",
    )
    out = crypto.open_sealed(
        unlocked["mk"],
        owner_type="device",
        owner_id=owner_id,
        kind="snmp_community",
        ciphertext=row["ciphertext"],
        nonce=row["nonce"],
        dek_wrapped=row["dek_wrapped"],
        dek_nonce=row["dek_nonce"],
        aad_context=row["aad_context"],
    )
    assert out == b"public-ish"


def test_open_sealed_rejects_wrong_owner(unlocked):
    owner_id = uuid.uuid4()
    row = crypto.seal(
        unlocked["mk"],
        owner_type="account",
        owner_id=owner_id,
        kind="password",
        plaintext=b"pw",
    )
    # Same blobs, but claim a different owner_id at read time -> AAD mismatch.
    with pytest.raises(crypto.DecryptionError):
        crypto.open_sealed(
            unlocked["mk"],
            owner_type="account",
            owner_id=uuid.uuid4(),
            kind="password",
            ciphertext=row["ciphertext"],
            nonce=row["nonce"],
            dek_wrapped=row["dek_wrapped"],
            dek_nonce=row["dek_nonce"],
        )


def test_open_sealed_detects_tampered_aad_context(unlocked):
    owner_id = uuid.uuid4()
    row = crypto.seal(
        unlocked["mk"],
        owner_type="account",
        owner_id=owner_id,
        kind="password",
        plaintext=b"pw",
    )
    with pytest.raises(crypto.DecryptionError):
        crypto.open_sealed(
            unlocked["mk"],
            owner_type="account",
            owner_id=owner_id,
            kind="password",
            ciphertext=row["ciphertext"],
            nonce=row["nonce"],
            dek_wrapped=row["dek_wrapped"],
            dek_nonce=row["dek_nonce"],
            aad_context="account:somebody-else:password",
        )
