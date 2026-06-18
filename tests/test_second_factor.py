"""P1-T7 acceptance + security-property tests (Annex A 5.2; Annex G 4).

Brief acceptance criteria:
- unlock works with passphrase + factor
- with the factor missing or wrong, the wrapped-MK decrypt fails
- a database-only copy with no factor cannot derive the MK

The keyfile fallback is exercised end to end on the dev box. The TPM provider
is exercised through an injected seal/unseal seam (no hardware here); the real
tpm2 tooling is finalised on the hardened server (P0-T6).
"""

import os

import nacl.bindings as sodium
import pytest

from apps.vault import crypto, second_factor
from apps.vault.kdf import DEV_PARAMS, generate_salt
from apps.vault.second_factor import (
    KeyfileSecondFactor,
    SecondFactorUnavailable,
    TPMSecondFactor,
    unlock_master_key,
)

PASSPHRASE = b"a-very-long-admin-passphrase-for-tests"


def _provision_vault(provider):
    """Install-time: generate MK, derive KWK from passphrase + factor, wrap MK.

    Returns only what would live in the database (salt + wrapped MK), plus the
    real MK for the test to compare against.
    """
    salt = generate_salt()
    secret = provider.get_secret()
    kwk = crypto.derive_kwk(PASSPHRASE, salt, DEV_PARAMS, secret)
    mk = crypto.generate_master_key()
    mk_wrapped, mk_nonce = crypto.wrap_master_key(mk, kwk)
    return {"salt": salt, "mk": mk, "mk_wrapped": mk_wrapped, "mk_nonce": mk_nonce}


# --- keyfile provider -----------------------------------------------------


def test_keyfile_provision_creates_256bit_secret(tmp_path):
    path = tmp_path / "vault.keyfile"
    kf = KeyfileSecondFactor.provision(str(path))
    secret = kf.get_secret()
    assert len(secret) == second_factor.SECOND_FACTOR_BYTES == 32
    assert path.exists()


def test_keyfile_secret_is_stable_and_random(tmp_path):
    a = KeyfileSecondFactor.provision(str(tmp_path / "a"))
    b = KeyfileSecondFactor.provision(str(tmp_path / "b"))
    assert a.get_secret() == a.get_secret()  # stable across reads
    assert a.get_secret() != b.get_secret()  # independent randomness


@pytest.mark.skipif(os.name != "posix", reason="POSIX file permissions")
def test_keyfile_has_owner_only_permissions(tmp_path):
    path = tmp_path / "kf"
    KeyfileSecondFactor.provision(str(path))
    mode = path.stat().st_mode & 0o777
    assert mode & 0o077 == 0  # no group/other access


def test_missing_keyfile_raises_unavailable(tmp_path):
    kf = KeyfileSecondFactor(str(tmp_path / "nope"))
    with pytest.raises(SecondFactorUnavailable):
        kf.get_secret()


def test_truncated_keyfile_rejected(tmp_path):
    path = tmp_path / "short"
    path.write_bytes(b"\x00" * 8)
    with pytest.raises(SecondFactorUnavailable):
        KeyfileSecondFactor(str(path)).get_secret()


def test_keyfile_write_is_byte_exact_even_with_newline_bytes(tmp_path, monkeypatch):
    # Regression: on Windows os.open defaults to text mode, expanding 0x0A to
    # 0x0D0A and corrupting the keyfile. The secret must round-trip byte-exactly.
    tricky = bytes(range(32))  # includes 0x0A and 0x0D
    monkeypatch.setattr(second_factor.sodium, "randombytes", lambda n: tricky)
    path = tmp_path / "kf"
    kf = KeyfileSecondFactor.provision(str(path))
    assert path.stat().st_size == 32  # no newline expansion on write
    assert kf.get_secret() == tricky


# --- unlock: passphrase + factor ------------------------------------------


def test_unlock_succeeds_with_passphrase_and_factor(tmp_path):
    kf = KeyfileSecondFactor.provision(str(tmp_path / "kf"))
    v = _provision_vault(kf)
    mk = unlock_master_key(kf, PASSPHRASE, v["salt"], DEV_PARAMS, v["mk_wrapped"], v["mk_nonce"])
    assert mk == v["mk"]


def test_unlock_fails_with_wrong_factor(tmp_path):
    kf = KeyfileSecondFactor.provision(str(tmp_path / "kf"))
    v = _provision_vault(kf)
    other = KeyfileSecondFactor.provision(str(tmp_path / "kf2"))
    with pytest.raises(crypto.DecryptionError):
        unlock_master_key(other, PASSPHRASE, v["salt"], DEV_PARAMS, v["mk_wrapped"], v["mk_nonce"])


def test_unlock_fails_with_missing_factor(tmp_path):
    kf = KeyfileSecondFactor.provision(str(tmp_path / "kf"))
    v = _provision_vault(kf)
    absent = KeyfileSecondFactor(str(tmp_path / "gone"))
    with pytest.raises(SecondFactorUnavailable):
        unlock_master_key(absent, PASSPHRASE, v["salt"], DEV_PARAMS, v["mk_wrapped"], v["mk_nonce"])


def test_unlock_fails_with_wrong_passphrase(tmp_path):
    kf = KeyfileSecondFactor.provision(str(tmp_path / "kf"))
    v = _provision_vault(kf)
    with pytest.raises(crypto.DecryptionError):
        unlock_master_key(kf, b"wrong-pass", v["salt"], DEV_PARAMS, v["mk_wrapped"], v["mk_nonce"])


def test_database_only_copy_without_factor_cannot_derive_mk(tmp_path):
    # Everything an attacker gets from the database: salt, wrapped MK + nonce,
    # and even the passphrase. WITHOUT the out-of-database factor the MK cannot
    # be derived; the best they can do is guess the 256-bit factor.
    kf = KeyfileSecondFactor.provision(str(tmp_path / "kf"))
    v = _provision_vault(kf)
    guessed_factor = sodium.randombytes(32)
    bad_kwk = crypto.derive_kwk(PASSPHRASE, v["salt"], DEV_PARAMS, guessed_factor)
    with pytest.raises(crypto.DecryptionError):
        crypto.unwrap_master_key(v["mk_wrapped"], v["mk_nonce"], bad_kwk)


# --- TPM provider (injected seam; real tooling finalised on the server) ----


class FakeTPM:
    """In-memory stand-in for a TPM 2.0 seal/unseal pair.

    NOT secure and NOT hardware-bound — it only exercises the provider contract
    on a box without a TPM. The real seal/unseal shells out to tpm2 tooling on
    the server (see deploy/README.md).
    """

    def __init__(self):
        self._blob = None

    def seal(self, secret: bytes) -> bytes:
        self._blob = b"sealed::" + secret
        return self._blob

    def unseal(self, blob: bytes) -> bytes:
        if blob != self._blob:
            raise SecondFactorUnavailable("unknown sealed blob")
        return blob[len(b"sealed::") :]


def test_tpm_provider_roundtrip_via_injected_seam():
    tpm = FakeTPM()
    prov = TPMSecondFactor.provision(seal_fn=tpm.seal, unseal_fn=tpm.unseal)
    secret = prov.get_secret()
    assert len(secret) == 32
    assert prov.get_secret() == secret  # stable across unseals


def test_tpm_secret_plugs_into_the_same_kwk_path(tmp_path):
    tpm = FakeTPM()
    prov = TPMSecondFactor.provision(seal_fn=tpm.seal, unseal_fn=tpm.unseal)
    v = _provision_vault(prov)
    mk = unlock_master_key(prov, PASSPHRASE, v["salt"], DEV_PARAMS, v["mk_wrapped"], v["mk_nonce"])
    assert mk == v["mk"]


def test_tpm_without_tooling_fails_loudly_not_silently():
    # No injected seam and no tpm2 tooling: must raise, never return a weak/empty
    # secret that would silently degrade security.
    prov = TPMSecondFactor(sealed_blob=b"opaque")
    with pytest.raises(SecondFactorUnavailable):
        prov.get_secret()


# --- factory --------------------------------------------------------------


def test_factory_selects_keyfile(settings, tmp_path):
    path = tmp_path / "kf"
    KeyfileSecondFactor.provision(str(path))
    settings.LLAVERO_SECOND_FACTOR_MODE = "keyfile"
    settings.LLAVERO_KEYFILE_PATH = str(path)
    prov = second_factor.load_second_factor()
    assert isinstance(prov, KeyfileSecondFactor)
    assert len(prov.get_secret()) == 32


def test_factory_rejects_unknown_mode(settings):
    settings.LLAVERO_SECOND_FACTOR_MODE = "magic"
    with pytest.raises(SecondFactorUnavailable):
        second_factor.load_second_factor()
