"""P1-T15 acceptance + security-property tests (Annex D 1, 2; Annex C 4.1, 4.2).

Brief acceptance criteria:
- login needs password + a valid WebAuthn/TOTP
- WebAuthn sign_count replay is rejected
- an Admin login enters the vault-unlock path, a Viewer login does not

Plus: the login password hash is Argon2id and distinct from the vault; the TOTP
seed is stored encrypted (not plaintext) and unreadable without the second
factor; wrong/expired codes fail.
"""

from types import SimpleNamespace
from unittest import mock

import pyotp
import pytest

from apps.operators import auth
from apps.operators.auth import AuthResult, ReplayDetected
from apps.operators.models import Operator, OperatorTotpDevice, OperatorWebAuthnCredential

SECOND_FACTOR = b"\x11" * 32


@pytest.fixture
def admin(db):
    op = Operator.objects.create(
        username="admin", display_name="Admin", role=Operator.Role.ADMINISTRATOR, password_hash=""
    )
    auth.set_password(op, "correct horse battery staple")
    return op


@pytest.fixture
def viewer(db):
    op = Operator.objects.create(
        username="viewer", display_name="Viewer", role=Operator.Role.VIEWER, password_hash=""
    )
    auth.set_password(op, "viewer-pass-phrase")
    return op


# --- password (Argon2id login hash, separate from the vault) --------------


@pytest.mark.django_db
def test_password_hash_is_argon2id_and_verifies(admin):
    assert admin.password_hash.startswith("$argon2id$")
    assert auth.check_password(admin, "correct horse battery staple")
    assert not auth.check_password(admin, "wrong")


@pytest.mark.django_db
def test_password_hash_is_not_the_raw_password(admin):
    assert "correct horse battery staple" not in admin.password_hash


# --- TOTP fallback (pyotp), encrypted seed --------------------------------


@pytest.mark.django_db
def test_totp_enroll_and_verify(admin):
    seed, uri = auth.enroll_totp(admin, SECOND_FACTOR)
    assert uri.startswith("otpauth://totp/")
    code = pyotp.TOTP(seed).now()
    assert auth.verify_totp(admin, code, SECOND_FACTOR)
    assert not auth.verify_totp(admin, "000000", SECOND_FACTOR)


@pytest.mark.django_db
def test_totp_seed_stored_encrypted_not_plaintext(admin):
    seed, _ = auth.enroll_totp(admin, SECOND_FACTOR)
    device = OperatorTotpDevice.objects.get(operator=admin)
    assert seed.encode() not in bytes(device.ciphertext)
    # The seed cannot be recovered without the correct server second factor.
    assert not auth.verify_totp(admin, pyotp.TOTP(seed).now(), b"\x22" * 32)


@pytest.mark.django_db
def test_totp_confirmed_on_first_success(admin):
    seed, _ = auth.enroll_totp(admin, SECOND_FACTOR)
    assert not OperatorTotpDevice.objects.get(operator=admin).confirmed
    auth.verify_totp(admin, pyotp.TOTP(seed).now(), SECOND_FACTOR)
    assert OperatorTotpDevice.objects.get(operator=admin).confirmed


# --- WebAuthn sign_count replay rejection ---------------------------------


@pytest.mark.django_db
def test_sign_count_must_increase(admin):
    cred = OperatorWebAuthnCredential.objects.create(
        operator=admin, credential_id=b"c1", public_key=b"pk", sign_count=5
    )
    # A higher count is accepted and stored.
    auth.check_and_update_sign_count(cred, 6)
    cred.refresh_from_db()
    assert cred.sign_count == 6
    # Equal or lower is a replay/clone -> rejected, counter unchanged.
    with pytest.raises(ReplayDetected):
        auth.check_and_update_sign_count(cred, 6)
    with pytest.raises(ReplayDetected):
        auth.check_and_update_sign_count(cred, 3)
    cred.refresh_from_db()
    assert cred.sign_count == 6


@pytest.mark.django_db
def test_sign_count_zero_zero_is_allowed(admin):
    # An authenticator without a counter reports 0; no regression to reject.
    cred = OperatorWebAuthnCredential.objects.create(
        operator=admin, credential_id=b"c2", public_key=b"pk", sign_count=0
    )
    auth.check_and_update_sign_count(cred, 0)
    cred.refresh_from_db()
    assert cred.sign_count == 0


@pytest.mark.django_db
def test_webauthn_auth_applies_replay_rule(admin):
    cred = OperatorWebAuthnCredential.objects.create(
        operator=admin, credential_id=b"c3", public_key=b"pk", sign_count=10
    )
    # Mock py_webauthn's crypto verification; assert OUR replay rule then bites.
    with mock.patch("webauthn.verify_authentication_response") as mocked:
        mocked.return_value = SimpleNamespace(new_sign_count=9)  # not increasing
        with pytest.raises(ReplayDetected):
            auth.verify_webauthn_authentication(
                cred,
                credential_response="{}",
                expected_challenge=b"chal",
                expected_rp_id="llavero.internal",
                expected_origin="https://llavero.internal",
            )
    cred.refresh_from_db()
    assert cred.sign_count == 10  # unchanged after rejected replay


# --- role routing: Admin unlocks the vault, Viewer does not ---------------


@pytest.mark.django_db
def test_admin_login_requires_vault_unlock(admin):
    result = auth.login_outcome(admin)
    assert isinstance(result, AuthResult)
    assert result.role == Operator.Role.ADMINISTRATOR
    assert result.requires_vault_unlock is True


@pytest.mark.django_db
def test_viewer_login_does_not_unlock_vault(viewer):
    result = auth.login_outcome(viewer)
    assert result.role == Operator.Role.VIEWER
    assert result.requires_vault_unlock is False


@pytest.mark.django_db
def test_inactive_operator_cannot_complete_login(admin):
    admin.is_active = False
    admin.save(update_fields=["is_active"])
    with pytest.raises(PermissionError):
        auth.login_outcome(admin)
