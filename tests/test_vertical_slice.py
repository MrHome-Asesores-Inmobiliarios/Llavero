"""P1-T19 acceptance test (Annex I 3): the thin vertical slice end to end.

- one login, one entity create, one secret stored and revealed, one logged change
- each step writes the right audit entry
- the chain verifies green
- a Viewer cannot reveal (keyless)
"""

import uuid

import pytest

from apps import vertical_slice as slice_
from apps.audit.models import AuditEntry
from apps.audit.verify import verify_chain
from apps.operators import auth, sessions
from apps.operators.models import Operator
from apps.operators.stepup import StepUpRequired
from apps.vault import key_holders
from apps.vault.kdf import DEV_PARAMS
from apps.vault.memory import MasterKeyLocked

SECOND_FACTOR = b"\x11" * 32
PASSPHRASE = b"admin vault passphrase, long and unique"
LOGIN_PW = "admin login password"


@pytest.fixture(autouse=True)
def _lock_after():
    yield
    sessions.lock_vault()


def _make_admin():
    op = Operator.objects.create(
        username="admin", display_name="Admin", role=Operator.Role.ADMINISTRATOR, password_hash=""
    )
    auth.set_password(op, LOGIN_PW)
    key_holders.install_vault(
        operator=op, passphrase=PASSPHRASE, second_factor=SECOND_FACTOR, params=DEV_PARAMS
    )
    auth.enroll_totp(op, SECOND_FACTOR)
    return op


def _totp_code(op):
    import pyotp

    seed = auth._load_totp_secret(op, SECOND_FACTOR)
    return pyotp.TOTP(seed).now()


@pytest.mark.django_db
def test_full_happy_path_with_audit_and_verify():
    admin = _make_admin()

    # 1. login (password + TOTP) and unlock the vault.
    session, token = slice_.login(
        operator=admin,
        password=LOGIN_PW,
        totp_code=_totp_code(admin),
        second_factor=SECOND_FACTOR,
        passphrase=PASSPHRASE,
    )
    assert sessions.is_vault_unlocked()
    assert session.token_hash != token  # only the hash is stored

    # 2. create an entity (logged).
    person = slice_.create_person(operator=admin, session=session, full_name="Ada Lovelace")

    # 3. store a secret for that person (step-up + logged).
    secret = slice_.store_secret(
        operator=admin,
        session=session,
        owner_type="account",
        owner_id=person.id,
        kind="password",
        plaintext=b"s3cr3t-value",
        label="Ada O365",
        fresh_factor=True,
    )

    # 4. reveal it (per-action step-up + logged), value round-trips.
    revealed = slice_.reveal_secret(
        operator=admin,
        session=session,
        secret=secret,
        reason="rotating credentials",
        fresh_factor=True,
    )
    assert revealed == b"s3cr3t-value"

    # 5. the right audit entries were written, in order.
    actions = list(AuditEntry.objects.order_by("seq").values_list("action", flat=True))
    assert actions == [
        "login_success",
        "vault_unlock",
        "create",
        "secret_create",
        "secret_reveal",
    ]

    # 6. the reveal logged the reason but NEVER the secret value.
    reveal_entry = AuditEntry.objects.get(action="secret_reveal")
    assert reveal_entry.metadata["reason"] == "rotating credentials"
    for entry in AuditEntry.objects.all():
        blob = (str(entry.changes) + str(entry.metadata)).encode()
        assert b"s3cr3t-value" not in blob

    # 7. the chain verifies green.
    assert verify_chain().ok


@pytest.mark.django_db
def test_reveal_requires_step_up_every_time():
    admin = _make_admin()
    session, _ = slice_.login(
        operator=admin,
        password=LOGIN_PW,
        totp_code=_totp_code(admin),
        second_factor=SECOND_FACTOR,
        passphrase=PASSPHRASE,
    )
    secret = slice_.store_secret(
        operator=admin,
        session=session,
        owner_type="account",
        owner_id=uuid.uuid4(),
        kind="password",
        plaintext=b"x",
        fresh_factor=True,
    )
    # Without a fresh factor the reveal is refused (no caching).
    with pytest.raises(StepUpRequired):
        slice_.reveal_secret(
            operator=admin, session=session, secret=secret, reason="r", fresh_factor=False
        )


@pytest.mark.django_db
def test_viewer_cannot_reveal():
    admin = _make_admin()
    # An admin stores a secret first.
    a_session, _ = slice_.login(
        operator=admin,
        password=LOGIN_PW,
        totp_code=_totp_code(admin),
        second_factor=SECOND_FACTOR,
        passphrase=PASSPHRASE,
    )
    secret = slice_.store_secret(
        operator=admin,
        session=a_session,
        owner_type="account",
        owner_id=uuid.uuid4(),
        kind="password",
        plaintext=b"top",
        fresh_factor=True,
    )

    viewer = Operator.objects.create(
        username="v", display_name="V", role=Operator.Role.VIEWER, password_hash=""
    )
    auth.set_password(viewer, "viewer pw")
    auth.enroll_totp(viewer, SECOND_FACTOR)
    v_session, _ = slice_.login(
        operator=viewer,
        password="viewer pw",
        totp_code=_totp_code(viewer),
        second_factor=SECOND_FACTOR,
    )
    assert not sessions.is_vault_unlocked()  # Viewer holds no MK
    # The reveal flow has nothing to decrypt with.
    with pytest.raises(MasterKeyLocked):
        slice_.reveal_secret(
            operator=viewer, session=v_session, secret=secret, reason="x", fresh_factor=True
        )
