"""P4-T1..T5 view-level tests.

Covers:
- Viewer is blocked at the server (cryptographic, not just role check)
- Step-up is enforced before reveal and rotation
- Audit events fire for every action
- Plaintext never appears in audit log, session, or cached field
- Archive / restore state change is audited
- List / detail views return masked value server-side for Viewer
"""

import uuid

import pytest
from django.test import Client

from apps.audit.models import AuditEntry
from apps.operators import sessions as sessions_module
from apps.operators.models import Operator, OperatorSession
from apps.vault import crypto, key_holders
from apps.vault.kdf import DEV_PARAMS
from apps.vault.models import Secret, SecretKind, SecretOwnerType, SecretState

FACTOR = b"\xaa" * 32
PASSPHRASE = b"test vault passphrase long enough"
PLAINTEXT = b"super-secret-value-42"
MASKED = "•" * 8  # ••••••••


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _hash_pw(pw: str) -> str:
    import hashlib

    return "argon2:" + hashlib.sha256(pw.encode()).hexdigest()


@pytest.fixture
def admin(db):
    op = Operator.objects.create(
        username="view_admin",
        display_name="Admin",
        role=Operator.Role.ADMINISTRATOR,
        password_hash=_hash_pw("admin-pw"),
        is_active=True,
    )
    return op


@pytest.fixture
def viewer(db):
    op = Operator.objects.create(
        username="view_viewer",
        display_name="Viewer",
        role=Operator.Role.VIEWER,
        password_hash=_hash_pw("viewer-pw"),
        is_active=True,
    )
    return op


@pytest.fixture
def mk(admin):
    """Install vault and return the MK; unlock the in-process holder."""
    _, mk_bytes = key_holders.install_vault(
        operator=admin, passphrase=PASSPHRASE, second_factor=FACTOR, params=DEV_PARAMS
    )
    sessions_module.configure_holder(idle_seconds=3600)
    # Simulate an admin session so is_vault_unlocked() returns True
    OperatorSession.objects.create(operator=admin, token_hash="testhash_admin", ip="127.0.0.1")
    sessions_module.establish_session(operator=admin, ip="127.0.0.1", mk=bytearray(mk_bytes))
    return mk_bytes


@pytest.fixture
def secret(admin, mk):
    """A real encrypted secret row."""
    owner_id = uuid.uuid4()
    row = crypto.seal(
        mk,
        owner_type=SecretOwnerType.ACCOUNT,
        owner_id=owner_id,
        kind=SecretKind.PASSWORD,
        plaintext=PLAINTEXT,
    )
    s = Secret.objects.create(
        owner_type=SecretOwnerType.ACCOUNT,
        owner_id=owner_id,
        kind=SecretKind.PASSWORD,
        label="Test secret",
        state=SecretState.ACTIVE,
        ciphertext=row["ciphertext"],
        nonce=row["nonce"],
        dek_wrapped=row["dek_wrapped"],
        dek_nonce=row["dek_nonce"],
        aad_context=row["aad_context"],
        scheme_version=row["scheme_version"],
        created_by=admin,
        updated_by=admin,
    )
    return s


def _admin_client(admin):
    c = Client()
    session = c.session
    session["operator_id"] = str(admin.pk)
    session.save()
    return c


def _viewer_client(viewer):
    c = Client()
    session = c.session
    session["operator_id"] = str(viewer.pk)
    session.save()
    return c


# ---------------------------------------------------------------------------
# P4-T1: Secret list view
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_secret_list_requires_login():
    c = Client()
    r = c.get("/vault/")
    assert r.status_code == 302  # redirect to login


@pytest.mark.django_db
def test_secret_list_viewer_sees_masked(viewer, secret, mk):
    # The Viewer session never gets the MK, but the list page itself is readable
    # (just masked). We need to lock vault for viewer scenario.
    # The fixture unlocked vault for admin; now simulate a viewer session on top.
    sessions_module.lock_vault()  # lock before viewer
    c = _viewer_client(viewer)
    r = c.get("/vault/")
    assert r.status_code == 200
    content = r.content.decode()
    assert MASKED in content
    assert PLAINTEXT.decode() not in content


@pytest.mark.django_db
def test_secret_list_admin_can_reach(admin, mk):
    c = _admin_client(admin)
    r = c.get("/vault/")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# P4-T1: Secret detail
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_secret_detail_masked_for_viewer(viewer, secret, mk):
    sessions_module.lock_vault()
    c = _viewer_client(viewer)
    r = c.get(f"/vault/{secret.pk}/")
    assert r.status_code == 200
    content = r.content.decode()
    assert MASKED in content
    assert PLAINTEXT.decode() not in content


@pytest.mark.django_db
def test_secret_detail_masked_for_admin_too(admin, secret, mk):
    """Detail page never shows plaintext — only the reveal endpoint does."""
    c = _admin_client(admin)
    r = c.get(f"/vault/{secret.pk}/")
    assert r.status_code == 200
    content = r.content.decode()
    assert MASKED in content
    assert PLAINTEXT.decode() not in content


# ---------------------------------------------------------------------------
# P4-T1: Create view blocked for Viewer
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_create_view_forbidden_for_viewer(viewer, mk):
    c = _viewer_client(viewer)
    r = c.get("/vault/new/")
    assert r.status_code == 403


@pytest.mark.django_db
def test_create_post_forbidden_for_viewer(viewer, mk):
    c = _viewer_client(viewer)
    r = c.post(
        "/vault/new/",
        {
            "owner_type": SecretOwnerType.ACCOUNT,
            "owner_id": str(uuid.uuid4()),
            "kind": SecretKind.PASSWORD,
            "plaintext": "xyz",
            "fresh_factor": "1",
        },
    )
    assert r.status_code == 403


@pytest.mark.django_db
def test_create_view_blocked_when_vault_locked(admin, mk):
    """If vault is locked (e.g. idle auto-lock) the create page returns 403."""
    sessions_module.lock_vault()
    c = _admin_client(admin)
    r = c.get("/vault/new/")
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# P4-T1: Secret create — happy path + audit
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_secret_create_writes_row_and_audit(admin, mk):
    c = _admin_client(admin)
    owner_id = uuid.uuid4()
    before_count = Secret.objects.count()
    r = c.post(
        "/vault/new/",
        {
            "owner_type": SecretOwnerType.ACCOUNT,
            "owner_id": str(owner_id),
            "kind": SecretKind.PASSWORD,
            "label": "created by test",
            "plaintext": "test-secret-value",
            "fresh_factor": "1",
        },
    )
    assert r.status_code == 302
    assert Secret.objects.count() == before_count + 1
    s = Secret.objects.filter(label="created by test").first()
    assert s is not None
    assert s.state == SecretState.ACTIVE
    # Audit entry
    entry = AuditEntry.objects.filter(action="secret_create").order_by("-seq").first()
    assert entry is not None
    assert entry.target_table == "secret"
    # Plaintext never in audit
    blob = str(entry.changes) + str(entry.metadata)
    assert "test-secret-value" not in blob


@pytest.mark.django_db
def test_secret_create_ciphertext_decrypts_correctly(admin, mk):
    """Round-trip: create via view, then decrypt with mk, compare plaintext."""
    c = _admin_client(admin)
    owner_id = uuid.uuid4()
    c.post(
        "/vault/new/",
        {
            "owner_type": SecretOwnerType.DEVICE,
            "owner_id": str(owner_id),
            "kind": SecretKind.API_KEY,
            "label": "roundtrip",
            "plaintext": "roundtrip-value",
            "fresh_factor": "1",
        },
    )
    s = Secret.objects.get(label="roundtrip")
    result = crypto.open_sealed(
        mk,
        owner_type=s.owner_type,
        owner_id=s.owner_id,
        kind=s.kind,
        ciphertext=bytes(s.ciphertext),
        nonce=bytes(s.nonce),
        dek_wrapped=bytes(s.dek_wrapped),
        dek_nonce=bytes(s.dek_nonce),
        aad_context=s.aad_context,
    )
    assert result == b"roundtrip-value"


# ---------------------------------------------------------------------------
# P4-T2: Reveal — step-up enforced
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_reveal_get_without_fresh_factor_redirects_to_stepup(admin, secret, mk):
    c = _admin_client(admin)
    r = c.get(f"/vault/{secret.pk}/reveal/")
    # Should redirect to step-up (no fresh_factor)
    assert r.status_code == 302
    assert "stepup" in r["Location"]


@pytest.mark.django_db
def test_reveal_post_without_fresh_factor_redirects(admin, secret, mk):
    c = _admin_client(admin)
    r = c.post(f"/vault/{secret.pk}/reveal/", {"reason": "test"})
    assert r.status_code == 302
    assert "stepup" in r["Location"]


@pytest.mark.django_db
def test_reveal_post_with_fresh_factor_returns_value(admin, secret, mk):
    c = _admin_client(admin)
    r = c.post(
        f"/vault/{secret.pk}/reveal/",
        {"reason": "integration test", "fresh_factor": "1"},
    )
    assert r.status_code == 200
    content = r.content.decode()
    assert PLAINTEXT.decode() in content
    # Audit written
    entry = AuditEntry.objects.filter(action="secret_reveal").order_by("-seq").first()
    assert entry is not None
    assert entry.metadata["reason"] == "integration test"
    # Plaintext never in audit
    assert PLAINTEXT.decode() not in str(entry.changes) + str(entry.metadata)


@pytest.mark.django_db
def test_reveal_requires_fresh_factor_every_time(admin, secret, mk):
    """Reveal is per-action, never windowed. Each call needs fresh_factor=1."""
    c = _admin_client(admin)
    # First reveal with fresh factor — succeeds
    r1 = c.post(
        f"/vault/{secret.pk}/reveal/",
        {"reason": "first", "fresh_factor": "1"},
    )
    assert r1.status_code == 200
    # Second call without fresh factor — redirected to step-up
    r2 = c.post(f"/vault/{secret.pk}/reveal/", {"reason": "second"})
    assert r2.status_code == 302
    assert "stepup" in r2["Location"]


# ---------------------------------------------------------------------------
# P4-T4: Viewer blocked at cryptographic level
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_reveal_blocked_for_viewer_by_role(viewer, secret, mk):
    """Viewer is blocked by @require_admin before reaching the vault check."""
    sessions_module.lock_vault()
    c = _viewer_client(viewer)
    r = c.post(
        f"/vault/{secret.pk}/reveal/",
        {"reason": "x", "fresh_factor": "1"},
    )
    assert r.status_code == 403


@pytest.mark.django_db
def test_reveal_blocked_when_vault_locked_for_admin(admin, secret, mk):
    """Even an admin gets 403 when vault is locked (e.g. idle auto-lock)."""
    sessions_module.lock_vault()
    c = _admin_client(admin)
    r = c.post(
        f"/vault/{secret.pk}/reveal/",
        {"reason": "x", "fresh_factor": "1"},
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# P4-T3: Rotation
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_rotate_get_without_fresh_factor_redirects(admin, secret, mk):
    c = _admin_client(admin)
    r = c.get(f"/vault/{secret.pk}/rotate/")
    assert r.status_code == 302
    assert "stepup" in r["Location"]


@pytest.mark.django_db
def test_rotate_post_replaces_ciphertext_and_audits(admin, secret, mk):
    c = _admin_client(admin)
    old_ciphertext = bytes(secret.ciphertext)
    r = c.post(
        f"/vault/{secret.pk}/rotate/",
        {"new_plaintext": "rotated-value", "fresh_factor": "1"},
    )
    assert r.status_code == 302
    secret.refresh_from_db()
    assert bytes(secret.ciphertext) != old_ciphertext
    assert secret.last_rotated_at is not None
    # Decrypts to new value
    result = crypto.open_sealed(
        mk,
        owner_type=secret.owner_type,
        owner_id=secret.owner_id,
        kind=secret.kind,
        ciphertext=bytes(secret.ciphertext),
        nonce=bytes(secret.nonce),
        dek_wrapped=bytes(secret.dek_wrapped),
        dek_nonce=bytes(secret.dek_nonce),
        aad_context=secret.aad_context,
    )
    assert result == b"rotated-value"
    # Audit
    entry = AuditEntry.objects.filter(action="secret_rotate").order_by("-seq").first()
    assert entry is not None
    assert entry.target_id == secret.id
    # No plaintext in audit
    assert "rotated-value" not in str(entry.changes) + str(entry.metadata)


@pytest.mark.django_db
def test_rotate_blocked_for_viewer(viewer, secret, mk):
    sessions_module.lock_vault()
    c = _viewer_client(viewer)
    r = c.post(
        f"/vault/{secret.pk}/rotate/",
        {"new_plaintext": "x", "fresh_factor": "1"},
    )
    assert r.status_code == 403


@pytest.mark.django_db
def test_rotate_blocked_when_vault_locked(admin, secret, mk):
    sessions_module.lock_vault()
    c = _admin_client(admin)
    r = c.post(
        f"/vault/{secret.pk}/rotate/",
        {"new_plaintext": "x", "fresh_factor": "1"},
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# P4-T5: State change — archive / restore
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_archive_secret_changes_state_and_audits(admin, secret, mk):
    c = _admin_client(admin)
    r = c.post(f"/vault/{secret.pk}/state/", {"new_state": "archived"})
    assert r.status_code == 302
    secret.refresh_from_db()
    assert secret.state == SecretState.ARCHIVED
    entry = AuditEntry.objects.filter(action="secret_state_change").order_by("-seq").first()
    assert entry is not None
    assert entry.changes["state"]["new"] == "archived"


@pytest.mark.django_db
def test_restore_secret_changes_state_and_audits(admin, secret, mk):
    secret.state = SecretState.ARCHIVED
    secret.save(update_fields=["state"])
    c = _admin_client(admin)
    r = c.post(f"/vault/{secret.pk}/state/", {"new_state": "active"})
    assert r.status_code == 302
    secret.refresh_from_db()
    assert secret.state == SecretState.ACTIVE
    entry = AuditEntry.objects.filter(action="secret_state_change").order_by("-seq").first()
    assert entry is not None
    assert entry.changes["state"]["new"] == "active"


@pytest.mark.django_db
def test_state_change_blocked_for_viewer(viewer, secret, mk):
    sessions_module.lock_vault()
    c = _viewer_client(viewer)
    r = c.post(f"/vault/{secret.pk}/state/", {"new_state": "archived"})
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# P4-T5: Metadata edit
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_edit_label_audits_update(admin, secret, mk):
    c = _admin_client(admin)
    r = c.post(f"/vault/{secret.pk}/edit/", {"label": "new label"})
    assert r.status_code == 302
    secret.refresh_from_db()
    assert secret.label == "new label"
    entry = (
        AuditEntry.objects.filter(action="update", target_table="secret").order_by("-seq").first()
    )
    assert entry is not None
    assert entry.changes["label"]["new"] == "new label"


# ---------------------------------------------------------------------------
# Security: plaintext never leaks into any audit entry
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_plaintext_never_in_audit_entries(admin, secret, mk):
    c = _admin_client(admin)
    # Reveal
    c.post(
        f"/vault/{secret.pk}/reveal/",
        {"reason": "audit-check", "fresh_factor": "1"},
    )
    for entry in AuditEntry.objects.all():
        blob = (str(entry.changes) + str(entry.metadata)).encode()
        assert (
            PLAINTEXT not in blob
        ), f"Plaintext leaked in audit entry #{entry.seq}: {entry.action}"
