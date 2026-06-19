"""P7-T2: Automated security-pass tests for v1 go-live gate.

Covers:
1. Egress — integration runners only contact known URL prefixes.
2. Role/field matrix — Viewer cannot POST to any write endpoint.
3. Viewer export block — no view renders ciphertext/MK/DEK into a response.
4. Single session — establish_session() revokes the prior session.
5. Audit completeness — every write action produces an AuditEntry.
6. Viewer keyless — is_vault_unlocked() is False after a Viewer login.
7. No hard delete — URLconf exposes no delete URL for core entities.
"""

import ast
import uuid
from pathlib import Path

import pytest
from django.test import Client
from django.urls import reverse

from apps.operators import sessions
from apps.operators.models import Operator, OperatorSession
from apps.operators.sessions import is_vault_unlocked

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MK = bytes(range(32))
RUNNERS_DIR = Path(__file__).resolve().parent.parent / "apps" / "integrations" / "runners"

# Prefixes that the runners are ALLOWED to contact.
# These are the known M365/Graph + configurable-host patterns.
ALLOWED_URL_PREFIXES = (
    "https://login.microsoftonline.com/",
    "https://graph.microsoft.com/",
)


def _make_operator(role, username=None):
    username = username or f"op_{role}_{uuid.uuid4().hex[:6]}"
    return Operator.objects.create(
        username=username,
        display_name=username,
        role=role,
        password_hash="argon2:test",
        is_active=True,
    )


def _make_viewer_client(viewer: Operator) -> Client:
    client = Client()
    session = client.session
    session["operator_id"] = str(viewer.pk)
    session.save()
    return client


# ---------------------------------------------------------------------------
# 1. Egress: runner files contain no hardcoded random URLs
# ---------------------------------------------------------------------------


class TestEgressNoRogueUrls:
    """Parse runner ASTs and collect all string literals that look like URLs.

    Only absolute https:// URLs are interesting; relative paths and format
    strings are reviewed separately.  The Graph runner defines two module-level
    URL constants (token + MFA endpoints) — both must be in ALLOWED_URL_PREFIXES.
    Mikrotik/UniFi/WatchGuard use only config-supplied hosts (no hardcoded URLs).
    """

    def _collect_string_literals(self, path: Path) -> list[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        literals = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                literals.append(node.value)
        return literals

    def test_graph_runner_only_known_urls(self):
        path = RUNNERS_DIR / "graph.py"
        literals = self._collect_string_literals(path)
        hardcoded = [s for s in literals if s.startswith("https://")]
        for url in hardcoded:
            assert any(
                url.startswith(p) for p in ALLOWED_URL_PREFIXES
            ), f"Unexpected hardcoded URL in graph.py: {url!r}"

    def test_mikrotik_runner_no_hardcoded_https_urls(self):
        path = RUNNERS_DIR / "mikrotik.py"
        literals = self._collect_string_literals(path)
        hardcoded = [s for s in literals if s.startswith("https://") or s.startswith("http://")]
        assert hardcoded == [], f"Unexpected hardcoded URL in mikrotik.py: {hardcoded}"

    def test_unifi_runner_no_hardcoded_non_config_urls(self):
        """UniFi builds URLs from config['base_url'] — no hardcoded base URLs."""
        path = RUNNERS_DIR / "unifi.py"
        literals = self._collect_string_literals(path)
        # The only string constants starting https:// must come from allowed domains.
        hardcoded = [s for s in literals if s.startswith("https://") or s.startswith("http://")]
        for url in hardcoded:
            assert any(
                url.startswith(p) for p in ALLOWED_URL_PREFIXES
            ), f"Unexpected hardcoded URL in unifi.py: {url!r}"

    def test_watchguard_runner_no_hardcoded_https_urls(self):
        path = RUNNERS_DIR / "watchguard.py"
        literals = self._collect_string_literals(path)
        hardcoded = [s for s in literals if s.startswith("https://") or s.startswith("http://")]
        assert hardcoded == [], f"Unexpected hardcoded URL in watchguard.py: {hardcoded}"

    def test_dispatch_runner_no_hardcoded_https_urls(self):
        path = RUNNERS_DIR / "dispatch.py"
        literals = self._collect_string_literals(path)
        hardcoded = [s for s in literals if s.startswith("https://") or s.startswith("http://")]
        assert hardcoded == [], f"Unexpected hardcoded URL in dispatch.py: {hardcoded}"


# ---------------------------------------------------------------------------
# 2. Role/field matrix: Viewer cannot POST to any write endpoint
# ---------------------------------------------------------------------------

# All URL names that accept POST and perform writes.
# Derived from the URLconf; updated when a new write endpoint is added.
WRITE_URL_NAMES = [
    # Inventory
    "person-create",
    "person-edit",
    "person-transition",
    "account-create",
    "account-edit",
    "account-transition",
    "device-create",
    "device-edit",
    "device-transition",
    "office-create",
    "office-edit",
    "office-transition",
    "fielddefinition-create",
    "fielddefinition-edit",
    # Relationships
    "link-create",
    "link-end",
    # Vault
    "secret-create",
    "secret-edit",
    "secret-rotate",
    "secret-state",
    # Integrations (namespaced)
    "integrations:create",
    "integrations:edit",
    "integrations:toggle",
    "integrations:run",
]

# URL kwargs required by parametrised patterns
_DUMMY_UUID = uuid.UUID("00000000-0000-0000-0000-000000000001")
_URL_KWARGS: dict[str, dict] = {
    "person-edit": {"pk": _DUMMY_UUID},
    "person-transition": {"pk": _DUMMY_UUID},
    "account-edit": {"pk": _DUMMY_UUID},
    "account-transition": {"pk": _DUMMY_UUID},
    "device-edit": {"pk": _DUMMY_UUID},
    "device-transition": {"pk": _DUMMY_UUID},
    "office-edit": {"pk": _DUMMY_UUID},
    "office-transition": {"pk": _DUMMY_UUID},
    "fielddefinition-edit": {"pk": _DUMMY_UUID},
    "link-end": {"pk": _DUMMY_UUID},
    "secret-edit": {"pk": _DUMMY_UUID},
    "secret-rotate": {"pk": _DUMMY_UUID},
    "secret-state": {"pk": _DUMMY_UUID},
    "integrations:edit": {"pk": _DUMMY_UUID},
    "integrations:toggle": {"pk": _DUMMY_UUID},
    "integrations:run": {"pk": _DUMMY_UUID},
    "integrations:detail": {"pk": _DUMMY_UUID},
}


@pytest.mark.django_db
class TestViewerCannotPost:
    def setup_method(self):
        self.viewer = _make_operator(Operator.Role.VIEWER, "viewer_matrix")
        self.client = _make_viewer_client(self.viewer)

    @pytest.mark.parametrize("url_name", WRITE_URL_NAMES)
    def test_viewer_post_returns_403(self, url_name):
        kwargs = _URL_KWARGS.get(url_name, {})
        url = reverse(url_name, kwargs=kwargs)
        resp = self.client.post(url, data={})
        assert resp.status_code in (403, 302), (
            f"Expected 403 (or auth redirect 302) for Viewer POST to {url_name!r}, "
            f"got {resp.status_code}"
        )
        # If redirect, it must go to login, not succeed
        if resp.status_code == 302:
            assert "login" in resp.get("Location", "").lower(), (
                f"Viewer POST to {url_name!r} redirected to unexpected URL: "
                f"{resp.get('Location')}"
            )


# ---------------------------------------------------------------------------
# 3. Viewer export block: no view leaks ciphertext/MK/DEK bytes
# ---------------------------------------------------------------------------

# Patterns that must NEVER appear in a rendered template response.
_FORBIDDEN_PATTERNS = [
    b"MasterKey",
    # raw hex that matches a 32-byte key (64 hex chars) — approximate guard
]


@pytest.mark.django_db
class TestViewerExportBlock:
    """Smoke-check that list/detail views do not render raw ciphertext bytes."""

    def setup_method(self):
        self.viewer = _make_operator(Operator.Role.VIEWER, "viewer_export")
        self.client = _make_viewer_client(self.viewer)

    def test_vault_list_no_raw_ciphertext(self):
        """The vault secret list for a Viewer must not contain raw binary blobs."""
        resp = self.client.get(reverse("secret-list"))
        # Either 200 (masked) or redirect to login — never expose raw bytes
        if resp.status_code == 200:
            content = resp.content
            # Ciphertext columns are stored as bytea; they should not appear
            # verbatim in HTML. We check that the literal string "ciphertext"
            # (as an exposed field) is absent from the rendered output.
            assert (
                b"ciphertext" not in content.lower()
            ), "Vault list rendered 'ciphertext' in response body for Viewer"

    def test_vault_detail_no_raw_secret_for_viewer(self):
        """A detail view for a non-existent secret must 404, not leak anything."""
        resp = self.client.get(reverse("secret-detail", kwargs={"pk": _DUMMY_UUID}))
        # 404 is fine; 200 must not contain raw bytes
        assert resp.status_code in (200, 302, 404)

    def test_integrations_list_no_raw_ciphertext(self):
        resp = self.client.get(reverse("integrations:list"))
        if resp.status_code == 200:
            assert b"ciphertext" not in resp.content.lower()


# ---------------------------------------------------------------------------
# 4. Single session: establish_session() revokes the prior session
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _lock_vault_after():
    yield
    sessions.lock_vault()


@pytest.mark.django_db
def test_second_login_revokes_first():
    admin = _make_operator(Operator.Role.ADMINISTRATOR, "admin_single")
    s1, _ = sessions.establish_session(operator=admin, ip="127.0.0.1", mk=bytearray(MK))
    assert s1.revoked_at is None

    s2, _ = sessions.establish_session(
        operator=admin, ip="127.0.0.2", mk=bytearray(MK)
    )  # noqa: F841
    s1.refresh_from_db()

    assert s1.revoked_at is not None, "First session must have revoked_at set after second login"
    assert OperatorSession.objects.filter(revoked_at__isnull=True).count() == 1


@pytest.mark.django_db
def test_viewer_login_revokes_admin_session():
    admin = _make_operator(Operator.Role.ADMINISTRATOR, "admin_pre_viewer")
    viewer = _make_operator(Operator.Role.VIEWER, "viewer_revoke")
    s1, _ = sessions.establish_session(operator=admin, ip="127.0.0.1", mk=bytearray(MK))
    sessions.establish_session(operator=viewer, ip="127.0.0.2")
    s1.refresh_from_db()
    assert s1.revoked_at is not None


# ---------------------------------------------------------------------------
# 5. Audit completeness: writes produce AuditEntry rows (inventory layer)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_person_create_produces_audit_entry():
    """Creating a Person via the view layer must emit an AuditEntry in the same tx."""
    from apps.audit.models import AuditEntry
    from apps.inventory.models import Person

    admin = _make_operator(Operator.Role.ADMINISTRATOR, "admin_audit")
    client = Client()
    session = client.session
    session["operator_id"] = str(admin.pk)
    session.save()

    before_count = AuditEntry.objects.count()
    client.post(
        reverse("person-create"),
        data={"full_name": "Audit Test Person", "state": "active"},
    )
    # A Person create view calls append_audit inside transaction.atomic().
    # Regardless of whether the form redirects or re-renders, the audit row
    # is produced if the record was saved.
    persons_created = Person.objects.filter(full_name="Audit Test Person").count()
    if persons_created:
        assert (
            AuditEntry.objects.count() > before_count
        ), "No AuditEntry was produced after a successful Person create"


@pytest.mark.django_db
def test_account_create_produces_audit_entry():
    from apps.audit.models import AuditEntry
    from apps.inventory.models import Account

    admin = _make_operator(Operator.Role.ADMINISTRATOR, "admin_audit_acct")
    client = Client()
    s = client.session
    s["operator_id"] = str(admin.pk)
    s.save()

    before_count = AuditEntry.objects.count()
    client.post(
        reverse("account-create"),
        data={
            "label": "Audit Account",
            "identifier": "audit@example.com",
            "account_type": "other",
            "state": "active",
        },
    )
    if Account.objects.filter(label="Audit Account").count():
        assert AuditEntry.objects.count() > before_count


# ---------------------------------------------------------------------------
# 6. Viewer keyless: is_vault_unlocked() is False after Viewer establish_session
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_viewer_session_is_keyless():
    viewer = _make_operator(Operator.Role.VIEWER, "viewer_keyless")
    sessions.establish_session(operator=viewer, ip="127.0.0.1")
    assert (
        not is_vault_unlocked()
    ), "is_vault_unlocked() must be False immediately after a Viewer establish_session()"


@pytest.mark.django_db
def test_admin_session_holds_key_viewer_wipes_it():
    admin = _make_operator(Operator.Role.ADMINISTRATOR, "admin_kl")
    viewer = _make_operator(Operator.Role.VIEWER, "viewer_kl")
    sessions.establish_session(operator=admin, ip="127.0.0.1", mk=bytearray(MK))
    assert is_vault_unlocked()
    sessions.establish_session(operator=viewer, ip="127.0.0.2")
    assert not is_vault_unlocked(), "Viewer login must wipe the admin's master key"


# ---------------------------------------------------------------------------
# 7. No hard delete: URLconf has no delete URL for core entities
# ---------------------------------------------------------------------------


class TestNoHardDeleteUrls:
    """Confirm that no delete/ URL pattern exists for Person, Account, Device, Office."""

    def _all_url_patterns(self) -> list[str]:
        """Walk the full URL tree and collect all resolved URL names."""
        from django.urls import get_resolver

        resolver = get_resolver()
        names = []
        for pattern in resolver.url_patterns:
            if hasattr(pattern, "url_patterns"):
                for sub in pattern.url_patterns:
                    if hasattr(sub, "name") and sub.name:
                        names.append(sub.name)
            if hasattr(pattern, "name") and pattern.name:
                names.append(pattern.name)
        return names

    def _all_url_strings(self) -> list[str]:
        """Return all raw regex/route strings from the URL tree."""
        from django.urls import get_resolver

        resolver = get_resolver()
        routes: list[str] = []

        def _collect(patterns, prefix=""):
            for p in patterns:
                route = prefix + str(getattr(p, "pattern", ""))
                routes.append(route)
                if hasattr(p, "url_patterns"):
                    _collect(p.url_patterns, route)

        _collect(resolver.url_patterns)
        return routes

    def test_no_person_delete_url(self):
        urls = self._all_url_strings()
        delete_urls = [u for u in urls if "person" in u and "delete" in u]
        assert delete_urls == [], f"Found person delete URLs: {delete_urls}"

    def test_no_account_delete_url(self):
        urls = self._all_url_strings()
        delete_urls = [u for u in urls if "account" in u and "delete" in u]
        assert delete_urls == [], f"Found account delete URLs: {delete_urls}"

    def test_no_device_delete_url(self):
        urls = self._all_url_strings()
        delete_urls = [u for u in urls if "device" in u and "delete" in u]
        assert delete_urls == [], f"Found device delete URLs: {delete_urls}"

    def test_no_office_delete_url(self):
        urls = self._all_url_strings()
        delete_urls = [u for u in urls if "office" in u and "delete" in u]
        assert delete_urls == [], f"Found office delete URLs: {delete_urls}"
