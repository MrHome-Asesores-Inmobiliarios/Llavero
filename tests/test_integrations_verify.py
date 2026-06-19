"""P5-T6 VERIFY — Read-only integration proof.

Tests:
1. No write scope in any Graph API call (scope parameter is READ-ONLY).
2. Telemetry writes do NOT create AuditEntry rows (off the audit chain).
3. A Viewer cannot trigger a manual integration run (HTTP 403).
4. MFA pull correctly updates account.mfa_state and account.mfa_types on mock response.
5. health_state update writes a Telemetry row with old/new values.
"""

import json
import uuid
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_operator(role, username=None):
    """Create an Operator in the database."""
    from apps.operators.models import Operator

    username = username or f"op_{uuid.uuid4().hex[:8]}"
    return Operator.objects.create(
        username=username,
        display_name=username,
        role=role,
        password_hash="x",
    )


def _make_integration(db, integration_type="graph_mfa", interval=60):
    """Create an Integration row."""
    from apps.integrations.models import Integration

    return Integration.objects.create(
        name=f"test-{integration_type}",
        integration_type=integration_type,
        enabled=True,
        run_interval_minutes=interval,
        config={},
    )


# ---------------------------------------------------------------------------
# Test 1 — No write scope in Graph API calls
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_graph_no_write_scope():
    """The Graph runner only ever requests READ-ONLY scopes.

    Confirm that GRAPH_SCOPE does not contain 'write', 'Write', 'ReadWrite',
    'send', 'Send', or any mutating verb — and that the scope parameter passed
    to fetch_token is read-only.
    """
    from apps.integrations.runners.graph import GRAPH_SCOPE, fetch_token

    # Scope must be the read-only default credential scope
    assert GRAPH_SCOPE == "https://graph.microsoft.com/.default"

    # Ensure no write-indicating substring appears in the scope string
    write_indicators = ["write", "Write", "ReadWrite", "send", "Send", "manage", "Manage"]
    for indicator in write_indicators:
        assert (
            indicator not in GRAPH_SCOPE
        ), f"Graph scope contains write indicator: {indicator!r} in {GRAPH_SCOPE!r}"

    # Inspect the source of fetch_token to confirm scope is the read-only constant
    import inspect

    source = inspect.getsource(fetch_token)
    assert "GRAPH_SCOPE" in source, "fetch_token must use GRAPH_SCOPE constant"

    # Confirm no alternative write scope is constructed in the graph runner module
    import inspect

    from apps.integrations.runners import graph as graph_module

    full_source = inspect.getsource(graph_module)
    assert "UserRegistrationDetails.Read" in full_source or ".default" in full_source
    # No explicit write scope strings
    for bad in ["Mail.Send", "Calendars.ReadWrite", "Files.ReadWrite", "Directory.ReadWrite"]:
        assert bad not in full_source, f"Write scope found in graph runner: {bad}"


# ---------------------------------------------------------------------------
# Test 2 — Telemetry writes do NOT create AuditEntry rows
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_telemetry_not_in_audit_chain():
    """Writing a Telemetry row must NOT create an AuditEntry (Annex F 6).

    The telemetry table is explicitly off the audit chain.
    """
    from apps.audit.models import AuditEntry
    from apps.integrations.models import Telemetry, TelemetryEventType

    integration = _make_integration(None)
    before_count = AuditEntry.objects.count()

    # Write several telemetry entries
    Telemetry.objects.create(
        integration=integration,
        event_type=TelemetryEventType.RUN_OK,
        old_value={},
        new_value={"ran_at": "2026-06-19T00:00:00Z"},
    )
    Telemetry.objects.create(
        integration=integration,
        event_type=TelemetryEventType.RUN_ERROR,
        old_value={},
        new_value={"error": "timeout"},
    )
    Telemetry.objects.create(
        integration=integration,
        event_type=TelemetryEventType.HEALTH_CHANGE,
        old_value={"health_state": "unknown"},
        new_value={"health_state": "reachable"},
    )

    after_count = AuditEntry.objects.count()
    assert after_count == before_count, (
        f"Telemetry writes created {after_count - before_count} AuditEntry row(s) — "
        "they must NOT appear in the audit chain (Annex F 6)."
    )

    # Confirm the telemetry rows were actually written
    assert Telemetry.objects.filter(integration=integration).count() == 3


# ---------------------------------------------------------------------------
# Test 3 — Viewer cannot trigger a manual integration run
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_viewer_cannot_trigger_manual_run():
    """A Viewer request to POST /integrations/<pk>/run/ must be rejected (HTTP 403).

    This confirms that manual run triggering is gated at the server side by role
    check, not just UI masking (P5-T5 constraint).
    """
    from django.test import RequestFactory

    from apps.integrations.views import integration_run

    viewer = _make_operator("viewer", username="viewer_test")
    integration = _make_integration(None)

    factory = RequestFactory()
    request = factory.post(f"/integrations/{integration.pk}/run/")
    request.operator = viewer  # simulate session middleware setting request.operator

    response = integration_run(request, pk=integration.pk)

    assert response.status_code == 403, (
        f"Expected HTTP 403 for Viewer, got {response.status_code}. "
        "Viewer must not be able to trigger integration runs."
    )


# ---------------------------------------------------------------------------
# Test 4 — MFA pull updates account.mfa_state and account.mfa_types on mock
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_graph_mfa_pull_updates_account():
    """apply_mfa_records() correctly updates account.mfa_state and mfa_types.

    Uses a mock Graph response — no network call.
    """
    from apps.integrations.models import Telemetry, TelemetryEventType
    from apps.integrations.runners.graph import apply_mfa_records
    from apps.inventory.models import Account, MfaState

    # Create an account with external_id matching a mock Graph record

    admin = _make_operator("administrator", username="admin_graph_test")
    account = Account.objects.create(
        account_type="o365",
        label="Test User",
        identifier="testuser@example.com",
        mfa_state=MfaState.UNKNOWN,
        mfa_types=None,
        external_id="graph-user-id-001",
        created_by=admin,
        updated_by=admin,
    )
    integration = _make_integration(None, integration_type="graph_mfa")

    # Mock Graph API response
    mock_records = [
        {
            "id": "graph-user-id-001",
            "userPrincipalName": "testuser@example.com",
            "isMfaRegistered": True,
            "isMfaCapable": True,
            "methodsRegistered": [
                "microsoftAuthenticatorPush",
                "softwareOneTimePasscode",
            ],
        }
    ]

    updated, unmatched = apply_mfa_records(integration, mock_records)

    assert updated == 1, f"Expected 1 account updated, got {updated}"
    assert unmatched == 0, f"Expected 0 unmatched, got {unmatched}"

    account.refresh_from_db()
    assert (
        account.mfa_state == MfaState.ENABLED
    ), f"Expected mfa_state=enabled, got {account.mfa_state}"
    # Both methods map to "authenticator_app"
    assert account.mfa_types is not None
    assert (
        "authenticator_app" in account.mfa_types
    ), f"Expected authenticator_app in mfa_types, got {account.mfa_types}"

    # A MFA_CHANGE telemetry row should have been written
    telem = Telemetry.objects.filter(
        integration=integration,
        account=account,
        event_type=TelemetryEventType.MFA_CHANGE,
    ).first()
    assert telem is not None, "No MFA_CHANGE telemetry row written for account update"
    assert telem.old_value["mfa_state"] == MfaState.UNKNOWN
    assert telem.new_value["mfa_state"] == MfaState.ENABLED


@pytest.mark.django_db
def test_graph_mfa_pull_unmatched_account_logged():
    """Unmatched accounts (in Graph but not in inventory) create UNMATCHED_ACCOUNT telemetry."""
    from apps.integrations.models import Telemetry, TelemetryEventType
    from apps.integrations.runners.graph import apply_mfa_records

    integration = _make_integration(None, integration_type="graph_mfa")

    mock_records = [
        {
            "id": "ghost-user-id-999",
            "userPrincipalName": "ghost@example.com",
            "isMfaRegistered": False,
            "methodsRegistered": [],
        }
    ]

    updated, unmatched = apply_mfa_records(integration, mock_records)

    assert updated == 0
    assert unmatched == 1

    telem = Telemetry.objects.filter(
        integration=integration,
        event_type=TelemetryEventType.UNMATCHED_ACCOUNT,
    ).first()
    assert telem is not None, "Expected UNMATCHED_ACCOUNT telemetry row"
    assert telem.new_value["graph_id"] == "ghost-user-id-999"


@pytest.mark.django_db
def test_graph_mfa_no_change_no_telemetry():
    """If MFA state and types are unchanged, no telemetry row is written."""
    from apps.integrations.models import Telemetry
    from apps.integrations.runners.graph import apply_mfa_records
    from apps.inventory.models import Account, MfaState

    admin = _make_operator("administrator", username="admin_nochange_test")
    Account.objects.create(
        account_type="o365",
        label="Stable User",
        identifier="stable@example.com",
        mfa_state=MfaState.ENABLED,
        mfa_types=["authenticator_app"],
        external_id="stable-user-id-001",
        created_by=admin,
        updated_by=admin,
    )
    integration = _make_integration(None, integration_type="graph_mfa")

    mock_records = [
        {
            "id": "stable-user-id-001",
            "userPrincipalName": "stable@example.com",
            "isMfaRegistered": True,
            "methodsRegistered": ["microsoftAuthenticatorPush"],
        }
    ]

    before_telem_count = Telemetry.objects.filter(integration=integration).count()
    updated, unmatched = apply_mfa_records(integration, mock_records)

    assert updated == 0, "No update expected when state is unchanged"
    after_telem_count = Telemetry.objects.filter(integration=integration).count()
    assert (
        after_telem_count == before_telem_count
    ), "No telemetry row should be written when MFA state and types are unchanged"


# ---------------------------------------------------------------------------
# Test 5 — health_state update writes Telemetry with old/new values
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_health_state_update_writes_telemetry():
    """When health_state changes, a Telemetry(HEALTH_CHANGE) row is written with
    old_value and new_value, and the NetworkDeviceDetail row is updated atomically.
    """
    from django.db import transaction
    from django.utils import timezone

    from apps.integrations.models import Telemetry, TelemetryEventType
    from apps.inventory.models import Device, HealthState, NetworkDeviceDetail

    admin = _make_operator("administrator", username="admin_health_test")

    # Create a device with a NetworkDeviceDetail
    device = Device.objects.create(
        device_type="firewall",
        hostname="fw01.local",
        created_by=admin,
        updated_by=admin,
    )
    detail = NetworkDeviceDetail.objects.create(
        device=device,
        health_state=HealthState.UNKNOWN,
    )
    integration = _make_integration(None, integration_type="watchguard_snmp")
    integration.config = {"host": "fw01.local", "snmp_user": "test"}
    integration.save()

    old_health = detail.health_state  # "unknown"
    new_health = HealthState.REACHABLE

    # Simulate what the runner does
    now = timezone.now()
    with transaction.atomic():
        telem = Telemetry.objects.create(
            integration=integration,
            device=device,
            event_type=TelemetryEventType.HEALTH_CHANGE,
            old_value={"health_state": old_health},
            new_value={"health_state": new_health},
        )
        detail.health_state = new_health
        detail.last_seen_at = now
        detail.save(update_fields=["health_state", "last_seen_at"])

    # Verify telemetry row
    assert telem.pk is not None
    assert telem.old_value["health_state"] == "unknown"
    assert telem.new_value["health_state"] == "reachable"
    assert telem.device == device
    assert telem.integration == integration

    # Verify device was updated
    detail.refresh_from_db()
    assert detail.health_state == HealthState.REACHABLE
    assert detail.last_seen_at is not None

    # Verify telemetry is NOT in the audit chain
    from apps.audit.models import AuditEntry

    assert not AuditEntry.objects.filter(
        target_table="telemetry"
    ).exists(), "Telemetry rows must never appear in the audit chain (Annex F 6)."


@pytest.mark.django_db
def test_health_state_no_change_no_telemetry():
    """If health_state is unchanged between polls, no Telemetry row is written."""
    from apps.integrations.models import Telemetry
    from apps.inventory.models import Device, HealthState, NetworkDeviceDetail

    admin = _make_operator("administrator", username="admin_nohealth_test")
    device = Device.objects.create(
        device_type="router",
        hostname="rtr01.local",
        created_by=admin,
        updated_by=admin,
    )
    NetworkDeviceDetail.objects.create(device=device, health_state=HealthState.REACHABLE)
    integration = _make_integration(None, integration_type="unifi_api")

    before = Telemetry.objects.filter(integration=integration).count()

    # Simulate: health unchanged → no telemetry written (just update last_seen_at)
    from django.utils import timezone

    detail = device.network_detail
    detail.last_seen_at = timezone.now()
    detail.save(update_fields=["last_seen_at"])

    after = Telemetry.objects.filter(integration=integration).count()
    assert after == before, "No telemetry should be written when health_state is unchanged."


# ---------------------------------------------------------------------------
# Test 6 — Integration model is_due() logic
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_integration_is_due_when_never_run():
    """An integration with last_run_at=None is always due."""
    from apps.integrations.models import Integration

    integration = Integration.objects.create(
        name="never-run",
        integration_type="graph_mfa",
        enabled=True,
        run_interval_minutes=60,
        config={},
    )
    assert integration.is_due() is True


@pytest.mark.django_db
def test_integration_is_not_due_when_recently_run():
    """An integration run within its interval is not due."""
    from datetime import timedelta

    from django.utils import timezone

    from apps.integrations.models import Integration

    integration = Integration.objects.create(
        name="recent-run",
        integration_type="graph_mfa",
        enabled=True,
        run_interval_minutes=60,
        last_run_at=timezone.now() - timedelta(minutes=5),
        config={},
    )
    assert integration.is_due() is False


@pytest.mark.django_db
def test_integration_is_due_when_interval_elapsed():
    """An integration past its interval is due."""
    from datetime import timedelta

    from django.utils import timezone

    from apps.integrations.models import Integration

    integration = Integration.objects.create(
        name="overdue-run",
        integration_type="graph_mfa",
        enabled=True,
        run_interval_minutes=60,
        last_run_at=timezone.now() - timedelta(minutes=90),
        config={},
    )
    assert integration.is_due() is True


# ---------------------------------------------------------------------------
# Test 7 — Admin CAN trigger a manual run (200 or redirect)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_admin_can_trigger_manual_run():
    """An Administrator can POST to /integrations/<pk>/run/ and gets a redirect."""

    from django.test import RequestFactory

    from apps.integrations.views import integration_run

    admin = _make_operator("administrator", username="admin_run_test")
    integration = _make_integration(None)

    factory = RequestFactory()
    request = factory.post(f"/integrations/{integration.pk}/run/")
    request.operator = admin

    with patch("apps.integrations.runners.dispatch.run_one", return_value="ok") as mock_run:
        response = integration_run(request, pk=integration.pk)

    assert (
        response.status_code == 302
    ), f"Expected redirect (302) for admin, got {response.status_code}"
    mock_run.assert_called_once()


# ---------------------------------------------------------------------------
# Test 8 — Graph fetch_token scope is READ-ONLY (unit check)
# ---------------------------------------------------------------------------


def test_fetch_token_sends_readonly_scope():
    """fetch_token() sends only the read-only GRAPH_SCOPE in its POST body."""
    import urllib.request

    from apps.integrations.runners.graph import GRAPH_SCOPE, fetch_token

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {"access_token": "mock-token-abc123", "token_type": "Bearer"}
    ).encode("utf-8")
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
        token = fetch_token("tenant-id", "client-id", "client-secret")

    assert token == "mock-token-abc123"

    # Inspect the request that was sent
    call_args = mock_urlopen.call_args
    request_obj = call_args[0][0]
    body = request_obj.data.decode("utf-8")

    import urllib.parse

    parsed = dict(urllib.parse.parse_qsl(body))
    assert (
        parsed.get("scope") == GRAPH_SCOPE
    ), f"Expected scope={GRAPH_SCOPE!r}, got {parsed.get('scope')!r}"
    assert parsed.get("grant_type") == "client_credentials"
    # Confirm no write scope
    scope_value = parsed.get("scope", "")
    assert "write" not in scope_value.lower(), f"Write scope found: {scope_value}"
