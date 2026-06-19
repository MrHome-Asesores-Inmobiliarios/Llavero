"""P6-T8: Alert system verification tests.

Tests:
1. Each of the 13 rules fires on seeded data matching its condition
2. Each rule clears (auto-resolve) when the condition is fixed
3. Alert state changes are audited; eval reads are not
4. E-13 fires when a chain entry hash is tampered
5. Viewer can view dashboard but cannot acknowledge

Uses Django's TestCase with an in-memory SQLite or the test DB.
"""

import uuid
from datetime import date, timedelta
from unittest.mock import patch

import pytest
from django.test import Client, TestCase
from django.utils import timezone

# ─── Factories ────────────────────────────────────────────────────────────────


def make_operator(role="administrator", username=None):
    from apps.operators.models import Operator

    username = username or f"op_{uuid.uuid4().hex[:6]}"
    return Operator.objects.create(
        username=username,
        display_name=username,
        role=role,
        password_hash="x",
        is_active=True,
    )


def make_person(state="active", exit_date=None):
    from apps.inventory.models import Person

    op = make_operator()
    return Person.objects.create(
        full_name=f"Test Person {uuid.uuid4().hex[:4]}",
        state=state,
        exit_date=exit_date,
        created_by=op,
        updated_by=op,
    )


def make_account(
    state="active", account_type="other", mfa_state="enabled", last_password_change=None
):
    from apps.inventory.models import Account

    op = make_operator()
    return Account.objects.create(
        label=f"Account {uuid.uuid4().hex[:4]}",
        identifier=f"user{uuid.uuid4().hex[:4]}@example.com",
        state=state,
        account_type=account_type,
        mfa_state=mfa_state,
        last_password_change=last_password_change,
        created_by=op,
        updated_by=op,
    )


def make_device(state="in_use", device_type="laptop", warranty_expiry=None):
    from apps.inventory.models import Device

    op = make_operator()
    return Device.objects.create(
        device_type=device_type,
        state=state,
        brand="Test",
        warranty_expiry=warranty_expiry,
        created_by=op,
        updated_by=op,
    )


def make_office(state="active"):
    from apps.inventory.models import Office

    op = make_operator()
    return Office.objects.create(
        name=f"Office {uuid.uuid4().hex[:4]}",
        state=state,
        created_by=op,
        updated_by=op,
    )


def make_network_detail(device, health_state="unknown"):
    from apps.inventory.models import NetworkDeviceDetail

    return NetworkDeviceDetail.objects.create(
        device=device,
        health_state=health_state,
    )


def make_device_assignment(person, device, state="active"):
    from apps.relationships.models import DeviceAssignment

    op = make_operator()
    return DeviceAssignment.objects.create(
        person=person,
        device=device,
        state=state,
        created_by=op,
        updated_by=op,
    )


def make_account_ownership(person, account, state="active", role="primary"):
    from apps.relationships.models import AccountOwnership

    op = make_operator()
    return AccountOwnership.objects.create(
        person=person,
        account=account,
        state=state,
        role=role,
        created_by=op,
        updated_by=op,
    )


def make_account_device_config(account, device, state="active"):
    from apps.relationships.models import AccountDeviceConfig

    op = make_operator()
    return AccountDeviceConfig.objects.create(
        account=account,
        device=device,
        state=state,
        created_by=op,
        updated_by=op,
    )


def make_account_recovery(recovery_account, target_account, state="active"):
    from apps.relationships.models import AccountRecovery

    op = make_operator()
    return AccountRecovery.objects.create(
        recovery_account=recovery_account,
        target_account=target_account,
        state=state,
        created_by=op,
        updated_by=op,
    )


def make_office_membership(person, office, role="responsible", state="active"):
    from apps.relationships.models import OfficeMembership

    op = make_operator()
    return OfficeMembership.objects.create(
        person=person,
        office=office,
        role=role,
        state=state,
        created_by=op,
        updated_by=op,
    )


def make_secret(state="active", last_rotated_at=None, created_at=None):
    from apps.vault.models import Secret

    op = make_operator()
    secret = Secret(
        owner_type="account",
        owner_id=uuid.uuid4(),
        kind="password",
        label="test secret",
        ciphertext=b"x",
        nonce=b"x",
        dek_wrapped=b"x",
        dek_nonce=b"x",
        aad_context="test",
        state=state,
        last_rotated_at=last_rotated_at,
        created_by=op,
        updated_by=op,
    )
    if created_at:
        secret.created_at = created_at
    secret.save()
    if created_at:
        # Override auto_now_add
        Secret.objects.filter(pk=secret.pk).update(created_at=created_at)
    return secret


# ─── Alert count helpers ──────────────────────────────────────────────────────


def open_alerts_for(rule_id, target_id=None):
    from apps.alerts.models import Alert, AlertStatus

    qs = Alert.objects.filter(
        rule_id=rule_id, status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]
    )
    if target_id is not None:
        qs = qs.filter(target_id=target_id)
    return qs.count()


def resolved_alerts_for(rule_id, target_id=None):
    from apps.alerts.models import Alert, AlertStatus

    qs = Alert.objects.filter(rule_id=rule_id, status=AlertStatus.RESOLVED)
    if target_id is not None:
        qs = qs.filter(target_id=target_id)
    return qs.count()


# ─── Tests ───────────────────────────────────────────────────────────────────


@pytest.mark.django_db
class TestE1UnrecoverableDevice(TestCase):
    def test_fires_when_o365_phone_has_no_recovery(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e1_unrecoverable_device

        person = make_person()
        phone = make_device(device_type="phone")
        o365_account = make_account(account_type="o365")
        make_device_assignment(person, phone)
        make_account_device_config(o365_account, phone)

        rule_e1_unrecoverable_device()
        assert open_alerts_for(AlertRuleId.E1_UNRECOVERABLE_DEVICE, phone.id) == 1

    def test_clears_when_recovery_added(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e1_unrecoverable_device

        person = make_person()
        phone = make_device(device_type="phone")
        o365_account = make_account(account_type="o365")
        recovery_account = make_account(account_type="other")
        make_device_assignment(person, phone)
        make_account_device_config(o365_account, phone)

        # Fire once without recovery
        rule_e1_unrecoverable_device()
        assert open_alerts_for(AlertRuleId.E1_UNRECOVERABLE_DEVICE, phone.id) == 1

        # Add recovery and re-run
        make_account_recovery(recovery_account, o365_account)
        rule_e1_unrecoverable_device()
        assert resolved_alerts_for(AlertRuleId.E1_UNRECOVERABLE_DEVICE, phone.id) == 1

    def test_no_fire_for_non_o365(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e1_unrecoverable_device

        person = make_person()
        phone = make_device(device_type="phone")
        google_account = make_account(account_type="google")
        make_device_assignment(person, phone)
        make_account_device_config(google_account, phone)

        rule_e1_unrecoverable_device()
        assert open_alerts_for(AlertRuleId.E1_UNRECOVERABLE_DEVICE, phone.id) == 0


@pytest.mark.django_db
class TestE2AccountNoMfa(TestCase):
    def test_fires_when_mfa_disabled(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e2_account_no_mfa

        account = make_account(mfa_state="disabled")
        rule_e2_account_no_mfa()
        assert open_alerts_for(AlertRuleId.E2_ACCOUNT_NO_MFA, account.id) == 1

    def test_clears_when_mfa_enabled(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e2_account_no_mfa
        from apps.inventory.models import Account

        account = make_account(mfa_state="disabled")
        rule_e2_account_no_mfa()
        assert open_alerts_for(AlertRuleId.E2_ACCOUNT_NO_MFA, account.id) == 1

        Account.objects.filter(pk=account.pk).update(mfa_state="enabled")
        rule_e2_account_no_mfa()
        assert resolved_alerts_for(AlertRuleId.E2_ACCOUNT_NO_MFA, account.id) == 1


@pytest.mark.django_db
class TestE3AccountCompromised(TestCase):
    def test_fires_when_compromised(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e3_account_compromised

        account = make_account(state="compromised")
        rule_e3_account_compromised()
        assert open_alerts_for(AlertRuleId.E3_ACCOUNT_COMPROMISED, account.id) == 1

    def test_auto_resolves_when_state_returns_active(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e3_account_compromised
        from apps.inventory.models import Account

        account = make_account(state="compromised")
        rule_e3_account_compromised()
        Account.objects.filter(pk=account.pk).update(state="active")
        rule_e3_account_compromised()
        assert resolved_alerts_for(AlertRuleId.E3_ACCOUNT_COMPROMISED, account.id) == 1


@pytest.mark.django_db
class TestE4AccountNeedsRotation(TestCase):
    def test_fires_when_needs_rotation(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e4_account_needs_rotation

        account = make_account(state="needs_rotation")
        rule_e4_account_needs_rotation()
        assert open_alerts_for(AlertRuleId.E4_ACCOUNT_NEEDS_ROTATION, account.id) == 1

    def test_auto_resolves_on_active(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e4_account_needs_rotation
        from apps.inventory.models import Account

        account = make_account(state="needs_rotation")
        rule_e4_account_needs_rotation()
        Account.objects.filter(pk=account.pk).update(state="active")
        rule_e4_account_needs_rotation()
        assert resolved_alerts_for(AlertRuleId.E4_ACCOUNT_NEEDS_ROTATION, account.id) == 1


@pytest.mark.django_db
class TestE5DeviceUnassigned(TestCase):
    def test_fires_for_in_use_without_assignment(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e5_device_unassigned

        device = make_device(state="in_use")
        rule_e5_device_unassigned()
        assert open_alerts_for(AlertRuleId.E5_DEVICE_UNASSIGNED, device.id) == 1

    def test_clears_when_assigned(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e5_device_unassigned

        person = make_person()
        device = make_device(state="in_use")
        rule_e5_device_unassigned()
        assert open_alerts_for(AlertRuleId.E5_DEVICE_UNASSIGNED, device.id) == 1

        make_device_assignment(person, device)
        rule_e5_device_unassigned()
        assert resolved_alerts_for(AlertRuleId.E5_DEVICE_UNASSIGNED, device.id) == 1


@pytest.mark.django_db
class TestE6DeviceWarrantyExpired(TestCase):
    def test_fires_when_warranty_expired(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e6_device_warranty_expired

        expired = date.today() - timedelta(days=10)
        device = make_device(warranty_expiry=expired)
        rule_e6_device_warranty_expired()
        assert open_alerts_for(AlertRuleId.E6_DEVICE_WARRANTY_EXPIRED, device.id) == 1

    def test_no_fire_for_future_warranty(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e6_device_warranty_expired

        future = date.today() + timedelta(days=100)
        device = make_device(warranty_expiry=future)
        rule_e6_device_warranty_expired()
        assert open_alerts_for(AlertRuleId.E6_DEVICE_WARRANTY_EXPIRED, device.id) == 0


@pytest.mark.django_db
class TestE7PersonNoAccount(TestCase):
    def test_fires_when_active_person_has_no_account(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e7_person_no_account

        person = make_person(state="active")
        rule_e7_person_no_account()
        assert open_alerts_for(AlertRuleId.E7_PERSON_NO_ACCOUNT, person.id) == 1

    def test_clears_when_account_assigned(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e7_person_no_account

        person = make_person(state="active")
        account = make_account()
        rule_e7_person_no_account()
        assert open_alerts_for(AlertRuleId.E7_PERSON_NO_ACCOUNT, person.id) == 1

        make_account_ownership(person, account)
        rule_e7_person_no_account()
        assert resolved_alerts_for(AlertRuleId.E7_PERSON_NO_ACCOUNT, person.id) == 1


@pytest.mark.django_db
class TestE8OfficeNoResponsible(TestCase):
    def test_fires_for_active_office_without_responsible(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e8_office_no_responsible

        office = make_office(state="active")
        rule_e8_office_no_responsible()
        assert open_alerts_for(AlertRuleId.E8_OFFICE_NO_RESPONSIBLE, office.id) == 1

    def test_clears_when_responsible_added(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e8_office_no_responsible

        office = make_office(state="active")
        person = make_person()
        rule_e8_office_no_responsible()
        assert open_alerts_for(AlertRuleId.E8_OFFICE_NO_RESPONSIBLE, office.id) == 1

        make_office_membership(person, office, role="responsible")
        rule_e8_office_no_responsible()
        assert resolved_alerts_for(AlertRuleId.E8_OFFICE_NO_RESPONSIBLE, office.id) == 1


@pytest.mark.django_db
class TestE9AccountStale(TestCase):
    def test_fires_when_password_old(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e9_account_stale

        old_date = date.today() - timedelta(days=100)
        account = make_account(last_password_change=old_date)
        rule_e9_account_stale()
        assert open_alerts_for(AlertRuleId.E9_ACCOUNT_STALE, account.id) == 1

    def test_clears_when_password_recent(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e9_account_stale
        from apps.inventory.models import Account

        old_date = date.today() - timedelta(days=100)
        account = make_account(last_password_change=old_date)
        rule_e9_account_stale()
        assert open_alerts_for(AlertRuleId.E9_ACCOUNT_STALE, account.id) == 1

        Account.objects.filter(pk=account.pk).update(last_password_change=date.today())
        rule_e9_account_stale()
        assert resolved_alerts_for(AlertRuleId.E9_ACCOUNT_STALE, account.id) == 1

    def test_fires_when_null_and_old_created_at(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e9_account_stale

        account = make_account(last_password_change=None)
        rule_e9_account_stale()
        # Account with no password change date should fire
        assert open_alerts_for(AlertRuleId.E9_ACCOUNT_STALE, account.id) == 1


@pytest.mark.django_db
class TestE10DeviceOffline(TestCase):
    def test_fires_when_network_device_offline(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e10_device_offline

        device = make_device()
        make_network_detail(device, health_state="offline")
        rule_e10_device_offline()
        assert open_alerts_for(AlertRuleId.E10_DEVICE_OFFLINE, device.id) == 1

    def test_clears_when_device_reachable(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e10_device_offline
        from apps.inventory.models import NetworkDeviceDetail

        device = make_device()
        detail = make_network_detail(device, health_state="offline")
        rule_e10_device_offline()
        assert open_alerts_for(AlertRuleId.E10_DEVICE_OFFLINE, device.id) == 1

        NetworkDeviceDetail.objects.filter(pk=detail.pk).update(health_state="reachable")
        rule_e10_device_offline()
        assert resolved_alerts_for(AlertRuleId.E10_DEVICE_OFFLINE, device.id) == 1


@pytest.mark.django_db
class TestE11SecretNotRotated(TestCase):
    def test_fires_when_secret_old(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e11_secret_not_rotated

        old_time = timezone.now() - timedelta(days=200)
        secret = make_secret(last_rotated_at=old_time)
        rule_e11_secret_not_rotated()
        assert open_alerts_for(AlertRuleId.E11_SECRET_NOT_ROTATED, secret.id) == 1

    def test_clears_when_rotated(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e11_secret_not_rotated
        from apps.vault.models import Secret

        old_time = timezone.now() - timedelta(days=200)
        secret = make_secret(last_rotated_at=old_time)
        rule_e11_secret_not_rotated()
        assert open_alerts_for(AlertRuleId.E11_SECRET_NOT_ROTATED, secret.id) == 1

        Secret.objects.filter(pk=secret.pk).update(last_rotated_at=timezone.now())
        rule_e11_secret_not_rotated()
        assert resolved_alerts_for(AlertRuleId.E11_SECRET_NOT_ROTATED, secret.id) == 1


@pytest.mark.django_db
class TestE12PersonOffboardingStale(TestCase):
    def test_fires_when_offboarding_past_exit_date(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e12_person_offboarding_stale

        past_date = date.today() - timedelta(days=5)
        person = make_person(state="offboarding", exit_date=past_date)
        rule_e12_person_offboarding_stale()
        assert open_alerts_for(AlertRuleId.E12_PERSON_OFFBOARDING_STALE, person.id) == 1

    def test_clears_when_person_terminated(self):
        from apps.alerts.models import AlertRuleId
        from apps.alerts.rules import rule_e12_person_offboarding_stale
        from apps.inventory.models import Person

        past_date = date.today() - timedelta(days=5)
        person = make_person(state="offboarding", exit_date=past_date)
        rule_e12_person_offboarding_stale()
        assert open_alerts_for(AlertRuleId.E12_PERSON_OFFBOARDING_STALE, person.id) == 1

        Person.objects.filter(pk=person.pk).update(state="terminated")
        rule_e12_person_offboarding_stale()
        assert resolved_alerts_for(AlertRuleId.E12_PERSON_OFFBOARDING_STALE, person.id) == 1


@pytest.mark.django_db
class TestE13ChainIntegrity(TestCase):
    def test_fires_when_chain_fails(self):
        # Patch at the location where rules.py imported verify_restore
        from unittest.mock import MagicMock

        from apps.alerts.models import Alert, AlertRuleId, AlertStatus
        from apps.alerts.rules import rule_e13_chain_integrity

        mock_report = MagicMock()
        mock_report.chain_ok = False
        mock_report.chain_reason = "tampered hash at seq 5"

        with patch("apps.alerts.rules.verify_restore", return_value=mock_report):
            rule_e13_chain_integrity()

        assert (
            Alert.objects.filter(
                rule_id=AlertRuleId.E13_CHAIN_INTEGRITY,
                status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
            ).count()
            == 1
        )

    def test_clears_when_chain_ok(self):
        from unittest.mock import MagicMock

        from apps.alerts.models import Alert, AlertRuleId, AlertStatus
        from apps.alerts.rules import rule_e13_chain_integrity

        bad_report = MagicMock()
        bad_report.chain_ok = False
        bad_report.chain_reason = "tampered"

        good_report = MagicMock()
        good_report.chain_ok = True
        good_report.chain_reason = None

        with patch("apps.alerts.rules.verify_restore", return_value=bad_report):
            rule_e13_chain_integrity()

        assert (
            Alert.objects.filter(
                rule_id=AlertRuleId.E13_CHAIN_INTEGRITY,
                status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
            ).count()
            == 1
        )

        with patch("apps.alerts.rules.verify_restore", return_value=good_report):
            rule_e13_chain_integrity()

        assert (
            Alert.objects.filter(
                rule_id=AlertRuleId.E13_CHAIN_INTEGRITY,
                status=AlertStatus.RESOLVED,
            ).count()
            == 1
        )


@pytest.mark.django_db
class TestAuditBehavior(TestCase):
    """Alert state changes ARE audited; eval reads are NOT."""

    def test_acknowledge_creates_audit_entry(self):
        from apps.alerts.models import Alert, AlertRuleId
        from apps.audit.models import AuditEntry

        admin = make_operator(role="administrator", username="testadmin")
        account = make_account(mfa_state="disabled")

        # Seed an open alert
        from apps.alerts.rules import rule_e2_account_no_mfa

        rule_e2_account_no_mfa()

        alert = Alert.objects.get(rule_id=AlertRuleId.E2_ACCOUNT_NO_MFA, target_id=account.id)

        audit_count_before = AuditEntry.objects.count()

        # Simulate a logged-in admin session
        client = Client()
        session = client.session
        session["operator_id"] = str(admin.id)
        session.save()

        response = client.post(
            f"/alerts/{alert.id}/acknowledge/",
            {"note": "Testing acknowledge action"},
        )
        # Should redirect to dashboard
        assert response.status_code in (200, 302)

        audit_count_after = AuditEntry.objects.count()
        # An audit entry should have been created for the acknowledge
        assert audit_count_after > audit_count_before

    def test_eval_does_not_create_audit_entry(self):
        from apps.alerts.rules import rule_e2_account_no_mfa
        from apps.audit.models import AuditEntry

        count_before = AuditEntry.objects.count()
        make_account(mfa_state="disabled")
        rule_e2_account_no_mfa()
        count_after = AuditEntry.objects.count()

        # Running the evaluator must not add audit entries
        assert count_after == count_before


@pytest.mark.django_db
class TestIdempotency(TestCase):
    """Re-running the evaluator on the same condition must not duplicate Alert rows."""

    def test_no_duplicate_alerts(self):
        from apps.alerts.models import Alert, AlertRuleId
        from apps.alerts.rules import rule_e2_account_no_mfa

        account = make_account(mfa_state="disabled")
        rule_e2_account_no_mfa()
        rule_e2_account_no_mfa()
        rule_e2_account_no_mfa()

        count = Alert.objects.filter(
            rule_id=AlertRuleId.E2_ACCOUNT_NO_MFA,
            target_id=account.id,
        ).count()
        assert count == 1


@pytest.mark.django_db
class TestViewerPermissions(TestCase):
    """Viewer can view dashboard but cannot acknowledge."""

    def test_viewer_can_access_dashboard(self):

        viewer = make_operator(role="viewer", username="testviewer")
        client = Client()
        session = client.session
        session["operator_id"] = str(viewer.id)
        session.save()

        response = client.get("/")
        # Should succeed (200) or redirect (viewer is authenticated)
        assert response.status_code in (200, 302)

    def test_viewer_cannot_acknowledge(self):
        from apps.alerts.models import Alert, AlertRuleId, AlertStatus
        from apps.alerts.rules import rule_e2_account_no_mfa

        viewer = make_operator(role="viewer", username="testviewer2")
        account = make_account(mfa_state="disabled")
        rule_e2_account_no_mfa()
        alert = Alert.objects.get(rule_id=AlertRuleId.E2_ACCOUNT_NO_MFA, target_id=account.id)

        client = Client()
        session = client.session
        session["operator_id"] = str(viewer.id)
        session.save()

        response = client.post(
            f"/alerts/{alert.id}/acknowledge/",
            {"note": "Viewer trying to acknowledge"},
        )
        # Must be forbidden (403) or redirect, NOT 200
        assert response.status_code in (403, 302)
        # Alert must remain open
        alert.refresh_from_db()
        assert alert.status == AlertStatus.OPEN


@pytest.mark.django_db
class TestE13TamperedChain(TestCase):
    """E-13 fires when a chain entry hash is tampered.

    The audit_entry table has an append-only DB trigger, so we cannot tamper
    the hash in a test. Instead we mock verify_restore() to return chain_ok=False,
    which is the exact path E-13 would follow on a real tamper.
    """

    def test_fires_on_tampered_hash(self):
        """E-13 fires when verify_restore reports chain_ok=False (simulates tampered hash).

        The audit_entry table has an append-only trigger that prevents direct UPDATE,
        so tampering is simulated by mocking verify_restore to return chain_ok=False,
        which is exactly the code path a real hash mismatch would exercise.
        """
        from unittest.mock import MagicMock

        from apps.alerts.models import Alert, AlertRuleId, AlertStatus
        from apps.alerts.rules import rule_e13_chain_integrity

        mock_report = MagicMock()
        mock_report.chain_ok = False
        mock_report.chain_reason = "hash mismatch at seq 42 — tampered"

        with patch("apps.alerts.rules.verify_restore", return_value=mock_report):
            rule_e13_chain_integrity()

        assert (
            Alert.objects.filter(
                rule_id=AlertRuleId.E13_CHAIN_INTEGRITY,
                status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
            ).count()
            == 1
        )
