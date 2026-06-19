"""Alert evaluation rules E-1 through E-13 (P6-T3, Annex E 6).

Each rule is a pure function that queries the DB and calls fire_alert() or
clear_alert(). Rules never modify inventory data. System reads during evaluation
are NOT logged in the audit chain.

Idempotent: (rule_id, target_type, target_id) is the unique key.
Re-firing an open alert only updates last_seen_at.
Clearing an alert sets resolved_at.
"""

from datetime import date, timedelta

from django.utils import timezone

from apps.alerts.models import Alert, AlertRuleId, AlertSeverity, AlertStatus, AlertTargetType

# Import verify_restore at module level so it can be patched in tests
from apps.backup.restore_verify import verify_restore

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_SYSTEM_TARGET = "system"
_SYSTEM_UUID = None  # system-level alerts have no entity target_id


def _get_setting(rule_id: str, key: str, default):
    """Read a threshold from AlertSetting, fall back to default."""
    from apps.alerts.models import AlertSetting

    try:
        setting = AlertSetting.objects.get(rule_id=rule_id)
        return setting.threshold_json.get(key, default)
    except AlertSetting.DoesNotExist:
        return default


def fire_alert(
    rule_id: str,
    target_type: str,
    target_id,
    severity: str,
    details: dict,
) -> Alert:
    """Create or update an alert (idempotent by (rule_id, target_type, target_id)).

    On first fire: creates open alert.
    On re-fire: updates last_seen_at (and re-opens if it was resolved).
    Acknowledged alerts that re-fire stay acknowledged for this cycle
    (P6-T4: acknowledgement counts as exception for one cycle).
    """
    now = timezone.now()

    # Normalize target_id to UUID or None
    import uuid as _uuid

    if target_id is not None and not isinstance(target_id, _uuid.UUID):
        target_id = _uuid.UUID(str(target_id))

    # For system-level alerts (no target_id), use a sentinel key
    if target_id is None:
        # Use filter+create manually since UniqueConstraint only covers non-null target_id
        alert = Alert.objects.filter(
            rule_id=rule_id,
            target_type=target_type,
            target_id=None,
        ).first()
        if alert is None:
            alert = Alert(
                rule_id=rule_id,
                target_type=target_type,
                target_id=None,
                severity=severity,
                status=AlertStatus.OPEN,
                details=details,
                last_seen_at=now,
            )
            alert.save(force_insert=True)
        else:
            # Re-fire: update last_seen_at. Re-open if it was resolved.
            update_fields = ["last_seen_at", "severity", "details"]
            alert.last_seen_at = now
            alert.severity = severity
            alert.details = details
            if alert.status == AlertStatus.RESOLVED:
                alert.status = AlertStatus.OPEN
                alert.resolved_at = None
                update_fields += ["status", "resolved_at"]
            alert.save(update_fields=update_fields)
        return alert
    else:
        alert, created = Alert.objects.get_or_create(
            rule_id=rule_id,
            target_type=target_type,
            target_id=target_id,
            defaults={
                "severity": severity,
                "status": AlertStatus.OPEN,
                "details": details,
                "last_seen_at": now,
            },
        )
        if not created:
            update_fields = ["last_seen_at", "severity", "details"]
            alert.last_seen_at = now
            alert.severity = severity
            alert.details = details
            if alert.status == AlertStatus.RESOLVED:
                alert.status = AlertStatus.OPEN
                alert.resolved_at = None
                update_fields += ["status", "resolved_at"]
            alert.save(update_fields=update_fields)
        return alert


def clear_alert(rule_id: str, target_type: str, target_id) -> None:
    """Resolve an open (or acknowledged) alert when the condition clears."""
    import uuid as _uuid

    if target_id is not None and not isinstance(target_id, _uuid.UUID):
        target_id = _uuid.UUID(str(target_id))

    now = timezone.now()
    qs = Alert.objects.filter(
        rule_id=rule_id,
        target_type=target_type,
        target_id=target_id,
    ).exclude(status=AlertStatus.RESOLVED)
    qs.update(status=AlertStatus.RESOLVED, resolved_at=now)


# ---------------------------------------------------------------------------
# E-1: unrecoverable_device
# A phone assigned to a person has no active account_recovery link AND the
# account is O365. Uses account_device_config join table (CLAUDE.md known fix).
# ---------------------------------------------------------------------------


def rule_e1_unrecoverable_device():
    """E-1: Phone with O365 account configured on it has no active account_recovery."""
    from apps.common.models import LinkState
    from apps.inventory.models import AccountType, DeviceType
    from apps.relationships.models import AccountDeviceConfig, AccountRecovery, DeviceAssignment

    # Find all active phone assignments
    active_phone_assignments = DeviceAssignment.objects.filter(
        state=LinkState.ACTIVE,
        device__device_type=DeviceType.PHONE,
    ).select_related("device", "person")

    flagged_device_ids = set()

    for assignment in active_phone_assignments:
        device = assignment.device

        # Find O365 accounts configured on this device (account_device_config)
        o365_configs = AccountDeviceConfig.objects.filter(
            state=LinkState.ACTIVE,
            device=device,
            account__account_type=AccountType.O365,
        ).select_related("account")

        for config in o365_configs:
            account = config.account

            # Check if this account has any active account_recovery link
            has_recovery = AccountRecovery.objects.filter(
                state=LinkState.ACTIVE,
                target_account=account,
            ).exists()

            if not has_recovery:
                flagged_device_ids.add(device.id)
                fire_alert(
                    rule_id=AlertRuleId.E1_UNRECOVERABLE_DEVICE,
                    target_type=AlertTargetType.DEVICE,
                    target_id=device.id,
                    severity=AlertSeverity.CRITICAL,
                    details={
                        "device_id": str(device.id),
                        "account_id": str(account.id),
                        "account_label": account.label,
                        "account_type": account.account_type,
                        "person_id": str(assignment.person_id),
                    },
                )

    # Clear alerts for devices that no longer match the condition
    open_alerts = Alert.objects.filter(
        rule_id=AlertRuleId.E1_UNRECOVERABLE_DEVICE,
        status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
    )
    for alert in open_alerts:
        if alert.target_id not in flagged_device_ids:
            clear_alert(
                AlertRuleId.E1_UNRECOVERABLE_DEVICE,
                AlertTargetType.DEVICE,
                alert.target_id,
            )


# ---------------------------------------------------------------------------
# E-2: account_no_mfa
# account.mfa_state = disabled
# ---------------------------------------------------------------------------


def rule_e2_account_no_mfa():
    """E-2: Account with MFA disabled."""
    from apps.inventory.models import Account, MfaState

    flagged_ids = set()

    for account in Account.objects.filter(mfa_state=MfaState.DISABLED):
        flagged_ids.add(account.id)
        fire_alert(
            rule_id=AlertRuleId.E2_ACCOUNT_NO_MFA,
            target_type=AlertTargetType.ACCOUNT,
            target_id=account.id,
            severity=AlertSeverity.HIGH,
            details={"account_id": str(account.id), "label": account.label},
        )

    open_alerts = Alert.objects.filter(
        rule_id=AlertRuleId.E2_ACCOUNT_NO_MFA,
        status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
    )
    for alert in open_alerts:
        if alert.target_id not in flagged_ids:
            clear_alert(AlertRuleId.E2_ACCOUNT_NO_MFA, AlertTargetType.ACCOUNT, alert.target_id)


# ---------------------------------------------------------------------------
# E-3: account_compromised
# account.state = compromised
# ---------------------------------------------------------------------------


def rule_e3_account_compromised():
    """E-3: Account marked as compromised."""
    from apps.inventory.models import Account, AccountState

    flagged_ids = set()

    for account in Account.objects.filter(state=AccountState.COMPROMISED):
        flagged_ids.add(account.id)
        fire_alert(
            rule_id=AlertRuleId.E3_ACCOUNT_COMPROMISED,
            target_type=AlertTargetType.ACCOUNT,
            target_id=account.id,
            severity=AlertSeverity.CRITICAL,
            details={"account_id": str(account.id), "label": account.label},
        )

    open_alerts = Alert.objects.filter(
        rule_id=AlertRuleId.E3_ACCOUNT_COMPROMISED,
        status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
    )
    for alert in open_alerts:
        if alert.target_id not in flagged_ids:
            clear_alert(
                AlertRuleId.E3_ACCOUNT_COMPROMISED, AlertTargetType.ACCOUNT, alert.target_id
            )


# ---------------------------------------------------------------------------
# E-4: account_needs_rotation
# account.state = needs_rotation
# ---------------------------------------------------------------------------


def rule_e4_account_needs_rotation():
    """E-4: Account that needs credential rotation."""
    from apps.inventory.models import Account, AccountState

    flagged_ids = set()

    for account in Account.objects.filter(state=AccountState.NEEDS_ROTATION):
        flagged_ids.add(account.id)
        fire_alert(
            rule_id=AlertRuleId.E4_ACCOUNT_NEEDS_ROTATION,
            target_type=AlertTargetType.ACCOUNT,
            target_id=account.id,
            severity=AlertSeverity.HIGH,
            details={"account_id": str(account.id), "label": account.label},
        )

    open_alerts = Alert.objects.filter(
        rule_id=AlertRuleId.E4_ACCOUNT_NEEDS_ROTATION,
        status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
    )
    for alert in open_alerts:
        if alert.target_id not in flagged_ids:
            clear_alert(
                AlertRuleId.E4_ACCOUNT_NEEDS_ROTATION, AlertTargetType.ACCOUNT, alert.target_id
            )


# ---------------------------------------------------------------------------
# E-5: device_unassigned
# Device with state=in_use has no active DeviceAssignment
# ---------------------------------------------------------------------------


def rule_e5_device_unassigned():
    """E-5: Device in_use with no active assignment."""
    from apps.common.models import LinkState
    from apps.inventory.models import Device, DeviceState
    from apps.relationships.models import DeviceAssignment

    flagged_ids = set()

    in_use_devices = Device.objects.filter(state=DeviceState.IN_USE)
    assigned_device_ids = set(
        DeviceAssignment.objects.filter(state=LinkState.ACTIVE).values_list("device_id", flat=True)
    )

    for device in in_use_devices:
        if device.id not in assigned_device_ids:
            flagged_ids.add(device.id)
            fire_alert(
                rule_id=AlertRuleId.E5_DEVICE_UNASSIGNED,
                target_type=AlertTargetType.DEVICE,
                target_id=device.id,
                severity=AlertSeverity.MEDIUM,
                details={"device_id": str(device.id), "device_type": device.device_type},
            )

    open_alerts = Alert.objects.filter(
        rule_id=AlertRuleId.E5_DEVICE_UNASSIGNED,
        status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
    )
    for alert in open_alerts:
        if alert.target_id not in flagged_ids:
            clear_alert(AlertRuleId.E5_DEVICE_UNASSIGNED, AlertTargetType.DEVICE, alert.target_id)


# ---------------------------------------------------------------------------
# E-6: device_warranty_expired
# warranty_expiry < today
# ---------------------------------------------------------------------------


def rule_e6_device_warranty_expired():
    """E-6: Device warranty has expired."""
    from apps.inventory.models import Device

    today = date.today()
    flagged_ids = set()

    for device in Device.objects.filter(warranty_expiry__lt=today, warranty_expiry__isnull=False):
        flagged_ids.add(device.id)
        fire_alert(
            rule_id=AlertRuleId.E6_DEVICE_WARRANTY_EXPIRED,
            target_type=AlertTargetType.DEVICE,
            target_id=device.id,
            severity=AlertSeverity.LOW,
            details={
                "device_id": str(device.id),
                "warranty_expiry": str(device.warranty_expiry),
            },
        )

    open_alerts = Alert.objects.filter(
        rule_id=AlertRuleId.E6_DEVICE_WARRANTY_EXPIRED,
        status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
    )
    for alert in open_alerts:
        if alert.target_id not in flagged_ids:
            clear_alert(
                AlertRuleId.E6_DEVICE_WARRANTY_EXPIRED, AlertTargetType.DEVICE, alert.target_id
            )


# ---------------------------------------------------------------------------
# E-7: person_no_account
# person.state = active has no active AccountOwnership
# ---------------------------------------------------------------------------


def rule_e7_person_no_account():
    """E-7: Active person with no active account ownership."""
    from apps.common.models import LinkState
    from apps.inventory.models import Person, PersonState
    from apps.relationships.models import AccountOwnership

    flagged_ids = set()

    persons_with_accounts = set(
        AccountOwnership.objects.filter(state=LinkState.ACTIVE).values_list("person_id", flat=True)
    )

    for person in Person.objects.filter(state=PersonState.ACTIVE):
        if person.id not in persons_with_accounts:
            flagged_ids.add(person.id)
            fire_alert(
                rule_id=AlertRuleId.E7_PERSON_NO_ACCOUNT,
                target_type=AlertTargetType.PERSON,
                target_id=person.id,
                severity=AlertSeverity.MEDIUM,
                details={"person_id": str(person.id), "full_name": person.full_name},
            )

    open_alerts = Alert.objects.filter(
        rule_id=AlertRuleId.E7_PERSON_NO_ACCOUNT,
        status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
    )
    for alert in open_alerts:
        if alert.target_id not in flagged_ids:
            clear_alert(AlertRuleId.E7_PERSON_NO_ACCOUNT, AlertTargetType.PERSON, alert.target_id)


# ---------------------------------------------------------------------------
# E-8: office_no_responsible
# office.state = active has no active OfficeMembership with role=responsible
# ---------------------------------------------------------------------------


def rule_e8_office_no_responsible():
    """E-8: Active office with no active responsible member."""
    from apps.common.models import LinkState
    from apps.inventory.models import Office, OfficeState
    from apps.relationships.models import MembershipRole, OfficeMembership

    flagged_ids = set()

    offices_with_responsible = set(
        OfficeMembership.objects.filter(
            state=LinkState.ACTIVE, role=MembershipRole.RESPONSIBLE
        ).values_list("office_id", flat=True)
    )

    for office in Office.objects.filter(state=OfficeState.ACTIVE):
        if office.id not in offices_with_responsible:
            flagged_ids.add(office.id)
            fire_alert(
                rule_id=AlertRuleId.E8_OFFICE_NO_RESPONSIBLE,
                target_type=AlertTargetType.OFFICE,
                target_id=office.id,
                severity=AlertSeverity.MEDIUM,
                details={"office_id": str(office.id), "office_name": office.name},
            )

    open_alerts = Alert.objects.filter(
        rule_id=AlertRuleId.E8_OFFICE_NO_RESPONSIBLE,
        status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
    )
    for alert in open_alerts:
        if alert.target_id not in flagged_ids:
            clear_alert(
                AlertRuleId.E8_OFFICE_NO_RESPONSIBLE, AlertTargetType.OFFICE, alert.target_id
            )


# ---------------------------------------------------------------------------
# E-9: account_stale
# account.last_password_change is older than threshold (default 90 days)
# ---------------------------------------------------------------------------


def rule_e9_account_stale():
    """E-9: Account password not changed within threshold."""
    days = _get_setting(AlertRuleId.E9_ACCOUNT_STALE, "days", 90)
    threshold_date = date.today() - timedelta(days=days)

    from django.db.models import Q

    from apps.inventory.models import Account

    flagged_ids = set()

    stale_accounts = Account.objects.filter(
        Q(last_password_change__lt=threshold_date) | Q(last_password_change__isnull=True)
    )

    for account in stale_accounts:
        flagged_ids.add(account.id)
        fire_alert(
            rule_id=AlertRuleId.E9_ACCOUNT_STALE,
            target_type=AlertTargetType.ACCOUNT,
            target_id=account.id,
            severity=AlertSeverity.MEDIUM,
            details={
                "account_id": str(account.id),
                "label": account.label,
                "last_password_change": (
                    str(account.last_password_change) if account.last_password_change else None
                ),
                "threshold_days": days,
            },
        )

    open_alerts = Alert.objects.filter(
        rule_id=AlertRuleId.E9_ACCOUNT_STALE,
        status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
    )
    for alert in open_alerts:
        if alert.target_id not in flagged_ids:
            clear_alert(AlertRuleId.E9_ACCOUNT_STALE, AlertTargetType.ACCOUNT, alert.target_id)


# ---------------------------------------------------------------------------
# E-10: device_offline
# NetworkDeviceDetail.health_state = offline
# ---------------------------------------------------------------------------


def rule_e10_device_offline():
    """E-10: Network device is offline."""
    from apps.inventory.models import HealthState, NetworkDeviceDetail

    flagged_ids = set()

    for detail in NetworkDeviceDetail.objects.filter(
        health_state=HealthState.OFFLINE
    ).select_related("device"):
        device_id = detail.device_id
        flagged_ids.add(device_id)
        fire_alert(
            rule_id=AlertRuleId.E10_DEVICE_OFFLINE,
            target_type=AlertTargetType.DEVICE,
            target_id=device_id,
            severity=AlertSeverity.HIGH,
            details={
                "device_id": str(device_id),
                "last_seen_at": (detail.last_seen_at.isoformat() if detail.last_seen_at else None),
            },
        )

    open_alerts = Alert.objects.filter(
        rule_id=AlertRuleId.E10_DEVICE_OFFLINE,
        status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
    )
    for alert in open_alerts:
        if alert.target_id not in flagged_ids:
            clear_alert(AlertRuleId.E10_DEVICE_OFFLINE, AlertTargetType.DEVICE, alert.target_id)


# ---------------------------------------------------------------------------
# E-11: secret_not_rotated
# Secret.last_rotated_at older than threshold (default 180 days) or null
# with created_at older than threshold
# ---------------------------------------------------------------------------


def rule_e11_secret_not_rotated():
    """E-11: Secret not rotated within threshold."""
    days = _get_setting(AlertRuleId.E11_SECRET_NOT_ROTATED, "days", 180)
    threshold = timezone.now() - timedelta(days=days)

    from django.db.models import Q

    from apps.vault.models import Secret, SecretState

    flagged_ids = set()

    stale_secrets = Secret.objects.filter(state=SecretState.ACTIVE).filter(
        Q(last_rotated_at__lt=threshold) | Q(last_rotated_at__isnull=True, created_at__lt=threshold)
    )

    for secret in stale_secrets:
        flagged_ids.add(secret.id)
        fire_alert(
            rule_id=AlertRuleId.E11_SECRET_NOT_ROTATED,
            target_type=AlertTargetType.ACCOUNT,  # polymorphic; use closest entity type
            target_id=secret.id,
            severity=AlertSeverity.MEDIUM,
            details={
                "secret_id": str(secret.id),
                "secret_kind": secret.kind,
                "owner_type": secret.owner_type,
                "owner_id": str(secret.owner_id),
                "last_rotated_at": (
                    secret.last_rotated_at.isoformat() if secret.last_rotated_at else None
                ),
                "threshold_days": days,
            },
        )

    open_alerts = Alert.objects.filter(
        rule_id=AlertRuleId.E11_SECRET_NOT_ROTATED,
        status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
    )
    for alert in open_alerts:
        if alert.target_id not in flagged_ids:
            clear_alert(
                AlertRuleId.E11_SECRET_NOT_ROTATED, AlertTargetType.ACCOUNT, alert.target_id
            )


# ---------------------------------------------------------------------------
# E-12: person_offboarding_stale
# person.state = offboarding AND exit_date < today
# ---------------------------------------------------------------------------


def rule_e12_person_offboarding_stale():
    """E-12: Person in offboarding state with past exit date."""
    today = date.today()
    flagged_ids = set()

    from apps.inventory.models import Person, PersonState

    for person in Person.objects.filter(
        state=PersonState.OFFBOARDING, exit_date__lt=today, exit_date__isnull=False
    ):
        flagged_ids.add(person.id)
        fire_alert(
            rule_id=AlertRuleId.E12_PERSON_OFFBOARDING_STALE,
            target_type=AlertTargetType.PERSON,
            target_id=person.id,
            severity=AlertSeverity.HIGH,
            details={
                "person_id": str(person.id),
                "full_name": person.full_name,
                "exit_date": str(person.exit_date),
            },
        )

    open_alerts = Alert.objects.filter(
        rule_id=AlertRuleId.E12_PERSON_OFFBOARDING_STALE,
        status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
    )
    for alert in open_alerts:
        if alert.target_id not in flagged_ids:
            clear_alert(
                AlertRuleId.E12_PERSON_OFFBOARDING_STALE,
                AlertTargetType.PERSON,
                alert.target_id,
            )


# ---------------------------------------------------------------------------
# E-13: chain_integrity
# Runs verify_restore(); fires critical if chain_ok=False
# ---------------------------------------------------------------------------


def rule_e13_chain_integrity():
    """E-13: Audit chain integrity check."""
    try:
        report = verify_restore()
        chain_ok = report.chain_ok
        reason = report.chain_reason or ""
    except Exception as exc:  # noqa: BLE001
        chain_ok = False
        reason = str(exc)

    if not chain_ok:
        fire_alert(
            rule_id=AlertRuleId.E13_CHAIN_INTEGRITY,
            target_type=AlertTargetType.SYSTEM,
            target_id=None,
            severity=AlertSeverity.CRITICAL,
            details={"chain_reason": reason},
        )
    else:
        clear_alert(AlertRuleId.E13_CHAIN_INTEGRITY, AlertTargetType.SYSTEM, None)


# ---------------------------------------------------------------------------
# Evaluator entry point
# ---------------------------------------------------------------------------

RULES = [
    rule_e1_unrecoverable_device,
    rule_e2_account_no_mfa,
    rule_e3_account_compromised,
    rule_e4_account_needs_rotation,
    rule_e5_device_unassigned,
    rule_e6_device_warranty_expired,
    rule_e7_person_no_account,
    rule_e8_office_no_responsible,
    rule_e9_account_stale,
    rule_e10_device_offline,
    rule_e11_secret_not_rotated,
    rule_e12_person_offboarding_stale,
    rule_e13_chain_integrity,
]


def run_all_enabled_rules():
    """Run all enabled alert rules.

    Each rule is run independently; an error in one does not abort others.
    Returns a list of (rule_name, error_or_None) tuples.
    """
    from apps.alerts.models import AlertSetting

    # Build enabled set from DB settings (default: all enabled)
    try:
        disabled_rule_ids = set(
            AlertSetting.objects.filter(enabled=False).values_list("rule_id", flat=True)
        )
    except Exception:  # noqa: BLE001
        disabled_rule_ids = set()

    results = []
    for rule_fn in RULES:
        # Derive rule_id from function name, e.g. rule_e1_unrecoverable_device -> E-1
        name = rule_fn.__name__
        results.append(_run_rule(rule_fn, name, disabled_rule_ids))
    return results


def _run_rule(rule_fn, name, disabled_rule_ids):
    """Run a single rule, catching exceptions."""
    # Map function names to rule IDs
    _fn_to_rule = {
        "rule_e1_unrecoverable_device": AlertRuleId.E1_UNRECOVERABLE_DEVICE,
        "rule_e2_account_no_mfa": AlertRuleId.E2_ACCOUNT_NO_MFA,
        "rule_e3_account_compromised": AlertRuleId.E3_ACCOUNT_COMPROMISED,
        "rule_e4_account_needs_rotation": AlertRuleId.E4_ACCOUNT_NEEDS_ROTATION,
        "rule_e5_device_unassigned": AlertRuleId.E5_DEVICE_UNASSIGNED,
        "rule_e6_device_warranty_expired": AlertRuleId.E6_DEVICE_WARRANTY_EXPIRED,
        "rule_e7_person_no_account": AlertRuleId.E7_PERSON_NO_ACCOUNT,
        "rule_e8_office_no_responsible": AlertRuleId.E8_OFFICE_NO_RESPONSIBLE,
        "rule_e9_account_stale": AlertRuleId.E9_ACCOUNT_STALE,
        "rule_e10_device_offline": AlertRuleId.E10_DEVICE_OFFLINE,
        "rule_e11_secret_not_rotated": AlertRuleId.E11_SECRET_NOT_ROTATED,
        "rule_e12_person_offboarding_stale": AlertRuleId.E12_PERSON_OFFBOARDING_STALE,
        "rule_e13_chain_integrity": AlertRuleId.E13_CHAIN_INTEGRITY,
    }
    rule_id = _fn_to_rule.get(name)
    if rule_id and rule_id in disabled_rule_ids:
        return (name, None, "skipped_disabled")
    try:
        rule_fn()
        return (name, None, "ok")
    except Exception as exc:  # noqa: BLE001
        return (name, exc, "error")
