"""WatchGuard SNMPv3 runner (P5-T3, Annex F 3).

Walks standard SNMP OIDs (sysUpTime, ifOperStatus) via pysnmp.
All operations are READ-ONLY (SNMP GET/WALK — no SET).

Credential (auth password + priv password) is passed in as a dict; callers
retrieve plaintext from the vault before calling ``run()``.
"""

import logging

logger = logging.getLogger(__name__)

# Standard OIDs
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"  # walk this subtree


def _pysnmp_available() -> bool:
    try:
        import pysnmp  # noqa: F401

        return True
    except ImportError:
        return False


def _walk_device(host: str, port: int, auth_data, transport_target) -> dict:
    """Walk OIDs and return {uptime_ticks, interfaces_up, interfaces_down}."""
    from pysnmp.hlapi import (
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        getCmd,
        nextCmd,
    )

    engine = SnmpEngine()

    # sysUpTime
    uptime_ticks = None
    for error_indication, error_status, _, var_binds in getCmd(
        engine,
        auth_data,
        transport_target,
        ContextData(),
        ObjectType(ObjectIdentity(OID_SYS_UPTIME)),
    ):
        if not error_indication and not error_status:
            uptime_ticks = int(var_binds[0][1])

    # ifOperStatus walk
    up_count = 0
    down_count = 0
    for error_indication, error_status, _, var_binds in nextCmd(
        engine,
        auth_data,
        transport_target,
        ContextData(),
        ObjectType(ObjectIdentity(OID_IF_OPER_STATUS)),
        lexicographicMode=False,
    ):
        if error_indication or error_status:
            break
        for _, val in var_binds:
            status = int(val)
            if status == 1:
                up_count += 1
            else:
                down_count += 1

    return {
        "uptime_ticks": uptime_ticks,
        "interfaces_up": up_count,
        "interfaces_down": down_count,
    }


def _determine_health(walk_result: dict) -> str:
    """Derive HealthState from SNMP walk results."""
    if walk_result.get("interfaces_down", 0) > 0:
        return "alerting"
    if walk_result.get("interfaces_up", 0) > 0 or walk_result.get("uptime_ticks") is not None:
        return "reachable"
    return "offline"


def run(integration, *, credential_plaintext: str | None = None) -> tuple[int, int]:
    """Poll WatchGuard device(s) via SNMPv3 and update NetworkDeviceDetail rows.

    ``credential_plaintext`` must be JSON with keys: auth_password, priv_password.
    Callers retrieve this from the vault before calling.

    Returns (updated, errors).
    """
    import json

    from django.db import transaction
    from django.utils import timezone

    from apps.integrations.models import Telemetry, TelemetryEventType
    from apps.inventory.models import Device, NetworkDeviceDetail

    if not _pysnmp_available():
        raise RuntimeError(
            "pysnmp is not installed. Add pysnmp to requirements/base.txt and install it."
        )

    config = integration.config
    host = config.get("host", "")
    port = int(config.get("port", 161))
    snmp_user = config.get("snmp_user", "")
    auth_protocol = config.get("auth_protocol", "SHA")
    priv_protocol = config.get("priv_protocol", "AES")

    if not host or not snmp_user:
        raise ValueError("watchguard_snmp requires host and snmp_user in config")

    cred_data = json.loads(credential_plaintext) if credential_plaintext else {}
    auth_password = cred_data.get("auth_password", "")
    priv_password = cred_data.get("priv_password", "")

    from pysnmp.hlapi import (
        UdpTransportTarget,
        UsmUserData,
        usmAesCfb128Protocol,
        usmDESPrivProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
    )

    auth_proto = (
        usmHMACSHAAuthProtocol if auth_protocol.upper() == "SHA" else usmHMACMD5AuthProtocol
    )
    priv_proto = usmAesCfb128Protocol if priv_protocol.upper() == "AES" else usmDESPrivProtocol

    auth_data = UsmUserData(
        snmp_user,
        authKey=auth_password,
        privKey=priv_password,
        authProtocol=auth_proto,
        privProtocol=priv_proto,
    )
    transport_target = UdpTransportTarget((host, port), timeout=5, retries=1)

    updated = 0
    errors = 0

    try:
        walk_result = _walk_device(host, port, auth_data, transport_target)
        new_health = _determine_health(walk_result)
    except Exception as exc:
        logger.warning("watchguard_snmp: SNMP walk failed for %s: %s", host, exc)
        errors += 1
        return updated, errors

    # Match device by hostname or IP
    device = (
        Device.objects.filter(hostname=host).first()
        or Device.objects.filter(ip_addresses__contains=[host]).first()
    )
    if device is None:
        logger.warning("watchguard_snmp: no Device matched for host=%s", host)
        return updated, errors

    try:
        detail = device.network_detail
    except NetworkDeviceDetail.DoesNotExist:
        logger.warning("watchguard_snmp: device %s has no NetworkDeviceDetail", device.id)
        return updated, errors

    old_health = detail.health_state
    now = timezone.now()

    if old_health != new_health:
        with transaction.atomic():
            Telemetry.objects.create(
                integration=integration,
                device=device,
                event_type=TelemetryEventType.HEALTH_CHANGE,
                old_value={"health_state": old_health},
                new_value={"health_state": new_health},
            )
            detail.health_state = new_health
            detail.last_seen_at = now
            detail.save(update_fields=["health_state", "last_seen_at"])
        updated += 1
    else:
        detail.last_seen_at = now
        detail.save(update_fields=["last_seen_at"])

    logger.info(
        "watchguard_snmp run complete: integration=%s host=%s health=%s",
        integration.id,
        host,
        new_health,
    )
    return updated, errors
