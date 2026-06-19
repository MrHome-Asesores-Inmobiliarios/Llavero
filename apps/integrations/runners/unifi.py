"""UniFi Controller API runner (P5-T3, Annex F 3).

Uses HTTPS REST (stdlib urllib.request) to query the UniFi controller.
All operations are READ-ONLY — only GET /api/s/default/stat/device.

Credential (username + password) is passed in as a dict; callers retrieve
plaintext from the vault before calling ``run()``.

UniFi controller login uses cookie-based sessions (POST /api/login, then
authenticated GETs using the session cookie).
"""

import json
import logging
import ssl
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)


def _make_opener(verify_ssl: bool = False) -> urllib.request.OpenerDirector:
    """Build an opener that handles cookies and optionally skips TLS verification."""
    import http.cookiejar

    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    cookie_jar = http.cookiejar.CookieJar()
    cookie_handler = urllib.request.HTTPCookieProcessor(cookie_jar)
    https_handler = urllib.request.HTTPSHandler(context=ctx)
    return urllib.request.build_opener(cookie_handler, https_handler)


def _login(opener, base_url: str, username: str, password: str) -> None:
    """POST /api/login to obtain a session cookie (read-only session)."""
    url = f"{base_url}/api/login"
    payload = json.dumps({"username": username, "password": password}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST")  # noqa: S310
    req.add_header("Content-Type", "application/json")
    with opener.open(req, timeout=15) as resp:
        body = json.loads(resp.read())
    if body.get("meta", {}).get("rc") != "ok":
        raise PermissionError(f"UniFi login failed: {body}")


def _get_devices(opener, base_url: str, site: str = "default") -> list[dict]:
    """GET /api/s/{site}/stat/device — read-only device list."""
    url = f"{base_url}/api/s/{site}/stat/device"
    req = urllib.request.Request(url, method="GET")  # noqa: S310
    req.add_header("Accept", "application/json")
    with opener.open(req, timeout=15) as resp:
        body = json.loads(resp.read())
    return body.get("data", [])


def _logout(opener, base_url: str) -> None:
    """POST /api/logout to cleanly end the read-only session."""
    try:
        url = f"{base_url}/api/logout"
        req = urllib.request.Request(url, data=b"{}", method="POST")  # noqa: S310
        req.add_header("Content-Type", "application/json")
        opener.open(req, timeout=5)
    except Exception:  # noqa: S110
        logger.debug("UniFi logout failed (non-fatal)")


def _health_from_device(device: dict) -> str:
    """Map UniFi device state to our HealthState choices."""
    state = device.get("state", 0)
    # UniFi state: 1 = connected/online, 0 = disconnected
    if state == 1:
        return "reachable"
    elif state == 5:
        return "alerting"
    else:
        return "offline"


def run(integration, *, credential_plaintext: str | None = None) -> tuple[int, int]:
    """Poll UniFi controller and update NetworkDeviceDetail health_state.

    ``credential_plaintext`` must be JSON: {"username": "...", "password": "..."}.
    Callers decrypt from the vault before calling.

    Returns (updated, errors).
    """
    from django.db import transaction
    from django.utils import timezone

    from apps.integrations.models import Telemetry, TelemetryEventType
    from apps.inventory.models import Device, NetworkDeviceDetail

    config = integration.config
    base_url = config.get("base_url", "").rstrip("/")
    site = config.get("site", "default")
    verify_ssl = bool(config.get("verify_ssl", False))

    if not base_url:
        raise ValueError("unifi_api integration requires base_url in config")

    cred_data = json.loads(credential_plaintext) if credential_plaintext else {}
    username = cred_data.get("username", "")
    password = cred_data.get("password", "")

    updated = 0
    errors = 0

    opener = _make_opener(verify_ssl=verify_ssl)
    try:
        _login(opener, base_url, username, password)
        unifi_devices = _get_devices(opener, base_url, site)
    except Exception as exc:
        logger.warning("unifi_api: API call failed for %s: %s", base_url, exc)
        errors += 1
        return updated, errors
    finally:
        _logout(opener, base_url)

    now = timezone.now()

    for unifi_dev in unifi_devices:
        # Match by IP (ip field) or hostname (name field)
        dev_ip = unifi_dev.get("ip", "")
        dev_name = unifi_dev.get("name", "") or unifi_dev.get("hostname", "")
        mac = unifi_dev.get("mac", "")

        device = None
        if dev_ip:
            device = Device.objects.filter(ip_addresses__contains=[dev_ip]).first()
        if device is None and dev_name:
            device = Device.objects.filter(hostname=dev_name).first()

        if device is None:
            logger.debug(
                "unifi_api: no Device matched for ip=%s name=%s mac=%s", dev_ip, dev_name, mac
            )
            continue

        try:
            detail = device.network_detail
        except NetworkDeviceDetail.DoesNotExist:
            continue

        new_health = _health_from_device(unifi_dev)
        old_health = detail.health_state

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
        "unifi_api run complete: integration=%s base_url=%s updated=%d",
        integration.id,
        base_url,
        updated,
    )
    return updated, errors
