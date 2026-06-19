"""MikroTik RouterOS API runner (P5-T3, Annex F 3).

Connects to the RouterOS API on port 8729 (TLS) using plain socket + ssl.
All queries are READ-ONLY (/interface/print, /system/health).

Credential (username + password) is passed in as a dict; callers retrieve
plaintext from the vault before calling ``run()``.

MikroTik RouterOS API protocol:
- Words are length-prefixed byte strings.
- A sentence ends with an empty word (b'\\x00').
- Login: /login, then MD5-challenge response or plain login (>= RouterOS 6.43).
"""

import logging
import socket
import ssl
import struct

logger = logging.getLogger(__name__)

MIKROTIK_API_TLS_PORT = 8729


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    elif length < 0x4000:
        return struct.pack(">H", length | 0x8000)
    elif length < 0x200000:
        b = struct.pack(">I", length | 0xC00000)
        return b[1:]
    else:
        return b"\xe0" + struct.pack(">I", length)


def _encode_word(word: str) -> bytes:
    encoded = word.encode("utf-8")
    return _encode_length(len(encoded)) + encoded


def _encode_sentence(words: list[str]) -> bytes:
    return b"".join(_encode_word(w) for w in words) + b"\x00"


def _read_length(sock) -> int:
    b = sock.recv(1)
    if not b:
        raise ConnectionError("MikroTik API: connection closed")
    first = b[0]
    if first < 0x80:
        return first
    elif first < 0xC0:
        second = sock.recv(1)[0]
        return ((first & 0x3F) << 8) | second
    elif first < 0xE0:
        rest = sock.recv(2)
        return ((first & 0x1F) << 16) | (rest[0] << 8) | rest[1]
    else:
        rest = sock.recv(4)
        return struct.unpack(">I", rest)[0]


def _read_sentence(sock) -> list[str]:
    words = []
    while True:
        length = _read_length(sock)
        if length == 0:
            break
        word = b""
        remaining = length
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                raise ConnectionError("MikroTik API: connection closed mid-word")
            word += chunk
            remaining -= len(chunk)
        words.append(word.decode("utf-8", errors="replace"))
    return words


def _read_response(sock) -> list[list[str]]:
    sentences = []
    while True:
        sentence = _read_sentence(sock)
        sentences.append(sentence)
        if sentence and sentence[0] in ("!done", "!fatal", "!trap"):
            break
    return sentences


def _login(sock, username: str, password: str) -> None:
    """Plain-text login for RouterOS >= 6.43. Sends /login with name and password."""
    sock.sendall(_encode_sentence(["/login", f"=name={username}", f"=password={password}"]))
    resp = _read_response(sock)
    for sentence in resp:
        if sentence and sentence[0] == "!trap":
            raise PermissionError(f"MikroTik login failed: {sentence}")


def _query(sock, command: str) -> list[dict[str, str]]:
    """Send a read-only command and parse the response into a list of dicts."""
    sock.sendall(_encode_sentence([command]))
    response = _read_response(sock)
    results = []
    for sentence in response:
        if not sentence or sentence[0] != "!re":
            continue
        row = {}
        for word in sentence[1:]:
            if word.startswith("="):
                parts = word[1:].split("=", 1)
                if len(parts) == 2:
                    row[parts[0]] = parts[1]
        results.append(row)
    return results


def _connect_tls(host: str, port: int) -> ssl.SSLSocket:
    """Open a TLS-wrapped socket to the MikroTik API port."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # internal network; cert pinning is an ops concern
    raw = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(raw, server_hostname=host)


def _determine_health(interfaces: list[dict], health: list[dict]) -> str:
    """Derive HealthState from interface list and health query results."""
    down_count = sum(1 for iface in interfaces if iface.get("running", "true") == "false")
    if down_count > 0:
        return "alerting"
    if interfaces:
        return "reachable"
    return "offline"


def run(integration, *, credential_plaintext: str | None = None) -> tuple[int, int]:
    """Poll a MikroTik device via RouterOS API (TLS, port 8729) and update health.

    ``credential_plaintext`` must be JSON: {"username": "...", "password": "..."}.
    Callers decrypt from the vault before calling.

    Returns (updated, errors).
    """
    import json

    from django.db import transaction
    from django.utils import timezone

    from apps.integrations.models import Telemetry, TelemetryEventType
    from apps.inventory.models import Device, NetworkDeviceDetail

    config = integration.config
    host = config.get("host", "")
    port = int(config.get("port", MIKROTIK_API_TLS_PORT))

    if not host:
        raise ValueError("mikrotik_api integration requires host in config")

    cred_data = json.loads(credential_plaintext) if credential_plaintext else {}
    username = cred_data.get("username", "")
    password = cred_data.get("password", "")

    updated = 0
    errors = 0

    try:
        with _connect_tls(host, port) as sock:
            _login(sock, username, password)
            interfaces = _query(sock, "/interface/print")
            health_data = _query(sock, "/system/health/print")
        new_health = _determine_health(interfaces, health_data)
    except Exception as exc:
        logger.warning("mikrotik_api: connection/query failed for %s: %s", host, exc)
        errors += 1
        return updated, errors

    # Match device by hostname or IP
    device = (
        Device.objects.filter(hostname=host).first()
        or Device.objects.filter(ip_addresses__contains=[host]).first()
    )
    if device is None:
        logger.warning("mikrotik_api: no Device matched for host=%s", host)
        return updated, errors

    try:
        detail = device.network_detail
    except NetworkDeviceDetail.DoesNotExist:
        logger.warning("mikrotik_api: device %s has no NetworkDeviceDetail", device.id)
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
        "mikrotik_api run complete: integration=%s host=%s health=%s",
        integration.id,
        host,
        new_health,
    )
    return updated, errors
