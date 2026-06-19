"""Graph MFA pull runner (P5-T2, Annex F 2).

Uses plain ``requests``-style calls (via stdlib ``urllib.request``) with the
OAuth 2.0 client_credentials grant.  READ-ONLY scopes only — no write scope
is ever requested.

Credentials (client_secret / certificate PEM) live in vault.Secret rows. The
management command must supply the decrypted client_secret as a string; this
module never touches the vault directly so it can be tested without a live MK.

The access token is wiped (set to None) immediately after the Graph calls
finish — it is never stored, never logged, never persisted.

Matched accounts: Account rows where ``external_id`` equals the Graph object
``id``.  Unmatched accounts (in Graph but not in inventory) are written as
Telemetry(UNMATCHED_ACCOUNT) rows.
"""

import logging
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

# READ-ONLY scope — never request a write scope (hard constraint, Annex F 1)
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
GRAPH_MFA_URL = (
    "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"
)

# Map Graph methodsRegistered strings -> MfaType values
_GRAPH_METHOD_MAP = {
    "microsoftAuthenticatorPush": "authenticator_app",
    "microsoftAuthenticatorPasswordless": "authenticator_app",
    "softwareOneTimePasscode": "authenticator_app",
    "hardwareOneTimePasscode": "hardware_key",
    "sms": "sms",
    "voice": "voice",
    "email": "email",
    "windowsHelloForBusiness": "windows_hello",
    "fido2SecurityKey": "hardware_key",
    "passkey": "passkey",
    "temporaryAccessPass": "unknown",
}


def fetch_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Obtain an OAuth 2.0 access token using client_credentials (read-only scope).

    The returned bearer token must be wiped from memory by the caller after use.
    It is NEVER logged or persisted.
    """
    url = GRAPH_TOKEN_URL.format(tenant_id=tenant_id)
    data = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": GRAPH_SCOPE,
        }
    ).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")  # noqa: S310
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        import json

        body = json.loads(resp.read())
    token = body.get("access_token", "")
    if not token:
        raise RuntimeError("Graph token endpoint returned no access_token")
    return token


def fetch_mfa_details(token: str) -> list[dict[str, Any]]:
    """GET /v1.0/reports/authenticationMethods/userRegistrationDetails (read-only).

    Handles OData @odata.nextLink pagination.
    Token is consumed here and must be wiped by the caller immediately after.
    """
    import json

    results: list[dict[str, Any]] = []
    url: str | None = GRAPH_MFA_URL
    while url:
        req = urllib.request.Request(url, method="GET")  # noqa: S310
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            body = json.loads(resp.read())
        results.extend(body.get("value", []))
        url = body.get("@odata.nextLink")
    return results


def apply_mfa_records(integration, mfa_records: list[dict[str, Any]]) -> tuple[int, int]:
    """Match Graph records to Account rows and write transition Telemetry.

    Returns (updated, unmatched).
    """
    from django.db import transaction

    from apps.integrations.models import Telemetry, TelemetryEventType
    from apps.inventory.models import Account, MfaState

    external_ids = {r.get("id") for r in mfa_records if r.get("id")}
    accounts_by_ext_id = {
        a.external_id: a
        for a in Account.objects.filter(external_id__in=external_ids)
        if a.external_id
    }

    updated = 0
    unmatched = 0

    for record in mfa_records:
        ext_id = record.get("id")
        if not ext_id:
            continue

        account = accounts_by_ext_id.get(ext_id)
        if account is None:
            # Account present in Graph but not in inventory — log it
            Telemetry.objects.create(
                integration=integration,
                event_type=TelemetryEventType.UNMATCHED_ACCOUNT,
                old_value={},
                new_value={
                    "graph_id": ext_id,
                    "userPrincipalName": record.get("userPrincipalName", ""),
                },
            )
            unmatched += 1
            continue

        is_mfa = record.get("isMfaRegistered", False) or record.get("isMfaCapable", False)
        new_mfa_state = MfaState.ENABLED if is_mfa else MfaState.DISABLED

        methods = record.get("methodsRegistered", [])
        new_mfa_types = sorted(
            {_GRAPH_METHOD_MAP.get(m, "unknown") for m in methods if m in _GRAPH_METHOD_MAP}
        )

        old_mfa_state = account.mfa_state
        old_mfa_types = sorted(account.mfa_types or [])

        if old_mfa_state != new_mfa_state or old_mfa_types != new_mfa_types:
            with transaction.atomic():
                Telemetry.objects.create(
                    integration=integration,
                    account=account,
                    event_type=TelemetryEventType.MFA_CHANGE,
                    old_value={"mfa_state": old_mfa_state, "mfa_types": old_mfa_types},
                    new_value={"mfa_state": new_mfa_state, "mfa_types": new_mfa_types},
                )
                account.mfa_state = new_mfa_state
                account.mfa_types = new_mfa_types or None
                account.save(update_fields=["mfa_state", "mfa_types"])
            updated += 1

    return updated, unmatched


def run(integration, *, client_secret: str) -> tuple[int, int, int]:
    """Pull MFA details from Graph and update Account rows.

    ``client_secret`` must be the already-decrypted plaintext string — callers
    retrieve it from the vault before calling this function. This module never
    touches the vault directly.

    Returns (updated, unmatched, errors).
    """
    config = integration.config
    tenant_id = config.get("tenant_id", "")
    client_id = config.get("client_id", "")

    if not tenant_id or not client_id:
        raise ValueError("graph_mfa integration requires tenant_id and client_id in config")

    token = None
    try:
        token = fetch_token(tenant_id, client_id, client_secret)
        mfa_records = fetch_mfa_details(token)
    finally:
        # Wipe access token — never persist or log it
        token = None  # noqa: F841

    updated, unmatched = apply_mfa_records(integration, mfa_records)
    logger.info(
        "graph_mfa run complete: integration=%s updated=%d unmatched=%d",
        integration.id,
        updated,
        unmatched,
    )
    return updated, unmatched, 0
