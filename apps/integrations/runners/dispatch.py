"""Integration runner dispatcher (P5-T1).

Selects the correct runner module for an Integration row and invokes it.
The dispatcher decrypts the credential (if any) from the vault before passing
the plaintext to the runner. The plaintext is wiped from memory after the call.

Access tokens and API keys MUST NOT be logged or persisted.
"""

import logging

logger = logging.getLogger(__name__)


def _decrypt_credential(credential_row, mk: bytes) -> str | None:
    """Decrypt a vault.Secret and return plaintext as UTF-8 string.

    Returns None if the row is None. Never logs the plaintext.
    """
    if credential_row is None:
        return None
    from apps.vault import crypto

    plaintext = crypto.open_sealed(
        mk,
        owner_type=credential_row.owner_type,
        owner_id=credential_row.owner_id,
        kind=credential_row.kind,
        ciphertext=bytes(credential_row.ciphertext),
        nonce=bytes(credential_row.nonce),
        dek_wrapped=bytes(credential_row.dek_wrapped),
        dek_nonce=bytes(credential_row.dek_nonce),
        aad_context=credential_row.aad_context,
    )
    return plaintext.decode("utf-8")


def run_one(integration, *, mk: bytes | None = None) -> str:
    """Run a single integration and update its last_run_at / last_status.

    ``mk`` is the vault master key in bytes. If None, credential decryption is
    skipped (the runner will receive credential_plaintext=None).

    Returns the final status string: "ok" or "error".
    """
    from django.utils import timezone

    from apps.integrations.models import (
        IntegrationStatus,
        IntegrationType,
        Telemetry,
        TelemetryEventType,
    )

    integration_type = integration.integration_type
    now = timezone.now()

    credential_plaintext = None
    try:
        if mk is not None and integration.credential_id is not None:
            credential_plaintext = _decrypt_credential(integration.credential, mk)

        if integration_type == IntegrationType.GRAPH_MFA:
            from apps.integrations.runners import graph

            if credential_plaintext is None:
                raise ValueError("graph_mfa requires a vault credential (client secret)")
            graph.run(integration, client_secret=credential_plaintext)

        elif integration_type == IntegrationType.WATCHGUARD_SNMP:
            from apps.integrations.runners import watchguard

            watchguard.run(integration, credential_plaintext=credential_plaintext)

        elif integration_type == IntegrationType.MIKROTIK_API:
            from apps.integrations.runners import mikrotik

            mikrotik.run(integration, credential_plaintext=credential_plaintext)

        elif integration_type == IntegrationType.UNIFI_API:
            from apps.integrations.runners import unifi

            unifi.run(integration, credential_plaintext=credential_plaintext)

        else:
            raise NotImplementedError(f"No runner for integration_type={integration_type}")

        status = IntegrationStatus.OK
        error_msg = ""

    except Exception as exc:
        logger.exception(
            "Integration run failed: integration=%s type=%s error=%s",
            integration.id,
            integration_type,
            exc,
        )
        status = IntegrationStatus.ERROR
        error_msg = str(exc)

        # Write a RUN_ERROR telemetry record
        Telemetry.objects.create(
            integration=integration,
            event_type=TelemetryEventType.RUN_ERROR,
            old_value={},
            new_value={"error": error_msg},
        )

    finally:
        # Wipe the credential plaintext from memory
        credential_plaintext = None  # noqa: F841

    if status == IntegrationStatus.OK:
        Telemetry.objects.create(
            integration=integration,
            event_type=TelemetryEventType.RUN_OK,
            old_value={},
            new_value={"ran_at": now.isoformat()},
        )

    integration.last_run_at = now
    integration.last_status = status
    integration.last_error = error_msg if status == IntegrationStatus.ERROR else ""
    integration.save(update_fields=["last_run_at", "last_status", "last_error"])

    return status
