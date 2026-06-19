"""Integration table and Telemetry (P5-T1, P5-T4, Annex F 6).

Integration: configuration + schedule for each read-only integration type.
Telemetry: transition-only log of health/MFA state changes. OFF the audit chain
(Annex F 6 — these are read telemetry events, not security events).

Credentials (client_id, cert PEM, API keys) are stored as vault.Secret rows and
retrieved at runtime via decrypt_secret(). They are NEVER hardcoded or logged.
"""

import uuid

from django.db import models


class IntegrationType(models.TextChoices):
    GRAPH_MFA = "graph_mfa", "Microsoft Graph — MFA"
    WATCHGUARD_SNMP = "watchguard_snmp", "WatchGuard SNMPv3"
    MIKROTIK_API = "mikrotik_api", "MikroTik RouterOS API"
    UNIFI_API = "unifi_api", "UniFi Controller API"


class IntegrationStatus(models.TextChoices):
    OK = "ok", "OK"
    ERROR = "error", "Error"
    NEVER = "never", "Never run"


class Integration(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.TextField()
    integration_type = models.TextField(choices=IntegrationType.choices)
    enabled = models.BooleanField(default=True)
    run_interval_minutes = models.IntegerField(default=60)
    last_run_at = models.DateTimeField(null=True, blank=True)
    last_status = models.TextField(
        choices=IntegrationStatus.choices, default=IntegrationStatus.NEVER
    )
    last_error = models.TextField(blank=True, default="")
    # FK to vault.Secret — the API credential (client cert, password, community string, etc.).
    # null=True: an integration may not yet have a credential configured.
    credential = models.ForeignKey(
        "vault.Secret",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="integrations",
    )
    # JSON config: endpoint, tenant_id, client_id, community name, etc.
    # Never stores the actual secret material — those live in the vault.Secret FK.
    config = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "integration"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(integration_type__in=IntegrationType.values),
                name="integration_type_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(last_status__in=IntegrationStatus.values),
                name="integration_last_status_valid",
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.integration_type})"

    def is_due(self):
        """Return True if this integration should run now."""
        from django.utils import timezone

        if self.last_run_at is None:
            return True
        from datetime import timedelta

        due_at = self.last_run_at + timedelta(minutes=self.run_interval_minutes)
        return timezone.now() >= due_at


class TelemetryEventType(models.TextChoices):
    HEALTH_CHANGE = "health_change", "Health change"
    MFA_CHANGE = "mfa_change", "MFA change"
    UNMATCHED_ACCOUNT = "unmatched_account", "Unmatched account"
    RUN_OK = "run_ok", "Run OK"
    RUN_ERROR = "run_error", "Run error"


class Telemetry(models.Model):
    """Transition-only log for integration events (P5-T4, Annex F 6).

    Records are only written when old_value != new_value (transitions, not every
    poll). This table is intentionally OFF the audit chain — it is read-only
    telemetry, not a security event. System actor reads are not logged.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="telemetry",
    )
    device = models.ForeignKey(
        "inventory.Device",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    account = models.ForeignKey(
        "inventory.Account",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    event_type = models.TextField(choices=TelemetryEventType.choices)
    old_value = models.JSONField(default=dict)
    new_value = models.JSONField(default=dict)
    recorded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "telemetry"
        indexes = [
            models.Index(fields=["integration", "-recorded_at"], name="telemetry_integration_idx"),
            models.Index(fields=["event_type"], name="telemetry_event_type_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(event_type__in=TelemetryEventType.values),
                name="telemetry_event_type_valid",
            ),
        ]

    def __str__(self):
        return f"{self.event_type} @ {self.recorded_at}"
