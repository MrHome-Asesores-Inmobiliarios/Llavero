"""Alert and AlertSetting models (P6-T1, Annex E).

Alert rows are keyed by (rule_id, target_type, target_id) — get_or_create on
first fire, update last_seen_at on re-fire, resolved_at set when condition clears.

System-actor reads of Alert for evaluation are NOT logged in the audit chain.
Operator actions (acknowledge, setting change) ARE audited.
"""

import uuid

from django.db import models
from django.utils import timezone


class AlertRuleId(models.TextChoices):
    E1_UNRECOVERABLE_DEVICE = "E-1", "E-1: Device sin recuperación (O365+phone)"
    E2_ACCOUNT_NO_MFA = "E-2", "E-2: Cuenta sin MFA"
    E3_ACCOUNT_COMPROMISED = "E-3", "E-3: Cuenta comprometida"
    E4_ACCOUNT_NEEDS_ROTATION = "E-4", "E-4: Cuenta requiere rotación"
    E5_DEVICE_UNASSIGNED = "E-5", "E-5: Dispositivo en uso sin asignación"
    E6_DEVICE_WARRANTY_EXPIRED = "E-6", "E-6: Garantía vencida"
    E7_PERSON_NO_ACCOUNT = "E-7", "E-7: Persona activa sin cuenta"
    E8_OFFICE_NO_RESPONSIBLE = "E-8", "E-8: Oficina sin responsable"
    E9_ACCOUNT_STALE = "E-9", "E-9: Contraseña sin rotación"
    E10_DEVICE_OFFLINE = "E-10", "E-10: Dispositivo de red offline"
    E11_SECRET_NOT_ROTATED = "E-11", "E-11: Secreto sin rotación"
    E12_PERSON_OFFBOARDING_STALE = "E-12", "E-12: Offboarding pendiente"
    E13_CHAIN_INTEGRITY = "E-13", "E-13: Integridad de cadena de auditoría"


class AlertSeverity(models.TextChoices):
    CRITICAL = "critical", "Crítico"
    HIGH = "high", "Alto"
    MEDIUM = "medium", "Medio"
    LOW = "low", "Bajo"


class AlertStatus(models.TextChoices):
    OPEN = "open", "Abierto"
    ACKNOWLEDGED = "acknowledged", "Reconocido"
    RESOLVED = "resolved", "Resuelto"


class AlertTargetType(models.TextChoices):
    PERSON = "person", "Persona"
    ACCOUNT = "account", "Cuenta"
    DEVICE = "device", "Dispositivo"
    OFFICE = "office", "Oficina"
    SYSTEM = "system", "Sistema"


# Severity ordering for sorting (lower = higher priority)
SEVERITY_ORDER = {
    AlertSeverity.CRITICAL: 0,
    AlertSeverity.HIGH: 1,
    AlertSeverity.MEDIUM: 2,
    AlertSeverity.LOW: 3,
}


class Alert(models.Model):
    """A single alert instance, keyed by (rule_id, target_type, target_id).

    Idempotent: get_or_create on first fire, update last_seen_at on re-fire,
    resolved_at set when condition clears.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    rule_id = models.TextField(choices=AlertRuleId.choices)
    target_type = models.TextField(choices=AlertTargetType.choices)
    target_id = models.UUIDField(null=True, blank=True)
    severity = models.TextField(choices=AlertSeverity.choices)
    status = models.TextField(choices=AlertStatus.choices, default=AlertStatus.OPEN)
    # Non-sensitive context only — never log secrets, keys, or plaintext
    details = models.JSONField(default=dict)
    acknowledged_by = models.ForeignKey(
        "operators.Operator",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="acknowledged_alerts",
    )
    acknowledged_note = models.TextField(blank=True, default="")
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "alert"
        indexes = [
            models.Index(fields=["status", "severity"], name="alert_status_severity_idx"),
            models.Index(fields=["rule_id"], name="alert_rule_idx"),
            models.Index(fields=["target_type", "target_id"], name="alert_target_idx"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["rule_id", "target_type", "target_id"],
                name="alert_unique_key",
                condition=models.Q(target_id__isnull=False),
            ),
            models.CheckConstraint(
                condition=models.Q(rule_id__in=AlertRuleId.values),
                name="alert_rule_id_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(severity__in=AlertSeverity.values),
                name="alert_severity_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=AlertStatus.values),
                name="alert_status_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(target_type__in=AlertTargetType.values),
                name="alert_target_type_valid",
            ),
        ]

    def __str__(self):
        return f"{self.rule_id} {self.target_type}:{self.target_id} [{self.status}]"

    @property
    def is_open(self):
        return self.status == AlertStatus.OPEN

    @property
    def severity_order(self):
        return SEVERITY_ORDER.get(self.severity, 99)


class AlertSetting(models.Model):
    """Per-rule configuration: enabled flag and rule-specific thresholds.

    One row per rule_id. threshold_json holds rule-specific values,
    e.g. {"days": 90} for stale password threshold.
    """

    rule_id = models.TextField(choices=AlertRuleId.choices, unique=True)
    enabled = models.BooleanField(default=True)
    threshold_json = models.JSONField(default=dict)
    updated_by = models.ForeignKey(
        "operators.Operator",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "alert_setting"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(rule_id__in=AlertRuleId.values),
                name="alert_setting_rule_id_valid",
            ),
        ]

    def __str__(self):
        return f"AlertSetting({self.rule_id}, enabled={self.enabled})"
