"""Initial migration for alerts app (P6-T1)."""

import uuid

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("operators", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Alert",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "rule_id",
                    models.TextField(
                        choices=[
                            ("E-1", "E-1: Device sin recuperación (O365+phone)"),
                            ("E-2", "E-2: Cuenta sin MFA"),
                            ("E-3", "E-3: Cuenta comprometida"),
                            ("E-4", "E-4: Cuenta requiere rotación"),
                            ("E-5", "E-5: Dispositivo en uso sin asignación"),
                            ("E-6", "E-6: Garantía vencida"),
                            ("E-7", "E-7: Persona activa sin cuenta"),
                            ("E-8", "E-8: Oficina sin responsable"),
                            ("E-9", "E-9: Contraseña sin rotación"),
                            ("E-10", "E-10: Dispositivo de red offline"),
                            ("E-11", "E-11: Secreto sin rotación"),
                            ("E-12", "E-12: Offboarding pendiente"),
                            ("E-13", "E-13: Integridad de cadena de auditoría"),
                        ]
                    ),
                ),
                (
                    "target_type",
                    models.TextField(
                        choices=[
                            ("person", "Persona"),
                            ("account", "Cuenta"),
                            ("device", "Dispositivo"),
                            ("office", "Oficina"),
                            ("system", "Sistema"),
                        ]
                    ),
                ),
                ("target_id", models.UUIDField(blank=True, null=True)),
                (
                    "severity",
                    models.TextField(
                        choices=[
                            ("critical", "Crítico"),
                            ("high", "Alto"),
                            ("medium", "Medio"),
                            ("low", "Bajo"),
                        ]
                    ),
                ),
                (
                    "status",
                    models.TextField(
                        choices=[
                            ("open", "Abierto"),
                            ("acknowledged", "Reconocido"),
                            ("resolved", "Resuelto"),
                        ],
                        default="open",
                    ),
                ),
                ("details", models.JSONField(default=dict)),
                ("acknowledged_note", models.TextField(blank=True, default="")),
                ("acknowledged_at", models.DateTimeField(blank=True, null=True)),
                ("resolved_at", models.DateTimeField(blank=True, null=True)),
                ("first_seen_at", models.DateTimeField(auto_now_add=True)),
                ("last_seen_at", models.DateTimeField(default=django.utils.timezone.now)),
                (
                    "acknowledged_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="acknowledged_alerts",
                        to="operators.operator",
                    ),
                ),
            ],
            options={
                "db_table": "alert",
                "indexes": [
                    models.Index(
                        fields=["status", "severity"],
                        name="alert_status_severity_idx",
                    ),
                    models.Index(fields=["rule_id"], name="alert_rule_idx"),
                    models.Index(
                        fields=["target_type", "target_id"],
                        name="alert_target_idx",
                    ),
                ],
                "constraints": [
                    models.UniqueConstraint(
                        condition=models.Q(target_id__isnull=False),
                        fields=["rule_id", "target_type", "target_id"],
                        name="alert_unique_key",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            rule_id__in=[
                                "E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7",
                                "E-8", "E-9", "E-10", "E-11", "E-12", "E-13",
                            ]
                        ),
                        name="alert_rule_id_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            severity__in=["critical", "high", "medium", "low"]
                        ),
                        name="alert_severity_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            status__in=["open", "acknowledged", "resolved"]
                        ),
                        name="alert_status_valid",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            target_type__in=["person", "account", "device", "office", "system"]
                        ),
                        name="alert_target_type_valid",
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name="AlertSetting",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "rule_id",
                    models.TextField(
                        choices=[
                            ("E-1", "E-1: Device sin recuperación (O365+phone)"),
                            ("E-2", "E-2: Cuenta sin MFA"),
                            ("E-3", "E-3: Cuenta comprometida"),
                            ("E-4", "E-4: Cuenta requiere rotación"),
                            ("E-5", "E-5: Dispositivo en uso sin asignación"),
                            ("E-6", "E-6: Garantía vencida"),
                            ("E-7", "E-7: Persona activa sin cuenta"),
                            ("E-8", "E-8: Oficina sin responsable"),
                            ("E-9", "E-9: Contraseña sin rotación"),
                            ("E-10", "E-10: Dispositivo de red offline"),
                            ("E-11", "E-11: Secreto sin rotación"),
                            ("E-12", "E-12: Offboarding pendiente"),
                            ("E-13", "E-13: Integridad de cadena de auditoría"),
                        ],
                        unique=True,
                    ),
                ),
                ("enabled", models.BooleanField(default=True)),
                ("threshold_json", models.JSONField(default=dict)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "updated_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="+",
                        to="operators.operator",
                    ),
                ),
            ],
            options={
                "db_table": "alert_setting",
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(
                            rule_id__in=[
                                "E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7",
                                "E-8", "E-9", "E-10", "E-11", "E-12", "E-13",
                            ]
                        ),
                        name="alert_setting_rule_id_valid",
                    ),
                ],
            },
        ),
    ]
