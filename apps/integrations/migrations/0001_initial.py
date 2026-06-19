"""Initial migration for apps.integrations (P5-T1, P5-T4)."""

import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("vault", "0002_vaultkeyholder"),
        ("inventory", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Integration",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)),
                ("name", models.TextField()),
                (
                    "integration_type",
                    models.TextField(
                        choices=[
                            ("graph_mfa", "Microsoft Graph — MFA"),
                            ("watchguard_snmp", "WatchGuard SNMPv3"),
                            ("mikrotik_api", "MikroTik RouterOS API"),
                            ("unifi_api", "UniFi Controller API"),
                        ]
                    ),
                ),
                ("enabled", models.BooleanField(default=True)),
                ("run_interval_minutes", models.IntegerField(default=60)),
                ("last_run_at", models.DateTimeField(blank=True, null=True)),
                (
                    "last_status",
                    models.TextField(
                        choices=[("ok", "OK"), ("error", "Error"), ("never", "Never run")],
                        default="never",
                    ),
                ),
                ("last_error", models.TextField(blank=True, default="")),
                (
                    "credential",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="integrations",
                        to="vault.secret",
                    ),
                ),
                ("config", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "db_table": "integration",
            },
        ),
        migrations.AddConstraint(
            model_name="integration",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    integration_type__in=[
                        "graph_mfa",
                        "watchguard_snmp",
                        "mikrotik_api",
                        "unifi_api",
                    ]
                ),
                name="integration_type_valid",
            ),
        ),
        migrations.AddConstraint(
            model_name="integration",
            constraint=models.CheckConstraint(
                condition=models.Q(last_status__in=["ok", "error", "never"]),
                name="integration_last_status_valid",
            ),
        ),
        migrations.CreateModel(
            name="Telemetry",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)),
                (
                    "integration",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="telemetry",
                        to="integrations.integration",
                    ),
                ),
                (
                    "device",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="inventory.device",
                    ),
                ),
                (
                    "account",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="inventory.account",
                    ),
                ),
                (
                    "event_type",
                    models.TextField(
                        choices=[
                            ("health_change", "Health change"),
                            ("mfa_change", "MFA change"),
                            ("unmatched_account", "Unmatched account"),
                            ("run_ok", "Run OK"),
                            ("run_error", "Run error"),
                        ]
                    ),
                ),
                ("old_value", models.JSONField(default=dict)),
                ("new_value", models.JSONField(default=dict)),
                ("recorded_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "db_table": "telemetry",
            },
        ),
        migrations.AddIndex(
            model_name="telemetry",
            index=models.Index(
                fields=["integration", "-recorded_at"], name="telemetry_integration_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="telemetry",
            index=models.Index(fields=["event_type"], name="telemetry_event_type_idx"),
        ),
        migrations.AddConstraint(
            model_name="telemetry",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    event_type__in=[
                        "health_change",
                        "mfa_change",
                        "unmatched_account",
                        "run_ok",
                        "run_error",
                    ]
                ),
                name="telemetry_event_type_valid",
            ),
        ),
    ]
