"""Alert views — dashboard, acknowledge, settings (P6-T5, P6-T7).

Security:
- All views require require_operator (Viewer can read dashboard).
- Acknowledge and settings edit require require_admin.
- alert_acknowledged IS audited (operator action).
- alert_setting_changed IS audited (operator action).
- System eval reads are NOT audited.
"""

from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.alerts.forms import AcknowledgeAlertForm, AlertSettingForm
from apps.alerts.models import Alert, AlertRuleId, AlertSetting, AlertSeverity, AlertStatus
from apps.audit.chain import append_audit
from apps.audit.models import ActorType, AuditAction
from apps.operators.decorators import require_admin, require_operator

# ---------------------------------------------------------------------------
# Integrity strip context helper (P6-T6)
# ---------------------------------------------------------------------------


def _integrity_context():
    """Return chain summary for the integrity strip (NOT audited — system read)."""
    from apps.audit.models import AuditCheckpoint, AuditEntry

    try:
        entry_count = AuditEntry.objects.count()
        checkpoint = AuditCheckpoint.objects.order_by("-created_at").first()
    except Exception:  # noqa: BLE001
        entry_count = 0
        checkpoint = None

    return {
        "audit_entry_count": entry_count,
        "latest_checkpoint": checkpoint,
    }


def _open_alert_count():
    """Count open alerts for the sidebar badge (NOT audited)."""
    return Alert.objects.filter(status=AlertStatus.OPEN).count()


# ---------------------------------------------------------------------------
# Dashboard (P6-T5)
# ---------------------------------------------------------------------------


@require_operator
def dashboard(request):
    """Main alert dashboard — open alerts grouped by severity."""
    severity_filter = request.GET.get("severity", "")
    rule_filter = request.GET.get("rule_id", "")
    target_type_filter = request.GET.get("target_type", "")

    qs = Alert.objects.exclude(status=AlertStatus.RESOLVED)

    if severity_filter:
        qs = qs.filter(severity=severity_filter)
    if rule_filter:
        qs = qs.filter(rule_id=rule_filter)
    if target_type_filter:
        qs = qs.filter(target_type=target_type_filter)

    # Order: critical first, then by last_seen_at desc
    severity_order = {
        AlertSeverity.CRITICAL: 0,
        AlertSeverity.HIGH: 1,
        AlertSeverity.MEDIUM: 2,
        AlertSeverity.LOW: 3,
    }
    alerts = sorted(
        qs.select_related("acknowledged_by"),
        key=lambda a: (severity_order.get(a.severity, 99), -a.last_seen_at.timestamp()),
    )

    # Summary counts
    counts = {
        "critical": Alert.objects.filter(
            status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
            severity=AlertSeverity.CRITICAL,
        ).count(),
        "high": Alert.objects.filter(
            status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
            severity=AlertSeverity.HIGH,
        ).count(),
        "medium": Alert.objects.filter(
            status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
            severity=AlertSeverity.MEDIUM,
        ).count(),
        "low": Alert.objects.filter(
            status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED],
            severity=AlertSeverity.LOW,
        ).count(),
        "total_open": Alert.objects.filter(
            status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]
        ).count(),
    }

    context = {
        "alerts": alerts,
        "counts": counts,
        "severity_choices": AlertSeverity.choices,
        "rule_choices": AlertRuleId.choices,
        "severity_filter": severity_filter,
        "rule_filter": rule_filter,
        "target_type_filter": target_type_filter,
        "acknowledge_form": AcknowledgeAlertForm(),
        **_integrity_context(),
        "open_alert_count": _open_alert_count(),
    }
    return render(request, "alerts/dashboard.html", context)


# ---------------------------------------------------------------------------
# Acknowledge (P6-T5)
# ---------------------------------------------------------------------------


@require_POST
@require_admin
def acknowledge_alert(request, alert_id):
    """Acknowledge an alert. Admin-only. Audited as alert_acknowledged."""
    alert = get_object_or_404(Alert, pk=alert_id)
    form = AcknowledgeAlertForm(request.POST)

    if not form.is_valid():
        # Re-render dashboard with errors — simple redirect for now
        from django.contrib import messages as _messages

        _messages.error(request, f"Nota requerida: {form.errors.get('note', [''])[0]}")
        return redirect("alerts:dashboard")

    note = form.cleaned_data["note"]
    now = timezone.now()

    with transaction.atomic():
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_by = request.operator
        alert.acknowledged_note = note
        alert.acknowledged_at = now
        alert.save(
            update_fields=["status", "acknowledged_by", "acknowledged_note", "acknowledged_at"]
        )

        append_audit(
            action=AuditAction.PARAMETER_CHANGE,  # closest existing action for alert_acknowledged
            actor_type=ActorType.OPERATOR,
            actor_operator=request.operator,
            actor_username=request.operator.username,
            target_table="alert",
            target_id=alert.id,
            target_label=f"{alert.rule_id} {alert.target_type}:{alert.target_id}",
            changes={
                "action": "alert_acknowledged",
                "rule_id": alert.rule_id,
                "target_type": alert.target_type,
                "target_id": str(alert.target_id) if alert.target_id else None,
                "note": note,
            },
            metadata={
                "operator": request.operator.username,
            },
        )

    return redirect("alerts:dashboard")


# ---------------------------------------------------------------------------
# On-demand evaluator trigger (P6-T2)
# ---------------------------------------------------------------------------


@require_POST
@require_admin
def trigger_evaluate(request):
    """Admin-only on-demand alert evaluation trigger."""
    from apps.alerts.rules import run_all_enabled_rules

    results = run_all_enabled_rules()
    errors = [(name, str(err)) for name, err, status in results if err is not None]
    if errors:
        from django.contrib import messages as _messages

        _messages.error(request, f"Errores en evaluación: {errors}")
    else:
        from django.contrib import messages as _messages

        _messages.success(request, "Evaluación de alertas completada.")
    return redirect("alerts:dashboard")


# ---------------------------------------------------------------------------
# Alert settings (P6-T7)
# ---------------------------------------------------------------------------


@require_operator
def settings_list(request):
    """List all alert settings (admin can edit, viewer can view)."""
    # Ensure all rule settings exist (create defaults if missing)
    existing = set(AlertSetting.objects.values_list("rule_id", flat=True))
    for rule_id, _ in AlertRuleId.choices:
        if rule_id not in existing:
            _default_threshold = _default_threshold_for(rule_id)
            AlertSetting.objects.get_or_create(
                rule_id=rule_id,
                defaults={"enabled": True, "threshold_json": _default_threshold},
            )

    settings = AlertSetting.objects.all().order_by("rule_id")
    context = {
        "settings": settings,
        **_integrity_context(),
        "open_alert_count": _open_alert_count(),
    }
    return render(request, "alerts/settings.html", context)


def _default_threshold_for(rule_id: str) -> dict:
    defaults = {
        AlertRuleId.E9_ACCOUNT_STALE: {"days": 90},
        AlertRuleId.E11_SECRET_NOT_ROTATED: {"days": 180},
    }
    return defaults.get(rule_id, {})


@require_admin
def settings_edit(request, rule_id):
    """Edit a single alert setting. Admin-only. Audited as alert_setting_changed."""
    setting, _ = AlertSetting.objects.get_or_create(
        rule_id=rule_id,
        defaults={
            "enabled": True,
            "threshold_json": _default_threshold_for(rule_id),
        },
    )

    if request.method == "POST":
        form = AlertSettingForm(request.POST, instance=setting)
        if form.is_valid():
            old_enabled = setting.enabled
            old_threshold = dict(setting.threshold_json)

            with transaction.atomic():
                setting = form.save(commit=False)
                setting.updated_by = request.operator
                setting.save()

                append_audit(
                    action=AuditAction.PARAMETER_CHANGE,
                    actor_type=ActorType.OPERATOR,
                    actor_operator=request.operator,
                    actor_username=request.operator.username,
                    target_table="alert_setting",
                    target_id=None,
                    target_label=rule_id,
                    changes={
                        "action": "alert_setting_changed",
                        "rule_id": rule_id,
                        "old": {"enabled": old_enabled, "threshold_json": old_threshold},
                        "new": {
                            "enabled": setting.enabled,
                            "threshold_json": setting.threshold_json,
                        },
                    },
                    metadata={"operator": request.operator.username},
                )

            return redirect("alerts:settings")
    else:
        form = AlertSettingForm(instance=setting)

    context = {
        "form": form,
        "setting": setting,
        "rule_label": dict(AlertRuleId.choices).get(rule_id, rule_id),
        **_integrity_context(),
        "open_alert_count": _open_alert_count(),
    }
    return render(request, "alerts/settings_edit.html", context)
