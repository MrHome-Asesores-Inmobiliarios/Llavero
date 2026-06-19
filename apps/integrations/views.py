"""Views for the integrations dashboard (P5-T5).

URL structure:
    integrations/                   -> list
    integrations/<uuid>/            -> detail + telemetry log
    integrations/new/               -> create (admin only)
    integrations/<uuid>/edit/       -> edit (admin only)
    integrations/<uuid>/toggle/     -> enable/disable (admin only, POST)
    integrations/<uuid>/run/        -> manual run (admin only, POST)

Viewer: read-only; cannot toggle, edit, or trigger manual runs.
Administrator: full access.

Telemetry reads are NOT logged to the audit chain (Annex F 6).
"""

import logging

from django.http import HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from apps.integrations.models import Integration, Telemetry
from apps.operators.models import Operator

logger = logging.getLogger(__name__)


def _require_operator(request):
    """Return the operator from request, or None if not authenticated."""
    return getattr(request, "operator", None)


def _require_admin(request):
    """Return True iff the current operator is an Administrator."""
    op = _require_operator(request)
    return op is not None and op.role == Operator.Role.ADMINISTRATOR


def integration_list(request):
    """List all integrations with their current status."""
    operator = _require_operator(request)
    if operator is None:
        return HttpResponseForbidden("Autenticación requerida.")

    integrations = Integration.objects.order_by("name").select_related("credential")
    return render(
        request,
        "integrations/list.html",
        {
            "integrations": integrations,
            "is_admin": _require_admin(request),
        },
    )


def integration_detail(request, pk):
    """Detail view: integration info + last 50 telemetry records."""
    operator = _require_operator(request)
    if operator is None:
        return HttpResponseForbidden("Autenticación requerida.")

    integration = get_object_or_404(Integration, pk=pk)
    telemetry = (
        Telemetry.objects.filter(integration=integration)
        .order_by("-recorded_at")
        .select_related("device", "account")[:50]
    )
    return render(
        request,
        "integrations/detail.html",
        {
            "integration": integration,
            "telemetry": telemetry,
            "is_admin": _require_admin(request),
        },
    )


def integration_create(request):
    """Create a new integration (admin only)."""
    if not _require_admin(request):
        return HttpResponseForbidden("Solo los administradores pueden crear integraciones.")

    from apps.integrations.forms import IntegrationForm

    if request.method == "POST":
        form = IntegrationForm(request.POST)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect(reverse("integrations:list"))
    else:
        form = IntegrationForm()

    return render(request, "integrations/form.html", {"form": form, "action": "Crear"})


def integration_edit(request, pk):
    """Edit an existing integration (admin only)."""
    if not _require_admin(request):
        return HttpResponseForbidden("Solo los administradores pueden editar integraciones.")

    from apps.integrations.forms import IntegrationForm

    integration = get_object_or_404(Integration, pk=pk)
    if request.method == "POST":
        form = IntegrationForm(request.POST, instance=integration)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect(reverse("integrations:detail", args=[pk]))
    else:
        form = IntegrationForm(instance=integration)

    return render(
        request,
        "integrations/form.html",
        {"form": form, "action": "Editar", "integration": integration},
    )


@require_POST
def integration_toggle(request, pk):
    """Toggle enabled/disabled for an integration (admin only, POST)."""
    if not _require_admin(request):
        return HttpResponseForbidden(
            "Solo los administradores pueden activar/desactivar integraciones."
        )

    integration = get_object_or_404(Integration, pk=pk)
    integration.enabled = not integration.enabled
    integration.save(update_fields=["enabled", "updated_at"])
    return HttpResponseRedirect(reverse("integrations:detail", args=[pk]))


@require_POST
def integration_run(request, pk):
    """Trigger a manual run of an integration (admin only, POST).

    Confirms that only administrators can trigger manual runs (P5-T6 verify #3).
    Runs without vault MK (no credential decryption in the HTTP context).
    """
    if not _require_admin(request):
        return HttpResponseForbidden(
            "Solo los administradores pueden ejecutar integraciones manualmente."
        )

    integration = get_object_or_404(Integration, pk=pk)
    from apps.integrations.runners.dispatch import run_one

    # Run without MK — HTTP context does not expose the vault MK to view code.
    # To run with credentials, use the management command: run_integrations.
    try:
        run_one(integration, mk=None)
    except Exception as exc:
        logger.exception("Manual integration run failed: %s", exc)

    return HttpResponseRedirect(reverse("integrations:detail", args=[pk]))
