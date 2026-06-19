"""Relationship link views (Phase 3 — Annex C 5, 6).

Two generic views handle creating and ending any of the nine link types.
All writes run inside transaction.atomic() and call append_audit.
HTMX-friendly: returns HX-Refresh on success.
"""

import uuid

from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.views import View

from apps.audit.chain import append_audit
from apps.audit.models import AuditEntry
from apps.common.models import LinkState
from apps.inventory.models import Account, Device, Office, Person
from apps.operators.decorators import require_admin
from apps.operators.models import OperatorSession
from apps.relationships.models import (
    AccountDeviceConfig,
    AccountOwnership,
    AccountRecovery,
    AccountRecoveryContact,
    DeviceAssignment,
    DeviceDependency,
    DeviceLocation,
    DeviceRecoveryContact,
    OfficeMembership,
)

# Map link_type -> (model_class, source_field, target_field, qualifier_field, qualifier_choices)
_LINK_MAP = {
    "account_ownership": (AccountOwnership, "person", "account", "role", None),
    "device_assignment": (DeviceAssignment, "person", "device", "role", None),
    "account_device_config": (AccountDeviceConfig, "account", "device", "purpose", None),
    "account_recovery": (AccountRecovery, "recovery_account", "target_account", "priority", None),
    "account_recovery_contact": (AccountRecoveryContact, "person", "account", "channel", None),
    "device_recovery_contact": (DeviceRecoveryContact, "person", "device", "channel", None),
    "device_location": (DeviceLocation, "device", "office", None, None),
    "office_membership": (OfficeMembership, "person", "office", "role", None),
    "device_dependency": (
        DeviceDependency,
        "dependent_device",
        "depends_on_device",
        "nature",
        None,
    ),
}

_SOURCE_MODEL_MAP = {
    "person": Person,
    "account": Account,
    "device": Device,
    "office": Office,
    "recovery_account": Account,
    "target_account": Account,
    "dependent_device": Device,
    "depends_on_device": Device,
}


def _active_session(request):
    return (
        OperatorSession.objects.filter(operator=request.operator, revoked_at__isnull=True)
        .order_by("-created_at")
        .first()
    )


def _source_ip(request):
    return request.META.get("REMOTE_ADDR")


def _is_htmx(request):
    return request.headers.get("HX-Request") == "true"


class LinkCreateView(View):
    @require_admin
    def post(self, request):
        link_type = request.POST.get("link_type", "")
        if link_type not in _LINK_MAP:
            return HttpResponse(f"Unknown link_type: {link_type}", status=400)

        model_cls, source_field, target_field, qualifier_field, _ = _LINK_MAP[link_type]

        source_pk = request.POST.get("source_pk", "")
        target_pk = request.POST.get("target_pk", "")

        if not source_pk or not target_pk:
            return HttpResponse("source_pk and target_pk are required", status=400)

        try:
            source_uuid = uuid.UUID(str(source_pk))
            target_uuid = uuid.UUID(str(target_pk))
        except ValueError:
            return HttpResponse("Invalid UUID in source_pk or target_pk", status=400)

        # Resolve source and target entity models from the link map field names
        source_model = _SOURCE_MODEL_MAP.get(source_field, Person)
        target_model = _SOURCE_MODEL_MAP.get(target_field, Account)

        source_obj = get_object_or_404(source_model, pk=source_uuid)
        target_obj = get_object_or_404(target_model, pk=target_uuid)

        with transaction.atomic():
            kwargs = {
                source_field: source_obj,
                target_field: target_obj,
                "created_by": request.operator,
                "updated_by": request.operator,
                "state": LinkState.ACTIVE,
            }
            if qualifier_field:
                qualifier_value = request.POST.get(qualifier_field, "")
                if qualifier_value:
                    kwargs[qualifier_field] = qualifier_value

            link = model_cls.objects.create(**kwargs)

            append_audit(
                action=AuditEntry.Action.RELATIONSHIP_CREATE,
                actor_type=AuditEntry.ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=_active_session(request),
                source_ip=_source_ip(request),
                target_table=model_cls._meta.db_table,
                target_id=str(link.pk),
                target_label=f"{link_type}: {source_obj} -> {target_obj}",
                changes={
                    "link_type": link_type,
                    "source_pk": str(source_uuid),
                    "target_pk": str(target_uuid),
                },
            )

        if _is_htmx(request):
            response = HttpResponse("", status=200)
            response["HX-Refresh"] = "true"
            return response

        return HttpResponse("Link created.", status=201)


class LinkEndView(View):
    @require_admin
    def post(self, request, pk):
        link_type = request.POST.get("link_type", "")
        if link_type not in _LINK_MAP:
            return HttpResponse(f"Unknown link_type: {link_type}", status=400)

        model_cls = _LINK_MAP[link_type][0]
        link = get_object_or_404(model_cls, pk=pk)

        if link.state == LinkState.FORMER:
            return HttpResponse("Link is already ended.", status=400)

        with transaction.atomic():
            link.end(by=request.operator)
            append_audit(
                action=AuditEntry.Action.RELATIONSHIP_END,
                actor_type=AuditEntry.ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=_active_session(request),
                source_ip=_source_ip(request),
                target_table=model_cls._meta.db_table,
                target_id=str(link.pk),
                target_label=f"{link_type} ended",
                changes={"link_type": link_type, "ended_at": str(link.valid_to)},
            )

        if _is_htmx(request):
            response = HttpResponse("", status=200)
            response["HX-Refresh"] = "true"
            return response

        return HttpResponse("Link ended.", status=200)
