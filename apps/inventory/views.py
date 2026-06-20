"""Inventory UI views (Phase 3 — Annex C 4.4-4.10).

All permission checks are server-side. Viewer can read; Administrator can write.
All writes run inside transaction.atomic() and call append_audit.
State transitions are the only lifecycle operation — no hard deletes.
"""

import json

from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from apps.audit.chain import append_audit
from apps.audit.models import AuditEntry
from apps.inventory.forms import (
    AccountForm,
    DeviceForm,
    FieldDefinitionForm,
    NetworkDeviceDetailForm,
    OfficeForm,
    PersonForm,
)
from apps.inventory.models import (
    Account,
    AccountState,
    Device,
    DeviceState,
    FieldDefinition,
    NetworkDeviceDetail,
    Office,
    OfficeState,
    Person,
    PersonState,
)
from apps.operators.decorators import require_admin, require_operator
from apps.operators.models import OperatorSession
from apps.relationships.models import (
    AccountDeviceConfig,
    AccountOwnership,
    AccountRecoveryContact,
    DeviceAssignment,
    DeviceDependency,
    DeviceLocation,
    DeviceRecoveryContact,
    OfficeMembership,
)

# Terminal states — once entered, cannot leave
_TERMINAL_STATES = {
    "person": {PersonState.TERMINATED},
    "account": {AccountState.COMPROMISED, AccountState.DISABLED},
    "device": {DeviceState.DECOMMISSIONED},
    "office": {OfficeState.CLOSED},
}


def _active_session(request):
    """Return the most-recent non-revoked session for the current operator."""
    return (
        OperatorSession.objects.filter(operator=request.operator, revoked_at__isnull=True)
        .order_by("-created_at")
        .first()
    )


def _source_ip(request):
    return request.META.get("REMOTE_ADDR")


def _is_htmx(request):
    return request.headers.get("HX-Request") == "true"


def _is_admin(request):
    from apps.operators.models import Operator

    return request.operator.role == Operator.Role.ADMINISTRATOR


def _custom_fields_for(entity_type, is_viewer):
    """Return active FieldDefinitions for entity_type, filtering viewer_visible if needed."""
    qs = FieldDefinition.objects.filter(entity_type=entity_type, active=True).order_by(
        "display_order", "key"
    )
    if is_viewer:
        qs = qs.filter(viewer_visible=True)
    return list(qs)


def _save_custom_fields(request, instance, entity_type):
    """Read cf_<key> POST params and save to instance.custom_fields."""
    field_defs = FieldDefinition.objects.filter(entity_type=entity_type, active=True)
    cf = dict(instance.custom_fields or {})
    for fd in field_defs:
        value = request.POST.get(f"cf_{fd.key}", "")
        if value:
            cf[fd.key] = value
        else:
            cf.pop(fd.key, None)
    instance.custom_fields = cf
    instance.save(update_fields=["custom_fields"])


# ---------------------------------------------------------------------------
# Person views
# ---------------------------------------------------------------------------


class PersonListView(View):
    @require_operator
    def get(self, request):
        q = request.GET.get("q", "").strip()
        qs = Person.objects.order_by("full_name")
        if q:
            qs = qs.filter(full_name__icontains=q)
            action = AuditEntry.Action.SEARCH
        else:
            action = AuditEntry.Action.LIST_VIEW
        persons = list(qs)
        with transaction.atomic():
            append_audit(
                action=action,
                actor_type=AuditEntry.ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=_active_session(request),
                source_ip=_source_ip(request),
                target_table="person",
                metadata={"q": q} if q else {},
            )
        return render(request, "inventory/person_list.html", {"persons": persons, "q": q})


class PersonDetailView(View):
    @require_operator
    def get(self, request, pk):
        person = get_object_or_404(Person, pk=pk)
        viewer = not _is_admin(request)
        custom_fields = _custom_fields_for("person", viewer)
        # Relationships
        account_ownerships = AccountOwnership.objects.filter(
            person=person, state="active"
        ).select_related("account")
        device_assignments = DeviceAssignment.objects.filter(
            person=person, state="active"
        ).select_related("device")
        office_memberships = OfficeMembership.objects.filter(
            person=person, state="active"
        ).select_related("office")
        with transaction.atomic():
            append_audit(
                action=AuditEntry.Action.RECORD_VIEW,
                actor_type=AuditEntry.ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=_active_session(request),
                source_ip=_source_ip(request),
                target_table="person",
                target_id=str(person.pk),
                target_label=str(person),
            )
        return render(
            request,
            "inventory/person_detail.html",
            {
                "person": person,
                "custom_fields": custom_fields,
                "viewer": viewer,
                "account_ownerships": account_ownerships,
                "device_assignments": device_assignments,
                "office_memberships": office_memberships,
            },
        )


class PersonCreateView(View):
    @require_admin
    def get(self, request):
        form = PersonForm()
        custom_fields = _custom_fields_for("person", False)
        return render(
            request,
            "inventory/person_form.html",
            {"form": form, "custom_fields": custom_fields, "action": "Crear"},
        )

    @require_admin
    def post(self, request):
        form = PersonForm(request.POST)
        custom_fields = _custom_fields_for("person", False)
        if form.is_valid():
            with transaction.atomic():
                person = form.save(commit=False)
                person.created_by = request.operator
                person.updated_by = request.operator
                person.save()
                _save_custom_fields(request, person, "person")
                append_audit(
                    action=AuditEntry.Action.CREATE,
                    actor_type=AuditEntry.ActorType.OPERATOR,
                    actor_operator=request.operator,
                    actor_username=request.operator.username,
                    session=_active_session(request),
                    source_ip=_source_ip(request),
                    target_table="person",
                    target_id=str(person.pk),
                    target_label=str(person),
                    changes={"full_name": person.full_name},
                )
            return redirect("person-detail", pk=person.pk)
        return render(
            request,
            "inventory/person_form.html",
            {"form": form, "custom_fields": custom_fields, "action": "Crear"},
        )


class PersonEditView(View):
    @require_admin
    def get(self, request, pk):
        person = get_object_or_404(Person, pk=pk)
        form = PersonForm(instance=person)
        custom_fields = _custom_fields_for("person", False)
        return render(
            request,
            "inventory/person_form.html",
            {"form": form, "person": person, "custom_fields": custom_fields, "action": "Editar"},
        )

    @require_admin
    def post(self, request, pk):
        person = get_object_or_404(Person, pk=pk)
        form = PersonForm(request.POST, instance=person)
        custom_fields = _custom_fields_for("person", False)
        if form.is_valid():
            with transaction.atomic():
                person = form.save(commit=False)
                person.updated_by = request.operator
                person.save()
                _save_custom_fields(request, person, "person")
                append_audit(
                    action=AuditEntry.Action.UPDATE,
                    actor_type=AuditEntry.ActorType.OPERATOR,
                    actor_operator=request.operator,
                    actor_username=request.operator.username,
                    session=_active_session(request),
                    source_ip=_source_ip(request),
                    target_table="person",
                    target_id=str(person.pk),
                    target_label=str(person),
                    changes={"fields": list(form.changed_data)},
                )
            return redirect("person-detail", pk=person.pk)
        return render(
            request,
            "inventory/person_form.html",
            {"form": form, "person": person, "custom_fields": custom_fields, "action": "Editar"},
        )


# ---------------------------------------------------------------------------
# Account views
# ---------------------------------------------------------------------------


class AccountListView(View):
    @require_operator
    def get(self, request):
        q = request.GET.get("q", "").strip()
        qs = Account.objects.order_by("label")
        if q:
            qs = qs.filter(identifier__icontains=q) | Account.objects.filter(label__icontains=q)
            qs = qs.order_by("label")
            action = AuditEntry.Action.SEARCH
        else:
            action = AuditEntry.Action.LIST_VIEW
        accounts = list(qs)
        with transaction.atomic():
            append_audit(
                action=action,
                actor_type=AuditEntry.ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=_active_session(request),
                source_ip=_source_ip(request),
                target_table="account",
                metadata={"q": q} if q else {},
            )
        return render(request, "inventory/account_list.html", {"accounts": accounts, "q": q})


class AccountDetailView(View):
    @require_operator
    def get(self, request, pk):
        account = get_object_or_404(Account, pk=pk)
        viewer = not _is_admin(request)
        custom_fields = _custom_fields_for("account", viewer)
        ownerships = AccountOwnership.objects.filter(
            account=account, state="active"
        ).select_related("person")
        device_configs = AccountDeviceConfig.objects.filter(
            account=account, state="active"
        ).select_related("device")
        recovery_contacts = AccountRecoveryContact.objects.filter(
            account=account, state="active"
        ).select_related("person")
        with transaction.atomic():
            append_audit(
                action=AuditEntry.Action.RECORD_VIEW,
                actor_type=AuditEntry.ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=_active_session(request),
                source_ip=_source_ip(request),
                target_table="account",
                target_id=str(account.pk),
                target_label=str(account),
            )
        return render(
            request,
            "inventory/account_detail.html",
            {
                "account": account,
                "custom_fields": custom_fields,
                "viewer": viewer,
                "ownerships": ownerships,
                "device_configs": device_configs,
                "recovery_contacts": recovery_contacts,
            },
        )


class AccountCreateView(View):
    @require_admin
    def get(self, request):
        form = AccountForm()
        custom_fields = _custom_fields_for("account", False)
        return render(
            request,
            "inventory/account_form.html",
            {"form": form, "custom_fields": custom_fields, "action": "Crear"},
        )

    @require_admin
    def post(self, request):
        form = AccountForm(request.POST)
        custom_fields = _custom_fields_for("account", False)
        if form.is_valid():
            with transaction.atomic():
                account = form.save(commit=False)
                account.created_by = request.operator
                account.updated_by = request.operator
                account.save()
                _save_custom_fields(request, account, "account")
                append_audit(
                    action=AuditEntry.Action.CREATE,
                    actor_type=AuditEntry.ActorType.OPERATOR,
                    actor_operator=request.operator,
                    actor_username=request.operator.username,
                    session=_active_session(request),
                    source_ip=_source_ip(request),
                    target_table="account",
                    target_id=str(account.pk),
                    target_label=str(account),
                    changes={"label": account.label, "identifier": account.identifier},
                )
                # Auto-link to person if link_person query param provided
                link_person_id = request.GET.get("link_person", "")
                if link_person_id:
                    try:
                        person = Person.objects.get(pk=link_person_id)
                        AccountOwnership.objects.create(
                            person=person,
                            account=account,
                            role=AccountOwnership.Role.SHARED,
                            created_by=request.operator,
                            updated_by=request.operator,
                        )
                    except (Person.DoesNotExist, ValueError):
                        pass
            return redirect("account-detail", pk=account.pk)
        return render(
            request,
            "inventory/account_form.html",
            {"form": form, "custom_fields": custom_fields, "action": "Crear"},
        )


class AccountEditView(View):
    @require_admin
    def get(self, request, pk):
        account = get_object_or_404(Account, pk=pk)
        form = AccountForm(instance=account)
        custom_fields = _custom_fields_for("account", False)
        return render(
            request,
            "inventory/account_form.html",
            {"form": form, "account": account, "custom_fields": custom_fields, "action": "Editar"},
        )

    @require_admin
    def post(self, request, pk):
        account = get_object_or_404(Account, pk=pk)
        form = AccountForm(request.POST, instance=account)
        custom_fields = _custom_fields_for("account", False)
        if form.is_valid():
            with transaction.atomic():
                account = form.save(commit=False)
                account.updated_by = request.operator
                account.save()
                _save_custom_fields(request, account, "account")
                append_audit(
                    action=AuditEntry.Action.UPDATE,
                    actor_type=AuditEntry.ActorType.OPERATOR,
                    actor_operator=request.operator,
                    actor_username=request.operator.username,
                    session=_active_session(request),
                    source_ip=_source_ip(request),
                    target_table="account",
                    target_id=str(account.pk),
                    target_label=str(account),
                    changes={"fields": list(form.changed_data)},
                )
            return redirect("account-detail", pk=account.pk)
        return render(
            request,
            "inventory/account_form.html",
            {"form": form, "account": account, "custom_fields": custom_fields, "action": "Editar"},
        )


# ---------------------------------------------------------------------------
# Device views
# ---------------------------------------------------------------------------


class DeviceListView(View):
    @require_operator
    def get(self, request):
        q = request.GET.get("q", "").strip()
        qs = Device.objects.order_by("hostname", "serial_number")
        if q:
            qs = qs.filter(hostname__icontains=q) | Device.objects.filter(
                serial_number__icontains=q
            )
            qs = qs.order_by("hostname")
            action = AuditEntry.Action.SEARCH
        else:
            action = AuditEntry.Action.LIST_VIEW
        devices = list(qs)
        with transaction.atomic():
            append_audit(
                action=action,
                actor_type=AuditEntry.ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=_active_session(request),
                source_ip=_source_ip(request),
                target_table="device",
                metadata={"q": q} if q else {},
            )
        return render(request, "inventory/device_list.html", {"devices": devices, "q": q})


class DeviceDetailView(View):
    @require_operator
    def get(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        viewer = not _is_admin(request)
        custom_fields = _custom_fields_for("device", viewer)
        try:
            network_detail = device.network_detail
        except NetworkDeviceDetail.DoesNotExist:
            network_detail = None
        assignments = DeviceAssignment.objects.filter(device=device, state="active").select_related(
            "person"
        )
        locations = DeviceLocation.objects.filter(device=device, state="active").select_related(
            "office"
        )
        account_configs = AccountDeviceConfig.objects.filter(
            device=device, state="active"
        ).select_related("account")
        recovery_contacts = DeviceRecoveryContact.objects.filter(
            device=device, state="active"
        ).select_related("person")
        dependencies = DeviceDependency.objects.filter(
            dependent_device=device, state="active"
        ).select_related("depends_on_device")
        with transaction.atomic():
            append_audit(
                action=AuditEntry.Action.RECORD_VIEW,
                actor_type=AuditEntry.ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=_active_session(request),
                source_ip=_source_ip(request),
                target_table="device",
                target_id=str(device.pk),
                target_label=str(device),
            )
        return render(
            request,
            "inventory/device_detail.html",
            {
                "device": device,
                "custom_fields": custom_fields,
                "viewer": viewer,
                "network_detail": network_detail,
                "assignments": assignments,
                "locations": locations,
                "account_configs": account_configs,
                "recovery_contacts": recovery_contacts,
                "dependencies": dependencies,
            },
        )


class DeviceCreateView(View):
    @require_admin
    def get(self, request):
        form = DeviceForm()
        net_form = NetworkDeviceDetailForm()
        custom_fields = _custom_fields_for("device", False)
        return render(
            request,
            "inventory/device_form.html",
            {"form": form, "net_form": net_form, "custom_fields": custom_fields, "action": "Crear"},
        )

    @require_admin
    def post(self, request):
        form = DeviceForm(request.POST)
        net_form = NetworkDeviceDetailForm(request.POST)
        custom_fields = _custom_fields_for("device", False)
        if form.is_valid():
            with transaction.atomic():
                device = form.save(commit=False)
                device.created_by = request.operator
                device.updated_by = request.operator
                device.save()
                _save_custom_fields(request, device, "device")
                # Optionally save network detail if any net_form fields filled
                if net_form.is_valid() and any(
                    v
                    for k, v in net_form.cleaned_data.items()
                    if v not in (None, "", "none", "unknown")
                ):
                    nd = net_form.save(commit=False)
                    nd.device = device
                    nd.save()
                append_audit(
                    action=AuditEntry.Action.CREATE,
                    actor_type=AuditEntry.ActorType.OPERATOR,
                    actor_operator=request.operator,
                    actor_username=request.operator.username,
                    session=_active_session(request),
                    source_ip=_source_ip(request),
                    target_table="device",
                    target_id=str(device.pk),
                    target_label=str(device),
                    changes={"device_type": device.device_type, "hostname": device.hostname},
                )
                # Auto-link to person if link_person query param provided
                link_person_id = request.GET.get("link_person", "")
                if link_person_id:
                    try:
                        person = Person.objects.get(pk=link_person_id)
                        DeviceAssignment.objects.create(
                            person=person,
                            device=device,
                            role=DeviceAssignment.Role.PRIMARY_USER,
                            created_by=request.operator,
                            updated_by=request.operator,
                        )
                    except (Person.DoesNotExist, ValueError):
                        pass
            return redirect("device-detail", pk=device.pk)
        return render(
            request,
            "inventory/device_form.html",
            {"form": form, "net_form": net_form, "custom_fields": custom_fields, "action": "Crear"},
        )


class DeviceEditView(View):
    @require_admin
    def get(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        form = DeviceForm(instance=device)
        try:
            network_detail = device.network_detail
        except NetworkDeviceDetail.DoesNotExist:
            network_detail = None
        net_form = NetworkDeviceDetailForm(instance=network_detail)
        custom_fields = _custom_fields_for("device", False)
        return render(
            request,
            "inventory/device_form.html",
            {
                "form": form,
                "net_form": net_form,
                "device": device,
                "custom_fields": custom_fields,
                "action": "Editar",
            },
        )

    @require_admin
    def post(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        form = DeviceForm(request.POST, instance=device)
        try:
            network_detail = device.network_detail
        except NetworkDeviceDetail.DoesNotExist:
            network_detail = None
        net_form = NetworkDeviceDetailForm(request.POST, instance=network_detail)
        custom_fields = _custom_fields_for("device", False)
        if form.is_valid():
            with transaction.atomic():
                device = form.save(commit=False)
                device.updated_by = request.operator
                device.save()
                _save_custom_fields(request, device, "device")
                if net_form.is_valid():
                    nd = net_form.save(commit=False)
                    nd.device = device
                    nd.save()
                append_audit(
                    action=AuditEntry.Action.UPDATE,
                    actor_type=AuditEntry.ActorType.OPERATOR,
                    actor_operator=request.operator,
                    actor_username=request.operator.username,
                    session=_active_session(request),
                    source_ip=_source_ip(request),
                    target_table="device",
                    target_id=str(device.pk),
                    target_label=str(device),
                    changes={"fields": list(form.changed_data)},
                )
            return redirect("device-detail", pk=device.pk)
        return render(
            request,
            "inventory/device_form.html",
            {
                "form": form,
                "net_form": net_form,
                "device": device,
                "custom_fields": custom_fields,
                "action": "Editar",
            },
        )


# ---------------------------------------------------------------------------
# Office views
# ---------------------------------------------------------------------------


class OfficeListView(View):
    @require_operator
    def get(self, request):
        q = request.GET.get("q", "").strip()
        qs = Office.objects.order_by("name")
        if q:
            qs = qs.filter(name__icontains=q)
            action = AuditEntry.Action.SEARCH
        else:
            action = AuditEntry.Action.LIST_VIEW
        offices = list(qs)
        with transaction.atomic():
            append_audit(
                action=action,
                actor_type=AuditEntry.ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=_active_session(request),
                source_ip=_source_ip(request),
                target_table="office",
                metadata={"q": q} if q else {},
            )
        return render(request, "inventory/office_list.html", {"offices": offices, "q": q})


class OfficeDetailView(View):
    @require_operator
    def get(self, request, pk):
        office = get_object_or_404(Office, pk=pk)
        viewer = not _is_admin(request)
        custom_fields = _custom_fields_for("office", viewer)
        memberships = OfficeMembership.objects.filter(office=office, state="active").select_related(
            "person"
        )
        device_locations = DeviceLocation.objects.filter(
            office=office, state="active"
        ).select_related("device")
        with transaction.atomic():
            append_audit(
                action=AuditEntry.Action.RECORD_VIEW,
                actor_type=AuditEntry.ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=_active_session(request),
                source_ip=_source_ip(request),
                target_table="office",
                target_id=str(office.pk),
                target_label=str(office),
            )
        return render(
            request,
            "inventory/office_detail.html",
            {
                "office": office,
                "custom_fields": custom_fields,
                "viewer": viewer,
                "memberships": memberships,
                "device_locations": device_locations,
            },
        )


class OfficeCreateView(View):
    @require_admin
    def get(self, request):
        form = OfficeForm()
        custom_fields = _custom_fields_for("office", False)
        return render(
            request,
            "inventory/office_form.html",
            {"form": form, "custom_fields": custom_fields, "action": "Crear"},
        )

    @require_admin
    def post(self, request):
        form = OfficeForm(request.POST)
        custom_fields = _custom_fields_for("office", False)
        if form.is_valid():
            with transaction.atomic():
                office = form.save(commit=False)
                office.created_by = request.operator
                office.updated_by = request.operator
                office.save()
                _save_custom_fields(request, office, "office")
                append_audit(
                    action=AuditEntry.Action.CREATE,
                    actor_type=AuditEntry.ActorType.OPERATOR,
                    actor_operator=request.operator,
                    actor_username=request.operator.username,
                    session=_active_session(request),
                    source_ip=_source_ip(request),
                    target_table="office",
                    target_id=str(office.pk),
                    target_label=str(office),
                    changes={"name": office.name},
                )
            return redirect("office-detail", pk=office.pk)
        return render(
            request,
            "inventory/office_form.html",
            {"form": form, "custom_fields": custom_fields, "action": "Crear"},
        )


class OfficeEditView(View):
    @require_admin
    def get(self, request, pk):
        office = get_object_or_404(Office, pk=pk)
        form = OfficeForm(instance=office)
        custom_fields = _custom_fields_for("office", False)
        return render(
            request,
            "inventory/office_form.html",
            {"form": form, "office": office, "custom_fields": custom_fields, "action": "Editar"},
        )

    @require_admin
    def post(self, request, pk):
        office = get_object_or_404(Office, pk=pk)
        form = OfficeForm(request.POST, instance=office)
        custom_fields = _custom_fields_for("office", False)
        if form.is_valid():
            with transaction.atomic():
                office = form.save(commit=False)
                office.updated_by = request.operator
                office.save()
                _save_custom_fields(request, office, "office")
                append_audit(
                    action=AuditEntry.Action.UPDATE,
                    actor_type=AuditEntry.ActorType.OPERATOR,
                    actor_operator=request.operator,
                    actor_username=request.operator.username,
                    session=_active_session(request),
                    source_ip=_source_ip(request),
                    target_table="office",
                    target_id=str(office.pk),
                    target_label=str(office),
                    changes={"fields": list(form.changed_data)},
                )
            return redirect("office-detail", pk=office.pk)
        return render(
            request,
            "inventory/office_form.html",
            {"form": form, "office": office, "custom_fields": custom_fields, "action": "Editar"},
        )


# ---------------------------------------------------------------------------
# State transition view
# ---------------------------------------------------------------------------

_MODEL_MAP = {
    "person": (Person, "person"),
    "account": (Account, "account"),
    "device": (Device, "device"),
    "office": (Office, "office"),
}

_DETAIL_URLS = {
    "person": "person-detail",
    "account": "account-detail",
    "device": "device-detail",
    "office": "office-detail",
}


class StateTransitionView(View):
    @require_admin
    def post(self, request, pk, model=None):
        if model not in _MODEL_MAP:
            return HttpResponse("Unknown model", status=400)

        model_cls, table_name = _MODEL_MAP[model]
        entity = get_object_or_404(model_cls, pk=pk)

        # Parse new_state from POST or JSON body
        try:
            if request.content_type and "json" in request.content_type:
                body = json.loads(request.body)
                new_state = body.get("new_state", "")
            else:
                new_state = request.POST.get("new_state", "")
        except (json.JSONDecodeError, ValueError):
            return HttpResponse("Invalid JSON", status=400)

        if not new_state:
            return HttpResponse("new_state is required", status=400)

        old_state = entity.state
        terminal = _TERMINAL_STATES.get(model, set())

        # Cannot leave terminal state
        if old_state in terminal:
            return HttpResponse(f"Cannot transition from terminal state '{old_state}'.", status=400)

        # Validate new_state is a valid choice for this model
        valid_states = [c[0] for c in entity._meta.get_field("state").choices]
        if new_state not in valid_states:
            return HttpResponse(
                f"Invalid state '{new_state}'. Valid: {', '.join(valid_states)}", status=400
            )

        with transaction.atomic():
            entity.state = new_state
            entity.updated_by = request.operator
            entity.save(update_fields=["state", "updated_by", "updated_at"])
            append_audit(
                action=AuditEntry.Action.STATE_CHANGE,
                actor_type=AuditEntry.ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=_active_session(request),
                source_ip=_source_ip(request),
                target_table=table_name,
                target_id=str(entity.pk),
                target_label=str(entity),
                changes={"old_state": old_state, "new_state": new_state},
            )

        if _is_htmx(request):
            response = HttpResponse("", status=200)
            response["HX-Refresh"] = "true"
            return response

        return redirect(_DETAIL_URLS[model], pk=pk)


# ---------------------------------------------------------------------------
# FieldDefinition views
# ---------------------------------------------------------------------------


class FieldDefinitionListView(View):
    @require_admin
    def get(self, request):
        field_defs = FieldDefinition.objects.order_by("entity_type", "display_order", "key")
        return render(request, "inventory/fielddefinition_list.html", {"field_defs": field_defs})


class FieldDefinitionCreateView(View):
    @require_admin
    def get(self, request):
        form = FieldDefinitionForm()
        return render(
            request, "inventory/fielddefinition_form.html", {"form": form, "action": "Crear"}
        )

    @require_admin
    def post(self, request):
        form = FieldDefinitionForm(request.POST)
        if form.is_valid():
            with transaction.atomic():
                fd = form.save()
                append_audit(
                    action=AuditEntry.Action.FIELD_DEFINITION_CHANGE,
                    actor_type=AuditEntry.ActorType.OPERATOR,
                    actor_operator=request.operator,
                    actor_username=request.operator.username,
                    session=_active_session(request),
                    source_ip=_source_ip(request),
                    target_table="field_definition",
                    target_id=str(fd.pk),
                    target_label=str(fd),
                    changes={"op": "create", "key": fd.key, "entity_type": fd.entity_type},
                )
            return redirect("fielddefinition-list")
        return render(
            request, "inventory/fielddefinition_form.html", {"form": form, "action": "Crear"}
        )


class FieldDefinitionEditView(View):
    @require_admin
    def get(self, request, pk):
        fd = get_object_or_404(FieldDefinition, pk=pk)
        form = FieldDefinitionForm(instance=fd)
        return render(
            request,
            "inventory/fielddefinition_form.html",
            {"form": form, "fd": fd, "action": "Editar"},
        )

    @require_admin
    def post(self, request, pk):
        fd = get_object_or_404(FieldDefinition, pk=pk)
        form = FieldDefinitionForm(request.POST, instance=fd)
        if form.is_valid():
            with transaction.atomic():
                fd = form.save()
                append_audit(
                    action=AuditEntry.Action.FIELD_DEFINITION_CHANGE,
                    actor_type=AuditEntry.ActorType.OPERATOR,
                    actor_operator=request.operator,
                    actor_username=request.operator.username,
                    session=_active_session(request),
                    source_ip=_source_ip(request),
                    target_table="field_definition",
                    target_id=str(fd.pk),
                    target_label=str(fd),
                    changes={"op": "update", "fields": list(form.changed_data)},
                )
            return redirect("fielddefinition-list")
        return render(
            request,
            "inventory/fielddefinition_form.html",
            {"form": form, "fd": fd, "action": "Editar"},
        )
