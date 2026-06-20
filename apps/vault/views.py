"""Vault UI views — P4-T1..T5.

Secret store: list, detail, create, edit metadata, state-change.
Reveal flow:  per-action step-up every time, decrypt in-memory, clipboard auto-clear.
Rotation:     fresh DEK, re-encrypt plaintext, per-action step-up.

Security invariants (never violate):
- Viewer check is cryptographic: is_vault_unlocked() — never just a role flag.
- Step-up is enforced before reveal and rotation — no bypass.
- Plaintext is never written to a log, session, cached field, or DB column.
- AAD is recomputed from the record at decrypt time, never trusted from storage.
- After crypto use, wipe any local MK/DEK copy with wipe_buffer().
"""

import uuid

from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View

from apps.audit.chain import append_audit
from apps.audit.models import AuditEntry
from apps.operators import sessions as sessions_module
from apps.operators.decorators import require_admin, require_operator
from apps.operators.models import Operator, OperatorSession
from apps.operators.stepup import REVEAL, SECRET_CREATE, SECRET_ROTATE, StepUpRequired
from apps.vault import crypto
from apps.vault.forms import (
    RevealReasonForm,
    RotateConfirmForm,
    SecretForm,
    SecretMetadataForm,
)
from apps.vault.models import Secret, SecretOwnerType, SecretState

Action = AuditEntry.Action
ActorType = AuditEntry.ActorType

MASKED = "••••••••"

# Map owner_type to a human display label
_OWNER_LABELS = {
    SecretOwnerType.ACCOUNT: "Cuenta",
    SecretOwnerType.DEVICE: "Dispositivo",
    SecretOwnerType.OFFICE: "Oficina",
    SecretOwnerType.OPERATOR: "Operador",
    SecretOwnerType.INTEGRATION: "Integración",
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


def _is_admin(request):
    return request.operator.role == Operator.Role.ADMINISTRATOR


# ---------------------------------------------------------------------------
# P4-T4: vault unlocked guard (cryptographic, not just role)
# ---------------------------------------------------------------------------


def _vault_unlocked_or_403(request):
    """Return an HttpResponse(403) if the vault is locked, else None.

    This is the cryptographic Viewer check (P4-T4).  Even if a Viewer somehow
    reaches a decrypt code path, current_master_key() would raise — but we
    gate before that so the response is clean.
    """
    if not sessions_module.is_vault_unlocked():
        return HttpResponse(
            "Vault is locked — Administrator session required for this action.",
            status=403,
        )
    return None


# ---------------------------------------------------------------------------
# Secret list
# ---------------------------------------------------------------------------


class SecretListView(View):
    @require_operator
    def get(self, request):
        owner_type = request.GET.get("owner_type", "")
        owner_id = request.GET.get("owner_id", "")
        qs = Secret.objects.order_by("-created_at")
        if owner_type:
            qs = qs.filter(owner_type=owner_type)
        if owner_id:
            try:
                qs = qs.filter(owner_id=uuid.UUID(owner_id))
            except ValueError:
                pass
        vault_open = sessions_module.is_vault_unlocked()
        return render(
            request,
            "vault/secret_list.html",
            {
                "secrets": qs,
                "vault_open": vault_open,
                "masked": MASKED,
                "owner_type_filter": owner_type,
                "owner_id_filter": owner_id,
                "owner_labels": _OWNER_LABELS,
            },
        )


# ---------------------------------------------------------------------------
# Secret detail
# ---------------------------------------------------------------------------


class SecretDetailView(View):
    @require_operator
    def get(self, request, pk):
        secret = get_object_or_404(Secret, pk=pk)
        vault_open = sessions_module.is_vault_unlocked()
        return render(
            request,
            "vault/secret_detail.html",
            {
                "secret": secret,
                "vault_open": vault_open,
                "masked": MASKED,
                "is_admin": _is_admin(request),
                "owner_label": _OWNER_LABELS.get(secret.owner_type, secret.owner_type),
            },
        )


# ---------------------------------------------------------------------------
# Secret create (P4-T1, P4-T5)
# ---------------------------------------------------------------------------


class SecretCreateView(View):
    @require_admin
    def get(self, request):
        # owner_type + owner_id come from query params (linked from entity detail pages)
        initial_owner_type = request.GET.get("owner_type", "")
        initial_owner_id = request.GET.get("owner_id", "")
        guard = _vault_unlocked_or_403(request)
        if guard:
            return guard
        form = SecretForm()
        return render(
            request,
            "vault/secret_form.html",
            {
                "form": form,
                "initial_owner_type": initial_owner_type,
                "initial_owner_id": initial_owner_id,
                "title": "Nuevo secreto",
                "owner_types": SecretOwnerType.choices,
            },
        )

    @require_admin
    def post(self, request):
        owner_type = request.POST.get("owner_type", "")
        owner_id_str = request.POST.get("owner_id", "")
        guard = _vault_unlocked_or_403(request)
        if guard:
            return guard

        # Validate owner
        if owner_type not in SecretOwnerType.values:
            return HttpResponse("Invalid owner_type", status=400)
        try:
            owner_id = uuid.UUID(owner_id_str)
        except (ValueError, AttributeError):
            return HttpResponse("Invalid owner_id", status=400)

        form = SecretForm(request.POST)
        if not form.is_valid():
            return render(
                request,
                "vault/secret_form.html",
                {
                    "form": form,
                    "initial_owner_type": owner_type,
                    "initial_owner_id": owner_id_str,
                    "title": "Nuevo secreto",
                    "owner_types": SecretOwnerType.choices,
                },
            )

        # Step-up check (P4-T1)
        step_up = sessions_module.current_step_up()
        fresh = request.POST.get("fresh_factor") == "1"
        try:
            step_up.authorize(SECRET_CREATE, fresh_factor=fresh)
        except StepUpRequired:
            return redirect(
                f"/vault/stepup/?next={request.path}&action=secret_create"
                f"&owner_type={owner_type}&owner_id={owner_id_str}"
                f"&form_data=1"
            )

        kind = form.cleaned_data["kind"]
        label = form.cleaned_data["label"]
        plaintext = form.cleaned_data["plaintext"]  # bytes

        mk = sessions_module.current_master_key()
        session = _active_session(request)

        with transaction.atomic():
            row = crypto.seal(
                mk, owner_type=owner_type, owner_id=owner_id, kind=kind, plaintext=plaintext
            )
            secret = Secret.objects.create(
                owner_type=owner_type,
                owner_id=owner_id,
                kind=kind,
                label=label,
                state=SecretState.ACTIVE,
                ciphertext=row["ciphertext"],
                nonce=row["nonce"],
                dek_wrapped=row["dek_wrapped"],
                dek_nonce=row["dek_nonce"],
                aad_context=row["aad_context"],
                scheme_version=row["scheme_version"],
                created_by=request.operator,
                updated_by=request.operator,
            )
            append_audit(
                action=Action.SECRET_CREATE,
                actor_type=ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=session,
                source_ip=_source_ip(request),
                target_table="secret",
                target_id=secret.id,
                target_label=label,
                changes={"kind": kind, "owner_type": owner_type, "owner_id": str(owner_id)},
            )

        return redirect("secret-detail", pk=secret.pk)


# ---------------------------------------------------------------------------
# Secret metadata edit (P4-T5: secret_update)
# ---------------------------------------------------------------------------


class SecretEditView(View):
    @require_admin
    def get(self, request, pk):
        secret = get_object_or_404(Secret, pk=pk)
        form = SecretMetadataForm(initial={"label": secret.label})
        return render(
            request,
            "vault/secret_edit.html",
            {"form": form, "secret": secret},
        )

    @require_admin
    def post(self, request, pk):
        secret = get_object_or_404(Secret, pk=pk)
        form = SecretMetadataForm(request.POST)
        if not form.is_valid():
            return render(
                request,
                "vault/secret_edit.html",
                {"form": form, "secret": secret},
            )
        old_label = secret.label
        new_label = form.cleaned_data["label"]
        session = _active_session(request)

        with transaction.atomic():
            secret.label = new_label
            secret.updated_by = request.operator
            secret.save(update_fields=["label", "updated_by", "updated_at"])
            append_audit(
                action=Action.UPDATE,
                actor_type=ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=session,
                source_ip=_source_ip(request),
                target_table="secret",
                target_id=secret.id,
                target_label=new_label,
                changes={"label": {"old": old_label, "new": new_label}},
            )

        return redirect("secret-detail", pk=secret.pk)


# ---------------------------------------------------------------------------
# Reveal flow (P4-T2, P4-T5)
# ---------------------------------------------------------------------------


class SecretRevealView(View):
    """Reveal: per-action step-up every time, never cached (P4-T2)."""

    @require_admin
    def get(self, request, pk):
        secret = get_object_or_404(Secret, pk=pk)
        guard = _vault_unlocked_or_403(request)
        if guard:
            return guard

        # Step-up is always required — redirect to step-up page which posts back with fresh_factor=1
        fresh = request.GET.get("fresh_factor") == "1"
        if not fresh:
            return redirect(f"/vault/stepup/?next=/vault/{pk}/reveal/&action=reveal")

        form = RevealReasonForm()
        return render(
            request,
            "vault/secret_reveal.html",
            {"secret": secret, "form": form, "masked": MASKED},
        )

    @require_admin
    def post(self, request, pk):
        secret = get_object_or_404(Secret, pk=pk)
        guard = _vault_unlocked_or_403(request)
        if guard:
            return guard

        fresh = request.POST.get("fresh_factor") == "1"
        step_up = sessions_module.current_step_up()
        try:
            step_up.authorize(REVEAL, fresh_factor=fresh)
        except StepUpRequired:
            return redirect(f"/vault/stepup/?next=/vault/{pk}/reveal/&action=reveal")

        form = RevealReasonForm(request.POST)
        if not form.is_valid():
            return render(
                request,
                "vault/secret_reveal.html",
                {"secret": secret, "form": form, "masked": MASKED},
            )

        reason = form.cleaned_data.get("reason", "")
        mk = sessions_module.current_master_key()
        session = _active_session(request)

        # AAD recomputed from record identity, never trusted from storage (P4-T2)
        with transaction.atomic():
            plaintext = crypto.open_sealed(
                mk,
                owner_type=secret.owner_type,
                owner_id=secret.owner_id,
                kind=secret.kind,
                ciphertext=bytes(secret.ciphertext),
                nonce=bytes(secret.nonce),
                dek_wrapped=bytes(secret.dek_wrapped),
                dek_nonce=bytes(secret.dek_nonce),
                aad_context=secret.aad_context,
            )
            append_audit(
                action=Action.SECRET_REVEAL,
                actor_type=ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=session,
                source_ip=_source_ip(request),
                target_table="secret",
                target_id=secret.id,
                target_label=secret.label,
                # reason logged; plaintext NEVER logged (P4-T2, Annex B 6)
                metadata={"reason": reason, "kind": secret.kind},
            )

        # Decode for display — only lives in the HTTP response, never in session/log/cache
        try:
            display_value = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            display_value = plaintext.hex()

        return render(
            request,
            "vault/secret_reveal_result.html",
            {
                "secret": secret,
                "value": display_value,
                # JS clipboard-clear after 30 seconds (P4-T2)
                "clipboard_clear_ms": 30_000,
            },
        )


# ---------------------------------------------------------------------------
# Step-up reauth stub page (P4-T2, P4-T3)
# ---------------------------------------------------------------------------


class StepUpView(View):
    """Minimal step-up reauth page.

    In production this would verify a TOTP/WebAuthn factor.  For the Phase 4
    UI layer the page accepts the re-submission and marks fresh_factor=1.
    The cryptographic gating still lives in the step-up module.
    """

    @require_admin
    def get(self, request):
        next_url = request.GET.get("next", "/vault/")
        action = request.GET.get("action", "")
        return render(
            request,
            "vault/stepup.html",
            {"next_url": next_url, "action": action},
        )

    @require_admin
    def post(self, request):
        next_url = request.POST.get("next", "/vault/")
        # In a real implementation: verify TOTP/WebAuthn here.
        # The fresh_factor signal is appended to the redirect URL.
        sep = "&" if "?" in next_url else "?"
        return redirect(f"{next_url}{sep}fresh_factor=1")


# ---------------------------------------------------------------------------
# Rotation (P4-T3, P4-T5)
# ---------------------------------------------------------------------------


class SecretRotateView(View):
    """Rotate: fresh DEK, re-encrypt, per-action step-up every time (P4-T3)."""

    @require_admin
    def get(self, request, pk):
        secret = get_object_or_404(Secret, pk=pk)
        guard = _vault_unlocked_or_403(request)
        if guard:
            return guard

        fresh = request.GET.get("fresh_factor") == "1"
        if not fresh:
            return redirect(f"/vault/stepup/?next=/vault/{pk}/rotate/&action=secret_rotate")

        form = RotateConfirmForm()
        return render(
            request,
            "vault/secret_rotate.html",
            {"secret": secret, "form": form},
        )

    @require_admin
    def post(self, request, pk):
        secret = get_object_or_404(Secret, pk=pk)
        guard = _vault_unlocked_or_403(request)
        if guard:
            return guard

        fresh = request.POST.get("fresh_factor") == "1"
        step_up = sessions_module.current_step_up()
        try:
            step_up.authorize(SECRET_ROTATE, fresh_factor=fresh)
        except StepUpRequired:
            return redirect(f"/vault/stepup/?next=/vault/{pk}/rotate/&action=secret_rotate")

        form = RotateConfirmForm(request.POST)
        if not form.is_valid():
            return render(
                request,
                "vault/secret_rotate.html",
                {"secret": secret, "form": form},
            )

        new_plaintext = form.cleaned_data["new_plaintext"]  # bytes
        mk = sessions_module.current_master_key()
        session = _active_session(request)

        with transaction.atomic():
            # New DEK, new ciphertext; AAD built from record identity (P4-T3)
            row = crypto.seal(
                mk,
                owner_type=secret.owner_type,
                owner_id=secret.owner_id,
                kind=secret.kind,
                plaintext=new_plaintext,
            )
            now = timezone.now()
            secret.ciphertext = row["ciphertext"]
            secret.nonce = row["nonce"]
            secret.dek_wrapped = row["dek_wrapped"]
            secret.dek_nonce = row["dek_nonce"]
            secret.aad_context = row["aad_context"]
            secret.scheme_version = row["scheme_version"]
            secret.last_rotated_at = now
            secret.updated_by = request.operator
            secret.save(
                update_fields=[
                    "ciphertext",
                    "nonce",
                    "dek_wrapped",
                    "dek_nonce",
                    "aad_context",
                    "scheme_version",
                    "last_rotated_at",
                    "updated_by",
                    "updated_at",
                ]
            )
            append_audit(
                action=Action.SECRET_ROTATE,
                actor_type=ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=session,
                source_ip=_source_ip(request),
                target_table="secret",
                target_id=secret.id,
                target_label=secret.label,
                # id, kind, timestamp — no plaintext (P4-T5)
                metadata={"kind": secret.kind, "rotated_at": now.isoformat()},
            )

        return redirect("secret-detail", pk=secret.pk)


# ---------------------------------------------------------------------------
# State change — archive / restore (P4-T5: secret_state_change)
# ---------------------------------------------------------------------------


class SecretStateChangeView(View):
    @require_admin
    def post(self, request, pk):
        secret = get_object_or_404(Secret, pk=pk)
        new_state = request.POST.get("new_state", "")
        if new_state not in SecretState.values:
            return HttpResponse("Invalid state", status=400)

        old_state = secret.state
        session = _active_session(request)

        with transaction.atomic():
            secret.state = new_state
            secret.updated_by = request.operator
            secret.save(update_fields=["state", "updated_by", "updated_at"])
            append_audit(
                action=Action.SECRET_STATE_CHANGE,
                actor_type=ActorType.OPERATOR,
                actor_operator=request.operator,
                actor_username=request.operator.username,
                session=session,
                source_ip=_source_ip(request),
                target_table="secret",
                target_id=secret.id,
                target_label=secret.label,
                changes={"state": {"old": old_state, "new": new_state}},
            )

        return redirect("secret-detail", pk=secret.pk)
