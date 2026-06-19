"""Operator authentication views — login, vault install/unlock, logout.

Login is two steps for Administrators:
  1. /auth/login/          — username + password + TOTP
  2. /auth/vault/install/  — (first login only) set + confirm vault passphrase
     /auth/vault/passphrase/ — (subsequent logins) enter vault passphrase

Viewers complete login in one step (no vault passphrase — keyless by design).

Security invariants:
- Passphrase is never stored; it is held in memory only for the duration of
  the Argon2id derivation, then wiped.
- The master key never touches the Django session, disk, or logs.
- A pending_operator_id in the Django session is cleared on completion or
  failure — it grants no privilege by itself.
"""

from django.shortcuts import redirect, render
from django.views import View
from django.views.decorators.http import require_POST

from apps.audit.chain import append_audit
from apps.audit.models import AuditEntry
from apps.operators import sessions as sessions_module
from apps.operators.auth import check_password, verify_totp
from apps.operators.decorators import require_operator
from apps.operators.models import Operator, OperatorSession
from apps.vault import key_holders
from apps.vault.kdf import DEV_PARAMS
from apps.vault.models import VaultKeyHolder
from apps.vault.second_factor import KeyfileSecondFactor, SecondFactorUnavailable, load_second_factor

Action = AuditEntry.Action
ActorType = AuditEntry.ActorType


def _source_ip(request):
    return request.META.get("REMOTE_ADDR", "unknown")


def _get_second_factor() -> bytes:
    try:
        return load_second_factor().get_secret()
    except SecondFactorUnavailable as exc:
        raise SecondFactorUnavailable(str(exc)) from exc


def _active_session(operator):
    return (
        OperatorSession.objects.filter(operator=operator, revoked_at__isnull=True)
        .order_by("-created_at")
        .first()
    )


def _log_login(operator, session):
    append_audit(
        action=Action.LOGIN_SUCCESS,
        actor_type=ActorType.OPERATOR,
        actor_operator=operator,
        actor_username=operator.username,
        session=session,
        source_ip=session.ip,
    )


def _log_vault_unlock(operator, session):
    append_audit(
        action=Action.VAULT_UNLOCK,
        actor_type=ActorType.OPERATOR,
        actor_operator=operator,
        actor_username=operator.username,
        session=session,
        source_ip=session.ip,
    )


def _finalize_session(request, operator, session, token):
    """Store session identifiers in the Django session cookie."""
    request.session["operator_id"] = str(operator.id)
    request.session["session_token"] = token
    request.session.pop("_pending_operator_id", None)


class LoginView(View):
    template = "operators/login.html"

    def get(self, request):
        if request.session.get("operator_id"):
            return redirect("/")
        return render(request, self.template)

    def post(self, request):
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        totp_code = request.POST.get("totp_code", "").strip()

        try:
            operator = Operator.objects.get(username=username)
        except Operator.DoesNotExist:
            return render(request, self.template, {"error": "Credenciales incorrectas."})

        if not operator.is_active:
            return render(request, self.template, {"error": "Operador inactivo."})

        if not check_password(operator, password):
            return render(request, self.template, {"error": "Credenciales incorrectas."})

        try:
            second_factor = _get_second_factor()
        except SecondFactorUnavailable as exc:
            return render(request, self.template, {"error": f"Segundo factor no disponible: {exc}"})

        if not verify_totp(operator, totp_code, second_factor):
            return render(request, self.template, {"error": "Código TOTP incorrecto."})

        if operator.role == Operator.Role.VIEWER:
            session, token = sessions_module.establish_session(operator=operator, ip=_source_ip(request))
            _log_login(operator, session)
            _finalize_session(request, operator, session, token)
            return redirect("/")

        # Administrator: proceed to vault step
        request.session["_pending_operator_id"] = str(operator.id)
        has_holder = VaultKeyHolder.objects.filter(operator=operator).exists()
        if not has_holder:
            return redirect("/auth/vault/install/")
        return redirect("/auth/vault/passphrase/")


class VaultInstallView(View):
    """First-time vault setup: generate MK, wrap under admin's KWK, establish session."""

    template = "operators/vault_install.html"

    def _get_pending_operator(self, request):
        op_id = request.session.get("_pending_operator_id")
        if not op_id:
            return None
        try:
            return Operator.objects.get(pk=op_id, role=Operator.Role.ADMINISTRATOR, is_active=True)
        except Operator.DoesNotExist:
            return None

    def get(self, request):
        if not request.session.get("_pending_operator_id"):
            return redirect("/auth/login/")
        return render(request, self.template)

    def post(self, request):
        operator = self._get_pending_operator(request)
        if operator is None:
            return redirect("/auth/login/")

        passphrase = request.POST.get("passphrase", "")
        passphrase_confirm = request.POST.get("passphrase_confirm", "")

        if not passphrase:
            return render(request, self.template, {"error": "La frase de contraseña no puede estar vacía."})
        if passphrase != passphrase_confirm:
            return render(request, self.template, {"error": "Las frases de contraseña no coinciden."})
        if len(passphrase) < 12:
            return render(request, self.template, {"error": "La frase de contraseña debe tener al menos 12 caracteres."})

        try:
            second_factor = _get_second_factor()
        except SecondFactorUnavailable as exc:
            return render(request, self.template, {"error": f"Segundo factor no disponible: {exc}"})

        passphrase_bytes = bytearray(passphrase.encode("utf-8"))
        try:
            _holder, mk = key_holders.install_vault(
                operator=operator,
                passphrase=bytes(passphrase_bytes),
                second_factor=second_factor,
                params=DEV_PARAMS,
                second_factor_ref="keyfile",
            )
        finally:
            for i in range(len(passphrase_bytes)):
                passphrase_bytes[i] = 0

        mk_buf = bytearray(mk)
        session, token = sessions_module.establish_session(
            operator=operator, ip=_source_ip(request), mk=mk_buf
        )
        from django.db import transaction
        with transaction.atomic():
            _log_login(operator, session)
            _log_vault_unlock(operator, session)

        _finalize_session(request, operator, session, token)
        return redirect("/")


class VaultPassphraseView(View):
    """Subsequent admin logins: derive KWK, unwrap MK, establish session."""

    template = "operators/vault_passphrase.html"

    def _get_pending_operator(self, request):
        op_id = request.session.get("_pending_operator_id")
        if not op_id:
            return None
        try:
            return Operator.objects.get(pk=op_id, role=Operator.Role.ADMINISTRATOR, is_active=True)
        except Operator.DoesNotExist:
            return None

    def get(self, request):
        if not request.session.get("_pending_operator_id"):
            return redirect("/auth/login/")
        return render(request, self.template)

    def post(self, request):
        operator = self._get_pending_operator(request)
        if operator is None:
            return redirect("/auth/login/")

        passphrase = request.POST.get("passphrase", "")
        if not passphrase:
            return render(request, self.template, {"error": "Ingrese la frase de contraseña."})

        try:
            second_factor = _get_second_factor()
        except SecondFactorUnavailable as exc:
            return render(request, self.template, {"error": f"Segundo factor no disponible: {exc}"})

        passphrase_bytes = bytearray(passphrase.encode("utf-8"))
        try:
            mk = key_holders.unlock_with_holder(operator, bytes(passphrase_bytes), second_factor)
        except Exception:
            return render(request, self.template, {"error": "Frase de contraseña incorrecta."})
        finally:
            for i in range(len(passphrase_bytes)):
                passphrase_bytes[i] = 0

        mk_buf = bytearray(mk)
        session, token = sessions_module.establish_session(
            operator=operator, ip=_source_ip(request), mk=mk_buf
        )
        from django.db import transaction
        with transaction.atomic():
            _log_login(operator, session)
            _log_vault_unlock(operator, session)

        _finalize_session(request, operator, session, token)
        return redirect("/")


@require_POST
@require_operator
def logout_view(request):
    op_id = request.session.get("operator_id")
    if op_id:
        session = _active_session(request.operator)
        if session:
            from django.db import transaction
            with transaction.atomic():
                append_audit(
                    action=Action.LOGOUT,
                    actor_type=ActorType.OPERATOR,
                    actor_operator=request.operator,
                    actor_username=request.operator.username,
                    session=session,
                    source_ip=_source_ip(request),
                )
            sessions_module.logout(session)
    request.session.flush()
    return redirect("/auth/login/")
