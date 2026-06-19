"""Phase 1 thin vertical slice (Annex I 3).

End-to-end happy path that proves the security spine composes: one login, one
entity create, one secret stored and revealed, each writing the right audit
entry into the tamper-evident chain — and the chain still verifies.

This is the service-layer slice; the HTMX UI is Phase 3. Every data change here
appends its audit entry in the SAME transaction (P1-T12), logs only
non-sensitive facts (never plaintext/ciphertext), and gates secret actions
behind step-up reauth (P1-T17) and the in-memory MK (P1-T8/T16).
"""

from django.db import transaction

from apps.audit.chain import append_audit
from apps.audit.models import AuditEntry
from apps.inventory.models import Person
from apps.operators import auth, sessions, stepup
from apps.operators.models import Operator
from apps.vault import crypto, key_holders
from apps.vault.models import Secret

Action = AuditEntry.Action
ActorType = AuditEntry.ActorType


class AuthFailed(Exception):
    """Login failed (password or second factor)."""


def login(
    *,
    operator: Operator,
    password: str,
    totp_code: str,
    second_factor: bytes,
    passphrase: bytes | None = None,
):
    """Authenticate (password + TOTP), unlock the vault for an Administrator,
    establish the single session, and log login_success (+ vault_unlock).

    Returns (session, raw_token). Local only — no Microsoft 365 dependency.
    """
    if not auth.check_password(operator, password):
        raise AuthFailed("bad password")
    if not auth.verify_totp(operator, totp_code, second_factor):
        raise AuthFailed("bad second factor")

    if operator.role == Operator.Role.ADMINISTRATOR:
        if passphrase is None:
            raise AuthFailed("administrator login requires the vault passphrase")
        mk = key_holders.unlock_with_holder(operator, passphrase, second_factor)
        session, token = sessions.establish_session(
            operator=operator, ip="127.0.0.1", mk=bytearray(mk)
        )
    else:
        session, token = sessions.establish_session(operator=operator, ip="127.0.0.1")

    with transaction.atomic():
        append_audit(
            action=Action.LOGIN_SUCCESS,
            actor_type=ActorType.OPERATOR,
            actor_operator=operator,
            actor_username=operator.username,
            session=session,
            source_ip=session.ip,
        )
        if operator.role == Operator.Role.ADMINISTRATOR:
            append_audit(
                action=Action.VAULT_UNLOCK,
                actor_type=ActorType.OPERATOR,
                actor_operator=operator,
                actor_username=operator.username,
                session=session,
                source_ip=session.ip,
            )
    return session, token


def create_person(*, operator: Operator, session, full_name: str) -> Person:
    """Create a Person and log the change in the same transaction."""
    with transaction.atomic():
        person = Person.objects.create(
            full_name=full_name, created_by=operator, updated_by=operator
        )
        append_audit(
            action=Action.CREATE,
            actor_type=ActorType.OPERATOR,
            actor_operator=operator,
            actor_username=operator.username,
            session=session,
            source_ip=session.ip,
            target_table="person",
            target_id=person.id,
            target_label=full_name,
            changes={"full_name": full_name, "state": person.state},
        )
    return person


def store_secret(
    *,
    operator: Operator,
    session,
    owner_type: str,
    owner_id,
    kind: str,
    plaintext: bytes,
    label: str = "",
    fresh_factor: bool,
) -> Secret:
    """Encrypt + store a secret under the session MK, gated by per-action step-up,
    and log secret_create (non-sensitive facts only) in the same transaction."""
    sessions.current_step_up().authorize(stepup.SECRET_CREATE, fresh_factor=fresh_factor)
    mk = sessions.current_master_key()  # raises if locked / Viewer (keyless)
    with transaction.atomic():
        row = crypto.seal(
            mk, owner_type=owner_type, owner_id=owner_id, kind=kind, plaintext=plaintext
        )
        secret = Secret.objects.create(
            owner_type=owner_type,
            owner_id=owner_id,
            kind=kind,
            label=label,
            ciphertext=row["ciphertext"],
            nonce=row["nonce"],
            dek_wrapped=row["dek_wrapped"],
            dek_nonce=row["dek_nonce"],
            aad_context=row["aad_context"],
            scheme_version=row["scheme_version"],
            created_by=operator,
            updated_by=operator,
        )
        append_audit(
            action=Action.SECRET_CREATE,
            actor_type=ActorType.OPERATOR,
            actor_operator=operator,
            actor_username=operator.username,
            session=session,
            source_ip=session.ip,
            target_table="secret",
            target_id=secret.id,
            target_label=label,
            # Non-sensitive facts only (Annex B 6): never the plaintext/ciphertext.
            changes={"kind": kind, "owner_type": owner_type, "owner_id": str(owner_id)},
        )
    return secret


def reveal_secret(
    *, operator: Operator, session, secret: Secret, reason: str, fresh_factor: bool
) -> bytes:
    """Reveal a secret: per-action step-up (every time), decrypt with the session
    MK, and log secret_reveal with the reason (never the value)."""
    sessions.current_step_up().authorize(stepup.REVEAL, fresh_factor=fresh_factor)
    mk = sessions.current_master_key()  # Viewer has no MK -> raises
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
            actor_operator=operator,
            actor_username=operator.username,
            session=session,
            source_ip=session.ip,
            target_table="secret",
            target_id=secret.id,
            metadata={"reason": reason},  # the reason is logged; the value is NEVER logged
        )
    return plaintext
