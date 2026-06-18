"""P1-T2 acceptance tests (Annex C 2, 3, 4, 9).

Brief acceptance criteria:
- migrations apply clean (covered by the test DB build itself)
- a CHECK rejects an invalid enum value
- created_by FK targets operator

Plus coverage of UUID PKs, native types, the 1:1 network detail, the
polymorphic secret, and the partial-uniqueness-adjacent unique constraints.
"""

import uuid

import pytest
from django.db import IntegrityError, transaction

from apps.inventory.models import (
    Account,
    Device,
    FieldDefinition,
    NetworkDeviceDetail,
    Office,
    Person,
)
from apps.operators.models import Operator, OperatorWebAuthnCredential
from apps.vault.models import Secret


@pytest.fixture
def operator(db):
    return Operator.objects.create(
        username="admin",
        display_name="Admin",
        role=Operator.Role.ADMINISTRATOR,
        password_hash="placeholder-set-in-p1-t15",
    )


# --- UUID primary keys ----------------------------------------------------


@pytest.mark.django_db
def test_entities_have_uuid_pk(operator):
    p = Person.objects.create(full_name="Ana", created_by=operator, updated_by=operator)
    assert isinstance(p.id, uuid.UUID)
    assert isinstance(operator.id, uuid.UUID)


# --- created_by / updated_by reference operator, never person -------------


@pytest.mark.parametrize("model", [Person, Account, Device, Office, Secret])
def test_audit_fks_target_operator(model):
    assert model._meta.get_field("created_by").related_model is Operator
    assert model._meta.get_field("updated_by").related_model is Operator


# --- CHECK constraints reject invalid enum values -------------------------


@pytest.mark.django_db
def test_invalid_person_state_rejected_by_check(operator):
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            Person.objects.create(
                full_name="Bad",
                state="not_a_state",
                created_by=operator,
                updated_by=operator,
            )


@pytest.mark.django_db
def test_invalid_account_type_rejected_by_check(operator):
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            Account.objects.create(
                account_type="not_a_type",
                label="x",
                identifier="x@example.com",
                created_by=operator,
                updated_by=operator,
            )


@pytest.mark.django_db
def test_invalid_secret_kind_rejected_by_check(operator):
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            Secret.objects.create(
                owner_type=Secret.OwnerType.ACCOUNT,
                owner_id=uuid.uuid4(),
                kind="not_a_kind",
                ciphertext=b"\x00",
                nonce=b"\x00",
                dek_wrapped=b"\x00",
                dek_nonce=b"\x00",
                aad_context="account:x:password",
                created_by=operator,
                updated_by=operator,
            )


@pytest.mark.django_db
def test_valid_enum_values_accepted(operator):
    a = Account.objects.create(
        account_type=Account.Type.GOOGLE,
        label="Gmail",
        identifier="ops@example.com",
        mfa_state=Account.MfaState.ENABLED,
        mfa_types=[Account.MfaType.AUTHENTICATOR_APP, Account.MfaType.PASSKEY],
        created_by=operator,
        updated_by=operator,
    )
    a.refresh_from_db()
    assert a.state == Account.State.ACTIVE
    assert a.mfa_types == ["authenticator_app", "passkey"]


# --- Native PostgreSQL types ---------------------------------------------


@pytest.mark.django_db
def test_device_macaddr_and_inet_arrays_round_trip(operator):
    d = Device.objects.create(
        device_type=Device.Type.LAPTOP,
        hostname="lt-01",
        mac_addresses=["08:00:2b:01:02:03"],
        ip_addresses=["10.0.0.5", "192.168.1.20"],
        created_by=operator,
        updated_by=operator,
    )
    d.refresh_from_db()
    assert d.mac_addresses == ["08:00:2b:01:02:03"]
    assert d.ip_addresses == ["10.0.0.5", "192.168.1.20"]


# --- 1:1 network detail and polymorphic secret ---------------------------


@pytest.mark.django_db
def test_network_device_detail_is_one_to_one(operator):
    d = Device.objects.create(
        device_type=Device.Type.FIREWALL,
        hostname="fw-01",
        created_by=operator,
        updated_by=operator,
    )
    detail = NetworkDeviceDetail.objects.create(
        device=d,
        monitoring_method=NetworkDeviceDetail.MonitoringMethod.SNMP,
        health_state=NetworkDeviceDetail.HealthState.REACHABLE,
    )
    assert detail.pk == d.pk
    assert d.network_detail == detail


@pytest.mark.django_db
def test_secret_stores_only_bytes_no_plaintext_column(operator):
    s = Secret.objects.create(
        owner_type=Secret.OwnerType.DEVICE,
        owner_id=uuid.uuid4(),
        kind=Secret.Kind.SNMP_COMMUNITY,
        ciphertext=b"\x01\x02\x03",
        nonce=b"\x00" * 24,
        dek_wrapped=b"\x04\x05",
        dek_nonce=b"\x00" * 24,
        aad_context="device:x:snmp_community",
        created_by=operator,
        updated_by=operator,
    )
    field_names = {f.name for f in Secret._meta.get_fields()}
    # There is no column that could hold plaintext.
    assert "plaintext" not in field_names
    assert "value" not in field_names
    assert s.scheme_version == 1


# --- Unique constraints ---------------------------------------------------


@pytest.mark.django_db
def test_field_definition_entity_key_unique():
    FieldDefinition.objects.create(
        entity_type=FieldDefinition.EntityType.DEVICE,
        key="imei",
        label="IMEI",
        data_type=FieldDefinition.DataType.STRING,
    )
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            FieldDefinition.objects.create(
                entity_type=FieldDefinition.EntityType.DEVICE,
                key="imei",
                label="IMEI duplicate",
                data_type=FieldDefinition.DataType.STRING,
            )


@pytest.mark.django_db
def test_webauthn_credential_id_unique(operator):
    OperatorWebAuthnCredential.objects.create(
        operator=operator, credential_id=b"cred-1", public_key=b"pk-1"
    )
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            OperatorWebAuthnCredential.objects.create(
                operator=operator, credential_id=b"cred-1", public_key=b"pk-2"
            )
