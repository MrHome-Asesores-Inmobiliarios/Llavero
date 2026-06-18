"""Core inventory entities (Annex C 4.4-4.8, 4.10).

Person, Account, Device, Office carry the full base mixin (BaseEntity).
NetworkDeviceDetail is a 1:1 extension of Device and carries no base mixin
(Annex C 4.7). FieldDefinition describes custom fields for the UI (4.10).

Every scalar enum is a TextChoices stored as text with a DB CHECK constraint,
so an invalid value is rejected by the database, not just the form layer.

Enums are module-level (so Meta CHECK constraints can reference ``.values``)
and aliased onto each model for ergonomic access, e.g. ``Person.State.ACTIVE``.
"""

from django.contrib.postgres.fields import ArrayField
from django.db import models

from apps.common.fields import MACAddressField
from apps.common.models import BaseEntity, UUIDModel

# --- Person ---------------------------------------------------------------


class PersonState(models.TextChoices):
    ACTIVE = "active", "Active"
    SUSPENDED = "suspended", "Suspended"
    OFFBOARDING = "offboarding", "Offboarding"
    TERMINATED = "terminated", "Terminated"


class Person(BaseEntity):
    State = PersonState

    state = models.TextField(choices=PersonState.choices, default=PersonState.ACTIVE)
    full_name = models.TextField()
    internal_code = models.TextField(null=True, blank=True, unique=True)
    job_title = models.TextField(blank=True, default="")
    department = models.TextField(blank=True, default="")
    personal_email = models.TextField(blank=True, default="")
    phone = models.TextField(blank=True, default="")
    extension = models.TextField(blank=True, default="")
    hire_date = models.DateField(null=True, blank=True)
    exit_date = models.DateField(null=True, blank=True)
    # Optional link to a login identity. PROTECT preserves no-hard-delete.
    operator = models.ForeignKey(
        "operators.Operator",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
    )

    class Meta:
        db_table = "person"
        indexes = [models.Index(fields=["state"], name="person_state_idx")]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(state__in=PersonState.values),
                name="person_state_valid",
            ),
        ]

    def __str__(self):
        return self.full_name


# --- Account --------------------------------------------------------------


class AccountType(models.TextChoices):
    O365 = "o365", "Office 365"
    MS_PERSONAL = "ms_personal", "Microsoft personal"
    GOOGLE = "google", "Google"
    SAMSUNG = "samsung", "Samsung"
    APPLE_ID = "apple_id", "Apple ID"
    ODOO = "odoo", "Odoo"
    NETWORK_ADMIN = "network_admin", "Network admin"
    EXTERNAL_SERVICE = "external_service", "External service"
    OTHER = "other", "Other"


class AccountState(models.TextChoices):
    ACTIVE = "active", "Active"
    DISABLED = "disabled", "Disabled"
    COMPROMISED = "compromised", "Compromised"
    NEEDS_ROTATION = "needs_rotation", "Needs rotation"


class MfaState(models.TextChoices):
    ENABLED = "enabled", "Enabled"
    DISABLED = "disabled", "Disabled"
    UNKNOWN = "unknown", "Unknown"


class MfaType(models.TextChoices):
    AUTHENTICATOR_APP = "authenticator_app", "Authenticator app"
    SMS = "sms", "SMS"
    VOICE = "voice", "Voice"
    EMAIL = "email", "Email"
    HARDWARE_KEY = "hardware_key", "Hardware key"
    WINDOWS_HELLO = "windows_hello", "Windows Hello"
    PASSKEY = "passkey", "Passkey"
    UNKNOWN = "unknown", "Unknown"


class Account(BaseEntity):
    Type = AccountType
    State = AccountState
    MfaState = MfaState
    MfaType = MfaType

    state = models.TextField(choices=AccountState.choices, default=AccountState.ACTIVE)
    account_type = models.TextField(choices=AccountType.choices)
    label = models.TextField()
    identifier = models.TextField()
    mfa_state = models.TextField(choices=MfaState.choices, default=MfaState.UNKNOWN)
    # Native text[]; element values come from MfaType (validated at app layer).
    mfa_types = ArrayField(
        models.CharField(max_length=32, choices=MfaType.choices),
        null=True,
        blank=True,
    )
    recovery_email = models.TextField(blank=True, default="")
    recovery_phone = models.TextField(blank=True, default="")
    last_password_change = models.DateField(null=True, blank=True)
    external_source = models.TextField(blank=True, default="")
    external_id = models.TextField(null=True, blank=True)

    class Meta:
        db_table = "account"
        indexes = [
            models.Index(fields=["state"], name="account_state_idx"),
            models.Index(fields=["mfa_state"], name="account_mfa_state_idx"),
            models.Index(fields=["account_type"], name="account_type_idx"),
            models.Index(fields=["external_id"], name="account_external_id_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(state__in=AccountState.values),
                name="account_state_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(account_type__in=AccountType.values),
                name="account_type_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(mfa_state__in=MfaState.values),
                name="account_mfa_state_valid",
            ),
        ]

    def __str__(self):
        return f"{self.label} ({self.identifier})"


# --- Device ---------------------------------------------------------------


class DeviceType(models.TextChoices):
    LAPTOP = "laptop", "Laptop"
    DESKTOP = "desktop", "Desktop"
    PHONE = "phone", "Phone"
    TABLET = "tablet", "Tablet"
    SERVER = "server", "Server"
    FIREWALL = "firewall", "Firewall"
    ROUTER = "router", "Router"
    SWITCH = "switch", "Switch"
    ACCESS_POINT = "access_point", "Access point"
    CONTROLLER = "controller", "Controller"
    PRINTER = "printer", "Printer"
    OTHER = "other", "Other"


class DeviceState(models.TextChoices):
    IN_USE = "in_use", "In use"
    IN_STORAGE = "in_storage", "In storage"
    PENDING_REPAIR = "pending_repair", "Pending repair"
    BROKEN = "broken", "Broken"
    DECOMMISSIONED = "decommissioned", "Decommissioned"


class Device(BaseEntity):
    Type = DeviceType
    State = DeviceState

    state = models.TextField(choices=DeviceState.choices, default=DeviceState.IN_USE)
    device_type = models.TextField(choices=DeviceType.choices)
    brand = models.TextField(blank=True, default="")
    model = models.TextField(blank=True, default="")
    serial_number = models.TextField(null=True, blank=True, unique=True)
    asset_tag = models.TextField(blank=True, default="")
    cpu = models.TextField(blank=True, default="")
    ram_gb = models.IntegerField(null=True, blank=True)
    storage_gb = models.IntegerField(null=True, blank=True)
    storage_type = models.TextField(blank=True, default="")
    hostname = models.TextField(blank=True, default="")
    mac_addresses = ArrayField(MACAddressField(), null=True, blank=True)
    ip_addresses = ArrayField(models.GenericIPAddressField(), null=True, blank=True)
    purchase_date = models.DateField(null=True, blank=True)
    warranty_expiry = models.DateField(null=True, blank=True)
    vendor = models.TextField(blank=True, default="")

    class Meta:
        db_table = "device"
        indexes = [
            models.Index(fields=["state"], name="device_state_idx"),
            models.Index(fields=["device_type"], name="device_type_idx"),
            models.Index(fields=["warranty_expiry"], name="device_warranty_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(state__in=DeviceState.values),
                name="device_state_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(device_type__in=DeviceType.values),
                name="device_type_valid",
            ),
        ]

    def __str__(self):
        return self.hostname or self.serial_number or str(self.id)


# --- NetworkDeviceDetail --------------------------------------------------


class MonitoringMethod(models.TextChoices):
    SNMP = "snmp", "SNMP"
    API = "api", "API"
    NONE = "none", "None"


class HealthState(models.TextChoices):
    REACHABLE = "reachable", "Reachable"
    ALERTING = "alerting", "Alerting"
    OFFLINE = "offline", "Offline"
    UNKNOWN = "unknown", "Unknown"


class NetworkDeviceDetail(models.Model):
    """1:1 extension of Device for network gear (Annex C 4.7).

    No base mixin: the PK is the device, and audit authorship lives on the
    parent Device row.
    """

    MonitoringMethod = MonitoringMethod
    HealthState = HealthState

    device = models.OneToOneField(
        "inventory.Device",
        primary_key=True,
        on_delete=models.PROTECT,
        related_name="network_detail",
        db_column="device_id",
    )
    firmware_version = models.TextField(blank=True, default="")
    last_firmware_update = models.DateField(null=True, blank=True)
    monitoring_method = models.TextField(
        choices=MonitoringMethod.choices, default=MonitoringMethod.NONE
    )
    monitoring_endpoint = models.TextField(blank=True, default="")
    management_url = models.TextField(blank=True, default="")
    health_state = models.TextField(choices=HealthState.choices, default=HealthState.UNKNOWN)
    last_seen_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "network_device_detail"
        indexes = [
            models.Index(fields=["health_state"], name="netdev_health_idx"),
            models.Index(fields=["last_seen_at"], name="netdev_last_seen_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(monitoring_method__in=MonitoringMethod.values),
                name="netdev_monitoring_method_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(health_state__in=HealthState.values),
                name="netdev_health_state_valid",
            ),
        ]


# --- Office ---------------------------------------------------------------


class OfficeState(models.TextChoices):
    ACTIVE = "active", "Active"
    IN_SETUP = "in_setup", "In setup"
    CLOSED = "closed", "Closed"


class Office(BaseEntity):
    State = OfficeState

    state = models.TextField(choices=OfficeState.choices, default=OfficeState.ACTIVE)
    name = models.TextField()
    address = models.TextField(blank=True, default="")
    isp = models.TextField(blank=True, default="")

    class Meta:
        db_table = "office"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(state__in=OfficeState.values),
                name="office_state_valid",
            ),
        ]

    def __str__(self):
        return self.name


# --- FieldDefinition ------------------------------------------------------


class FieldDefinitionEntityType(models.TextChoices):
    PERSON = "person", "Person"
    ACCOUNT = "account", "Account"
    DEVICE = "device", "Device"
    OFFICE = "office", "Office"


class FieldDefinitionDataType(models.TextChoices):
    STRING = "string", "String"
    INTEGER = "integer", "Integer"
    DATE = "date", "Date"
    BOOLEAN = "boolean", "Boolean"
    SELECT = "select", "Select"
    MULTISELECT = "multiselect", "Multi-select"


class FieldDefinition(UUIDModel):
    """Describes a custom field for the UI (Annex C 4.10).

    Only Administrator creates/edits these. ``viewer_visible`` hides a field
    from the Viewer role; secrets are always masked for Viewer regardless.
    """

    EntityType = FieldDefinitionEntityType
    DataType = FieldDefinitionDataType

    entity_type = models.TextField(choices=FieldDefinitionEntityType.choices)
    key = models.TextField()
    label = models.TextField()
    data_type = models.TextField(choices=FieldDefinitionDataType.choices)
    options = models.JSONField(null=True, blank=True)
    required = models.BooleanField(default=False)
    viewer_visible = models.BooleanField(default=True)
    display_order = models.IntegerField(default=0)
    active = models.BooleanField(default=True)

    class Meta:
        db_table = "field_definition"
        constraints = [
            models.UniqueConstraint(
                fields=["entity_type", "key"],
                name="field_definition_entity_key_unique",
            ),
            models.CheckConstraint(
                condition=models.Q(entity_type__in=FieldDefinitionEntityType.values),
                name="field_definition_entity_type_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(data_type__in=FieldDefinitionDataType.values),
                name="field_definition_data_type_valid",
            ),
        ]

    def __str__(self):
        return f"{self.entity_type}.{self.key}"
