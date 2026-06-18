"""Relationship join tables (Annex C 5, 6).

One explicit join table per relationship type, each with two real foreign keys
so the database enforces which entity types a link connects. All carry the
shared link columns from LinkBase (state, valid_from, valid_to + audit).

Database-enforced integrity highlights:
- Partial unique indexes: one active primary owner per account, one active
  holder per device, one active location per device, one active responsible
  person per office.
- CHECK a<>b on account_recovery and device_dependency (no self-links).
- FK columns are indexed by Django (db_index default on ForeignKey), covering
  the "index on each foreign key" requirement of Annex C 6.

Table names match Annex C exactly (note: account_device_config, NOT
account_configured_on_device — see CLAUDE.md known fix).
"""

from django.db import models

from apps.common.models import LinkBase, LinkState, link_state_check

# --- link role / qualifier enums (Annex C 3) ------------------------------


class OwnershipRole(models.TextChoices):
    PRIMARY = "primary", "Primary"
    SHARED = "shared", "Shared"


class AssignmentRole(models.TextChoices):
    PRIMARY_USER = "primary_user", "Primary user"
    TEMPORARY = "temporary", "Temporary"


class ConfigPurpose(models.TextChoices):
    SETUP = "setup", "Setup"
    MAIL = "mail", "Mail"
    MDM = "mdm", "MDM"
    OTHER = "other", "Other"


class ContactChannel(models.TextChoices):
    EMAIL = "email", "Email"
    PHONE = "phone", "Phone"
    OTHER = "other", "Other"


class MembershipRole(models.TextChoices):
    STAFF = "staff", "Staff"
    RESPONSIBLE = "responsible", "Responsible"


class DependencyNature(models.TextChoices):
    UPLINK = "uplink", "Uplink"
    POWER = "power", "Power"
    CONTROLLER = "controller", "Controller"
    OTHER = "other", "Other"


# --- 1. account_ownership -------------------------------------------------


class AccountOwnership(LinkBase):
    Role = OwnershipRole

    person = models.ForeignKey(
        "inventory.Person", on_delete=models.PROTECT, related_name="account_ownerships"
    )
    account = models.ForeignKey(
        "inventory.Account", on_delete=models.PROTECT, related_name="ownerships"
    )
    role = models.TextField(choices=OwnershipRole.choices, default=OwnershipRole.SHARED)

    class Meta:
        db_table = "account_ownership"
        constraints = [
            link_state_check("account_ownership_state_valid"),
            models.CheckConstraint(
                condition=models.Q(role__in=OwnershipRole.values),
                name="account_ownership_role_valid",
            ),
            models.UniqueConstraint(
                fields=["account"],
                condition=models.Q(role=OwnershipRole.PRIMARY, state=LinkState.ACTIVE),
                name="account_ownership_one_active_primary",
            ),
        ]


# --- 2. device_assignment -------------------------------------------------


class DeviceAssignment(LinkBase):
    Role = AssignmentRole

    person = models.ForeignKey(
        "inventory.Person", on_delete=models.PROTECT, related_name="device_assignments"
    )
    device = models.ForeignKey(
        "inventory.Device", on_delete=models.PROTECT, related_name="assignments"
    )
    role = models.TextField(choices=AssignmentRole.choices, default=AssignmentRole.PRIMARY_USER)

    class Meta:
        db_table = "device_assignment"
        constraints = [
            link_state_check("device_assignment_state_valid"),
            models.CheckConstraint(
                condition=models.Q(role__in=AssignmentRole.values),
                name="device_assignment_role_valid",
            ),
            models.UniqueConstraint(
                fields=["device"],
                condition=models.Q(state=LinkState.ACTIVE),
                name="device_assignment_one_active_holder",
            ),
        ]


# --- 3. account_device_config ---------------------------------------------


class AccountDeviceConfig(LinkBase):
    Purpose = ConfigPurpose

    account = models.ForeignKey(
        "inventory.Account", on_delete=models.PROTECT, related_name="device_configs"
    )
    device = models.ForeignKey(
        "inventory.Device", on_delete=models.PROTECT, related_name="account_configs"
    )
    purpose = models.TextField(choices=ConfigPurpose.choices, default=ConfigPurpose.OTHER)

    class Meta:
        db_table = "account_device_config"
        constraints = [
            link_state_check("account_device_config_state_valid"),
            models.CheckConstraint(
                condition=models.Q(purpose__in=ConfigPurpose.values),
                name="account_device_config_purpose_valid",
            ),
        ]


# --- 4. account_recovery --------------------------------------------------


class AccountRecovery(LinkBase):
    recovery_account = models.ForeignKey(
        "inventory.Account", on_delete=models.PROTECT, related_name="recovery_for"
    )
    target_account = models.ForeignKey(
        "inventory.Account", on_delete=models.PROTECT, related_name="recovery_accounts"
    )
    priority = models.IntegerField(default=0)

    class Meta:
        db_table = "account_recovery"
        constraints = [
            link_state_check("account_recovery_state_valid"),
            models.CheckConstraint(
                condition=~models.Q(recovery_account=models.F("target_account")),
                name="account_recovery_distinct",
            ),
        ]


# --- 5. account_recovery_contact ------------------------------------------


class AccountRecoveryContact(LinkBase):
    Channel = ContactChannel

    person = models.ForeignKey(
        "inventory.Person", on_delete=models.PROTECT, related_name="account_recovery_contacts"
    )
    account = models.ForeignKey(
        "inventory.Account", on_delete=models.PROTECT, related_name="recovery_contacts"
    )
    channel = models.TextField(choices=ContactChannel.choices, default=ContactChannel.EMAIL)

    class Meta:
        db_table = "account_recovery_contact"
        constraints = [
            link_state_check("account_recovery_contact_state_valid"),
            models.CheckConstraint(
                condition=models.Q(channel__in=ContactChannel.values),
                name="account_recovery_contact_channel_valid",
            ),
        ]


# --- 6. device_recovery_contact -------------------------------------------


class DeviceRecoveryContact(LinkBase):
    Channel = ContactChannel

    person = models.ForeignKey(
        "inventory.Person", on_delete=models.PROTECT, related_name="device_recovery_contacts"
    )
    device = models.ForeignKey(
        "inventory.Device", on_delete=models.PROTECT, related_name="recovery_contacts"
    )
    channel = models.TextField(choices=ContactChannel.choices, default=ContactChannel.EMAIL)

    class Meta:
        db_table = "device_recovery_contact"
        constraints = [
            link_state_check("device_recovery_contact_state_valid"),
            models.CheckConstraint(
                condition=models.Q(channel__in=ContactChannel.values),
                name="device_recovery_contact_channel_valid",
            ),
        ]


# --- 7. device_location ---------------------------------------------------


class DeviceLocation(LinkBase):
    device = models.ForeignKey(
        "inventory.Device", on_delete=models.PROTECT, related_name="locations"
    )
    office = models.ForeignKey(
        "inventory.Office", on_delete=models.PROTECT, related_name="device_locations"
    )

    class Meta:
        db_table = "device_location"
        constraints = [
            link_state_check("device_location_state_valid"),
            models.UniqueConstraint(
                fields=["device"],
                condition=models.Q(state=LinkState.ACTIVE),
                name="device_location_one_active",
            ),
        ]


# --- 8. office_membership -------------------------------------------------


class OfficeMembership(LinkBase):
    Role = MembershipRole

    person = models.ForeignKey(
        "inventory.Person", on_delete=models.PROTECT, related_name="office_memberships"
    )
    office = models.ForeignKey(
        "inventory.Office", on_delete=models.PROTECT, related_name="memberships"
    )
    role = models.TextField(choices=MembershipRole.choices, default=MembershipRole.STAFF)

    class Meta:
        db_table = "office_membership"
        constraints = [
            link_state_check("office_membership_state_valid"),
            models.CheckConstraint(
                condition=models.Q(role__in=MembershipRole.values),
                name="office_membership_role_valid",
            ),
            models.UniqueConstraint(
                fields=["office"],
                condition=models.Q(role=MembershipRole.RESPONSIBLE, state=LinkState.ACTIVE),
                name="office_membership_one_responsible",
            ),
        ]


# --- 9. device_dependency -------------------------------------------------


class DeviceDependency(LinkBase):
    Nature = DependencyNature

    dependent_device = models.ForeignKey(
        "inventory.Device", on_delete=models.PROTECT, related_name="dependencies"
    )
    depends_on_device = models.ForeignKey(
        "inventory.Device", on_delete=models.PROTECT, related_name="dependents"
    )
    nature = models.TextField(choices=DependencyNature.choices, default=DependencyNature.OTHER)

    class Meta:
        db_table = "device_dependency"
        constraints = [
            link_state_check("device_dependency_state_valid"),
            models.CheckConstraint(
                condition=models.Q(nature__in=DependencyNature.values),
                name="device_dependency_nature_valid",
            ),
            models.CheckConstraint(
                condition=~models.Q(dependent_device=models.F("depends_on_device")),
                name="device_dependency_distinct",
            ),
        ]
