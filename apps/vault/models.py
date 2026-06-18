"""Encrypted secret storage (Annex C 4.9, Annex A).

The Secret row holds only ciphertext and wrapping metadata. The envelope
encryption scheme (passphrase -> KWK -> MK -> per-secret DEK,
XChaCha20-Poly1305 with AAD) is implemented in P1-T6; this task defines the
storage shape only. No plaintext secret ever lives in a column.

The owner is polymorphic (owner_type + owner_id) and intentionally has no FK,
since a secret may belong to an account, device, office, operator, or a
future integration row.
"""

from django.db import models

from apps.common.models import AuditedModel


class SecretOwnerType(models.TextChoices):
    ACCOUNT = "account", "Account"
    DEVICE = "device", "Device"
    OFFICE = "office", "Office"
    OPERATOR = "operator", "Operator"
    INTEGRATION = "integration", "Integration"


class SecretKind(models.TextChoices):
    PASSWORD = "password", "Password"
    RECOVERY_CODES = "recovery_codes", "Recovery codes"
    PIN = "pin", "PIN"
    PASSPHRASE = "passphrase", "Passphrase"
    API_KEY = "api_key", "API key"
    WIFI_PSK = "wifi_psk", "Wi-Fi PSK"
    BIOS_PASSWORD = "bios_password", "BIOS password"
    DISK_RECOVERY_KEY = "disk_recovery_key", "Disk recovery key"
    TOTP_SEED = "totp_seed", "TOTP seed"
    SNMP_COMMUNITY = "snmp_community", "SNMP community"
    OTHER = "other", "Other"


class Secret(AuditedModel):
    OwnerType = SecretOwnerType
    Kind = SecretKind

    owner_type = models.TextField(choices=SecretOwnerType.choices)
    owner_id = models.UUIDField()
    kind = models.TextField(choices=SecretKind.choices)
    label = models.TextField(blank=True, default="")
    # XChaCha20-Poly1305 output and wrapping metadata (Annex A 3, 4, 11).
    ciphertext = models.BinaryField()
    nonce = models.BinaryField()
    dek_wrapped = models.BinaryField()
    dek_nonce = models.BinaryField()
    aad_context = models.TextField()
    scheme_version = models.IntegerField(default=1)
    last_rotated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "secret"
        indexes = [
            models.Index(fields=["owner_type", "owner_id"], name="secret_owner_idx"),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(owner_type__in=SecretOwnerType.values),
                name="secret_owner_type_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(kind__in=SecretKind.values),
                name="secret_kind_valid",
            ),
        ]

    def __str__(self):
        return f"{self.kind} for {self.owner_type}:{self.owner_id}"
