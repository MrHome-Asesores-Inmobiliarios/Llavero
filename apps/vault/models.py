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

from apps.common.models import AuditedModel, UUIDModel


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


class VaultKeyHolder(UUIDModel):
    """Per-administrator wrapped copy of the single vault master key (Annex A 13).

    One row per Administrator. The MK is wrapped under each admin's KWK
    (KWK = combine(Argon2id(passphrase, salt, params), second factor)), so each
    admin unlocks the same MK with their own credentials. Viewers never get a
    row, which is what makes a Viewer session keyless.

    Stores only the *wrapped* MK and the (non-secret) KDF parameters. The
    second factor itself is never stored — ``second_factor_ref`` is just a
    handle (keyfile id / TPM handle) resolved by the second-factor provider.
    """

    operator = models.OneToOneField(
        "operators.Operator",
        on_delete=models.PROTECT,
        related_name="vault_key_holder",
    )
    kdf_salt = models.BinaryField()
    kdf_memory = models.IntegerField()
    kdf_iterations = models.IntegerField()
    kdf_parallelism = models.IntegerField()
    scheme_version = models.IntegerField(default=1)
    mk_wrapped = models.BinaryField()
    mk_nonce = models.BinaryField()
    # Handle for the out-of-database second factor; NEVER the factor itself.
    second_factor_ref = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        "operators.Operator",
        on_delete=models.PROTECT,
        related_name="+",
    )

    class Meta:
        db_table = "vault_key_holder"

    def __str__(self):
        return f"vault key holder for operator {self.operator_id}"
