from django.apps import AppConfig


class VaultConfig(AppConfig):
    name = "apps.vault"
    label = "vault"
    verbose_name = "Vault"

    def ready(self):
        # Disable core dumps process-wide so the master key can never land in a
        # dump (Annex A 7; reinforces systemd LimitCORE=0 from P1-T1). No-op off
        # POSIX; safe to call for every management command.
        from apps.vault.memory import disable_core_dumps

        disable_core_dumps()
