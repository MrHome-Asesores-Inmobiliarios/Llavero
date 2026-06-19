"""Management command: run enabled integrations that are due (P5-T1).

Finds enabled Integration rows where last_run_at is null or
last_run_at + run_interval_minutes <= now, then runs each in turn via the
dispatcher. Updates last_run_at and last_status on each row.

The vault master key is required to decrypt credentials. In a management
command context the operator must supply the vault passphrase (and second
factor) on the command line, OR the command can be run with --no-decrypt to
skip credential decryption (integration runners receive credential_plaintext=None).

Usage:
    python manage.py run_integrations [--no-decrypt] [--integration-id UUID]
"""

import logging

from django.core.management.base import BaseCommand

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Run all enabled integrations that are due for their next poll."

    def add_arguments(self, parser):
        parser.add_argument(
            "--no-decrypt",
            action="store_true",
            default=False,
            help=(
                "Skip vault credential decryption. Runners receive no credential plaintext. "
                "Useful for dry runs or integrations that do not need vault credentials."
            ),
        )
        parser.add_argument(
            "--integration-id",
            dest="integration_id",
            default=None,
            help="Run only the specified integration UUID (overrides due-check).",
        )
        parser.add_argument(
            "--run-all",
            action="store_true",
            default=False,
            help="Run all enabled integrations regardless of schedule.",
        )

    def handle(self, *args, **options):
        from apps.integrations.models import Integration
        from apps.integrations.runners.dispatch import run_one

        no_decrypt = options["no_decrypt"]
        integration_id = options.get("integration_id")
        run_all = options["run_all"]

        # Vault MK — only needed if decrypting credentials
        mk: bytes | None = None
        if not no_decrypt:
            try:
                from apps.vault.memory import get_system_mk

                mk_buf = get_system_mk()
                if mk_buf is not None:
                    mk = bytes(mk_buf)
                else:
                    self.stderr.write(
                        "WARNING: vault MK not available — running without credential decryption. "
                        "Use --no-decrypt to suppress this warning."
                    )
            except Exception as exc:
                self.stderr.write(
                    f"WARNING: could not load vault MK ({exc}) — "
                    "running without credential decryption."
                )

        # Select integrations to run
        if integration_id:
            qs = Integration.objects.filter(id=integration_id, enabled=True)
        elif run_all:
            qs = Integration.objects.filter(enabled=True)
        else:
            # Run those that are due
            all_enabled = Integration.objects.filter(enabled=True)
            qs = [i for i in all_enabled if i.is_due()]

        total = 0
        ok = 0
        error = 0

        for integration in qs:
            self.stdout.write(
                f"Running integration: {integration.name} ({integration.integration_type})"
            )
            status = run_one(integration, mk=mk)
            total += 1
            if status == "ok":
                ok += 1
                self.stdout.write("  -> OK")
            else:
                error += 1
                self.stdout.write(f"  -> ERROR: {integration.last_error}")

        self.stdout.write(f"\nDone: {total} integration(s) run — {ok} ok, {error} error(s).")
