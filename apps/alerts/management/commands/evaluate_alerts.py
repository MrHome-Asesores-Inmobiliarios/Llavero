"""Management command: evaluate_alerts (P6-T2, Annex E 3).

Runs all enabled alert rules, updates Alert rows. Idempotent.
System actor reads during evaluation are NOT logged in the audit chain.
"""

from django.core.management.base import BaseCommand

from apps.alerts.rules import run_all_enabled_rules


class Command(BaseCommand):
    help = "Evaluate all enabled alert rules and update alert rows."

    def handle(self, *args, **options):
        self.stdout.write("Running alert evaluation...")
        results = run_all_enabled_rules()

        ok_count = sum(1 for _, err, status in results if err is None and status == "ok")
        skip_count = sum(1 for _, err, status in results if status == "skipped_disabled")
        error_count = sum(1 for _, err, status in results if err is not None)

        for name, err, status in results:
            if err is not None:
                self.stderr.write(self.style.ERROR(f"  ERROR {name}: {err}"))
            elif status == "skipped_disabled":
                self.stdout.write(f"  SKIP  {name} (disabled)")
            else:
                self.stdout.write(f"  OK    {name}")

        self.stdout.write(
            self.style.SUCCESS(f"Done: {ok_count} ok, {skip_count} skipped, {error_count} errors.")
        )
