"""Management command: prune the local backup archive per GFS retention (P2-T4, Annex H 6).

Usage::

    manage.py backup_prune [--archive-dir PATH] [--dry-run]

The command reads *.age files from the archive directory, applies the
grandfather-father-son rules (daily 14d / weekly 8w / monthly 12m), and
deletes files that fall outside every retention bucket. Unrecognised filenames
are always kept. The audit chain is never pruned.
"""

from datetime import date
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.backup.retention import files_to_prune


class Command(BaseCommand):
    help = "Prune the local backup archive per GFS retention (daily 14d / weekly 8w / monthly 12m)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--archive-dir",
            default=getattr(settings, "LLAVERO_BACKUP_ARCHIVE_DIR", "/var/backups/llavero/archive"),
            help="Path to the local backup archive directory.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="List files that would be pruned without deleting them.",
        )

    def handle(self, *args, **options):
        archive = Path(options["archive_dir"])
        dry_run = options["dry_run"]

        if not archive.exists():
            self.stdout.write(f"Archive directory does not exist: {archive}")
            return

        all_files = [f.name for f in archive.glob("*.age")]
        today = date.today()
        to_prune = files_to_prune(all_files, today)

        for name in sorted(to_prune):
            if dry_run:
                self.stdout.write(f"DRY RUN: would prune {name}")
            else:
                (archive / name).unlink()
                self.stdout.write(f"Pruned {name}")

        verb = "Would prune" if dry_run else "Pruned"
        self.stdout.write(
            f"{verb} {len(to_prune)} of {len(all_files)} backup(s) " f"from {archive}"
        )
