"""Management command: check whether the last backup is overdue (P2-T5, Annex H 10).

Reads the JSON status file written by backup.sh after every run and emits a
JSON status line to stdout. Exit 0 if OK; exit 1 if overdue or failed — so
systemd/monitoring can detect it without parsing the output.

Outputs::

    {"overdue": false, "last_backup": "...", "last_status": "ok", "hours_since": 1.2}
    {"overdue": true,  "last_backup": null, "reason": "no status file"}
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Check whether the last backup is overdue."

    def handle(self, *args, **options):
        status_path = Path(getattr(settings, "LLAVERO_BACKUP_STATUS_PATH", ""))
        overdue_hours = getattr(settings, "LLAVERO_BACKUP_OVERDUE_HOURS", 26)

        # No status file → never ran or path not configured.
        if not status_path or not status_path.exists():
            self._emit({"overdue": True, "last_backup": None, "reason": "no status file"})
            sys.exit(1)

        try:
            data = json.loads(status_path.read_text())
        except Exception as exc:
            self._emit({"overdue": True, "last_backup": None, "reason": f"bad status file: {exc}"})
            sys.exit(1)

        last_status = data.get("status", "unknown")
        last_backup = data.get("backup")
        raw_ts = data.get("timestamp")

        if last_status != "ok":
            self._emit(
                {
                    "overdue": True,
                    "last_backup": last_backup,
                    "last_status": last_status,
                    "reason": "last backup failed",
                }
            )
            sys.exit(1)

        try:
            last_ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except Exception:
            self._emit({"overdue": True, "last_backup": last_backup, "reason": "bad timestamp"})
            sys.exit(1)

        now = datetime.now(UTC)
        hours_since = (now - last_ts).total_seconds() / 3600

        if hours_since > overdue_hours:
            self._emit(
                {
                    "overdue": True,
                    "last_backup": last_backup,
                    "last_status": last_status,
                    "hours_since": round(hours_since, 1),
                    "threshold_hours": overdue_hours,
                }
            )
            sys.exit(1)

        self._emit(
            {
                "overdue": False,
                "last_backup": last_backup,
                "last_status": last_status,
                "hours_since": round(hours_since, 1),
            }
        )

    def _emit(self, data: dict) -> None:
        self.stdout.write(json.dumps(data))
