"""P2-T5 acceptance: backup_status command detects overdue/failed backups (Annex H 10).

The command reads the JSON status file written by backup.sh and exits 1 if the
backup is overdue (older than LLAVERO_BACKUP_OVERDUE_HOURS) or failed.
"""

import json
from datetime import UTC, datetime, timedelta
from io import StringIO

import pytest


def _write_status(path, status, hours_ago=1.0, backup_name="llavero_20260619T020000Z.sql.gz.age"):
    ts = (datetime.now(UTC) - timedelta(hours=hours_ago)).isoformat()
    path.write_text(json.dumps({"timestamp": ts, "status": status, "backup": backup_name}))


@pytest.mark.django_db
def test_ok_when_recent_successful_backup(tmp_path, settings):
    status_file = tmp_path / "backup-status.json"
    _write_status(status_file, "ok", hours_ago=1.0)
    settings.LLAVERO_BACKUP_STATUS_PATH = str(status_file)
    settings.LLAVERO_BACKUP_OVERDUE_HOURS = 26

    from django.core.management import call_command

    out = StringIO()
    call_command("backup_status", stdout=out)
    result = json.loads(out.getvalue())
    assert result["overdue"] is False
    assert result["last_status"] == "ok"
    assert result["hours_since"] < 2


@pytest.mark.django_db
def test_overdue_when_backup_is_old(tmp_path, settings):
    status_file = tmp_path / "backup-status.json"
    _write_status(status_file, "ok", hours_ago=30.0)
    settings.LLAVERO_BACKUP_STATUS_PATH = str(status_file)
    settings.LLAVERO_BACKUP_OVERDUE_HOURS = 26

    from django.core.management import call_command

    out = StringIO()
    with pytest.raises(SystemExit) as exc:
        call_command("backup_status", stdout=out)
    assert exc.value.code == 1
    result = json.loads(out.getvalue())
    assert result["overdue"] is True
    assert result["hours_since"] > 26


@pytest.mark.django_db
def test_overdue_when_status_file_missing(tmp_path, settings):
    settings.LLAVERO_BACKUP_STATUS_PATH = str(tmp_path / "nonexistent.json")
    settings.LLAVERO_BACKUP_OVERDUE_HOURS = 26

    from django.core.management import call_command

    out = StringIO()
    with pytest.raises(SystemExit) as exc:
        call_command("backup_status", stdout=out)
    assert exc.value.code == 1
    result = json.loads(out.getvalue())
    assert result["overdue"] is True
    assert "no status file" in result["reason"]


@pytest.mark.django_db
def test_overdue_when_status_path_not_configured(settings):
    settings.LLAVERO_BACKUP_STATUS_PATH = ""
    settings.LLAVERO_BACKUP_OVERDUE_HOURS = 26

    from django.core.management import call_command

    out = StringIO()
    with pytest.raises(SystemExit) as exc:
        call_command("backup_status", stdout=out)
    assert exc.value.code == 1
    result = json.loads(out.getvalue())
    assert result["overdue"] is True


@pytest.mark.django_db
def test_overdue_when_last_backup_failed(tmp_path, settings):
    status_file = tmp_path / "backup-status.json"
    _write_status(status_file, "failed", hours_ago=1.0)
    settings.LLAVERO_BACKUP_STATUS_PATH = str(status_file)
    settings.LLAVERO_BACKUP_OVERDUE_HOURS = 26

    from django.core.management import call_command

    out = StringIO()
    with pytest.raises(SystemExit) as exc:
        call_command("backup_status", stdout=out)
    assert exc.value.code == 1
    result = json.loads(out.getvalue())
    assert result["overdue"] is True
    assert result["last_status"] == "failed"


@pytest.mark.django_db
def test_backup_prune_dry_run_lists_old_files(tmp_path, settings):
    """P2-T4: backup_prune lists files to prune without deleting them."""
    from datetime import date

    archive = tmp_path / "archive"
    archive.mkdir()

    today = date.today()

    # Create a recent backup (kept) and an old one (pruned)
    recent = archive / f"llavero_{today.strftime('%Y%m%d')}T020000Z.sql.gz.age"
    old = archive / "llavero_20240101T020000Z.sql.gz.age"
    recent.touch()
    old.touch()

    settings.LLAVERO_BACKUP_ARCHIVE_DIR = str(archive)

    from django.core.management import call_command

    out = StringIO()
    call_command("backup_prune", archive_dir=str(archive), dry_run=True, stdout=out)
    output = out.getvalue()

    assert "DRY RUN" in output
    assert old.name in output
    assert recent.name not in output
    # Files still exist — dry run does not delete.
    assert old.exists()
    assert recent.exists()


@pytest.mark.django_db
def test_backup_prune_deletes_old_files(tmp_path, settings):
    """P2-T4: backup_prune deletes files outside the GFS window."""
    from datetime import date

    archive = tmp_path / "archive"
    archive.mkdir()

    today = date.today()
    recent = archive / f"llavero_{today.strftime('%Y%m%d')}T020000Z.sql.gz.age"
    old = archive / "llavero_20240101T020000Z.sql.gz.age"
    recent.touch()
    old.touch()

    from django.core.management import call_command

    call_command("backup_prune", archive_dir=str(archive), dry_run=False, stdout=StringIO())
    assert recent.exists()
    assert not old.exists()
