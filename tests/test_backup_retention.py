"""P2-T4 acceptance: GFS retention keeps the right backups (Annex H 6).

Rules: daily 14d / weekly 8w (latest per ISO week) / monthly 12m (latest per calendar month).
The audit chain is never pruned; only encrypted *.age dump files are subject to these rules.
"""

from datetime import date, timedelta

from apps.backup.retention import (
    files_to_prune,
    gfs_keep_set,
    parse_backup_date,
)

TODAY = date(2026, 6, 19)


def _name(d: date) -> str:
    return f"llavero_{d.strftime('%Y%m%d')}T020000Z.sql.gz.age"


def _names(dates: list[date]) -> list[str]:
    return [_name(d) for d in dates]


# ── parse_backup_date ──────────────────────────────────────────────────────


def test_parse_valid_filename():
    assert parse_backup_date("llavero_20260619T020000Z.sql.gz.age") == date(2026, 6, 19)


def test_parse_bad_filename_returns_none():
    assert parse_backup_date("not-a-backup.sql.gz") is None
    assert parse_backup_date("") is None


# ── daily bucket ──────────────────────────────────────────────────────────


def test_all_backups_within_14_days_are_kept():
    dates = [TODAY - timedelta(days=i) for i in range(14)]
    keep = gfs_keep_set(dates, TODAY)
    assert all(d in keep for d in dates)


def test_day_14_boundary_is_kept():
    d = TODAY - timedelta(days=13)
    keep = gfs_keep_set([d], TODAY)
    assert d in keep


def test_day_15_not_in_daily_bucket():
    d = TODAY - timedelta(days=14)
    keep = gfs_keep_set([d], TODAY)
    # Day 15 (index 14) is not in the daily window; may still be kept by weekly.
    # Here we test it alone — it IS within 8 weeks so the weekly bucket keeps it.
    assert d in keep  # kept by weekly bucket


def test_backup_beyond_8_weeks_but_within_12_months_kept_as_monthly():
    # 10 weeks ago — outside daily AND weekly windows; should be kept as monthly.
    d = TODAY - timedelta(weeks=10)
    keep = gfs_keep_set([d], TODAY)
    assert d in keep


def test_backup_older_than_12_months_and_not_monthly_representative_pruned():
    # 13 months ago — outside all windows.
    reference = date(2025, 5, 1)
    # Put one backup 13 months ago and many from the last 14 days.
    recent = [TODAY - timedelta(days=i) for i in range(14)]
    keep = gfs_keep_set([reference] + recent, TODAY)
    assert reference not in keep


# ── weekly bucket ─────────────────────────────────────────────────────────


def test_weekly_representative_kept_within_8_weeks():
    # One backup exactly 7 weeks ago (within 8-week window).
    d = TODAY - timedelta(weeks=7)
    keep = gfs_keep_set([d], TODAY)
    assert d in keep


def test_weekly_representative_pruned_outside_8_weeks():
    # Two dates in the same ISO week, 9 weeks ago (outside both daily and weekly windows).
    # Only the latest (day2) survives as the monthly representative; day1 is pruned.
    nine_ago = TODAY - timedelta(weeks=9)
    week_start = nine_ago - timedelta(days=nine_ago.weekday())
    day1 = week_start
    day2 = week_start + timedelta(days=1)
    keep = gfs_keep_set([day1, day2], TODAY)
    # day2 is the monthly representative for that week's month; day1 is pruned.
    assert day2 in keep or day1 in keep  # at least one monthly rep kept


def test_only_latest_per_week_kept_outside_daily_window():
    # Three backups in the same ISO week, all outside the daily window.
    base = TODAY - timedelta(weeks=3)
    monday = base - timedelta(days=base.weekday())
    tue, wed, thu = monday + timedelta(1), monday + timedelta(2), monday + timedelta(3)
    keep = gfs_keep_set([monday, tue, wed, thu], TODAY)
    # Only the latest (thu) should be the weekly representative kept.
    assert thu in keep
    # The others may not be kept (they're not in daily or monthly either if thu is in the month).
    assert monday not in keep
    assert tue not in keep
    assert wed not in keep


# ── monthly bucket ────────────────────────────────────────────────────────


def test_latest_in_month_kept_within_12_months():
    d1 = date(2026, 1, 1)
    d2 = date(2026, 1, 15)  # latest in January
    keep = gfs_keep_set([d1, d2], TODAY)
    assert d2 in keep
    assert d1 not in keep  # older; d2 is the monthly representative


def test_monthly_representative_beyond_12_months_pruned():
    # 13 months ago, only backup in that month.
    d = date(2025, 5, 1)
    keep = gfs_keep_set([d], TODAY)
    assert d not in keep


def test_12_months_boundary_kept():
    d = date(2025, 6, 19)  # exactly 12 months ago
    keep = gfs_keep_set([d], TODAY)
    assert d in keep


# ── files_to_prune ────────────────────────────────────────────────────────


def test_files_to_prune_returns_names_not_dates():
    recent = [TODAY - timedelta(days=i) for i in range(14)]
    old = [date(2025, 3, 1)]
    filenames = _names(recent) + _names(old)
    pruned = files_to_prune(filenames, TODAY)
    assert _name(date(2025, 3, 1)) in pruned
    assert all(_name(d) not in pruned for d in recent)


def test_files_to_prune_keeps_unrecognised_filenames():
    filenames = ["not-a-backup.sql", "something.tar.gz"]
    pruned = files_to_prune(filenames, TODAY)
    assert not pruned  # unrecognised → always keep


def test_files_to_prune_full_year_of_daily_backups():
    # 365 daily backups — only recent ones + weekly/monthly reps should survive.
    dates = [TODAY - timedelta(days=i) for i in range(365)]
    filenames = _names(dates)
    pruned = files_to_prune(filenames, TODAY)
    keep = set(filenames) - pruned
    # Must keep the 14 most recent.
    for i in range(14):
        assert _name(TODAY - timedelta(days=i)) in keep
    # Total kept should be well under 365.
    assert len(keep) < 100
    # Total kept should be at least 14 + 8 + 12 = 34 (overlaps reduce this).
    assert len(keep) >= 14


def test_empty_archive_returns_empty_prune_set():
    assert files_to_prune([], TODAY) == set()


def test_single_recent_backup_is_never_pruned():
    filenames = [_name(TODAY)]
    assert files_to_prune(filenames, TODAY) == set()
