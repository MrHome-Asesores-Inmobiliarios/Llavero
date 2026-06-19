"""GFS backup retention date calculations (P2-T4, Annex H 6).

Grandfather-father-son rules:
  daily   — keep all backups from the last 14 days
  weekly  — keep the latest backup in each of the last 8 ISO weeks
  monthly — keep the latest backup in each of the last 12 calendar months

The audit chain is never pruned; only encrypted database dumps are subject
to these rules. Any backup that falls in at least one bucket is kept.
"""

import re
from datetime import date, timedelta

# Filename pattern produced by backup.sh:  llavero_20260619T020000Z.sql.gz.age
_BACKUP_RE = re.compile(r"llavero_(\d{4})(\d{2})(\d{2})T\d{6}Z\.sql\.gz\.age")


def _months_ago(reference: date, n: int) -> date:
    """Return the first day of the month that was n months before reference."""
    year, month = reference.year, reference.month - n
    while month <= 0:
        month += 12
        year -= 1
    return date(year, month, 1)


def gfs_keep_set(
    dates: list[date],
    today: date,
    daily_days: int = 14,
    weekly_weeks: int = 8,
    monthly_months: int = 12,
) -> set[date]:
    """Return the set of backup dates that GFS retention requires keeping.

    *dates* may contain duplicates; only unique dates matter.
    Dates in the future (relative to *today*) are always kept.
    """
    unique = sorted(set(dates))
    keep: set[date] = set()

    # Daily bucket: any backup from the last daily_days days.
    for d in unique:
        if (today - d).days < daily_days:
            keep.add(d)

    # Weekly bucket: latest backup in each ISO week, within the last weekly_weeks weeks.
    by_week: dict[tuple[int, int], date] = {}
    for d in unique:
        wk = d.isocalendar()[:2]  # (iso_year, iso_week)
        if wk not in by_week or d > by_week[wk]:
            by_week[wk] = d
    cutoff_weekly = today - timedelta(weeks=weekly_weeks)
    for representative in by_week.values():
        if representative > cutoff_weekly:
            keep.add(representative)

    # Monthly bucket: latest backup in each calendar month, within the last monthly_months.
    by_month: dict[tuple[int, int], date] = {}
    for d in unique:
        mk = (d.year, d.month)
        if mk not in by_month or d > by_month[mk]:
            by_month[mk] = d
    cutoff_monthly = _months_ago(today, monthly_months)
    for representative in by_month.values():
        if representative >= cutoff_monthly:
            keep.add(representative)

    return keep


def parse_backup_date(filename: str) -> date | None:
    """Parse the backup date from a filename produced by backup.sh, or None."""
    m = _BACKUP_RE.match(filename)
    if not m:
        return None
    return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))


def files_to_prune(
    filenames: list[str],
    today: date,
    daily_days: int = 14,
    weekly_weeks: int = 8,
    monthly_months: int = 12,
) -> set[str]:
    """Return the set of filenames that should be pruned under GFS rules.

    Filenames that cannot be parsed (wrong format, not backup files) are
    always kept — prune only what you recognise.
    """
    by_date: dict[date, list[str]] = {}
    unrecognised: set[str] = set()

    for name in filenames:
        d = parse_backup_date(name)
        if d is None:
            unrecognised.add(name)
        else:
            by_date.setdefault(d, []).append(name)

    keep_dates = gfs_keep_set(
        list(by_date.keys()),
        today,
        daily_days=daily_days,
        weekly_weeks=weekly_weeks,
        monthly_months=monthly_months,
    )

    pruned: set[str] = set()
    for d, names in by_date.items():
        if d not in keep_dates:
            pruned.update(names)

    return pruned
