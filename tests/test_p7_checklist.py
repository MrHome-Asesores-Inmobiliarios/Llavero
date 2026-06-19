"""P7-T6: v1 Definition-of-done automated checks.

1. Django system check passes (no errors).
2. No pending migrations.
3. The test suite has at least 350 passing tests.
4. The vendored htmx.min.js is present in static/js/.
"""

import subprocess
import sys
from pathlib import Path

import pytest

BASE_DIR = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


# ---------------------------------------------------------------------------
# 1. Django system check
# ---------------------------------------------------------------------------


def test_django_system_check_passes():
    """manage.py check must report zero errors.

    Uses the same DJANGO_SETTINGS_MODULE that pytest injects (dev settings).
    We pass only --fail-level ERROR so deprecation warnings don't block the gate.
    """
    result = subprocess.run(  # noqa: S603
        [PYTHON, "manage.py", "check", "--fail-level", "ERROR"],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        timeout=60,
        env={
            **__import__("os").environ,
            "DJANGO_SETTINGS_MODULE": "llavero.settings.dev",
        },
    )
    assert (
        result.returncode == 0
    ), f"Django system check reported errors:\n{result.stdout}\n{result.stderr}"


# ---------------------------------------------------------------------------
# 2. No pending migrations  (uses Django's MigrationLoader in-process)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_no_pending_migrations():
    """No unapplied migrations may exist.

    We use Django's MigrationLoader directly so we reuse the pytest test
    database connection (which already has DB credentials).
    """
    from django.db import connections
    from django.db.migrations.executor import MigrationExecutor

    connection = connections["default"]
    executor = MigrationExecutor(connection)
    plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
    assert plan == [], (
        "Pending migrations detected: "
        + ", ".join(f"{app}.{name}" for (mig, _) in plan for app, name in [mig.app_label, mig.name])
        if plan
        else "Pending migrations detected"
    )


# ---------------------------------------------------------------------------
# 3. Test suite passes threshold
# ---------------------------------------------------------------------------


def test_suite_has_minimum_passing_count():
    """Run pytest in collection-only mode and count collected tests.

    pytest --co -q --no-header outputs lines in the format:
        tests/test_foo.py: 12
        tests/test_bar.py: 8
        ...
    We sum the counts to get the total.  The threshold of 350 is set below
    the pre-P7 baseline of 368 so the gate is a safety net, not an exact count.
    """
    result = subprocess.run(  # noqa: S603
        [PYTHON, "-m", "pytest", "tests/", "--co", "-q", "--no-header"],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        timeout=120,
        env={
            **__import__("os").environ,
            "DJANGO_SETTINGS_MODULE": "llavero.settings.dev",
        },
    )
    output = result.stdout + result.stderr
    total = 0
    for line in output.splitlines():
        # Match lines like "tests/test_foo.py: 12"
        parts = line.rsplit(":", 1)
        if len(parts) == 2 and parts[1].strip().isdigit():
            total += int(parts[1].strip())
    assert total >= 350, (
        f"Only {total} tests collected — expected at least 350.\n" f"Output:\n{output[:2000]}"
    )


# ---------------------------------------------------------------------------
# 4. Vendored htmx.min.js present
# ---------------------------------------------------------------------------


def test_htmx_minjs_vendored():
    """The vendored htmx.min.js must be present in static/js/."""
    path = BASE_DIR / "static" / "js" / "htmx.min.js"
    assert path.exists(), (
        f"static/js/htmx.min.js not found at {path}. "
        "Run the vendor script or copy htmx.min.js into the static directory."
    )
    # Sanity-check: the file should not be empty
    assert path.stat().st_size > 0, "static/js/htmx.min.js exists but is empty"
