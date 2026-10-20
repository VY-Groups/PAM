"""Session-scoped checks for the PostgreSQL test suite (ADR-0019 D5,
amended): PostgreSQL is the only storage engine (D10), so the session
refuses to run without one - a single honest failure up front instead of
one error per test - and every created database is dropped at teardown."""
from __future__ import annotations

import sys
import warnings
from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import _testdb  # noqa: E402


def pytest_configure(config) -> None:
    """One honest failure when the suite has no PostgreSQL to run against."""
    try:
        _testdb.require_override()
    except RuntimeError as exc:
        pytest.exit(str(exc))


@pytest.fixture(scope="session", autouse=True)
def _drop_created_test_databases():
    yield
    try:
        dropped = _testdb.drop_created_databases()
    except Exception as exc:  # teardown must never mask the run's result
        warnings.warn(f"test PostgreSQL teardown could not drop databases: {exc!r}")
    else:
        if dropped:
            print(f"\ntest databases dropped: {dropped}")
