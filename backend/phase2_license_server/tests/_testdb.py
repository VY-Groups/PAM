"""Central test-database resolution (ADR-0019 D5, amended).

PostgreSQL is the only storage engine (D10), so the suite REQUIRES one:
``PAM_TEST_DATABASE_URI`` must point at a running PostgreSQL server (the
CI job's service container, or a local ``postgres:16`` container). Every
call to ``test_database_uri`` receives its own freshly created database on
that server - main configs and peer configs never share state. Databases
are created lazily over a psycopg maintenance connection (the [binary]
wheel from ADR-0019 D1, so no system libpq is needed) and dropped at
session end by ``tests/conftest.py``. There is no embedded fallback:
without the variable the suite fails fast with the exact setup command.
"""
from __future__ import annotations

import itertools
import os
import sys
import threading
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

OVERRIDE_ENV = "PAM_TEST_DATABASE_URI"

SETUP_HINT = (
    f"{OVERRIDE_ENV} is not set: PostgreSQL is the only storage engine "
    "(ADR-0019). Start one and point the suite at it, e.g.\n"
    "  docker run --rm -d --name vypam-pg -e POSTGRES_USER=pam "
    "-e POSTGRES_PASSWORD=pam -e POSTGRES_DB=pam -p 5432:5432 "
    "--shm-size=1g postgres:16\n"
    f"  export {OVERRIDE_ENV}="
    "postgresql+psycopg://pam:pam@127.0.0.1:5432/pam"
)

_lock = threading.Lock()
_counter = itertools.count()
_created: list[str] = []


def require_override() -> str:
    """The override URI, or an honest setup failure - there is no embedded
    engine to fall back to."""
    override = os.getenv(OVERRIDE_ENV)
    if not override:
        raise RuntimeError(SETUP_HINT)
    if not override.startswith("postgres"):
        scheme = override.split("://", 1)[0] if "://" in override else override
        raise RuntimeError(
            f"{OVERRIDE_ENV} must be a PostgreSQL URI - PostgreSQL is the "
            f"only storage engine (ADR-0019); got {scheme!r}"
        )
    return override


def _maintenance_url(override: str) -> str:
    """The override URI rebased onto the 'postgres' maintenance database,
    in psycopg's native 'postgresql://' spelling."""
    from sqlalchemy.engine import make_url

    url = make_url(override).set(
        drivername=make_url(override).get_backend_name(), database="postgres"
    )
    return url.render_as_string(hide_password=False)


def _database_url(override: str, database: str) -> str:
    """The app-facing URI for one freshly created database - drivername
    preserved (postgresql+psycopg) so SQLAlchemy selects psycopg 3."""
    from sqlalchemy.engine import make_url

    return (
        make_url(override)
        .set(database=database)
        .render_as_string(hide_password=False)
    )


def test_database_uri(tmp_path: Path, name: str = "licenses.db") -> str:
    """A unique fresh PostgreSQL database per call (ADR-0019 D5); main
    configs and peer configs never share state. ``tmp_path`` and ``name``
    stay in the signature for the suite's call sites - the store no longer
    lives in a per-test file."""
    override = require_override()
    import psycopg

    database = f"pam_t_{os.getpid()}_{next(_counter)}_{os.urandom(3).hex()}"
    with psycopg.connect(_maintenance_url(override), autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{database}"')
    with _lock:
        _created.append(database)
    return _database_url(override, database)


def created_databases() -> list[str]:
    with _lock:
        return list(_created)


def drop_created_databases() -> int:
    """Drop every database this helper created (FORCE terminates stray
    pooled connections; PostgreSQL 13+, pinned image 16)."""
    with _lock:
        names = list(_created)
        _created.clear()
    if not names:
        return 0
    import psycopg

    override = require_override()
    dropped = 0
    with psycopg.connect(_maintenance_url(override), autocommit=True) as conn:
        for database in names:
            conn.execute(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)')
            dropped += 1
    return dropped
