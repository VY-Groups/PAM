"""SQLite access for VY-PAM MASTER (no ORM — the schema is two tables and
the product installs directly, no external services)."""
from __future__ import annotations

import sqlite3

from pam_master.config import Config

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id TEXT NOT NULL UNIQUE,
    data_ct TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS issuance_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_public_id TEXT NOT NULL
        REFERENCES customers (public_id),
    license_id TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_issuance_customer
    ON issuance_history (customer_public_id);
"""


def connect(config: Config) -> sqlite3.Connection:
    """Open the configured database (row factory + FK enforcement on)."""
    connection = sqlite3.connect(str(config.database_path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_schema(connection: sqlite3.Connection) -> None:
    """Create tables/indexes if absent (idempotent)."""
    connection.executescript(SCHEMA)


def table_count(connection: sqlite3.Connection) -> int:
    """Real count of application tables (used by /health)."""
    row = connection.execute(
        "SELECT count(*) FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchone()
    return int(row[0])
