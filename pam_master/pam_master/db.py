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
CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT NOT NULL UNIQUE,
    license_key TEXT NOT NULL,
    customer_public_id TEXT NOT NULL
        REFERENCES customers (public_id),
    license_type TEXT NOT NULL,
    tier TEXT NOT NULL,
    plan TEXT,
    algorithm TEXT NOT NULL,
    status TEXT NOT NULL,
    issued_date TEXT NOT NULL,
    expires_on TEXT,
    fingerprint TEXT NOT NULL,
    superseded_by TEXT,
    archive_ct TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_licenses_customer
    ON licenses (customer_public_id);
CREATE TABLE IF NOT EXISTS master_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    subject TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL
);
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
