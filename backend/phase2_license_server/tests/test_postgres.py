"""PostgreSQL storage-engine contract (ADR-0019, amended).

PostgreSQL is the only storage engine (D10), so this module always runs:
the suite requires ``PAM_TEST_DATABASE_URI`` (the CI job's service
container, or a local ``postgres:16``) and the central override (D5)
hands each test its own fresh database. Every property is checked against
the live engine - triggers, advisory-lock id allocation, inspector
migration, token at rest - plus the fail-fast startup contract (D8).
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest
from sqlalchemy import inspect as sa_inspect, text

SERVER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_DIR.parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

from app import create_app  # noqa: E402
from config import Config  # noqa: E402
from _testdb import test_database_uri  # noqa: E402
import audit as audit_module  # noqa: E402
from extensions import db  # noqa: E402
from models import SettingsEvent, ensure_schema  # noqa: E402

ADMIN = {"Authorization": "Bearer test-admin-token"}
ACTOR = {"X-Actor": "admin", "Authorization": "Bearer test-admin-token"}

APPEND_ONLY = "audit_events is append-only (architecture 19)"


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        database_uri=test_database_uri(tmp_path),
        private_key_path=REPO_ROOT / "license_private_key.pem",
        public_key_path=REPO_ROOT / "license_public_key.pem",
        ed25519_private_key_path=tmp_path / "license_ed25519_private.pem",
        ed25519_public_key_path=tmp_path / "license_ed25519_public_key.pem",
        secret_key="test-pg-secret",
        admin_token="test-admin-token",
        autogenerate_keys=False,
        default_trial_days=30,
        vault_key_path=tmp_path / "vault.key",
    )


@pytest.fixture
def app(config: Config):
    application = create_app(config)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def test_pg_startup_installs_both_triggers_and_relaxes_the_soft_index(app):
    # a fresh database: the startup path ran ensure_schema (D2) and the
    # trigger install (D3) during create_app
    with app.app_context():
        assert audit_module.triggers_installed(db.engine) is True
        indexes = {
            row["name"]: row
            for row in sa_inspect(db.engine).get_indexes("gateway_nodes")
        }
        soft = indexes["ix_gateway_nodes_name"]
        assert not soft.get("unique"), "the soft index must be relaxed to non-unique"
        zone_fks = [
            fk
            for fk in sa_inspect(db.engine).get_foreign_keys("gateway_nodes")
            if fk.get("name") == "gateway_nodes_zone_id_fkey"
        ]
        assert zone_fks == [], "the evidence FK is dropped at startup (ADR-0019)"
    # second startup over the same database is idempotent (D3/D2 contracts)
    with app.app_context():
        assert audit_module.ensure_audit_chain() == 0
        assert audit_module.triggers_installed(db.engine) is True
        assert ensure_schema(db.engine) == []


def test_pg_append_only_triggers_raise_the_verbatim_message(client, app):
    response = client.put(
        "/api/v1/settings/zsp", json={"tier0_quorum_approvers": 2}, headers=ACTOR
    )
    assert response.status_code == 200
    with app.app_context():
        seq = db.session.execute(
            text("SELECT seq FROM audit_events ORDER BY seq DESC LIMIT 1")
        ).scalar()
        assert seq is not None, "the settings write must be in the ledger"
        with pytest.raises(Exception) as update:
            db.session.execute(
                text("UPDATE audit_events SET action='tampered' WHERE seq=:seq"),
                {"seq": seq},
            )
        assert APPEND_ONLY in str(update.value)
        db.session.rollback()
        with pytest.raises(Exception) as delete:
            db.session.execute(
                text("DELETE FROM audit_events WHERE seq=:seq"), {"seq": seq}
            )
        assert APPEND_ONLY in str(delete.value)
        db.session.rollback()


def test_pg_id_allocation_takes_the_advisory_lock(app):
    with app.app_context():
        session = db.session
        row = SettingsEvent(group_name="pg", action="probe", changes={})
        pending: dict = {}
        audit_module._ensure_id(session, row, pending)
        assert row.id == 1, "a fresh database starts at 1 (max+1)"
        key = audit_module._id_lock_key("settings_events")
        held = session.execute(
            text(
                "SELECT count(*) FROM pg_locks "
                "WHERE locktype='advisory' AND pid = pg_backend_pid() "
                "AND classid = :classid AND objid = :objid"
            ),
            {"classid": (key >> 32) & 0xFFFFFFFF, "objid": key & 0xFFFFFFFF},
        ).scalar()
        assert held == 1, "the allocation lock for this table must be held"
        session.rollback()


def test_pg_concurrent_id_allocation_stays_unique(app):
    threads, per_thread = 8, 5
    start = threading.Barrier(threads)

    def worker() -> None:
        with app.app_context():
            start.wait()
            for index in range(per_thread):
                db.session.add(
                    SettingsEvent(group_name="pg-conc", action=f"w{index}", changes={})
                )
                db.session.commit()
            db.session.remove()

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()
    with app.app_context():
        ids = [
            value
            for (value,) in db.session.execute(
                text("SELECT id FROM settings_events ORDER BY id")
            ).fetchall()
        ]
    assert len(ids) == threads * per_thread
    assert len(set(ids)) == len(ids), "advisory-locked max+1 must never collide"


def test_pg_ensure_schema_readds_a_dropped_spec_column(app):
    with app.app_context():
        engine = db.engine
        with engine.begin() as conn:
            # last_reported_at is the spec's DATETIME token - the dialect map
            # must re-add it as TIMESTAMP on PostgreSQL (D2)
            conn.exec_driver_sql("ALTER TABLE licenses DROP COLUMN last_reported_at")
        added = ensure_schema(engine)
        assert "licenses.last_reported_at" in added
        columns = {
            column["name"]: column
            for column in sa_inspect(engine).get_columns("licenses")
        }
        assert "TIMESTAMP" in str(columns["last_reported_at"]["type"]).upper()
        assert ensure_schema(engine) == [], "a current schema reports no changes"


def test_config_refuses_a_missing_database_uri(monkeypatch):
    # D8 (fail-fast startup contract): no embedded default engine exists
    monkeypatch.delenv("LICENSE_DATABASE_URI", raising=False)
    with pytest.raises(ValueError, match="LICENSE_DATABASE_URI is not set"):
        Config.from_env()


def test_config_refuses_a_sqlite_uri(monkeypatch):
    # a stale .env line fails loudly at boot instead of silently reverting
    monkeypatch.setenv("LICENSE_DATABASE_URI", "sqlite:///licenses.db")
    with pytest.raises(ValueError, match="SQLite was removed"):
        Config.from_env()


def test_pg_role_binding_token_is_sha256_at_rest(client, app):
    created = client.post(
        "/api/v1/role-bindings",
        json={"principal": "svc-pg-nightly", "role": "auditor", "kind": "local"},
        headers=ADMIN,
    )
    assert created.status_code == 201, created.get_json()
    body = created.get_json()
    token = body.get("token")
    binding_id = body["binding"]["id"]
    assert token, "the token is shown once, at creation"
    with app.app_context():
        stored = db.session.execute(
            text("SELECT token_sha256 FROM role_bindings WHERE id=:id"),
            {"id": binding_id},
        ).scalar()
    assert stored and stored != token
    assert len(stored) == 64
