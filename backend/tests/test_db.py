"""Persistence: schema, seeding, write-through, and the stored audit chain.

Runs on SQLite by default. Set LOOKOUT_TEST_DATABASE_URL (for example
postgresql://lookout:lookout@localhost:5434/lookout) to run the same tests
against PostgreSQL; CI does.
"""

import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

import lookout.api as api_mod
from lookout.auth import DEMO_ACCOUNTS, AuthStore
from lookout.db.persistence import Persistence, normalise_url
from lookout.db.schema import TABLES, AuditLogRow, UserRow

PASSWORDS = {u: p for u, p, _ in DEMO_ACCOUNTS}
SPEC_TABLES = {
    "users", "roles", "permissions", "role_permissions", "login_events", "sessions",
    "activity_logs", "messages", "url_analysis", "threat_events", "alerts",
    "quarantined_messages", "incidents", "audit_logs", "risk_scores",
}


def _urls(tmp_path):
    urls = [f"sqlite:///{tmp_path / 'lookout.db'}"]
    pg = os.getenv("LOOKOUT_TEST_DATABASE_URL")
    if pg:
        urls.append(pg)
    return urls


@pytest.fixture(params=["sqlite", "postgres"])
def db(request, tmp_path):
    if request.param == "postgres":
        url = os.getenv("LOOKOUT_TEST_DATABASE_URL")
        if not url:
            pytest.skip("LOOKOUT_TEST_DATABASE_URL not set")
        # A private schema per test, so runs never collide or leave debris.
        schema = f"t_{uuid.uuid4().hex[:10]}"
        p = Persistence(url)
        with p.engine.begin() as c:
            c.execute(text(f"CREATE SCHEMA {schema}"))
        p.engine.dispose()
        p = Persistence(url)
        from sqlalchemy import event

        @event.listens_for(p.engine, "connect")
        def _search_path(dbapi, _):
            with dbapi.cursor() as cur:
                cur.execute(f"SET search_path TO {schema}")

        p.create_schema()
        yield p
        p.engine.dispose()
        cleanup = Persistence(url)
        with cleanup.engine.begin() as c:
            c.execute(text(f"DROP SCHEMA {schema} CASCADE"))
        cleanup.engine.dispose()
    else:
        p = Persistence(f"sqlite:///{tmp_path / 'lookout.db'}")
        p.create_schema()
        yield p
        p.engine.dispose()


def test_all_specified_tables_exist(db):
    assert SPEC_TABLES <= set(TABLES)
    from sqlalchemy import inspect

    assert SPEC_TABLES <= set(inspect(db.engine).get_table_names())


def test_url_normalisation():
    assert normalise_url("postgresql://u:p@h/d") == "postgresql+psycopg://u:p@h/d"
    assert normalise_url("postgres://u:p@h/d") == "postgresql+psycopg://u:p@h/d"
    assert normalise_url("sqlite:///x.db") == "sqlite:///x.db"


def test_seed_roles_permissions_users(db):
    auth = AuthStore()
    db.seed(auth)
    db.seed(auth)  # idempotent
    counts = db.counts()
    assert counts["users"] == len(DEMO_ACCOUNTS)
    assert counts["roles"] == 9 and counts["permissions"] >= 10 and counts["role_permissions"] > counts["permissions"]
    with db.Session() as s:
        admin = s.scalar(select(UserRow).where(UserRow.username == "n.pillai"))
        assert admin.role.name == "domain_admin" and admin.role.privilege_level == 6
        assert admin.password_hash.startswith("pbkdf2_sha256$")
        assert "Admin@Pillai12" not in admin.password_hash


def test_engine_decisions_write_through(db):
    from datetime import datetime

    from lookout.narrator import Narrator
    from lookout.pipeline import Engine
    from lookout.scenarios import build

    auth = AuthStore()
    db.seed(auth)
    engine = Engine(narrator=Narrator(api_key=""))
    engine.audit.listeners.append(db.record_audit)
    engine.listeners.append(db.record_decision)
    engine.warm_up()
    now = datetime(2026, 9, 28, 10, 0)
    engine.ingest_many(build("phishing_blast", now=now))
    engine.ingest_many(build("compromised_account", now=now))
    c = db.counts()
    assert c["activity_logs"] == 5 and c["risk_scores"] == 5
    assert c["login_events"] == 2
    assert c["messages"] == 2 and c["url_analysis"] == 2
    assert c["threat_events"] >= 3
    assert c["audit_logs"] == len(engine.audit.entries)
    assert db.audit_integrity() == {"ok": True, "rows": len(engine.audit.entries), "broken_at": None}


def test_tampering_with_stored_audit_rows_is_detected(db):
    from lookout.audit import AuditLog

    log = AuditLog()
    log.listeners.append(db.record_audit)
    for i in range(5):
        log.append("decision", {"i": i})
    with db.Session.begin() as s:
        row = s.scalar(select(AuditLogRow).where(AuditLogRow.seq == 2))
        row.integrity_hash = "f" * 64  # someone edits the stored hash in SQL
    result = db.audit_integrity()
    assert not result["ok"] and result["broken_at"] == 3


def test_a_broken_database_never_breaks_detection(tmp_path):
    p = Persistence(f"sqlite:///{tmp_path / 'x.db'}")  # schema never created
    from lookout.audit import AuditLog

    log = AuditLog()
    log.listeners.append(p.record_audit)
    log.append("decision", {"ok": True})  # must not raise
    assert len(log.entries) == 1


# -- through the API -------------------------------------------------------- #


@pytest.fixture
def api_with_db(db, monkeypatch):
    monkeypatch.setattr(api_mod, "_db", db)
    monkeypatch.setattr(api_mod, "_db_loaded", True)
    with TestClient(api_mod.app) as c:
        token = c.post("/api/auth/login", json={"username": "soc.analyst", "password": PASSWORDS["soc.analyst"]}).json()["token"]
        c.headers.update({"Authorization": f"Bearer {token}"})
        c.post("/api/reset")
        yield c, db


def test_api_persists_alerts_incidents_sessions_and_audit(api_with_db):
    c, db = api_with_db
    c.post("/api/scenarios/credential_stuffing/run")
    emp = c.post("/api/auth/login", json={"username": "p.nair", "password": PASSWORDS["p.nair"]}).json()["token"]
    c.post("/api/messages/scan", json={"sender": "p.nair", "recipient_count": 1,
                                      "body": "log in: https://meridianbamk.com/login"})
    inc = c.get("/api/incidents").json()[0]["id"]
    c.post(f"/api/incidents/{inc}/notes", json={"text": "persist me"})
    status = c.get("/api/db/status").json()
    assert status["enabled"] and status["audit_chain"]["ok"]
    rows = status["rows"]
    assert rows["alerts"] >= 1 and rows["incidents"] >= 1
    assert rows["quarantined_messages"] == 1
    assert rows["sessions"] >= 2
    from lookout.db.schema import IncidentRow

    with db.Session() as s:
        stored = s.scalar(select(IncidentRow).where(IncidentRow.id == inc, IncidentRow.run_id == db.run_id))
        assert any(n["text"] == "persist me" for n in stored.detail["notes"])
    assert emp


def test_db_status_when_disabled(monkeypatch):
    monkeypatch.setattr(api_mod, "_db", None)
    monkeypatch.setattr(api_mod, "_db_loaded", True)
    with TestClient(api_mod.app) as c:
        token = c.post("/api/auth/login", json={"username": "soc.analyst", "password": PASSWORDS["soc.analyst"]}).json()["token"]
        assert c.get("/api/db/status", headers={"Authorization": f"Bearer {token}"}).json()["enabled"] is False
