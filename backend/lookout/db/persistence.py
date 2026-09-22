"""Write-through persistence to PostgreSQL (or SQLite in tests).

Detection runs in memory -- baselines, the forest, session context and the
shadow ledger -- because the demo must start from a known state and warm up
in under a second. What an auditor or analyst needs to keep is written through
to the database as it happens: logins, activity, messages and their URL
analysis, threat events, risk scores, alerts, incidents, quarantine, sessions
and the hash-chained audit log.

Enabled by ``DATABASE_URL``. Without it Lookout behaves exactly as before. A
database failure is logged and swallowed: losing a row is bad, but blocking
detection because the database hiccupped would be worse.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session as DBSession
from sqlalchemy.orm import sessionmaker

from ..generator import BY_ACTOR
from ..models import PRIVILEGE_LEVEL, Action, ActionTaken, Decision, Role
from ..urlcheck import inspect_all
from .schema import (
    ActivityLogRow,
    AlertRow,
    AuditLogRow,
    Base,
    IncidentRow,
    LoginEventRow,
    MessageRow,
    PermissionRow,
    QuarantinedMessageRow,
    RiskScoreRow,
    RoleRow,
    SessionRow,
    ThreatEventRow,
    UrlAnalysisRow,
    UserRow,
)

if TYPE_CHECKING:
    from ..audit import AuditEntry
    from ..auth import AuthStore
    from ..incidents import Alert, Incident

log = logging.getLogger("lookout.db")

ROLE_DESCRIPTIONS = {
    "teller": "Branch teller: customer service, small transfers",
    "officer": "Relationship / loans officer",
    "analyst": "Data and risk analyst",
    "manager": "Branch manager: team oversight, approvals",
    "dba": "Database administrator (privileged)",
    "sysadmin": "Systems administrator (privileged)",
    "domain_admin": "Domain administrator (most privileged)",
    "soc_analyst": "Security operations analyst",
    "super_admin": "Platform super administrator",
}

#: (permission name, resource, action, roles granted it)
PERMISSIONS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("customer_db.read", "customer_database", "read", ("officer", "analyst", "manager", "dba", "domain_admin")),
    ("customer_db.export", "customer_database", "export", ("manager", "dba")),
    ("transactions.read", "transaction_database", "read", ("officer", "analyst", "manager", "dba")),
    ("funds.transfer", "payments", "transfer", ("teller", "officer", "manager")),
    ("messages.customer", "message_gateway", "send_customer", ("officer", "manager", "domain_admin")),
    ("messages.bulk", "message_gateway", "send_bulk", ("manager", "domain_admin")),
    ("payroll.read", "payroll_system", "read", ("manager",)),
    ("finance.read", "financial_records", "read", ("manager", "analyst")),
    ("auth_server.admin", "authentication_server", "admin", ("sysadmin", "domain_admin")),
    ("admin_console.use", "admin_console", "use", ("sysadmin", "domain_admin", "super_admin")),
    ("vault.read", "credential_vault", "read", ("dba", "sysadmin", "domain_admin")),
    ("iam.change", "iam", "change", ("sysadmin", "domain_admin", "super_admin")),
    ("soc.console", "soc_console", "use", ("soc_analyst", "super_admin")),
    ("policy.manage", "security_policy", "manage", ("super_admin",)),
)


def normalise_url(url: str) -> str:
    """psycopg 3 needs the ``postgresql+psycopg`` scheme; plain
    ``postgresql://`` would load psycopg2, which is not installed."""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime | None) -> datetime | None:
    """Simulated event times are naive; PostgreSQL hands back aware ones.
    Treat naive as UTC so the two can be compared and stored consistently."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


class Persistence:
    def __init__(self, url: str) -> None:
        self.url = normalise_url(url)
        kwargs: dict[str, Any] = {"future": True, "pool_pre_ping": True}
        if self.url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        else:
            # Fail fast on an unreachable server rather than hang start-up.
            kwargs["connect_args"] = {"connect_timeout": 5}
        self.engine = create_engine(self.url, **kwargs)
        self.Session = sessionmaker(self.engine, expire_on_commit=False)
        self.run_id = str(uuid.uuid4())
        self._user_ids: dict[str, int] = {}
        self._lock = threading.Lock()

    # -- setup ------------------------------------------------------------- #

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    def seed(self, auth: "AuthStore") -> None:
        """Roles, permissions, their links, and one row per account.
        Idempotent: safe on every start-up."""
        with self.Session.begin() as db:
            roles: dict[str, RoleRow] = {r.name: r for r in db.scalars(select(RoleRow))}
            for name, desc in ROLE_DESCRIPTIONS.items():
                if name not in roles:
                    level = PRIVILEGE_LEVEL[Role(name)] if name in {r.value for r in Role} else (7 if name == "super_admin" else 3)
                    roles[name] = RoleRow(name=name, description=desc, privilege_level=level)
                    db.add(roles[name])
            db.flush()
            perms = {p.name: p for p in db.scalars(select(PermissionRow))}
            for name, resource, action, granted in PERMISSIONS:
                perm = perms.get(name) or PermissionRow(name=name, resource=resource, action=action)
                db.add(perm)
                perm.roles = [roles[g] for g in granted]
            db.flush()
            users = {u.username: u for u in db.scalars(select(UserRow))}
            for acct in auth.accounts():
                name = acct["username"]
                staff = BY_ACTOR.get(name)
                role = staff.role.value if staff else ("super_admin" if acct["kind"] == "superadmin" else "soc_analyst")
                row = users.get(name) or UserRow(username=name, created_at=_now())
                row.email = f"{name.replace(chr(39), '')}@meridianbank.example"
                row.password_hash = auth.stored_hash(name)
                row.role_id = roles[role].id
                row.department = staff.city if staff else ("Security" if role == "soc_analyst" else "Head office")
                row.status = "disabled" if acct["disabled"] else "active"
                db.add(row)
            db.flush()
            self._user_ids = {u.username: u.id for u in db.scalars(select(UserRow))}

    def uid(self, username: str | None) -> int | None:
        return self._user_ids.get(username or "")

    # -- write-through --------------------------------------------------------- #

    def _write(self, fn) -> None:
        try:
            with self._lock, self.Session.begin() as db:
                fn(db)
        except Exception:  # noqa: BLE001 -- never let storage break detection
            log.exception("database write failed")

    def record_decision(self, d: Decision) -> None:
        def write(db: DBSession) -> None:
            e, uid = d.event, self.uid(d.event.actor)
            ts = _utc(e.ts)
            level = d.risk.band.value.upper()
            if e.action in (Action.LOGIN, Action.LOGIN_FAILED):
                db.add(LoginEventRow(
                    user_id=uid, event_id=e.event_id, timestamp=ts, ip_address=e.source_ip,
                    device_id=e.device_id, latitude=e.geo.lat, longitude=e.geo.lon,
                    location=f"{e.geo.city}, {e.geo.country}", success=e.success,
                    risk_score=d.risk.total, risk_level=level,
                ))
            db.add(ActivityLogRow(
                user_id=uid, event_id=e.event_id, activity_type=e.action.value, resource=e.resource,
                action=d.action_taken.value, timestamp=ts, risk_score=d.risk.total,
                metadata_={k: v for k, v in e.meta.items() if isinstance(v, (str, int, float, bool))},
            ))
            if e.message is not None:
                msg = MessageRow(
                    event_id=e.event_id, sender_id=uid, recipient=e.message.audience,
                    message_type=e.message.channel, content=e.message.body or e.message.subject,
                    recipient_count=e.message.recipient_count, timestamp=ts,
                    status=d.action_taken.value, risk_score=d.risk.total,
                )
                db.add(msg)
                db.flush()
                for v in inspect_all(e.message.urls):
                    db.add(UrlAnalysisRow(
                        message_id=msg.id, url=v.url, risk_score=round(v.score * 100, 1),
                        classification="suspicious" if v.suspicious else "clean",
                        reason="; ".join(v.findings),
                    ))
                if d.quarantine_id:
                    db.add(QuarantinedMessageRow(
                        id=d.quarantine_id, run_id=self.run_id, message_id=msg.id,
                        reason=d.policy or d.narrative, risk_score=d.risk.total,
                    ))
            if d.threat_class.value != "benign":
                db.add(ThreatEventRow(
                    user_id=uid, event_id=e.event_id, event_type=e.action.value,
                    classification=d.threat_class.value,
                    confidence=(d.ml or {}).get("confidence"),
                    ml_classification=(d.ml or {}).get("classification"),
                    risk_score=d.risk.total, timestamp=ts,
                ))
            db.add(RiskScoreRow(
                user_id=uid, event_id=e.event_id, score=d.risk.total, risk_level=level, timestamp=ts,
                explanation={
                    "reasons": [s.explanation for s in d.risk.signals],
                    "signals": {s.name: s.points for s in d.risk.signals},
                    "privilege_multiplier": d.risk.privilege_multiplier,
                    "action": d.action_taken.value,
                    "policy": d.policy,
                },
            ))
            session_id = str(e.meta.get("session_id") or "")
            if session_id:
                row = db.get(SessionRow, session_id)
                if row is None:
                    row = SessionRow(id=session_id, user_id=uid, device_id=e.device_id, ip_address=e.source_ip,
                                     start_time=ts, last_activity=ts)
                    db.add(row)
                row.last_activity = max(_utc(row.last_activity), ts) if row.last_activity else ts
                row.risk_score = max(row.risk_score or 0.0, d.risk.total)
                if d.action_taken is ActionTaken.BLOCK_AND_ALERT or (
                    d.action_taken is ActionTaken.BLOCK and e.action is Action.LOGIN
                ):
                    row.status = "revoked"
        self._write(write)

    def record_audit(self, entry: "AuditEntry") -> None:
        def write(db: DBSession) -> None:
            p = entry.payload
            db.add(AuditLogRow(
                run_id=self.run_id, seq=entry.seq, user_id=self.uid(p.get("actor") or p.get("username") or p.get("by")),
                action=entry.kind, resource=str(p.get("resource") or p.get("doc_ref") or p.get("reference") or ""),
                timestamp=_utc(entry.ts), ip_address=str(p.get("source_ip") or ""),
                integrity_hash=entry.entry_hash, prev_hash=entry.prev_hash,
                payload={k: v for k, v in p.items() if isinstance(v, (str, int, float, bool, list, dict, type(None)))},
            ))
        self._write(write)

    def upsert_alert(self, a: "Alert") -> None:
        def write(db: DBSession) -> None:
            row = db.get(AlertRow, (a.id, self.run_id)) or AlertRow(id=a.id, run_id=self.run_id, created_at=_utc(a.ts))
            row.user_id, row.severity, row.alert_type = self.uid(a.user), a.severity, a.alert_type
            row.description, row.risk_score, row.status = a.description, a.risk_score, a.status
            row.detail = {"reasons": a.reasons, "recommended_action": a.recommended_action,
                          "event_id": a.event_id, "incident_id": a.incident_id, "classification": a.classification}
            db.add(row)
        self._write(write)

    def upsert_incident(self, i: "Incident") -> None:
        def write(db: DBSession) -> None:
            row = db.get(IncidentRow, (i.id, self.run_id)) or IncidentRow(id=i.id, run_id=self.run_id, created_at=_utc(i.created_at))
            row.title, row.severity, row.user_id = i.title, i.severity, self.uid(i.user)
            row.description, row.status, row.assigned_to = i.ai_explanation, i.status, i.assigned_to
            row.resolved_at = _utc(i.resolved_at)
            row.detail = {"threat_type": i.threat_type, "risk_score": i.risk_score, "alert_ids": i.alert_ids,
                          "evidence": i.evidence, "actions_taken": i.actions_taken, "notes": i.notes,
                          "timeline": i.timeline}
            db.add(row)
        self._write(write)

    def review_quarantine(self, qid: str, reviewer: str, status: str) -> None:
        def write(db: DBSession) -> None:
            row = db.get(QuarantinedMessageRow, (qid, self.run_id))
            if row is not None:
                row.status, row.reviewed_by, row.reviewed_at = status, reviewer, _now()
        self._write(write)

    def open_session(self, session_id: str, username: str, device: str = "", ip: str = "") -> None:
        def write(db: DBSession) -> None:
            if db.get(SessionRow, session_id) is None:
                db.add(SessionRow(id=session_id, user_id=self.uid(username), device_id=device, ip_address=ip,
                                  start_time=_now(), last_activity=_now()))
        self._write(write)

    def close_session(self, session_id: str, status: str = "ended") -> None:
        def write(db: DBSession) -> None:
            row = db.get(SessionRow, session_id)
            if row is not None:
                row.status, row.last_activity = status, _now()
        self._write(write)

    def set_user_status(self, username: str, status: str) -> None:
        def write(db: DBSession) -> None:
            uid = self.uid(username)
            row = db.get(UserRow, uid) if uid else None
            if row is not None:
                row.status = status
        self._write(write)

    # -- reading ------------------------------------------------------------ #

    def counts(self) -> dict[str, int]:
        from sqlalchemy import func

        out = {}
        with self.Session() as db:
            for table in Base.metadata.sorted_tables:
                out[table.name] = db.scalar(select(func.count()).select_from(table)) or 0
        return out

    def audit_integrity(self, run_id: str | None = None) -> dict[str, Any]:
        """Re-check the persisted chain: each row's prev_hash must equal the
        previous row's integrity_hash."""
        run = run_id or self.run_id
        with self.Session() as db:
            rows = db.scalars(select(AuditLogRow).where(AuditLogRow.run_id == run).order_by(AuditLogRow.seq)).all()
        prev = "0" * 64
        for r in rows:
            if r.prev_hash != prev:
                return {"ok": False, "rows": len(rows), "broken_at": r.seq}
            prev = r.integrity_hash
        return {"ok": True, "rows": len(rows), "broken_at": None}


def from_env() -> Persistence | None:
    import os

    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        return None
    try:
        p = Persistence(url)
        p.create_schema()
    except Exception as e:  # noqa: BLE001 -- any connection failure means "no database"
        # A hosted free database can expire or be asleep. Run in memory rather
        # than refuse to start; /api/db/status then says the database is off.
        import logging

        logging.getLogger("lookout.db").error("database unavailable, running in memory: %s", e)
        return None
    return p

