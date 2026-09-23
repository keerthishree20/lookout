"""Routes added to cover the rest of the project specification.

Registered on the same app as :mod:`lookout.api` (imported at the bottom of
that module), so the same authentication middleware and role map apply:
``/api/portal/*`` is employees only, ``/api/admin/*`` Super Admin only, and
everything else here is the SOC console.

* spec §31 routes that were missing: ``/api/activity/analyze``,
  ``/api/risk/calculate``, ``/api/messages``, ``/api/audit-logs``,
  ``/api/quarantine/{id}/block``;
* quarantine Delete and Investigate (§19);
* the post-quantum protected store (§29);
* employee self-service: own profile, own activity, requesting a protected
  resource (§4, §8);
* the Privileged Administrator's admin operations, with enhanced monitoring,
  and privilege-escalation detection when anyone else tries them (§4, §9);
* Super Admin role and system configuration management (§4).
"""

from __future__ import annotations

import secrets
from typing import Any

from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from . import api as A
from .auth import Session
from .generator import BY_ACTOR, ROSTER
from .models import BULK_COMMS_ROLES, CUSTOMER_COMMS_ROLES, PRIVILEGE_LEVEL, TRANSFER_LIMITS, Action, Role
from .notify import NotifySettings
from .policy import POLICY, PolicyError
from .reporting import incident_report, report_filename
from .runtime import CONFIG, ROLE_OVERRIDES
from .runtime import update as update_config

app = A.app


def _signed_in(request: Request) -> str:
    return A.current_session(request).username


# --------------------------------------------------------------------------- #
# Spec §31 routes
# --------------------------------------------------------------------------- #


@app.post("/api/activity/analyze")
def analyze_activity(body: A.IngestRequest) -> dict[str, Any]:
    """Score and act on one activity (same as ``POST /api/events``)."""
    return A.ingest(body)


@app.post("/api/risk/calculate")
def calculate_risk(body: A.IngestRequest) -> dict[str, Any]:
    """What would Lookout do with this activity? Scores it without acting on
    it or recording it: no audit entry, no alert, no baseline update."""
    d = A.get_state().engine.assess(body.event)
    out = {
        "risk_score": d.risk.total,
        "risk_level": d.risk.band.value.upper(),
        "action": d.action_taken.value,
        "classification": d.threat_class.value,
        "policy": d.policy,
        "reasons": [s.explanation for s in d.risk.signals],
        "arithmetic": {
            "rule_points": d.risk.rule_points,
            "model_points": d.risk.model_points,
            "privilege_multiplier": d.risk.privilege_multiplier,
        },
        "recorded": False,
    }
    if d.event.action is Action.SEND_MESSAGE:
        out["message_components"] = A.message_components(d)
    return out


@app.get("/api/messages")
def messages(
    status: str | None = Query(None, pattern="^(DELIVERED|VERIFICATION_REQUIRED|QUARANTINED|BLOCKED)$"),
    q: str = "",
    limit: int = Query(200, ge=1, le=1000),
) -> list[dict[str, Any]]:
    """Every message the gateway has scanned, newest first."""
    rows = [
        A._message_row(d)
        for d in reversed(A.get_state().engine.decisions)
        if d.event.action is Action.SEND_MESSAGE
    ]
    if status:
        rows = [r for r in rows if r["status"] == status]
    if q.strip():
        needle = q.strip().lower()
        rows = [r for r in rows if needle in f"{r['sender']} {r['recipient']} {r['subject']} {r['body']}".lower()]
    return rows[:limit]


@app.get("/api/messages/{message_id}")
def message(message_id: str) -> dict[str, Any]:
    for d in reversed(A.get_state().engine.decisions):
        if d.event.event_id == message_id and d.event.action is Action.SEND_MESSAGE:
            return {**A._message_row(d), "decision": A._dump(d)}
    raise HTTPException(404, "no such message")


@app.get("/api/audit-logs")
def audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    action: str = "",
) -> dict[str, Any]:
    """The audit log, newest first, optionally filtered by action prefix
    (``decision``, ``auth.``, ``quarantine.``, ``policy.`` ...)."""
    log = A.get_state().engine.audit
    entries = [e.model_dump(mode="json") for e in reversed(log.entries)]
    if action:
        entries = [e for e in entries if e.get("kind", "").startswith(action)]
    return {
        "entries": entries[:limit],
        "total": len(log.entries),
        "checkpoints": [c.model_dump(mode="json") for c in log.checkpoints[-10:][::-1]],
    }


# --------------------------------------------------------------------------- #
# Quarantine: Block, Delete, Investigate (Release is in api.py)
# --------------------------------------------------------------------------- #


def _close(qid: str, outcome: str, request: Request) -> dict[str, Any]:
    reviewer = _signed_in(request)
    s = A.get_state()
    d = s.engine.close_quarantine(qid, outcome, reviewer)
    if d is None:
        raise HTTPException(404, "not in quarantine")
    if A.get_db() is not None:
        A.get_db().review_quarantine(qid, reviewer, outcome)
    s.incidents.note_for_user(d.event.actor, "quarantine", f"Held message {qid} {outcome} by {reviewer}.")
    return {outcome: qid, "by": reviewer, "sender": d.event.actor}


@app.post("/api/quarantine/{qid}/block")
def quarantine_block(qid: str, request: Request) -> dict[str, Any]:
    """Confirm the held message is bad: it is never delivered and counts
    against the sender's session."""
    return _close(qid, "blocked", request)


@app.post("/api/quarantine/{qid}/delete")
def quarantine_delete(qid: str, request: Request) -> dict[str, Any]:
    """Discard the held message (junk, duplicate, test)."""
    return _close(qid, "deleted", request)


@app.post("/api/quarantine/{qid}/investigate")
def quarantine_investigate(qid: str, request: Request) -> dict[str, Any]:
    """Keep holding it and open (or add to) the sender's incident."""
    reviewer = _signed_in(request)
    s = A.get_state()
    d = s.engine.quarantine.get(qid)
    if d is None:
        raise HTTPException(404, "not in quarantine")
    incident = s.incidents._open_for(d.event.actor)
    if incident is None:
        incident = s.incidents.create(
            title=f"Held message {qid} from {d.event.actor}",
            user=d.event.actor,
            severity="HIGH" if d.risk.total >= POLICY.current.high else "MEDIUM",
            description=d.narrative,
            by=reviewer,
        )
    incident.evidence.append(d.event.event_id)
    incident.log("quarantine", f"Held message {qid} put under investigation by {reviewer}.")
    s.engine.investigate_quarantine(qid, reviewer, incident.id)
    if A.get_db() is not None:
        A.get_db().upsert_incident(incident)
    s.engine.broadcast_extra("incident", incident.as_dict(full=False))
    return {"investigating": qid, "incident_id": incident.id, "by": reviewer}


# --------------------------------------------------------------------------- #
# Post-quantum protected store (spec §29)
# --------------------------------------------------------------------------- #


@app.get("/api/crypto/artefacts")
def artefacts() -> dict[str, Any]:
    """What is sealed, under which algorithm. Never the plaintexts."""
    s = A.get_state()
    return {"artefacts": s.vault.list(), "algorithm": s.engine.sealer.algorithm,
            "quantum_safe": s.engine.sealer.quantum_safe}


@app.post("/api/crypto/artefacts/verify")
def verify_artefacts() -> dict[str, Any]:
    """Open every artefact and check it against its digest. A failure raises
    a Quantum-Safe Key/Artefact Security Event."""
    s = A.get_state()
    results = s.vault.verify()
    failed = [r for r in results if not r["ok"]]
    s.engine.audit.append("crypto.artefacts_verified", {"checked": len(results), "failed": len(failed)},
                          critical=bool(failed))
    out: dict[str, Any] = {"ok": not failed, "results": results}
    if failed:
        out["alert"] = s.integrity_alert(
            f"{len(failed)} post-quantum sealed artefact(s) failed verification.",
            [f"{r['name']}: {r['reason']}" for r in failed],
        )
    return out


@app.post("/api/crypto/artefacts/tamper")
def tamper_artefact(name: str = Query(..., max_length=120)) -> dict[str, Any]:
    """Demo only: corrupt one sealed artefact, then verify to see it caught."""
    if not CONFIG["allow_tamper_demo"]:
        raise HTTPException(403, "tamper demo disabled")
    if not A.get_state().vault.tamper(name):
        raise HTTPException(404, "no such artefact")
    return {"tampered": name}


# --------------------------------------------------------------------------- #
# Employee self-service
# --------------------------------------------------------------------------- #


@app.get("/api/portal/me")
def my_profile(session: Session = Depends(A.require_employee)) -> dict[str, Any]:
    staff = BY_ACTOR[session.username]
    role = ROLE_OVERRIDES.get(staff.actor, staff.role)
    return {
        "username": staff.actor,
        "email": f"{staff.actor.replace(chr(39), '')}@meridianbank.example",
        "role": role.value,
        "privilege_level": PRIVILEGE_LEVEL[role],
        "privileged_administrator": PRIVILEGE_LEVEL[role] >= 4,
        "city": staff.city,
        "device": staff.device,
        "working_hours": f"{staff.start_hour:02d}:00-{staff.end_hour:02d}:00",
        "may_message_customers": role in CUSTOMER_COMMS_ROLES,
    }


_ACTIVITY_WORDS = {
    Action.LOGIN: "Signed in",
    Action.LOGIN_FAILED: "Failed sign-in",
    Action.LOGOUT: "Signed out",
    Action.DB_QUERY: "Opened records",
    Action.FILE_ACCESS: "Opened a file",
    Action.SEND_MESSAGE: "Sent a message",
    Action.FUND_TRANSFER: "Fund transfer",
    Action.PRIV_ESCALATE: "Requested elevated access",
    Action.CONFIG_CHANGE: "Changed a setting",
    Action.VAULT_READ: "Opened a vault secret",
    Action.ACCESS_DENIED: "Access refused",
}


@app.get("/api/portal/activity")
def my_activity(
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(A.require_employee),
) -> list[dict[str, Any]]:
    """The employee's own recent activity. What they did, not how it was
    scored: showing scores would teach an insider where the thresholds are."""
    mine = [d for d in A.get_state().engine.decisions if d.event.actor == session.username][-limit:]
    return [
        {"ts": d.event.ts.isoformat(), "activity": _ACTIVITY_WORDS.get(d.event.action, d.event.action.value),
         "resource": d.event.resource}
        for d in reversed(mine)
    ]


#: What each protected resource looks like as an event, for monitoring.
_RESOURCE_EVENT = {
    "customer_database": (Action.DB_QUERY, "core.customers"),
    "transaction_database": (Action.DB_QUERY, "core.transactions"),
    "payroll_system": (Action.FILE_ACCESS, "hr.payroll"),
    "financial_records": (Action.FILE_ACCESS, "finance.ledgers"),
    "authentication_server": (Action.CONFIG_CHANGE, "iam.auth-server"),
    "admin_console": (Action.CONFIG_CHANGE, "admin.console"),
}


@app.get("/api/portal/resources")
def my_resources(session: Session = Depends(A.require_employee)) -> list[dict[str, Any]]:
    """Protected resources and whether this employee's role reaches them."""
    staff = BY_ACTOR[session.username]
    level = PRIVILEGE_LEVEL[ROLE_OVERRIDES.get(staff.actor, staff.role)]
    return [
        {"resource": r, "min_level": lvl, "in_role": level >= lvl}
        for r, lvl in sorted(A.RESOURCE_MIN_LEVEL.items(), key=lambda kv: kv[1])
    ]


class OpenResource(BaseModel):
    otp: str | None = Field(None, pattern=r"^\d{6}$")


@app.post("/api/portal/resources/{resource}/open")
def open_resource(
    resource: str,
    request: Request,
    body: OpenResource | None = None,
    session: Session = Depends(A.require_employee),
) -> dict[str, Any]:
    """PAM in practice: the employee asks for a protected system. Role, then
    current risk, decide; every attempt, refused or not, is a scored event."""
    s = A.get_state()
    staff = BY_ACTOR[session.username]
    verdict = A.access_decision(staff.actor, resource)
    decision = verdict["decision"]

    if decision == "DENIED":
        d = s.engine.ingest(A._portal_event(staff, Action.ACCESS_DENIED, s, session.session_id, resource=resource))
        raise HTTPException(403, {"decision": "DENIED", "reason": verdict["reason"], "risk": d.risk.total})

    if decision == "BLOCK_AND_REVOKE":
        A.get_auth().revoke(session.session_id)
        s.engine.ctx.revoke(session.session_id)
        s.engine.audit.append("access.blocked", {"user": staff.actor, "resource": resource, **verdict}, critical=True)
        raise HTTPException(403, {"decision": decision, "reason": verdict["reason"]})

    if decision == "MFA_REQUIRED":
        key = f"{staff.actor}|{resource}"
        pending = s.mfa_challenges.get(key)
        if body is None or body.otp is None or pending is None or not secrets.compare_digest(body.otp, pending["otp"]):
            otp = f"{secrets.randbelow(1_000_000):06d}"
            s.mfa_challenges[key] = {"otp": otp}
            return {"decision": "MFA_REQUIRED", "reason": verdict["reason"], "demo_otp": otp,
                    "note": "Simulated second factor: re-send with this code."}
        s.mfa_challenges.pop(key, None)

    action, res = _RESOURCE_EVENT[resource]
    meta: dict[str, Any] = {"record_count": 25} if action is Action.DB_QUERY else {}
    d = s.engine.ingest(A._portal_event(staff, action, s, session.session_id, resource=res, **meta))
    s.ledger.record_activity(staff.actor, "opened a protected resource", resource=resource)
    return {
        "decision": "RESTRICTED" if decision == "RESTRICTED" else "ALLOWED",
        "access": "read-only, no export" if decision == "RESTRICTED" else "granted",
        "monitoring": verdict["monitoring"],
        "resource": resource,
        "event_id": d.event.event_id,
    }


# --------------------------------------------------------------------------- #
# Privileged Administrator operations (in the employee portal)
# --------------------------------------------------------------------------- #


def _require_privileged_admin(request: Request, session: Session, what: str) -> Any:
    """Level 4+ only. Anyone else trying is a privilege-escalation attempt,
    scored as one (spec §9), not merely refused."""
    staff = BY_ACTOR[session.username]
    role = ROLE_OVERRIDES.get(staff.actor, staff.role)
    if PRIVILEGE_LEVEL[role] >= 4:
        return staff
    s = A.get_state()
    d = s.engine.ingest(
        A._portal_event(staff, Action.PRIV_ESCALATE, s, session.session_id, resource="admin.console",
                        target_role=Role.DOMAIN_ADMIN.value, attempted=what)
    )
    raise HTTPException(403, {"decision": "DENIED", "reason": "administrators only",
                              "logged_as": "PRIVILEGE_ESCALATION_ATTEMPT", "risk": d.risk.total})


def _admin_event(staff, session: Session, resource: str, **meta) -> dict[str, Any]:
    """Every admin operation is a scored CONFIG_CHANGE: enhanced monitoring."""
    s = A.get_state()
    d = s.engine.ingest(A._portal_event(staff, Action.CONFIG_CHANGE, s, session.session_id, resource=resource, **meta))
    return {"risk": d.risk.total, "action": d.action_taken.value}


@app.get("/api/portal/admin/users")
def admin_users(request: Request, session: Session = Depends(A.require_employee)) -> list[dict[str, Any]]:
    _require_privileged_admin(request, session, "list users")
    disabled = {a["username"] for a in A.get_auth().accounts() if a.get("disabled")}
    return [
        {
            "username": st.actor,
            "role": ROLE_OVERRIDES.get(st.actor, st.role).value,
            "roster_role": st.role.value,
            "privilege_level": PRIVILEGE_LEVEL[ROLE_OVERRIDES.get(st.actor, st.role)],
            "city": st.city,
            "status": "disabled" if st.actor in disabled else "active",
        }
        for st in ROSTER
    ]


def _target(staff, username: str) -> Any:
    target = BY_ACTOR.get(username)
    if target is None:
        raise HTTPException(404, "no such employee")
    if target.actor == staff.actor:
        raise HTTPException(400, "you cannot change your own account")
    mine = PRIVILEGE_LEVEL[ROLE_OVERRIDES.get(staff.actor, staff.role)]
    theirs = PRIVILEGE_LEVEL[ROLE_OVERRIDES.get(target.actor, target.role)]
    if theirs >= mine:
        raise HTTPException(403, "you can only manage accounts below your own privilege level")
    return target


class AdminReason(BaseModel):
    reason: str = Field(..., min_length=3, max_length=200)


@app.post("/api/portal/admin/users/{username}/disable")
def admin_disable(username: str, body: AdminReason, request: Request,
                  session: Session = Depends(A.require_employee)) -> dict[str, Any]:
    staff = _require_privileged_admin(request, session, "disable an account")
    target = _target(staff, username)
    scored = _admin_event(staff, session, "iam.accounts", target=target.actor, change="disable")
    signed_out = A.get_auth().disable(target.actor, staff.actor, A.sanitize(body.reason))
    A.get_state().engine.audit.append(
        "admin.account_disabled", {"by": staff.actor, "username": target.actor, "reason": A.sanitize(body.reason)},
        critical=True,
    )
    return {"disabled": target.actor, "sessions_signed_out": signed_out, "monitored": scored}


@app.post("/api/portal/admin/users/{username}/enable")
def admin_enable(username: str, request: Request, session: Session = Depends(A.require_employee)) -> dict[str, Any]:
    staff = _require_privileged_admin(request, session, "enable an account")
    target = _target(staff, username)
    scored = _admin_event(staff, session, "iam.accounts", target=target.actor, change="enable")
    A.get_auth().enable(target.actor)
    A.get_state().engine.audit.append("admin.account_enabled", {"by": staff.actor, "username": target.actor}, critical=True)
    return {"enabled": target.actor, "monitored": scored}


class RoleChange(BaseModel):
    role: str


@app.post("/api/portal/admin/users/{username}/role")
def admin_role(username: str, body: RoleChange, request: Request,
               session: Session = Depends(A.require_employee)) -> dict[str, Any]:
    staff = _require_privileged_admin(request, session, "change a role")
    target = _target(staff, username)
    try:
        new_role = Role(body.role)
    except ValueError as e:
        raise HTTPException(400, f"role must be one of {[r.value for r in Role]}") from e
    mine = PRIVILEGE_LEVEL[ROLE_OVERRIDES.get(staff.actor, staff.role)]
    if PRIVILEGE_LEVEL[new_role] >= mine:
        raise HTTPException(403, "you can only grant roles below your own privilege level")
    before = ROLE_OVERRIDES.get(target.actor, target.role)
    scored = _admin_event(staff, session, "iam.roles", target=target.actor, change=f"{before.value}->{new_role.value}")
    if new_role is target.role:
        ROLE_OVERRIDES.pop(target.actor, None)
    else:
        ROLE_OVERRIDES[target.actor] = new_role
    A.get_state().engine.audit.append(
        "admin.role_changed", {"by": staff.actor, "username": target.actor, "from": before.value, "to": new_role.value},
        critical=True,
    )
    return {"username": target.actor, "from": before.value, "to": new_role.value, "monitored": scored}


class CommsPolicy(BaseModel):
    customer_comms_roles: list[str] | None = None
    bulk_comms_roles: list[str] | None = None
    bulk_threshold: int | None = None


@app.get("/api/portal/admin/comms-policy")
def admin_comms_policy(request: Request, session: Session = Depends(A.require_employee)) -> dict[str, Any]:
    _require_privileged_admin(request, session, "view communication policy")
    p = POLICY.current
    return {"customer_comms_roles": p.customer_comms_roles, "bulk_comms_roles": p.bulk_comms_roles,
            "bulk_threshold": p.bulk_threshold, "privileged_comms_step_up": p.privileged_comms_step_up}


@app.put("/api/portal/admin/comms-policy")
def admin_put_comms_policy(body: CommsPolicy, request: Request,
                           session: Session = Depends(A.require_employee)) -> dict[str, Any]:
    """Privileged administrators manage who may message customers. The risk
    thresholds stay with the Super Admin."""
    staff = _require_privileged_admin(request, session, "change communication policy")
    changes = body.model_dump(exclude_none=True)
    try:
        before, after = POLICY.update(changes)
    except PolicyError as e:
        raise HTTPException(400, str(e)) from e
    scored = _admin_event(staff, session, "policy.communications", change=",".join(sorted(changes)))
    changed = {k: {"from": before[k], "to": after[k]} for k in changes if before[k] != after[k]}
    A.get_state().engine.audit.append("policy.changed", {"by": staff.actor, "changes": changed}, critical=True)
    return {"changed": changed, "monitored": scored}


# --------------------------------------------------------------------------- #
# Super Admin: roles and system configuration
# --------------------------------------------------------------------------- #


@app.get("/api/admin/roles")
def roles() -> dict[str, Any]:
    """Every role, what it reaches, and who holds it."""
    out = []
    for role in sorted(Role, key=lambda r: PRIVILEGE_LEVEL[r]):
        level = PRIVILEGE_LEVEL[role]
        out.append({
            "role": role.value,
            "privilege_level": level,
            "privileged_administrator": level >= 4,
            "members": [st.actor for st in ROSTER if ROLE_OVERRIDES.get(st.actor, st.role) is role],
            "resources": [r for r, lvl in A.RESOURCE_MIN_LEVEL.items() if level >= lvl],
            "customer_messaging": role in CUSTOMER_COMMS_ROLES,
            "bulk_messaging": role in BULK_COMMS_ROLES,
            "transfer_limit": TRANSFER_LIMITS.get(role),
        })
    return {"roles": out, "resource_min_level": dict(A.RESOURCE_MIN_LEVEL),
            "overrides": {u: r.value for u, r in ROLE_OVERRIDES.items()}}


class ResourcePermissions(BaseModel):
    resource_min_level: dict[str, int]


@app.put("/api/admin/roles")
def put_roles(body: ResourcePermissions, request: Request) -> dict[str, Any]:
    """Change which privilege level each protected resource needs."""
    by = _signed_in(request)
    unknown = set(body.resource_min_level) - set(A.RESOURCE_MIN_LEVEL)
    if unknown:
        raise HTTPException(400, f"unknown resources: {sorted(unknown)}")
    if any(not 1 <= v <= 6 for v in body.resource_min_level.values()):
        raise HTTPException(400, "levels run from 1 (teller) to 6 (domain admin)")
    before = dict(A.RESOURCE_MIN_LEVEL)
    A.RESOURCE_MIN_LEVEL.update(body.resource_min_level)
    changed = {k: {"from": before[k], "to": v} for k, v in body.resource_min_level.items() if before[k] != v}
    A.get_state().engine.audit.append("roles.permissions_changed", {"by": by, "changes": changed}, critical=True)
    return {"resource_min_level": dict(A.RESOURCE_MIN_LEVEL), "changed": changed}


@app.get("/api/admin/config")
def get_config() -> dict[str, Any]:
    return dict(CONFIG)


@app.put("/api/admin/config")
def put_config(body: dict[str, Any], request: Request) -> dict[str, Any]:
    by = _signed_in(request)
    try:
        before, after = update_config(body)
    except (ValueError, TypeError) as e:
        raise HTTPException(400, str(e)) from e
    changed = {k: {"from": before[k], "to": after[k]} for k in after if before[k] != after[k]}
    A.get_state().engine.audit.append("config.changed", {"by": by, "changes": changed}, critical=True)
    return {"config": after, "changed": changed}


# --------------------------------------------------------------------------- #
# Incident reports (PDF)
# --------------------------------------------------------------------------- #


@app.get("/api/incidents/{incident_id}/report")
def incident_pdf(incident_id: str, request: Request) -> Response:
    """The incident as a PDF an auditor can read: summary, alerts, evidence
    with the reasons behind each score, timeline, actions and notes. Only what
    the system recorded goes in it, and downloading one is itself audited."""
    s = A.get_state()
    inc = s.incidents.incidents.get(incident_id)
    if inc is None:
        raise HTTPException(404, "no such incident")
    by = _signed_in(request)
    generated = datetime.now(timezone.utc)
    alerts = [s.incidents.alerts[a] for a in inc.alert_ids if a in s.incidents.alerts]
    evidence = set(inc.evidence)
    decisions = [d for d in s.engine.decisions if d.event.event_id in evidence]
    pdf = incident_report(
        inc,
        alerts=alerts,
        decisions=decisions,
        signing=s.engine.signer.algorithm,
        prepared_by=by,
        generated=generated,
    )
    s.engine.audit.append(
        "incident.report_exported",
        {"incident": inc.id, "by": by, "alerts": len(alerts), "evidence": len(decisions)},
    )
    inc.log("report", f"Report exported by {by}.")
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{report_filename(inc, generated)}"'},
    )


# --------------------------------------------------------------------------- #
# Alert notifications (Super Admin)
# --------------------------------------------------------------------------- #


class NotifyUpdate(BaseModel):
    enabled: bool | None = None
    webhook_url: str | None = Field(None, max_length=500)
    telegram_chat_id: str | None = Field(None, max_length=64)
    email_to: str | None = Field(None, max_length=200)
    email_from: str | None = Field(None, max_length=200)
    brevo_api_key: str | None = Field(None, max_length=200)
    min_severity: str | None = Field(None, pattern="^(HIGH|CRITICAL)$")
    max_per_hour: int | None = Field(None, ge=1, le=500)
    cooldown_seconds: int | None = Field(None, ge=0, le=86_400)


@app.get("/api/admin/notifications")
def notifications() -> dict[str, Any]:
    """Where critical alerts are sent, and how recent deliveries went.
    Secrets are redacted."""
    return A.get_notifier().status()


@app.put("/api/admin/notifications")
def put_notifications(body: NotifyUpdate, request: Request) -> dict[str, Any]:
    notifier = A.get_notifier()
    changes = body.model_dump(exclude_none=True)
    current = notifier.settings.as_dict(redact=False)
    unchanged_secret = {k: v for k, v in changes.items() if k in ("webhook_url", "brevo_api_key") and v == ""}
    merged = {**{k: v for k, v in current.items() if k in NotifySettings.__dataclass_fields__}, **changes}
    notifier.settings = NotifySettings(**merged)
    A.get_state().engine.audit.append(
        "notifications.changed",
        {"by": _signed_in(request), "fields": sorted(set(changes) - set(unchanged_secret)),
         "channels": notifier.settings.channels()},
        critical=True,
    )
    return notifier.status()


@app.post("/api/admin/notifications/test")
def test_notification(request: Request) -> dict[str, Any]:
    """Send a test alert now and report what each channel answered."""
    notifier = A.get_notifier()
    if not notifier.settings.channels():
        raise HTTPException(400, "no channel configured: set a webhook URL, or an email address with a Brevo key")
    results = [d.as_dict() for d in notifier.send_test()]
    A.get_state().engine.audit.append("notifications.test", {"by": _signed_in(request), "results": results})
    return {"results": results, "status": notifier.status()}
