"""HTTP surface: REST for the console, SSE for the live feed.

Run with ``uvicorn lookout.api:app --reload`` from ``backend/``.

The app owns one :class:`~lookout.pipeline.Engine`. On startup it replays a
month of synthetic history to build baselines and fit the behavioural model,
then (unless ``LOOKOUT_LIVE_TRAFFIC=0``) keeps a trickle of ordinary staff
activity flowing so the console shows a working bank rather than an empty room.
Scenarios are injected into that same stream.

Two audiences, two sets of routes:

* ``/api/auth/*`` and ``/api/portal/*`` -- the employee portal. Employees sign
  in, browse the (masked) customer book and export PDFs. Every sign-in and
  every export is an event scored by the same engine as everything else.
* everything else under ``/api/`` -- the SOC console, which requires a SOC
  analyst's session. Enforced once, in middleware, so a new route cannot be
  left open by forgetting a decorator.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import uuid
import zlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from . import scenarios as scenario_mod
from .auth import DEMO_ACCOUNTS, AuthStore, LoginLimiter, Session
from .banking import Bank
from .customers import customer_book, masked
from .db.persistence import Persistence
from .db.persistence import from_env as db_from_env
from .evaluate import run_evaluation
from .generator import BY_ACTOR, CITIES, ROSTER, generate_history
from .incidents import ALERT_STATUSES, IncidentBook
from .ml.model import ThreatClassifier, load_metrics
from .models import PRIVILEGE_LEVEL, Action, ActionTaken, Band, Decision, Event, MessagePayload, Role
from .narrator import Narrator
from .pipeline import Engine
from .policy import POLICY, PolicyError
from .portal import (
    MAX_EXPORT,
    ExportRecord,
    HoneypotLedger,
    TransferDecoy,
    choose_rows,
    export_filename,
    is_suspicious,
    new_doc_ref,
    now_utc,
    poison,
    render_pdf,
)
from .urlcheck import inspect_url

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #


class AppState:
    """Everything the process holds. Rebuilt wholesale by ``POST /api/reset``."""

    def __init__(self) -> None:
        self.engine: Engine = self._build_engine()
        self.clock: datetime = datetime(2026, 9, 21, 9, 0)
        self.traffic: list[Event] = []
        self.traffic_round = 0
        self.traffic_paused = False
        self.evaluation: dict[str, Any] | None = None
        self.book = customer_book()
        self.bank = Bank(self.book)
        self.ledger = HoneypotLedger()
        self.incidents = IncidentBook()
        self.access_requests: list[dict[str, Any]] = []
        self.engine.listeners.append(self._honeypot_trigger)
        self.engine.listeners.append(self._raise_alert)

    def _raise_alert(self, decision: Decision) -> None:
        alert = self.incidents.on_decision(decision)
        if alert is not None:
            self.engine.broadcast_extra("alert", alert.as_dict())
            db = get_db()
            if db is not None:
                db.upsert_alert(alert)
                db.upsert_incident(self.incidents.incidents[alert.incident_id])

    def _honeypot_trigger(self, decision: Decision) -> None:
        """Any high-risk decision about an employee moves them into the
        honeypot: from then on every portal page they open is served from
        fake data, and everything they do there is recorded for the SOC."""
        actor = decision.event.actor
        high = decision.risk.band in (Band.HIGH, Band.CRITICAL) or decision.action_taken in (
            ActionTaken.BLOCK,
            ActionTaken.BLOCK_AND_ALERT,
        )
        if not high or actor not in BY_ACTOR:
            return
        top = decision.risk.signals[0].name if decision.risk.signals else "risk score"
        reason = (
            f"{decision.risk.band.value} risk ({decision.risk.total:.0f}/100) on "
            f"{decision.event.action.value.replace('_', ' ')}: {top.replace('_', ' ')}"
        )
        if decision.policy:
            reason += f" ({decision.policy})"
        if self.ledger.watch(actor, reason):
            self.incidents.note_for_user(
                actor, "honeypot", f"Moved into the honeypot: {reason}. From now on they see only fake data."
            )
            self.engine.audit.append(
                "honeypot.activated",
                {"actor": actor, "reason": reason, "trigger_event": decision.event.event_id},
                critical=True,
            )

    @staticmethod
    def _build_engine() -> Engine:
        seed = os.getenv("LOOKOUT_AUDIT_SEED", "lookout-demo-seed-do-not-use-prod")
        engine = Engine(
            narrator=Narrator(),
            audit_seed=seed.encode().ljust(32, b"\0")[:32],
            classifier=get_classifier(),
        )
        db = get_db()
        if db is not None:
            # Attached before warm-up, so the persisted chain starts at seq 0
            # and verifies from the genesis hash.
            db.run_id = str(uuid.uuid4())
            engine.audit.listeners.append(db.record_audit)
            engine.listeners.append(db.record_decision)
        return engine.warm_up()

    def reset(self) -> None:
        self.__init__()

    def advance(self, ts: datetime) -> None:
        if ts > self.clock:
            self.clock = ts

    def next_traffic_event(self) -> Event:
        """Replay held-out benign days in order, generating another week
        whenever the current one runs out."""
        if not self.traffic:
            self.traffic_round += 1
            start = self.clock
            week = generate_history(
                days=7,
                seed=20260921 + self.traffic_round,
                end=start + timedelta(days=7),
            )
            self.traffic = [e for e in week if e.ts > start]
        return self.traffic.pop(0)


state: AppState | None = None
#: Outside AppState on purpose: a demo reset must not sign everyone out.
auth: AuthStore | None = None
_classifier: ThreatClassifier | None = None
_db: Persistence | None = None
_db_loaded = False


def get_db() -> Persistence | None:
    """Write-through database, if ``DATABASE_URL`` is set. Created once."""
    global _db, _db_loaded
    if not _db_loaded:
        _db = db_from_env()
        _db_loaded = True
    return _db


def get_classifier() -> ThreatClassifier | None:
    """Load the trained classifier once per process (training it first if the
    model file is missing). ``LOOKOUT_ML=0`` switches the second opinion off."""
    global _classifier
    if os.getenv("LOOKOUT_ML", "1") == "0":
        return None
    if _classifier is None:
        _classifier = ThreatClassifier.load_or_train()
    return _classifier


def get_state() -> AppState:
    assert state is not None, "app not started"
    return state


def get_auth() -> AuthStore:
    assert auth is not None, "app not started"
    return auth


async def _traffic_loop(interval: float) -> None:
    """Background trickle of ordinary work."""
    while True:
        await asyncio.sleep(interval)
        s = get_state()
        if s.traffic_paused:
            continue
        event = s.next_traffic_event()
        s.advance(event.ts)
        await asyncio.to_thread(s.engine.ingest, event)


@asynccontextmanager
async def lifespan(_: FastAPI):
    global state, auth
    if auth is None:
        auth = await asyncio.to_thread(AuthStore)
    db = await asyncio.to_thread(get_db)
    if db is not None:
        await asyncio.to_thread(db.seed, auth)
    state = await asyncio.to_thread(AppState)
    task = None
    if os.getenv("LOOKOUT_LIVE_TRAFFIC", "1") != "0":
        interval = float(os.getenv("LOOKOUT_TRAFFIC_INTERVAL", "1.5"))
        task = asyncio.create_task(_traffic_loop(interval))
    try:
        yield
    finally:
        if task:
            task.cancel()


app = FastAPI(
    title="Lookout",
    description="Privileged-access misuse and insider-threat detection for banking.",
    version="0.2.0",
    lifespan=lifespan,
    docs_url="/swagger",
    redoc_url="/redoc",
)

#: Who may call what. First matching prefix wins; anything else under /api/
#: is the SOC console (SOC analyst or Super Admin). Enforced once, here, so a
#: new route cannot be left open by forgetting a decorator.
PUBLIC = frozenset({"*"})
ROUTE_ACCESS: tuple[tuple[str, frozenset[str]], ...] = (
    ("/api/health", PUBLIC),
    ("/api/auth/", PUBLIC),
    ("/api/portal/", frozenset({"employee"})),
    ("/api/team/", frozenset({"employee"})),  # and the handler checks for a manager
    ("/api/admin/", frozenset({"superadmin"})),
)
CONSOLE = frozenset({"soc", "superadmin"})


def allowed_kinds(path: str) -> frozenset[str]:
    return next((kinds for prefix, kinds in ROUTE_ACCESS if path.startswith(prefix)), CONSOLE)


def _token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    # EventSource cannot set headers, so the live stream passes it as a query.
    return request.query_params.get("token")


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    # The API returns JSON and PDFs only; it never needs to run or embed anything.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


@app.middleware("http")
async def secure_headers(request: Request, call_next):
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        # The interactive docs (/swagger, /redoc) load scripts from a CDN, so
        # the no-scripts policy applies to the API itself only.
        if k == "Content-Security-Policy" and not request.url.path.startswith("/api/"):
            continue
        response.headers.setdefault(k, v)
    if request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


@app.middleware("http")
async def role_gate(request: Request, call_next):
    """Registered before CORS, so CORS wraps it and a 401 still carries the
    headers the browser needs to read it."""
    path = request.url.path
    if request.method == "OPTIONS" or not path.startswith("/api/"):
        return await call_next(request)
    kinds = allowed_kinds(path)
    if kinds is PUBLIC:
        return await call_next(request)
    session = get_auth().get(_token(request))
    if session is None:
        return JSONResponse({"detail": "sign in required"}, status_code=401)
    if session.kind not in kinds:
        return JSONResponse({"detail": "your role cannot use this"}, status_code=403)
    return await call_next(request)


def current_session(request: Request) -> Session:
    session = get_auth().get(_token(request))
    if session is None:
        raise HTTPException(401, "sign in required")
    return session


def require_manager(request: Request) -> Session:
    session = current_session(request)
    if session.kind != "employee" or session.profile.get("role") != "manager":
        raise HTTPException(403, "managers only")
    return session


def require_employee(request: Request) -> Session:
    session = get_auth().get(_token(request))
    if session is None:
        raise HTTPException(401, "sign in required")
    if session.kind != "employee":
        raise HTTPException(403, "employee portal only")
    return session


_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
    # Without this the browser hides the export's filename from the page.
    expose_headers=["Content-Disposition"],
)


def _wire(kind: str, item: Any) -> Any:
    return _dump(item) if kind == "decision" else item


def _dump(decision: Decision) -> dict[str, Any]:
    # The ground-truth label exists for offline evaluation only. It is never
    # read by a detector, and leaving it off the wire means nobody inspecting
    # the console's traffic has to take that on trust.
    return decision.model_dump(mode="json", exclude={"event": {"label"}})


# --------------------------------------------------------------------------- #
# Overview
# --------------------------------------------------------------------------- #


@app.get("/api/health")
def health() -> dict[str, Any]:
    s = get_state()
    return {
        "ok": True,
        "model_fitted": s.engine.model.fitted,
        "narrator": "llm" if s.engine.narrator.live else "template",
        "signing": s.engine.signer.algorithm,
    }


@app.get("/api/stats")
def stats() -> dict[str, Any]:
    s = get_state()
    return {
        **s.engine.stats(),
        "clock": s.clock.isoformat(),
        "traffic_paused": s.traffic_paused,
        "exports": len(s.ledger.records),
        "honeypots_served": len(s.ledger.honeypots()) + len(s.ledger.transfer_decoys()),
        "transfer_decoys": len(s.ledger.transfer_decoys()),
        "in_honeypot": len(s.ledger.watchlist()),
        "open_alerts": sum(a.status == "OPEN" for a in s.incidents.alerts.values()),
        "open_incidents": sum(i.status in ("OPEN", "INVESTIGATING") for i in s.incidents.incidents.values()),
        "active_sessions": len(get_auth().sessions()),
    }


@app.get("/api/crypto")
def crypto() -> dict[str, Any]:
    return get_state().engine.crypto()


# --------------------------------------------------------------------------- #
# Decisions and the live feed
# --------------------------------------------------------------------------- #


@app.get("/api/decisions")
def decisions(
    limit: int = Query(60, ge=1, le=500),
    flagged_only: bool = False,
) -> list[dict[str, Any]]:
    items = get_state().engine.recent(limit=2000 if flagged_only else limit)
    if flagged_only:
        items = [d for d in items if d.action_taken.value != "allow"][:limit]
    return [_dump(d) for d in items]


@app.get("/api/decisions/{event_id}")
def decision(event_id: str) -> dict[str, Any]:
    for d in reversed(get_state().engine.decisions):
        if d.event.event_id == event_id:
            return _dump(d)
    raise HTTPException(404, "no decision for that event")


@app.get("/api/stream")
async def stream(request: Request) -> EventSourceResponse:
    engine = get_state().engine
    queue = engine.subscribe()

    async def events():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    kind, item = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": "{}"}
                    continue
                yield {"event": kind, "data": json.dumps(_wire(kind, item))}
        finally:
            engine.unsubscribe(queue)

    return EventSourceResponse(events())


@app.get("/api/risk/{event_id}/explanation")
def risk_explanation(event_id: str) -> dict[str, Any]:
    """Why this activity was scored as it was: the rule arithmetic and each
    signal's sentence, plus the classifier's second opinion with SHAP
    contributions for the session it belongs to."""
    s = get_state()
    for d in reversed(s.engine.decisions):
        if d.event.event_id == event_id:
            return {
                "event_id": event_id,
                "risk_score": d.risk.total,
                "risk_level": d.risk.band.value.upper(),
                "action": d.action_taken.value,
                "classification": d.threat_class.value,
                "reasons": [s_.explanation for s_ in d.risk.signals],
                "arithmetic": {
                    "rule_points": d.risk.rule_points,
                    "model_points": d.risk.model_points,
                    "privilege_multiplier": d.risk.privilege_multiplier,
                },
                "ml_second_opinion": s.engine.explain(d),
            }
    raise HTTPException(404, "no decision for that event")


@app.get("/api/ml/metrics")
def ml_metrics() -> dict[str, Any]:
    """The classifier's real evaluation results, from training."""
    metrics = load_metrics()
    if metrics is None:
        raise HTTPException(404, "model not trained yet")
    return metrics


class IngestRequest(BaseModel):
    event: Event


@app.post("/api/events")
def ingest(body: IngestRequest) -> dict[str, Any]:
    s = get_state()
    d = s.engine.ingest(body.event)
    s.advance(body.event.ts)
    return _dump(d)


# --------------------------------------------------------------------------- #
# Scenarios and traffic
# --------------------------------------------------------------------------- #


@app.get("/api/scenarios")
def list_scenarios() -> list[dict[str, Any]]:
    return [s.as_dict() for s in scenario_mod.SCENARIOS]


@app.post("/api/scenarios/{key}/run")
def run_scenario(key: str) -> dict[str, Any]:
    if key not in scenario_mod.BY_KEY:
        raise HTTPException(404, f"unknown scenario {key!r}")
    s = get_state()
    start = s.clock + timedelta(minutes=5)
    events = scenario_mod.build(key, now=start, seed=len(s.engine.decisions))
    results = [s.engine.ingest(e) for e in events]
    s.advance(max(e.ts for e in events))
    peak = max(results, key=lambda d: d.risk.total)
    return {
        "scenario": scenario_mod.BY_KEY[key].as_dict(),
        "decisions": [_dump(d) for d in results],
        "peak": _dump(peak),
    }


@app.post("/api/traffic/{mode}")
def traffic(mode: str) -> dict[str, Any]:
    if mode not in ("pause", "resume"):
        raise HTTPException(400, "mode must be pause or resume")
    s = get_state()
    s.traffic_paused = mode == "pause"
    return {"traffic_paused": s.traffic_paused}


@app.post("/api/reset")
def reset() -> dict[str, Any]:
    s = get_state()
    subscribers = list(s.engine._subscribers)
    POLICY.reset()  # a demo reset also restores the default security policy
    limiter.__init__()
    s.reset()
    # Keep open dashboards connected across a reset.
    s.engine._subscribers.extend(subscribers)
    return {"ok": True, **s.engine.stats()}


# --------------------------------------------------------------------------- #
# Message gateway
# --------------------------------------------------------------------------- #


class MessageScanRequest(BaseModel):
    sender: str
    channel: str = "sms"
    recipient_count: int = Field(1, ge=1)
    audience: str = "customer"
    subject: str = ""
    body: str
    city: str | None = None


@app.post("/api/messages/scan")
def scan_message(body: MessageScanRequest) -> dict[str, Any]:
    """The gateway every outbound staff message passes through.

    Links are pulled from the body rather than trusted from a separate field,
    because a sender who wanted to hide a URL would simply leave it out of one.
    """
    staff = BY_ACTOR.get(body.sender)
    if staff is None:
        raise HTTPException(404, f"unknown sender {body.sender!r}")
    s = get_state()
    urls = sorted(set(URL_PATTERN.findall(body.body)))
    ts = s.clock + timedelta(seconds=30)
    event = Event(
        event_id=str(uuid.uuid4()),
        ts=ts,
        actor=staff.actor,
        actor_role=staff.role,
        action=Action.SEND_MESSAGE,
        resource="gateway.outbound",
        source_ip=f"{staff.ip_prefix}.77",
        device_id=staff.device,
        geo=CITIES[body.city or staff.city],
        message=MessagePayload(
            channel=body.channel,
            recipient_count=body.recipient_count,
            audience=body.audience,
            subject=body.subject,
            body=body.body,
            urls=urls,
        ),
        meta={"session_id": f"gw-{uuid.uuid4().hex[:8]}", "via": "gateway"},
    )
    d = s.engine.ingest(event)
    s.advance(ts)
    return {
        "delivered": d.action_taken.value in ("allow",),
        "held": d.action_taken.value == "quarantine",
        "requires_step_up": d.action_taken.value == "step_up",
        "urls": [inspect_url(u).as_dict() for u in urls],
        "decision": _dump(d),
    }


@app.post("/api/urls/inspect")
def inspect(body: dict[str, str]) -> dict[str, Any]:
    url = body.get("url", "").strip()
    if not url:
        raise HTTPException(400, "url is required")
    return inspect_url(url).as_dict()


@app.get("/api/quarantine")
def quarantine() -> list[dict[str, Any]]:
    return [
        {"quarantine_id": qid, **_dump(d)}
        for qid, d in get_state().engine.quarantine.items()
    ]


class ReleaseRequest(BaseModel):
    reviewer: str


@app.post("/api/quarantine/{qid}/release")
def release(qid: str, body: ReleaseRequest) -> dict[str, Any]:
    d = get_state().engine.release(qid, body.reviewer)
    if d is None:
        raise HTTPException(404, "not in quarantine")
    if get_db() is not None:
        get_db().review_quarantine(qid, body.reviewer, "released")
    return {"released": qid, "by": body.reviewer}


# --------------------------------------------------------------------------- #
# Identities
# --------------------------------------------------------------------------- #


@app.get("/api/users")
def users() -> list[dict[str, Any]]:
    s = get_state()
    out = []
    for b in sorted(s.engine.store.all(), key=lambda b: b.actor):
        recent = [d for d in s.engine.decisions if d.event.actor == b.actor]
        peak = max((d.risk.total for d in recent), default=0.0)
        out.append({**b.snapshot(), "peak_risk": peak, "decisions": len(recent)})
    return out


@app.get("/api/users/{actor}")
def user(actor: str) -> dict[str, Any]:
    s = get_state()
    staff = BY_ACTOR.get(actor)
    if staff is None:
        raise HTTPException(404, "unknown identity")
    baseline = s.engine.store.get(actor, staff.role)
    recent = [_dump(d) for d in s.engine.decisions if d.event.actor == actor][-25:][::-1]
    return {"baseline": baseline.snapshot(), "recent": recent}


# --------------------------------------------------------------------------- #
# Audit and cryptography
# --------------------------------------------------------------------------- #


@app.get("/api/audit")
def audit(limit: int = Query(40, ge=1, le=500)) -> dict[str, Any]:
    log = get_state().engine.audit
    return {
        "entries": [e.model_dump(mode="json") for e in log.tail(limit)],
        "checkpoints": [c.model_dump(mode="json") for c in log.checkpoints[-10:][::-1]],
        "total": len(log.entries),
    }


@app.get("/api/audit/verify")
def audit_verify() -> dict[str, Any]:
    return get_state().engine.audit.verify().model_dump()


@app.post("/api/audit/tamper/{seq}")
def audit_tamper(seq: int) -> dict[str, Any]:
    """Demo only: rewrite a past decision the way a malicious admin would, so
    the console can show verification catching it. ``POST /api/reset`` undoes."""
    if os.getenv("LOOKOUT_ALLOW_TAMPER", "1") != "1":
        raise HTTPException(403, "tamper demo disabled")
    log = get_state().engine.audit
    if not log.tamper(seq):
        raise HTTPException(404, "no such entry")
    return {"tampered": seq, "verify": log.verify().model_dump()}


class SealRequest(BaseModel):
    name: str
    secret: str


@app.post("/api/credentials/seal")
def seal(body: SealRequest) -> dict[str, Any]:
    engine = get_state().engine
    sealed = engine.seal_credential(body.name, body.secret)
    roundtrip = engine.unseal_credential(
        body.name, {k: sealed[k] for k in ("kem_ciphertext", "nonce", "ciphertext", "algorithm")}
    )
    return {**sealed, "roundtrip_ok": roundtrip == body.secret}


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #


@app.get("/api/evaluation")
async def evaluation(refresh: bool = False) -> dict[str, Any]:
    """Precision / recall against labelled synthetic data. Runs on a separate
    engine so it never touches live state. Cached, since it replays ~1,000
    events."""
    s = get_state()
    if s.evaluation is None or refresh:
        report = await asyncio.to_thread(run_evaluation)
        s.evaluation = report.as_dict()
    return s.evaluation


# --------------------------------------------------------------------------- #
# Sign-in (public)
# --------------------------------------------------------------------------- #


def _portal_event(staff, action: Action, s: AppState, session_id: str, **meta) -> Event:
    """An event from an employee at their usual desk. The portal runs on the
    bank's intranet, so location and device are the employee's own; what they
    *do* is what gets scored."""
    ts = s.clock + timedelta(seconds=30)
    s.advance(ts)
    return Event(
        event_id=str(uuid.uuid4()),
        ts=ts,
        actor=staff.actor,
        actor_role=staff.role,
        action=action,
        resource=meta.pop("resource", ""),
        source_ip=f"{staff.ip_prefix}.60",
        device_id=staff.device,
        geo=CITIES[staff.city],
        success=action is not Action.LOGIN_FAILED,
        meta={"session_id": session_id, "via": "portal", **meta},
    )


class LoginRequest(BaseModel):
    username: str
    password: str


limiter = LoginLimiter()


@app.post("/api/auth/login")
def login(body: LoginRequest, request: Request) -> dict[str, Any]:
    """Every employee sign-in -- including every wrong password -- is an event
    in the pipeline, so guessing at a colleague's account trips the same
    failed-login-burst and credential-misuse detectors as any other attack."""
    a, s = get_auth(), get_state()
    username = body.username.strip()
    staff = BY_ACTOR.get(username)
    client = request.client.host if request.client else "unknown"
    wait = limiter.check(username, client)
    if wait is not None:
        s.engine.audit.append("auth.rate_limited", {"username": username, "source_ip": client})
        raise HTTPException(429, f"too many sign-in attempts; try again in {wait} s", headers={"Retry-After": str(wait)})
    ok = a.verify(username, body.password)
    if ok:
        limiter.succeeded(username)
    else:
        limiter.failed(username)
    if ok and a.is_disabled(username):
        # An account the SOC or Super Admin switched off is refused outright --
        # unlike a merely risky sign-in, which lands in the honeypot.
        s.engine.audit.append("auth.disabled_account_attempt", {"username": username})
        raise HTTPException(403, "account disabled -- contact the security team")

    if not ok:
        if staff is not None:
            s.engine.ingest(
                _portal_event(staff, Action.LOGIN_FAILED, s, session_id="", resource="portal")
            )
        elif a.kind_of(username) in ("soc", "superadmin"):
            s.engine.audit.append("auth.console_login_failed", {"username": username})
        raise HTTPException(401, "wrong username or password")

    session = a.open_session(username)
    if staff is not None:
        decision = s.engine.ingest(
            _portal_event(staff, Action.LOGIN, s, session.session_id, resource="portal")
        )
        # A high-risk sign-in is *not* refused. The engine's listener has
        # already put this employee in the honeypot, so they land in a portal
        # that looks normal and is entirely fake -- a refused login would only
        # tell an intruder to try something else.
        s.ledger.record_activity(
            username, "signed in", risk=decision.risk.total, band=decision.risk.band.value
        )
    else:
        s.engine.audit.append("auth.console_login", {"username": username, "kind": session.kind})

    db = get_db()
    if db is not None:
        db.open_session(session.session_id, username, session.profile.get("device", ""))
    return {"token": session.token, "kind": session.kind, "profile": session.profile}


@app.post("/api/auth/logout")
def logout(request: Request) -> dict[str, Any]:
    token = _token(request)
    if token:
        sess = get_auth().get(token)
        get_auth().close(token)
        if sess is not None and get_db() is not None:
            get_db().close_session(sess.session_id, "logged_out")
    return {"ok": True}


@app.get("/api/auth/me")
def me(request: Request) -> dict[str, Any]:
    session = get_auth().get(_token(request))
    if session is None:
        raise HTTPException(401, "not signed in")
    return {"kind": session.kind, "profile": session.profile}


@app.get("/api/auth/demo-accounts")
def demo_accounts() -> list[dict[str, str]]:
    """The demo credentials, for the sign-in page. This is a simulated bank;
    set LOOKOUT_SHOW_DEMO_ACCOUNTS=0 to hide them."""
    if os.getenv("LOOKOUT_SHOW_DEMO_ACCOUNTS", "1") != "1":
        return []
    out = []
    for username, password, kind in DEMO_ACCOUNTS:
        staff = BY_ACTOR.get(username)
        out.append(
            {
                "username": username,
                "password": password,
                "kind": kind,
                "role": staff.role.value if staff else "soc_analyst",
                "city": staff.city if staff else "Chennai SOC",
            }
        )
    return out


# --------------------------------------------------------------------------- #
# Employee portal
# --------------------------------------------------------------------------- #


@app.get("/api/portal/customers")
def portal_customers(
    q: str = "",
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=MAX_EXPORT),
    session: Session = Depends(require_employee),
) -> dict[str, Any]:
    """The customer book as an employee sees it: PII masked."""
    s = get_state()
    book = s.book
    needle = q.strip().lower()
    s.ledger.record_activity(session.username, "viewed customer directory", search=q, offset=offset)
    rows = [c for c in book if not needle or needle in c.name.lower() or needle in c.customer_id.lower() or needle in c.city.lower()]
    return {
        "total": len(rows),
        "rows": [masked(c) for c in rows[offset : offset + limit]],
        "max_export": MAX_EXPORT,
    }


class ExportRequest(BaseModel):
    count: int = Field(10, ge=1, le=MAX_EXPORT)
    customer_ids: list[str] | None = None


@app.post("/api/portal/export")
def portal_export(body: ExportRequest, session: Session = Depends(require_employee)) -> Response:
    """Export customer records as a PDF -- or, if the request is suspicious, a
    decoy that is indistinguishable from one.

    The response is byte-for-byte the same *kind* of thing either way: same
    status, same headers, same filename pattern. Nothing in it tells the
    employee which they got.
    """
    s = get_state()
    staff = BY_ACTOR[session.username]
    rows = choose_rows(s.book, body.customer_ids, body.count)
    if not rows:
        raise HTTPException(400, "no matching customers")

    decision = s.engine.ingest(
        _portal_event(
            staff, Action.DB_QUERY, s, session.session_id,
            resource="core.customers", record_count=len(rows), export="pdf",
        )
    )
    suspicious, reason = is_suspicious(
        len(rows), decision.action_taken.value, caught=s.ledger.caught(staff.actor)
    )

    generated = now_utc()
    doc_ref = new_doc_ref()
    filename = export_filename(staff.actor, generated)
    file_rows = poison(rows, s.book) if suspicious else rows
    pdf = render_pdf(file_rows, actor=staff.actor, doc_ref=doc_ref, generated=generated)

    canaries = [c.account_no for c in file_rows] if suspicious else []
    entry = s.engine.audit.append(
        "export.decoy_served" if suspicious else "export.genuine",
        {
            "actor": staff.actor,
            "role": staff.role.value,
            "doc_ref": doc_ref,
            "records": len(rows),
            "reason": reason,
            "risk_total": decision.risk.total,
            "canary_accounts": len(canaries),
        },
        critical=suspicious,
    )
    s.ledger.add(
        ExportRecord(
            doc_ref=doc_ref,
            actor=staff.actor,
            role=staff.role.value,
            requested=len(rows),
            decoy=suspicious,
            reason=reason,
            ts=generated,
            risk_total=decision.risk.total,
            action_taken=decision.action_taken.value,
            audit_seq=entry.seq,
            filename=filename,
            canaries=canaries,
            customer_ids=[c.customer_id for c in rows],
        )
    )
    if suspicious:
        # The risk engine treats the rest of this session as coming from
        # someone already caught taking data.
        s.engine.ctx.strike(session.session_id)
    s.ledger.record_activity(
        staff.actor, "exported customers as PDF", records=len(rows), doc_ref=doc_ref, decoy=suspicious
    )

    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --------------------------------------------------------------------------- #
# Fund transfers (employee) -- with the honeypot transfer page
# --------------------------------------------------------------------------- #

ACCOUNT_RE = re.compile(r"^\d{9,18}$")
IFSC_RE = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")
OTP_ATTEMPTS = 3


class TransferRequest(BaseModel):
    #: Customer ID (C100001) or account number, for both sides.
    from_account: str
    to_account: str
    to_name: str = Field("", max_length=80)
    to_ifsc: str = Field("MERB0000001", max_length=11)
    amount: float = Field(..., gt=0, le=100_000_000)
    remarks: str = Field("", max_length=120)


class VerifyRequest(BaseModel):
    challenge_id: str
    code: str


#: Pending step-up challenges: id -> (actor, request, decoy, decision summary, code, attempts left)
_challenges: dict[str, dict[str, Any]] = {}


def _resolve(s: AppState, key: str) -> str:
    """Accept a customer ID (what the masked directory shows) or a full
    account number, and return the account number."""
    key = key.replace(" ", "").upper()
    if key.startswith("C"):
        return next((c.account_no for c in s.book if c.customer_id == key), key)
    return key


def _account_view(s: AppState, account: str, actor: str) -> dict[str, Any]:
    c = s.bank.customers[account]
    return {
        "customer_id": c.customer_id,
        "masked": f"•••• {account[-4:]}",
        "name": c.name,
        "product": c.product,
        "city": c.city,
        "balance": round(s.bank.balance(account, actor), 2),
    }


@app.get("/api/portal/accounts/{account}")
def portal_account(account: str, session: Session = Depends(require_employee)) -> dict[str, Any]:
    """Look up a source account for the transfer page. A caught employee sees
    their shadow balance -- including the fake debits they already made."""
    s = get_state()
    account = _resolve(s, account)
    if account not in s.bank.customers:
        raise HTTPException(404, "no such account")
    s.ledger.record_activity(session.username, "looked up account", account=f"•••• {account[-4:]}")
    return _account_view(s, account, session.username)


@app.get("/api/portal/transfers")
def portal_transfers(session: Session = Depends(require_employee)) -> list[dict[str, Any]]:
    s = get_state()
    s.ledger.record_activity(session.username, "viewed transfer history")
    return [_receipt(t) for t in s.bank.history(session.username)]


@app.post("/api/portal/transfers")
def portal_transfer(body: TransferRequest, session: Session = Depends(require_employee)) -> dict[str, Any]:
    """Transfer customer funds -- or, for an employee in the honeypot, appear to.

    The flow and the response are identical either way: same validation, same
    step-up challenge when risk is medium, same receipt. The only difference
    is which ledger the numbers land in.
    """
    s = get_state()
    staff = BY_ACTOR[session.username]
    source = _resolve(s, body.from_account)
    dest = _resolve(s, body.to_account)
    ifsc = body.to_ifsc.strip().upper()
    if source not in s.bank.customers:
        raise HTTPException(400, "source account not found")
    if not ACCOUNT_RE.match(dest):
        raise HTTPException(400, "beneficiary account must be 9-18 digits")
    if dest == source:
        raise HTTPException(400, "source and beneficiary are the same account")
    if not IFSC_RE.match(ifsc):
        raise HTTPException(400, "IFSC must look like ABCD0123456")
    if body.amount > s.bank.balance(source, staff.actor):
        raise HTTPException(400, "insufficient balance in source account")

    external = dest not in s.bank.customers
    decision = s.engine.ingest(
        _portal_event(
            staff, Action.FUND_TRANSFER, s, session.session_id,
            resource="core.payments", amount=float(body.amount),
            from_account=source, to_account=dest, external=external,
        )
    )
    # The listener has already moved a high-risk employee into the honeypot.
    decoy = s.ledger.caught(staff.actor)
    request = body.model_copy(update={"from_account": source, "to_account": dest, "to_ifsc": ifsc})

    if decision.action_taken is ActionTaken.STEP_UP:
        challenge_id = uuid.uuid4().hex
        code = f"{secrets.randbelow(10**6):06d}"
        _challenges[challenge_id] = {
            "actor": staff.actor,
            "request": request,
            "decoy": decoy,
            "decision": decision,
            "code": code,
            "attempts": OTP_ATTEMPTS,
        }
        s.ledger.record_activity(
            staff.actor, "was asked for a one-time code", amount=body.amount, to=f"•••• {dest[-4:]}"
        )
        return {
            "status": "VERIFICATION_REQUIRED",
            "challenge_id": challenge_id,
            "sent_to": f"registered mobile •••• {zlib.crc32(staff.actor.encode()) % 10000:04d}",
            # No real SMS is ever sent. The demo shows the code on screen.
            "demo_code": code,
        }

    return _execute(s, staff, request, decoy, decision)


@app.post("/api/portal/transfers/verify")
def portal_verify(body: VerifyRequest, session: Session = Depends(require_employee)) -> dict[str, Any]:
    s = get_state()
    ch = _challenges.get(body.challenge_id)
    if ch is None or ch["actor"] != session.username:
        raise HTTPException(404, "no such verification")
    if body.code.strip() != ch["code"]:
        ch["attempts"] -= 1
        if ch["attempts"] <= 0:
            _challenges.pop(body.challenge_id, None)
            s.ledger.record_activity(session.username, "failed one-time code three times")
            raise HTTPException(403, "too many wrong codes; transfer cancelled")
        raise HTTPException(400, f"wrong code, {ch['attempts']} attempts left")
    _challenges.pop(body.challenge_id, None)
    staff = BY_ACTOR[session.username]
    # Re-check: they may have been caught between the challenge and the code.
    decoy = ch["decoy"] or s.ledger.caught(staff.actor)
    return _execute(s, staff, ch["request"], decoy, ch["decision"])


def _execute(s: AppState, staff, req: TransferRequest, decoy: bool, decision: Decision) -> dict[str, Any]:
    txn = s.bank.transfer(
        actor=staff.actor,
        from_account=req.from_account,
        to_account=req.to_account,
        to_name=req.to_name,
        to_ifsc=req.to_ifsc,
        amount=float(req.amount),
        remarks=req.remarks,
        shadow=decoy,
    )
    if decoy:
        watch = next((w for w in s.ledger.watch_entries() if w.actor == staff.actor), None)
        entry = s.engine.audit.append(
            "transfer.decoy_executed",
            {
                "actor": staff.actor,
                "reference": txn.reference,
                "amount": txn.amount,
                "from": f"•••• {txn.from_account[-4:]}",
                "to": f"•••• {txn.to_account[-4:]}",
                "external": txn.external,
                "real_funds_moved": False,
                "risk_total": decision.risk.total,
            },
            critical=True,
        )
        s.ledger.add_transfer(
            TransferDecoy(
                reference=txn.reference, utr=txn.utr, actor=staff.actor, role=staff.role.value,
                ts=txn.ts, from_account=txn.from_account, from_name=txn.from_name,
                to_account=txn.to_account, to_name=txn.to_name, to_ifsc=txn.to_ifsc,
                external=txn.external, amount=txn.amount,
                reason=watch.reason if watch else "on the honeypot watchlist",
                risk_total=decision.risk.total, action_taken=decision.action_taken.value,
                audit_seq=entry.seq, shown_balance_after=txn.balance_after,
            )
        )
        s.ledger.record_activity(
            staff.actor, "made a transfer (fake -- no money moved)",
            amount=txn.amount, to=f"•••• {txn.to_account[-4:]}", reference=txn.reference,
        )
    else:
        s.engine.audit.append(
            "transfer.executed",
            {
                "actor": staff.actor,
                "reference": txn.reference,
                "amount": txn.amount,
                "from": f"•••• {txn.from_account[-4:]}",
                "to": f"•••• {txn.to_account[-4:]}",
                "risk_total": decision.risk.total,
            },
        )
    return {"status": "SUCCESS", "receipt": _receipt(txn)}


def _receipt(txn) -> dict[str, Any]:
    """Identical for real and fake transfers. Nothing here may differ."""
    return {
        "reference": txn.reference,
        "utr": txn.utr,
        "ts": txn.ts.isoformat(),
        "status": txn.status,
        "from_account": f"•••• {txn.from_account[-4:]}",
        "from_name": txn.from_name,
        "to_account": f"•••• {txn.to_account[-4:]}",
        "to_name": txn.to_name,
        "to_ifsc": txn.to_ifsc,
        "amount": txn.amount,
        "remarks": txn.remarks,
        "balance_after": round(txn.balance_after, 2),
    }


# --------------------------------------------------------------------------- #
# Honeypot (SOC)
# --------------------------------------------------------------------------- #


@app.get("/api/honeypots")
def honeypots() -> dict[str, Any]:
    s = get_state()
    return {
        "threshold": POLICY.current.honeypot_export_threshold,
        "watchlist": s.ledger.watchlist(),
        "watch": [w.as_dict() for w in s.ledger.watch_entries()],
        "served": [r.as_dict() for r in s.ledger.honeypots()],
        "transfer_decoys": [t.as_dict() for t in s.ledger.transfer_decoys()],
        "exports": [r.as_dict(include_canaries=False) for r in reversed(s.ledger.records)][:50],
    }


class ClearRequest(BaseModel):
    reviewer: str


@app.post("/api/honeypots/watchlist/{actor}/clear")
def clear_watchlist(actor: str, body: ClearRequest) -> dict[str, Any]:
    """The SOC has investigated and the employee may see real data again.
    Audited, because lifting a trap is a decision someone must own."""
    s = get_state()
    if not s.ledger.clear(actor):
        raise HTTPException(404, "not on the watchlist")
    discarded = s.bank.leave_shadow(actor)
    s.engine.audit.append(
        "honeypot.watchlist_cleared",
        {"actor": actor, "reviewer": body.reviewer, "fake_transfers_discarded": len(discarded)},
        critical=True,
    )
    return {"cleared": actor, "by": body.reviewer}


@app.get("/api/honeypots/trace")
def trace(q: str = Query(..., min_length=4)) -> dict[str, Any]:
    """Who did this? Accepts a PDF footer reference, an account number from a
    leaked file, or a transaction reference / UTR from a decoy transfer."""
    hit = get_state().ledger.trace(q)
    if hit is None:
        return {"found": False, "query": q}
    matched_by, rec = hit
    kind = "transfer" if isinstance(rec, TransferDecoy) else "export"
    return {"found": True, "query": q, "matched_by": matched_by, "kind": kind, "record": rec.as_dict()}


# --------------------------------------------------------------------------- #
# Access requests (employee asks, manager or Super Admin decides)
# --------------------------------------------------------------------------- #

REQUESTABLE = {
    "core.customers:export": "Bulk customer export",
    "core.transactions:read": "Transaction database (read)",
    "reporting.payroll:read": "Payroll system (read)",
    "admin.console": "Admin console",
    "vault/api-signing": "API signing credentials",
}


def team_of(manager: str) -> list[str]:
    """A manager's team: lower-privilege staff in the same branch."""
    boss = BY_ACTOR[manager]
    return [
        s.actor
        for s in ROSTER
        if s.city == boss.city and PRIVILEGE_LEVEL[s.role] < PRIVILEGE_LEVEL[boss.role]
    ]


def approver_for(actor: str) -> str:
    """The employee's branch manager, or the Super Admin where there is none."""
    for s in ROSTER:
        if s.role is Role.MANAGER and actor in team_of(s.actor):
            return s.actor
    return "super.admin"


class AccessRequestBody(BaseModel):
    resource: str
    reason: str = Field(..., min_length=5, max_length=300)


@app.get("/api/portal/access-requests")
def my_access_requests(session: Session = Depends(require_employee)) -> dict[str, Any]:
    s = get_state()
    return {
        "requestable": REQUESTABLE,
        "requests": [r for r in s.access_requests if r["user"] == session.username][::-1],
    }


@app.post("/api/portal/access-requests")
def request_access(body: AccessRequestBody, session: Session = Depends(require_employee)) -> dict[str, Any]:
    if body.resource not in REQUESTABLE:
        raise HTTPException(400, "unknown resource")
    s = get_state()
    req = {
        "id": f"AR-{len(s.access_requests) + 1:04d}",
        "user": session.username,
        "role": session.profile.get("role"),
        "resource": body.resource,
        "resource_name": REQUESTABLE[body.resource],
        "reason": body.reason,
        "status": "PENDING",
        "approver": approver_for(session.username),
        "decided_by": None,
        "note": "",
        "created_at": now_utc().isoformat(),
        "decided_at": None,
    }
    s.access_requests.append(req)
    s.ledger.record_activity(session.username, "requested access", resource=body.resource)
    s.engine.audit.append("access.requested", {k: req[k] for k in ("id", "user", "resource", "approver")})
    return req


class AccessDecision(BaseModel):
    approve: bool
    note: str = Field("", max_length=300)


def _decide_request(req_id: str, body: AccessDecision, by: str) -> dict[str, Any]:
    s = get_state()
    req = next((r for r in s.access_requests if r["id"] == req_id), None)
    if req is None:
        raise HTTPException(404, "no such request")
    if req["status"] != "PENDING":
        raise HTTPException(409, "already decided")
    if req["user"] == by:
        raise HTTPException(403, "you cannot approve your own request")
    req.update(
        status="APPROVED" if body.approve else "DENIED",
        decided_by=by,
        note=body.note,
        decided_at=now_utc().isoformat(),
    )
    s.engine.audit.append(
        "access.decided", {"id": req_id, "user": req["user"], "resource": req["resource"], "status": req["status"], "by": by}
    )
    return req


# --------------------------------------------------------------------------- #
# Manager: team view
# --------------------------------------------------------------------------- #


@app.get("/api/team/overview")
def team_overview(session: Session = Depends(require_manager)) -> dict[str, Any]:
    """Risk summary for the manager's team. Deliberately says nothing about the
    honeypot: a manager who knew could tip off the person being watched."""
    s = get_state()
    members = []
    for actor in team_of(session.username):
        mine = [d for d in s.engine.decisions if d.event.actor == actor]
        flagged = [d for d in mine if d.action_taken is not ActionTaken.ALLOW]
        members.append(
            {
                "user": actor,
                "role": BY_ACTOR[actor].role.value,
                "activities": len(mine),
                "flagged": len(flagged),
                "peak_risk": max((d.risk.total for d in mine), default=0.0),
                "last_activity": mine[-1].event.ts.isoformat() if mine else None,
                "risk_trend": [round(d.risk.total, 1) for d in mine[-20:]],
            }
        )
    return {"manager": session.username, "branch": BY_ACTOR[session.username].city, "members": members}


@app.get("/api/team/access-requests")
def team_requests(session: Session = Depends(require_manager)) -> list[dict[str, Any]]:
    return [r for r in get_state().access_requests if r["approver"] == session.username][::-1]


@app.post("/api/team/access-requests/{req_id}/decide")
def team_decide(req_id: str, body: AccessDecision, session: Session = Depends(require_manager)) -> dict[str, Any]:
    req = next((r for r in get_state().access_requests if r["id"] == req_id), None)
    if req is not None and req["approver"] != session.username:
        raise HTTPException(403, "not your team's request")
    return _decide_request(req_id, body, session.username)


# --------------------------------------------------------------------------- #
# Super Admin: policy and access requests without a manager
# --------------------------------------------------------------------------- #


@app.get("/api/policy")
def read_policy() -> dict[str, Any]:
    """The live thresholds, read-only, for the console's charts."""
    return POLICY.current.as_dict()


@app.get("/api/admin/policies")
def get_policies() -> dict[str, Any]:
    return POLICY.current.as_dict()


class PolicyUpdate(BaseModel):
    medium: float | None = None
    high: float | None = None
    critical: float | None = None
    honeypot_export_threshold: int | None = None
    transfer_limits: dict[str, int] | None = None


@app.put("/api/admin/policies")
def put_policies(body: PolicyUpdate, request: Request) -> dict[str, Any]:
    by = current_session(request).username
    try:
        before, after = POLICY.update(body.model_dump(exclude_none=True))
    except PolicyError as e:
        raise HTTPException(400, str(e)) from e
    changed = {k: {"from": before[k], "to": after[k]} for k in after if before[k] != after[k]}
    get_state().engine.audit.append("policy.changed", {"by": by, "changes": changed}, critical=True)
    return {"policy": after, "changed": changed}


@app.get("/api/admin/access-requests")
def admin_requests() -> list[dict[str, Any]]:
    return get_state().access_requests[::-1]


@app.post("/api/admin/access-requests/{req_id}/decide")
def admin_decide(req_id: str, body: AccessDecision, request: Request) -> dict[str, Any]:
    return _decide_request(req_id, body, current_session(request).username)


# --------------------------------------------------------------------------- #
# Accounts and sessions (SOC or Super Admin)
# --------------------------------------------------------------------------- #


@app.get("/api/accounts")
def accounts() -> list[dict[str, Any]]:
    out = []
    for a in get_auth().accounts():
        staff = BY_ACTOR.get(a["username"])
        a["role"] = staff.role.value if staff else a["kind"]
        a["privilege_level"] = PRIVILEGE_LEVEL[staff.role] if staff else None
        out.append(a)
    return out


class DisableBody(BaseModel):
    reason: str = Field(..., min_length=3, max_length=200)


@app.post("/api/accounts/{username}/disable")
def disable_account(username: str, body: DisableBody, request: Request) -> dict[str, Any]:
    by = current_session(request).username
    a = get_auth()
    if not a.exists(username):
        raise HTTPException(404, "no such account")
    if username == by:
        raise HTTPException(400, "you cannot disable yourself")
    signed_out = a.disable(username, by, body.reason)
    if get_db() is not None:
        get_db().set_user_status(username, "disabled")
    s = get_state()
    s.engine.audit.append("account.disabled", {"username": username, "by": by, "reason": body.reason}, critical=True)
    s.incidents.note_for_user(username, "action", f"Account disabled by {by}: {body.reason}")
    return {"disabled": username, "sessions_signed_out": signed_out}


@app.post("/api/accounts/{username}/enable")
def enable_account(username: str, request: Request) -> dict[str, Any]:
    by = current_session(request).username
    if not get_auth().enable(username):
        raise HTTPException(404, "account is not disabled")
    if get_db() is not None:
        get_db().set_user_status(username, "active")
    get_state().engine.audit.append("account.enabled", {"username": username, "by": by}, critical=True)
    return {"enabled": username}


@app.get("/api/sessions")
def sessions() -> list[dict[str, Any]]:
    return [
        {
            "session_id": x.session_id,
            "username": x.username,
            "kind": x.kind,
            "role": x.profile.get("role"),
            "expires": x.expires.isoformat(),
        }
        for x in get_auth().sessions()
    ]


@app.post("/api/sessions/{session_id}/revoke")
def revoke_session(session_id: str, request: Request) -> dict[str, Any]:
    by = current_session(request).username
    ended = get_auth().revoke(session_id)
    if ended is None:
        raise HTTPException(404, "no such session")
    s = get_state()
    s.engine.ctx.revoke(session_id)  # any further use of it is now a signal too
    if get_db() is not None:
        get_db().close_session(session_id, "revoked")
    s.engine.audit.append("session.revoked", {"session_id": session_id, "user": ended.username, "by": by}, critical=True)
    s.incidents.note_for_user(ended.username, "action", f"Session {session_id} revoked by {by}.")
    return {"revoked": session_id, "user": ended.username}


# --------------------------------------------------------------------------- #
# Alerts and incidents
# --------------------------------------------------------------------------- #


@app.get("/api/alerts")
def alerts(status: str | None = None, limit: int = Query(100, ge=1, le=1000)) -> list[dict[str, Any]]:
    items = list(get_state().incidents.alerts.values())[::-1]
    if status:
        items = [a for a in items if a.status == status.upper()]
    return [a.as_dict() for a in items[:limit]]


@app.get("/api/alerts/{alert_id}")
def alert(alert_id: str) -> dict[str, Any]:
    a = get_state().incidents.alerts.get(alert_id)
    if a is None:
        raise HTTPException(404, "no such alert")
    return a.as_dict()


class StatusBody(BaseModel):
    status: str


@app.post("/api/alerts/{alert_id}/status")
def alert_status(alert_id: str, body: StatusBody) -> dict[str, Any]:
    book = get_state().incidents
    if alert_id not in book.alerts:
        raise HTTPException(404, "no such alert")
    try:
        return book.set_alert_status(alert_id, body.status.upper()).as_dict()
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@app.get("/api/incidents")
def incidents(status: str | None = None) -> list[dict[str, Any]]:
    items = list(get_state().incidents.incidents.values())[::-1]
    if status:
        items = [i for i in items if i.status == status.upper()]
    return [i.as_dict(full=False) for i in items]


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=120)
    user: str
    severity: str = "HIGH"
    description: str = Field("", max_length=1000)


@app.post("/api/incidents")
def create_incident(body: IncidentCreate, request: Request) -> dict[str, Any]:
    if body.severity.upper() not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise HTTPException(400, "severity must be LOW, MEDIUM, HIGH or CRITICAL")
    inc = get_state().incidents.create(
        title=body.title, user=body.user, severity=body.severity.upper(),
        description=body.description, by=current_session(request).username,
    )
    return _saved(inc)


def _incident(incident_id: str):
    inc = get_state().incidents.incidents.get(incident_id)
    if inc is None:
        raise HTTPException(404, "no such incident")
    return inc


def _saved(inc) -> dict[str, Any]:
    """Persist an incident after an analyst changes it, then return it."""
    if get_db() is not None:
        get_db().upsert_incident(inc)
    return inc.as_dict()


@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str) -> dict[str, Any]:
    inc = _incident(incident_id)
    d = inc.as_dict()
    book = get_state().incidents
    d["alerts"] = [book.alerts[a].as_dict() for a in inc.alert_ids]
    d["honeypot"] = next(
        (w.as_dict() for w in get_state().ledger.watch_entries() if w.actor == inc.user), None
    )
    return d


class AssignBody(BaseModel):
    analyst: str = Field(..., min_length=2, max_length=60)


@app.post("/api/incidents/{incident_id}/assign")
def assign_incident(incident_id: str, body: AssignBody, request: Request) -> dict[str, Any]:
    _incident(incident_id)
    return _saved(get_state().incidents.assign(incident_id, body.analyst, current_session(request).username))


class NoteBody(BaseModel):
    text: str = Field(..., min_length=1, max_length=2000)


@app.post("/api/incidents/{incident_id}/notes")
def note_incident(incident_id: str, body: NoteBody, request: Request) -> dict[str, Any]:
    _incident(incident_id)
    return _saved(get_state().incidents.note(incident_id, body.text, current_session(request).username))


@app.post("/api/incidents/{incident_id}/status")
def incident_status(incident_id: str, body: StatusBody, request: Request) -> dict[str, Any]:
    _incident(incident_id)
    try:
        inc = get_state().incidents.set_status(incident_id, body.status.upper(), current_session(request).username)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    get_state().engine.audit.append("incident.status", {"id": incident_id, "status": inc.status})
    return _saved(inc)


class IncidentAction(BaseModel):
    action: str  # revoke_sessions | disable_account | enable_account
    reason: str = "incident response"


@app.post("/api/incidents/{incident_id}/actions")
def incident_action(incident_id: str, body: IncidentAction, request: Request) -> dict[str, Any]:
    inc = _incident(incident_id)
    by = current_session(request).username
    s, a = get_state(), get_auth()
    if body.action == "revoke_sessions":
        ended = [x for x in a.sessions() if x.username == inc.user]
        for x in ended:
            a.revoke(x.session_id)
            s.engine.ctx.revoke(x.session_id)
        detail = f"{len(ended)} session(s) ended"
    elif body.action == "disable_account":
        detail = f"account disabled, {a.disable(inc.user, by, body.reason)} session(s) ended"
    elif body.action == "enable_account":
        a.enable(inc.user)
        detail = "account re-enabled"
    else:
        raise HTTPException(400, "action must be revoke_sessions, disable_account or enable_account")
    s.engine.audit.append("incident.action", {"id": incident_id, "action": body.action, "by": by}, critical=True)
    return _saved(s.incidents.record_action(incident_id, body.action, by, detail))


# --------------------------------------------------------------------------- #
# Risk-based access control
# --------------------------------------------------------------------------- #

#: Minimum privilege level for each protected resource (role-based part).
RESOURCE_MIN_LEVEL = {
    "customer_database": 2,
    "transaction_database": 2,
    "payroll_system": 3,
    "financial_records": 3,
    "authentication_server": 5,
    "admin_console": 5,
}


class AccessCheck(BaseModel):
    user: str
    resource: str


@app.post("/api/access/check")
def access_check(body: AccessCheck) -> dict[str, Any]:
    """Role + behaviour + risk, not RBAC alone.

    Role decides whether the resource is in scope at all. The person's current
    risk (their latest score, and whether they are in the honeypot) then
    decides whether in-scope access is normal, needs MFA, or is refused.
    """
    staff = BY_ACTOR.get(body.user)
    if staff is None:
        raise HTTPException(404, "unknown user")
    if body.resource not in RESOURCE_MIN_LEVEL:
        raise HTTPException(400, f"resource must be one of {sorted(RESOURCE_MIN_LEVEL)}")
    s = get_state()
    level = PRIVILEGE_LEVEL[staff.role]
    recent = [d for d in s.engine.decisions if d.event.actor == body.user][-10:]
    risk = max((d.risk.total for d in recent), default=0.0)
    band = max((d.risk.band for d in recent), key=lambda b: list(Band).index(b), default=Band.LOW)
    approved = any(
        r["user"] == body.user and r["status"] == "APPROVED" and body.resource.split("_")[0] in r["resource"]
        for r in s.access_requests
    )
    in_scope = level >= RESOURCE_MIN_LEVEL[body.resource] or approved
    privileged = level >= 4

    if not in_scope:
        decision, why = "DENIED", "role is below the resource's minimum privilege and no approved request exists"
    elif band is Band.CRITICAL or (privileged and band is Band.HIGH):
        decision, why = "BLOCK_AND_REVOKE", f"{band.value} risk on a {'privileged ' if privileged else ''}account"
    elif band is Band.HIGH:
        decision, why = "RESTRICTED", "high current risk: read-only, no export"
    elif band is Band.MEDIUM or (privileged and body.resource in ("admin_console", "authentication_server")):
        decision, why = "MFA_REQUIRED", "medium risk, or privileged access to a critical system"
    else:
        decision, why = "ALLOWED", "in scope and low risk"
    monitoring = "enhanced" if privileged or decision != "ALLOWED" else "standard"
    return {
        "user": body.user,
        "role": staff.role.value,
        "resource": body.resource,
        "decision": decision,
        "reason": why,
        "current_risk": risk,
        "risk_band": band.value,
        "monitoring": monitoring,
    }


# --------------------------------------------------------------------------- #
# Dashboard aggregates
# --------------------------------------------------------------------------- #


@app.get("/api/dashboard/statistics")
def dashboard_statistics() -> dict[str, Any]:
    s = get_state()
    decisions = s.engine.decisions
    peak: dict[str, float] = {}
    for d in decisions:
        peak[d.event.actor] = max(peak.get(d.event.actor, 0.0), d.risk.total)
    alerts_ = list(s.incidents.alerts.values())
    return {
        "total_users": len(ROSTER),
        "active_sessions": len(get_auth().sessions()),
        "high_risk_users": sum(v >= POLICY.current.high for v in peak.values()),
        "critical_alerts": sum(a.severity == "CRITICAL" and a.status == "OPEN" for a in alerts_),
        "blocked_messages": sum(
            d.event.action is Action.SEND_MESSAGE and d.action_taken is ActionTaken.BLOCK_AND_ALERT for d in decisions
        ),
        "quarantined_messages": len(s.engine.quarantine),
        "privileged_accounts": sum(PRIVILEGE_LEVEL[x.role] >= 4 for x in ROSTER),
        "threat_distribution": {
            c: sum(d.threat_class.value == c for d in decisions)
            for c in ("negligent", "malicious", "compromised", "privilege_abuse")
        },
        "score_distribution": {
            band.value: sum(d.risk.band is band for d in decisions) for band in Band
        },
        "alerts_by_type": _count(a.alert_type for a in alerts_),
    }


@app.get("/api/dashboard/risk-trends")
def risk_trends(buckets: int = Query(24, ge=4, le=96)) -> dict[str, Any]:
    """Decisions bucketed over simulated time: volume, flagged, mean and peak risk."""
    ds = get_state().engine.decisions
    if not ds:
        return {"buckets": []}
    t0, t1 = ds[0].event.ts, ds[-1].event.ts
    span = max((t1 - t0).total_seconds(), 1.0) / buckets
    rows = [{"start": (t0 + timedelta(seconds=span * i)).isoformat(), "count": 0, "flagged": 0, "sum": 0.0, "peak": 0.0} for i in range(buckets)]
    for d in ds:
        i = min(buckets - 1, int((d.event.ts - t0).total_seconds() // span))
        r = rows[i]
        r["count"] += 1
        r["sum"] += d.risk.total
        r["peak"] = max(r["peak"], d.risk.total)
        r["flagged"] += d.action_taken is not ActionTaken.ALLOW
    for r in rows:
        r["mean"] = round(r.pop("sum") / r["count"], 1) if r["count"] else 0.0
    return {"buckets": rows}


@app.get("/api/users/{actor}/risk")
def user_risk(actor: str) -> dict[str, Any]:
    """Risk profile: trend, classification history, devices, places, alerts."""
    if actor not in BY_ACTOR:
        raise HTTPException(404, "unknown identity")
    s = get_state()
    mine = [d for d in s.engine.decisions if d.event.actor == actor]
    return {
        "user": actor,
        "role": BY_ACTOR[actor].role.value,
        "current_risk": mine[-1].risk.total if mine else 0.0,
        "peak_risk": max((d.risk.total for d in mine), default=0.0),
        "classification": next((d.threat_class.value for d in reversed(mine) if d.threat_class.value != "benign"), "benign"),
        "trend": [{"ts": d.event.ts.isoformat(), "risk": d.risk.total, "action": d.event.action.value} for d in mine[-60:]],
        "logins": [
            {"ts": d.event.ts.isoformat(), "city": d.event.geo.city, "device": d.event.device_id, "ip": d.event.source_ip,
             "success": d.event.success, "risk": d.risk.total}
            for d in mine if d.event.action in (Action.LOGIN, Action.LOGIN_FAILED)
        ][-20:],
        "devices": _count(d.event.device_id for d in mine),
        "locations": _count(d.event.geo.city for d in mine),
        "resources": _count(d.event.resource for d in mine if d.event.resource),
        "messages": sum(d.event.action is Action.SEND_MESSAGE for d in mine),
        "alerts": [a.as_dict() for a in s.incidents.alerts.values() if a.user == actor],
    }


@app.get("/api/users/{actor}/activity")
def user_activity(actor: str, limit: int = Query(50, ge=1, le=500)) -> list[dict[str, Any]]:
    if actor not in BY_ACTOR:
        raise HTTPException(404, "unknown identity")
    mine = [d for d in get_state().engine.decisions if d.event.actor == actor][-limit:]
    return [_dump(d) for d in reversed(mine)]


def _count(values) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: kv[1], reverse=True))


# --------------------------------------------------------------------------- #
# WebSocket live feed (same payloads as the SSE stream)
# --------------------------------------------------------------------------- #


@app.websocket("/api/ws")
async def ws_feed(ws: WebSocket) -> None:
    """Decisions and alerts pushed as JSON: {"type": "decision"|"alert", "data": ...}.
    The console route guard does not see WebSocket upgrades, so this checks
    the token itself."""
    session = get_auth().get(ws.query_params.get("token"))
    if session is None or session.kind not in CONSOLE:
        await ws.close(code=4401)
        return
    await ws.accept()
    engine = get_state().engine
    queue = engine.subscribe()
    try:
        while True:
            kind, item = await queue.get()
            await ws.send_json({"type": kind, "data": _wire(kind, item)})
    except WebSocketDisconnect:
        pass
    finally:
        engine.unsubscribe(queue)


@app.get("/api/db/status")
def db_status() -> dict[str, Any]:
    """Is the database on, what is in it, and does the stored audit chain hold."""
    db = get_db()
    if db is None:
        return {"enabled": False, "reason": "DATABASE_URL not set; running in memory only"}
    safe = re.sub(r"//([^:/@]+):[^@]*@", r"//\1:***@", db.url)
    return {
        "enabled": True,
        "url": safe,
        "dialect": db.engine.dialect.name,
        "run_id": db.run_id,
        "rows": db.counts(),
        "audit_chain": db.audit_integrity(),
    }
