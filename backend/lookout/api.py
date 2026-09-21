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
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from . import scenarios as scenario_mod
from .auth import DEMO_ACCOUNTS, AuthStore, Session
from .customers import customer_book, masked
from .evaluate import run_evaluation
from .generator import BY_ACTOR, CITIES, generate_history
from .models import Action, ActionTaken, Decision, Event, MessagePayload
from .narrator import Narrator
from .pipeline import Engine
from .portal import (
    HONEYPOT_THRESHOLD,
    MAX_EXPORT,
    ExportLedger,
    ExportRecord,
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
        self.ledger = ExportLedger()

    @staticmethod
    def _build_engine() -> Engine:
        seed = os.getenv("LOOKOUT_AUDIT_SEED", "lookout-demo-seed-do-not-use-prod")
        return Engine(
            narrator=Narrator(),
            audit_seed=seed.encode().ljust(32, b"\0")[:32],
        ).warm_up()

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
    state = await asyncio.to_thread(AppState)
    if auth is None:
        auth = await asyncio.to_thread(AuthStore)
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
    version="0.1.0",
    lifespan=lifespan,
)

#: Routes any visitor may call. Everything else under /api/ needs a SOC session.
PUBLIC_PREFIXES = ("/api/health", "/api/auth/", "/api/portal/")


def _token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    # EventSource cannot set headers, so the live stream passes it as a query.
    return request.query_params.get("token")


@app.middleware("http")
async def soc_only(request: Request, call_next):
    """Registered before CORS, so CORS wraps it and a 401 still carries the
    headers the browser needs to read it."""
    path = request.url.path
    if (
        request.method == "OPTIONS"
        or not path.startswith("/api/")
        or path.startswith(PUBLIC_PREFIXES)
    ):
        return await call_next(request)
    session = get_auth().get(_token(request))
    if session is None:
        return JSONResponse({"detail": "sign in as a SOC analyst"}, status_code=401)
    if session.kind != "soc":
        return JSONResponse({"detail": "SOC access only"}, status_code=403)
    return await call_next(request)


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
        "honeypots_served": len(s.ledger.honeypots()),
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
                    d = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": "{}"}
                    continue
                yield {"event": "decision", "data": json.dumps(_dump(d))}
        finally:
            engine.unsubscribe(queue)

    return EventSourceResponse(events())


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


@app.post("/api/auth/login")
def login(body: LoginRequest) -> dict[str, Any]:
    """Every employee sign-in -- including every wrong password -- is an event
    in the pipeline, so guessing at a colleague's account trips the same
    failed-login-burst and credential-misuse detectors as any other attack."""
    a, s = get_auth(), get_state()
    username = body.username.strip()
    staff = BY_ACTOR.get(username)
    ok = a.verify(username, body.password)

    if not ok:
        if staff is not None:
            s.engine.ingest(
                _portal_event(staff, Action.LOGIN_FAILED, s, session_id="", resource="portal")
            )
        elif a.kind_of(username) == "soc":
            s.engine.audit.append("auth.soc_login_failed", {"username": username})
        raise HTTPException(401, "wrong username or password")

    session = a.open_session(username)
    if staff is not None:
        decision = s.engine.ingest(
            _portal_event(staff, Action.LOGIN, s, session.session_id, resource="portal")
        )
        if decision.action_taken in (ActionTaken.BLOCK, ActionTaken.BLOCK_AND_ALERT):
            a.close(session.token)
            raise HTTPException(403, "sign-in blocked by security policy")
    else:
        s.engine.audit.append("auth.soc_login", {"username": username})

    return {"token": session.token, "kind": session.kind, "profile": session.profile}


@app.post("/api/auth/logout")
def logout(request: Request) -> dict[str, Any]:
    token = _token(request)
    if token:
        get_auth().close(token)
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
    book = get_state().book
    needle = q.strip().lower()
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

    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --------------------------------------------------------------------------- #
# Honeypot (SOC)
# --------------------------------------------------------------------------- #


@app.get("/api/honeypots")
def honeypots() -> dict[str, Any]:
    s = get_state()
    return {
        "threshold": HONEYPOT_THRESHOLD,
        "watchlist": s.ledger.watchlist(),
        "served": [r.as_dict() for r in s.ledger.honeypots()],
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
    s.engine.audit.append(
        "honeypot.watchlist_cleared", {"actor": actor, "reviewer": body.reviewer}, critical=True
    )
    return {"cleared": actor, "by": body.reviewer}


@app.get("/api/honeypots/trace")
def trace(q: str = Query(..., min_length=4)) -> dict[str, Any]:
    """Who took this file? Accepts the document reference from a PDF footer or
    any account number found in a leaked copy."""
    hit = get_state().ledger.trace(q)
    if hit is None:
        return {"found": False, "query": q}
    matched_by, rec = hit
    return {"found": True, "query": q, "matched_by": matched_by, "export": rec.as_dict()}
