"""HTTP surface: REST for the console, SSE for the live feed.

Run with ``uvicorn lookout.api:app --reload`` from ``backend/``.

The app owns one :class:`~lookout.pipeline.Engine`. On startup it replays a
month of synthetic history to build baselines and fit the behavioural model,
then (unless ``LOOKOUT_LIVE_TRAFFIC=0``) keeps a trickle of ordinary staff
activity flowing so the console shows a working bank rather than an empty room.
Scenarios are injected into that same stream.
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

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from . import scenarios as scenario_mod
from .evaluate import run_evaluation
from .generator import BY_ACTOR, CITIES, generate_history
from .models import Action, Decision, Event, MessagePayload
from .narrator import Narrator
from .pipeline import Engine
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


def get_state() -> AppState:
    assert state is not None, "app not started"
    return state


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
    global state
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
    version="0.1.0",
    lifespan=lifespan,
)

_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
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
