"""The engine: one event in, one explained decision out.

    event -> baseline lookup -> rules + model -> fused score -> graded action
          -> signed audit entry -> live feed

Order matters in two places. The baseline is read *before* it is updated, so a
detector never sees the event it is judging folded into that identity's normal.
And the audit entry is written before the decision is returned, so there is no
window in which Lookout acted without a record of acting.
"""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Callable, Iterable

from .anomaly import BehaviourModel, featurise, train_from_history
from .audit import AuditLog
from .baselines import BaselineStore
from .context import DetectionContext
from .crypto import SealedBlob, build_sealer, build_signer, crypto_status
from .generator import generate_history
from .models import Action, ActionTaken, Decision, Event, ThreatClass
from .narrator import Narrator
from .rules import run_detectors
from .scoring import (
    classify,
    decide,
    fuse,
    is_strike,
    should_lock_origin,
    should_revoke_session,
    step_up_requirement,
)

if TYPE_CHECKING:
    from .ml.model import ThreatClassifier


class Engine:
    """Holds all live state: baselines, model, audit chain, quarantine."""

    def __init__(
        self,
        narrator: Narrator | None = None,
        prefer_pqc: bool = True,
        audit_seed: bytes | None = None,
        classifier: "ThreatClassifier | None" = None,
    ) -> None:
        self.store = BaselineStore()
        self.ctx = DetectionContext()
        self.model = BehaviourModel()
        self.signer = build_signer(prefer_pqc, audit_seed)
        self.sealer = build_sealer(prefer_pqc)
        self.audit = AuditLog(self.signer)
        self.narrator = narrator or Narrator()
        self.decisions: list[Decision] = []
        self.quarantine: dict[str, Decision] = {}
        #: Review state for held messages: INVESTIGATING (still held, linked to
        #: an incident) or a final outcome once it has left the queue.
        self.quarantine_review: dict[str, dict[str, Any]] = {}
        self._quarantine_seq = 0
        self.history_size = 0
        #: Supervised second opinion. None disables it (and SHAP) entirely.
        self.classifier = classifier
        self._lock = threading.Lock()
        self._subscribers: list[asyncio.Queue] = []
        #: Called with every decision after it is recorded. The API uses this
        #: to move high-risk employees into the honeypot.
        self.listeners: list[Callable[[Decision], None]] = []

    # -- setup ------------------------------------------------------------ #

    def warm_up(self, days: int = 30, seed: int = 20260921) -> "Engine":
        """Replay a month of benign history to build baselines and fit the model.

        Nothing from warm-up is scored or audited: it is the past the system is
        assumed to have already lived through.
        """
        history = generate_history(days=days, seed=seed)
        self.model = train_from_history(history, self.store, self.ctx)
        self.history_size = len(history)
        self.audit.append(
            "engine.warm_up",
            {
                "history_events": len(history),
                "identities": len(self.store),
                "model_fitted": self.model.fitted,
                "model_trained_on": self.model.trained_on,
                "signing_algorithm": self.signer.algorithm,
            },
        )
        return self

    # -- the hot path ----------------------------------------------------- #

    def ingest(self, event: Event) -> Decision:
        """Score one event, act on it, record it. Thread-safe."""
        with self._lock:
            baseline = self.store.get(event.actor, event.actor_role)

            session = str(event.meta.get("session_id", ""))
            signals = run_detectors(event, baseline, self.ctx)
            anomaly = self.model.score(featurise(event, baseline, self.ctx))
            risk = fuse(event, signals, anomaly)
            action, policy = decide(risk, event)
            threat_class = (
                classify(signals, event, prior=self.ctx.prior_class(session))
                if action is not ActionTaken.ALLOW
                else ThreatClass.BENIGN
            )

            decision = Decision(
                event=event,
                risk=risk,
                action_taken=action,
                threat_class=threat_class,
                policy=policy,
            )
            self._respond(decision)
            if self.classifier is not None and action is not ActionTaken.ALLOW:
                decision.ml = self._second_opinion(event, baseline, session)
            decision.narrative = self.narrator.describe(decision)

            entry = self.audit.append(
                "decision",
                _audit_payload(decision),
                critical=action is ActionTaken.BLOCK_AND_ALERT,
            )
            decision.audit_seq = entry.seq

            # Learn from it only now, and only if it was let through clean: a
            # baseline that absorbs the attack normalises the attack.
            self.ctx.record(event)
            if action is ActionTaken.ALLOW:
                baseline.observe(event)

            self.decisions.append(decision)

        self._broadcast(decision)
        for listener in self.listeners:
            listener(decision)
        return decision

    def assess(self, event: Event) -> Decision:
        """Score an event without acting on it or recording it: no audit
        entry, no baseline update, no containment. For "what would Lookout do
        if..." questions (``POST /api/risk/calculate``)."""
        with self._lock:
            baseline = self.store.get(event.actor, event.actor_role)
            session = str(event.meta.get("session_id", ""))
            signals = run_detectors(event, baseline, self.ctx)
            anomaly = self.model.score(featurise(event, baseline, self.ctx))
            risk = fuse(event, signals, anomaly)
            action, policy = decide(risk, event)
            threat_class = (
                classify(signals, event, prior=self.ctx.prior_class(session))
                if action is not ActionTaken.ALLOW
                else ThreatClass.BENIGN
            )
            decision = Decision(
                event=event, risk=risk, action_taken=action, threat_class=threat_class, policy=policy
            )
            decision.narrative = self.narrator.describe(decision)
            return decision

    def _second_opinion(self, event: Event, baseline, session: str) -> dict[str, Any]:
        """Classify the whole session so far, not just this event."""
        from .ml.features import session_features

        events = self.ctx.session_events(event.actor, session, event.ts) + [event]
        features = session_features(events, baseline)
        opinion = self.classifier.opinion(features, explain=False)
        return {
            "classification": opinion.classification,
            "confidence": round(opinion.confidence, 4),
            "probabilities": {k: round(v, 4) for k, v in opinion.probabilities.items()},
            "session_events": len(events),
            "features": {k: round(v, 4) for k, v in features.items()},
        }

    def explain(self, decision: Decision) -> dict[str, Any]:
        """SHAP breakdown of the classifier's opinion on this decision's session."""
        if self.classifier is None or not decision.ml:
            return {"available": False}
        opinion = self.classifier.opinion(decision.ml["features"], explain=True, top=8)
        return {"available": True, **opinion.as_dict()}

    def ingest_many(self, events: Iterable[Event]) -> list[Decision]:
        return [self.ingest(e) for e in events]

    def _respond(self, decision: Decision) -> None:
        """Carry out the graded action. This is where the system stops being an
        observer."""
        event = decision.event
        session = str(event.meta.get("session_id", ""))
        taken = decision.action_taken

        if should_revoke_session(taken, event):
            self.ctx.revoke(session)
        if should_lock_origin(taken, event):
            self.ctx.lock_origin(event.actor, event.source_ip)
        if is_strike(taken):
            self.ctx.strike(session)
        self.ctx.remember_class(session, decision.threat_class)

        if decision.action_taken is ActionTaken.QUARANTINE:
            self._quarantine_seq += 1
            qid = f"q-{self._quarantine_seq:04d}"
            decision.quarantine_id = qid
            self.quarantine[qid] = decision

        if decision.action_taken is ActionTaken.STEP_UP:
            event.meta["step_up_required"] = step_up_requirement(decision.risk, event)

    # -- quarantine ------------------------------------------------------- #

    def release(self, quarantine_id: str, reviewer: str) -> Decision | None:
        """A human overrules the hold. Recorded, because overrides are exactly
        what an investigation later needs to see."""
        decision = self.quarantine.pop(quarantine_id, None)
        if decision is None:
            return None
        self.quarantine_review[quarantine_id] = {"status": "RELEASED", "by": reviewer}
        self.audit.append(
            "quarantine.release",
            {
                "quarantine_id": quarantine_id,
                "reviewer": reviewer,
                "original_event": decision.event.event_id,
                "original_score": decision.risk.total,
            },
            critical=True,
        )
        return decision

    def close_quarantine(self, quarantine_id: str, outcome: str, reviewer: str) -> Decision | None:
        """Take a held message out of the queue for good without delivering it.

        ``blocked`` keeps it on record as a confirmed bad message and counts a
        strike against the sender's session; ``deleted`` discards it as junk.
        Either way the message never reaches anyone, and the audit log says
        who decided.
        """
        if outcome not in ("blocked", "deleted"):
            raise ValueError("outcome must be blocked or deleted")
        decision = self.quarantine.pop(quarantine_id, None)
        if decision is None:
            return None
        if outcome == "blocked":
            self.ctx.strike(str(decision.event.meta.get("session_id", "")))
        self.quarantine_review[quarantine_id] = {"status": outcome.upper(), "by": reviewer}
        self.audit.append(
            {"blocked": "quarantine.block", "deleted": "quarantine.delete"}[outcome],
            {
                "quarantine_id": quarantine_id,
                "reviewer": reviewer,
                "sender": decision.event.actor,
                "original_event": decision.event.event_id,
                "original_score": decision.risk.total,
            },
            critical=True,
        )
        return decision

    def investigate_quarantine(self, quarantine_id: str, reviewer: str, incident_id: str) -> Decision | None:
        """Keep the message held and tie it to an incident."""
        decision = self.quarantine.get(quarantine_id)
        if decision is None:
            return None
        self.quarantine_review[quarantine_id] = {"status": "INVESTIGATING", "by": reviewer, "incident_id": incident_id}
        self.audit.append(
            "quarantine.investigate",
            {"quarantine_id": quarantine_id, "reviewer": reviewer, "incident_id": incident_id},
        )
        return decision

    # -- quantum-safe artefact sealing ------------------------------------ #

    def seal_credential(self, name: str, secret: str) -> dict[str, Any]:
        """Seal a credential artefact under ML-KEM and record that it happened.

        The audit entry deliberately holds the ciphertext's identity, never the
        plaintext: the log is meant to be readable by auditors who are not
        entitled to the secret.
        """
        blob = self.sealer.seal(secret.encode(), aad=name.encode())
        entry = self.audit.append(
            "credential.sealed",
            {
                "name": name,
                "algorithm": self.sealer.algorithm,
                "quantum_safe": self.sealer.quantum_safe,
                "ciphertext_bytes": len(blob.ciphertext),
            },
        )
        return {"name": name, "audit_seq": entry.seq, **blob.to_dict()}

    def unseal_credential(self, name: str, blob: dict[str, str]) -> str:
        return self.sealer.unseal(SealedBlob(**blob), aad=name.encode()).decode()

    # -- views ------------------------------------------------------------ #

    def crypto(self) -> dict[str, Any]:
        return crypto_status(self.signer, self.sealer)

    def stats(self) -> dict[str, Any]:
        by_action: dict[str, int] = {}
        by_class: dict[str, int] = {}
        for d in self.decisions:
            by_action[d.action_taken.value] = by_action.get(d.action_taken.value, 0) + 1
            by_class[d.threat_class.value] = by_class.get(d.threat_class.value, 0) + 1
        scored = [d.risk.total for d in self.decisions]
        return {
            "history_events": self.history_size,
            "identities": len(self.store),
            "decisions": len(self.decisions),
            "model_fitted": self.model.fitted,
            "model_trained_on": self.model.trained_on,
            "mean_risk": round(sum(scored) / len(scored), 1) if scored else 0.0,
            "quarantined": len(self.quarantine),
            "audit_entries": len(self.audit.entries),
            "audit_checkpoints": len(self.audit.checkpoints),
            "by_action": by_action,
            "by_threat_class": by_class,
        }

    def recent(self, limit: int = 50) -> list[Decision]:
        return self.decisions[-limit:][::-1]

    # -- live feed -------------------------------------------------------- #

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)

    def _broadcast(self, decision: Decision) -> None:
        self._push(("decision", decision))

    def broadcast_extra(self, kind: str, payload: dict[str, Any]) -> None:
        """Push something other than a decision (an alert, say) to the feed."""
        self._push((kind, payload))

    def _push(self, item: tuple[str, Any]) -> None:
        """Queue for every connected dashboard. Never blocks ingestion: a slow
        browser drops frames rather than back-pressuring the pipeline."""
        for q in list(self._subscribers):
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                pass


def _audit_payload(decision: Decision) -> dict[str, Any]:
    event = decision.event
    return {
        "event_id": event.event_id,
        "ts": event.ts.isoformat(),
        "actor": event.actor,
        "role": event.actor_role.value,
        "action": event.action.value,
        "resource": event.resource,
        "source_ip": event.source_ip,
        "city": event.geo.city,
        "risk_total": decision.risk.total,
        "band": decision.risk.band.value,
        "action_taken": decision.action_taken.value,
        "threat_class": decision.threat_class.value,
        "signals": [s.name for s in decision.risk.signals],
    }


def next_business_moment(base: datetime | None = None) -> datetime:
    """A sensible 'now' for replaying a scenario against the generated history."""
    return (base or datetime(2026, 9, 21, 9, 0)) + timedelta(minutes=30)
