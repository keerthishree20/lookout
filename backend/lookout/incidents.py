"""Security alerts and incident management.

Every HIGH or CRITICAL decision raises an **alert**. Alerts about the same
person roll up into one open **incident**, which is what an analyst actually
works: a timeline of what happened, the evidence behind it, the AI explanation,
what the system did automatically, what the analyst did, notes, and a status.

Grouping by person is deliberate. Seven alerts from one hijacked session are
one problem, and presenting them as seven tickets is how real attacks get lost
in alert fatigue.
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .models import ActionTaken, Band, Decision

ALERT_STATUSES = ("OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE")
INCIDENT_STATUSES = ALERT_STATUSES

#: Detector -> alert type, using the names from the project specification.
ALERT_TYPES: dict[str, str] = {
    "impossible_travel": "Impossible Travel",
    "abnormal_login_time": "Abnormal Login",
    "new_device_or_network": "Abnormal Login",
    "credential_misuse": "Credential Misuse",
    "failed_login_burst": "Credential Misuse",
    "privilege_escalation": "Privilege Escalation",
    "out_of_scope_admin_action": "Privilege Escalation",
    "dormant_privileged_account": "Privilege Escalation",
    "mass_record_access": "Sensitive Resource Access",
    "off_hours_data_access": "Sensitive Resource Access",
    "bulk_file_write": "Sensitive Resource Access",
    "vault_hoarding": "Sensitive Resource Access",
    "suspicious_url": "Phishing URL",
    "bulk_message_blast": "Bulk Message Attack",
    "unauthorized_customer_comms": "Suspicious Message",
    "revoked_session_use": "Session Anomaly",
    "locked_origin_use": "Session Anomaly",
    "persistence_after_block": "Session Anomaly",
    "suspicious_transfer": "Transfer Fraud",
    "behavioural_model": "Insider Threat",
}

RECOMMENDED: dict[str, str] = {
    "Impossible Travel": "Treat the account as compromised: reset credentials and review every session since the first login.",
    "Abnormal Login": "Confirm with the employee through a known channel that the sign-in was theirs.",
    "Credential Misuse": "Force a password reset and check the source IP against other accounts.",
    "Privilege Escalation": "Verify there is an approved change ticket; if not, revoke any granted rights and interview the employee.",
    "Sensitive Resource Access": "Establish the business need for the data accessed and check where it was sent.",
    "Phishing URL": "Take down the lookalike domain and warn customers who may have received it.",
    "Bulk Message Attack": "Confirm no messages reached customers and preserve the gateway logs.",
    "Suspicious Message": "Review the held message and the sender's communication mandate.",
    "Session Anomaly": "Invalidate all tokens for this identity and investigate how the revoked session was reused.",
    "Transfer Fraud": "Confirm no real funds moved, freeze the beneficiary if external, and interview the employee.",
    "Insider Threat": "Review the full session timeline before contacting the employee.",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Alert:
    id: str
    severity: str
    user: str
    alert_type: str
    event_id: str
    event: str
    risk_score: float
    ts: datetime
    description: str
    reasons: list[str]
    recommended_action: str
    classification: str
    status: str = "OPEN"
    incident_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        d = {k: getattr(self, k) for k in self.__dataclass_fields__}
        d["ts"] = self.ts.isoformat()
        return d


@dataclass
class Incident:
    id: str
    title: str
    threat_type: str
    user: str
    severity: str
    risk_score: float
    created_at: datetime
    status: str = "OPEN"
    assigned_to: str | None = None
    resolved_at: datetime | None = None
    alert_ids: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)  # event ids
    ai_explanation: str = ""
    ml_opinion: dict[str, Any] | None = None
    actions_taken: list[dict[str, Any]] = field(default_factory=list)
    notes: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)

    def log(self, kind: str, text: str, **detail: Any) -> None:
        self.timeline.append({"ts": _now().isoformat(), "kind": kind, "text": text, **detail})

    def as_dict(self, full: bool = True) -> dict[str, Any]:
        d = {
            "id": self.id,
            "title": self.title,
            "threat_type": self.threat_type,
            "user": self.user,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "created_at": self.created_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "alert_count": len(self.alert_ids),
        }
        if full:
            d.update(
                alert_ids=self.alert_ids,
                evidence=self.evidence,
                ai_explanation=self.ai_explanation,
                ml_opinion=self.ml_opinion,
                actions_taken=self.actions_taken,
                notes=self.notes,
                timeline=self.timeline,
            )
        return d


class IncidentBook:
    def __init__(self) -> None:
        self.alerts: dict[str, Alert] = {}
        self.incidents: dict[str, Incident] = {}
        self._alert_ids = itertools.count(1)
        self._incident_ids = itertools.count(1)
        self._lock = threading.Lock()

    # -- intake ------------------------------------------------------------ #

    def on_decision(self, decision: Decision) -> Alert | None:
        """Raise an alert for HIGH/CRITICAL decisions and file it in the
        person's open incident, opening one if needed."""
        band = decision.risk.band
        blocked = decision.action_taken in (ActionTaken.BLOCK, ActionTaken.BLOCK_AND_ALERT)
        if band not in (Band.HIGH, Band.CRITICAL) and not blocked:
            return None
        event = decision.event
        top = decision.risk.signals[0].name if decision.risk.signals else "behavioural_model"
        alert_type = ALERT_TYPES.get(top, "Insider Threat")
        if decision.threat_class.value == "compromised" and alert_type in ("Abnormal Login", "Insider Threat"):
            alert_type = "Compromised Account"
        severity = "CRITICAL" if band is Band.CRITICAL else "HIGH"

        with self._lock:
            alert = Alert(
                id=f"AL-{next(self._alert_ids):05d}",
                severity=severity,
                user=event.actor,
                alert_type=alert_type,
                event_id=event.event_id,
                event=event.action.value,
                risk_score=decision.risk.total,
                ts=_now(),
                description=decision.narrative,
                reasons=[s.explanation for s in decision.risk.signals],
                recommended_action=RECOMMENDED.get(alert_type, RECOMMENDED["Insider Threat"]),
                classification=decision.threat_class.value,
            )
            incident = self._open_for(event.actor)
            if incident is None:
                incident = Incident(
                    id=f"INC-{next(self._incident_ids):04d}",
                    title=f"{alert_type}: {event.actor}",
                    threat_type=decision.threat_class.value,
                    user=event.actor,
                    severity=severity,
                    risk_score=decision.risk.total,
                    created_at=_now(),
                )
                self.incidents[incident.id] = incident
                incident.log("opened", f"Incident opened by {alert.id} ({alert_type}).")
            alert.incident_id = incident.id
            self.alerts[alert.id] = alert

            incident.alert_ids.append(alert.id)
            incident.evidence.append(event.event_id)
            if decision.risk.total >= incident.risk_score:
                incident.risk_score = decision.risk.total
                incident.threat_type = decision.threat_class.value
                incident.ai_explanation = decision.narrative
                incident.ml_opinion = (
                    {k: v for k, v in decision.ml.items() if k != "features"} if decision.ml else None
                )
            if severity == "CRITICAL":
                incident.severity = "CRITICAL"
            incident.log(
                "alert",
                f"{alert.id} {severity} {alert_type} -- {event.action.value.replace('_', ' ')} "
                f"scored {decision.risk.total:.0f}",
                alert_id=alert.id,
            )
            automatic = {
                ActionTaken.STEP_UP: "Step-up authentication required",
                ActionTaken.QUARANTINE: "Message quarantined",
                ActionTaken.BLOCK: "Action blocked",
                ActionTaken.BLOCK_AND_ALERT: "Action blocked, session revoked, SOC paged",
            }.get(decision.action_taken)
            if automatic:
                incident.actions_taken.append(
                    {"ts": _now().isoformat(), "by": "lookout", "action": automatic, "event_id": event.event_id}
                )
            return alert

    def note_for_user(self, user: str, kind: str, text: str) -> None:
        """Add context (honeypot activity, decoys) to the user's open incident."""
        with self._lock:
            incident = self._open_for(user)
            if incident is not None:
                incident.log(kind, text)

    def _open_for(self, user: str) -> Incident | None:
        return next(
            (i for i in self.incidents.values() if i.user == user and i.status in ("OPEN", "INVESTIGATING")),
            None,
        )

    # -- analyst work -------------------------------------------------------- #

    def create(self, *, title: str, user: str, severity: str, description: str, by: str) -> Incident:
        with self._lock:
            inc = Incident(
                id=f"INC-{next(self._incident_ids):04d}",
                title=title,
                threat_type="manual",
                user=user,
                severity=severity,
                risk_score=0.0,
                created_at=_now(),
                ai_explanation=description,
            )
            inc.log("opened", f"Opened manually by {by}.")
            self.incidents[inc.id] = inc
            return inc

    def assign(self, incident_id: str, analyst: str, by: str) -> Incident:
        inc = self.incidents[incident_id]
        inc.assigned_to = analyst
        if inc.status == "OPEN":
            inc.status = "INVESTIGATING"
        inc.log("assigned", f"Assigned to {analyst} by {by}.")
        return inc

    def note(self, incident_id: str, text: str, by: str) -> Incident:
        inc = self.incidents[incident_id]
        inc.notes.append({"ts": _now().isoformat(), "by": by, "text": text})
        inc.log("note", f"{by}: {text}")
        return inc

    def set_status(self, incident_id: str, status: str, by: str) -> Incident:
        if status not in INCIDENT_STATUSES:
            raise ValueError(f"status must be one of {INCIDENT_STATUSES}")
        inc = self.incidents[incident_id]
        inc.status = status
        inc.resolved_at = _now() if status in ("RESOLVED", "FALSE_POSITIVE") else None
        for aid in inc.alert_ids:
            if status in ("RESOLVED", "FALSE_POSITIVE"):
                self.alerts[aid].status = status
            elif self.alerts[aid].status == "OPEN":
                self.alerts[aid].status = status
        inc.log("status", f"Status set to {status} by {by}.")
        return inc

    def record_action(self, incident_id: str, action: str, by: str, detail: str = "") -> Incident:
        inc = self.incidents[incident_id]
        inc.actions_taken.append({"ts": _now().isoformat(), "by": by, "action": action, "detail": detail})
        inc.log("action", f"{by}: {action}{' -- ' + detail if detail else ''}")
        return inc

    def set_alert_status(self, alert_id: str, status: str) -> Alert:
        if status not in ALERT_STATUSES:
            raise ValueError(f"status must be one of {ALERT_STATUSES}")
        alert = self.alerts[alert_id]
        alert.status = status
        return alert
