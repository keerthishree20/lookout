"""Turns a decision into the paragraph a SOC analyst reads first.

The language model is a *narrator*, never a judge. The score, the classification
and the action are all decided before this module is called, by the rules and
the forest. All an LLM does here is read the evidence Lookout already produced
and write it up as prose.

That boundary is the point. An analyst can disagree with the wording; they
cannot be misled about why an account was locked, because the wording cannot
change the decision. And with no API key configured, the deterministic template
below produces a perfectly serviceable summary -- the system never depends on a
network call to explain itself.
"""

from __future__ import annotations

import os

import httpx

from .models import ActionTaken, Band, Decision, ThreatClass

PROMPT = """You are a SOC analyst at a bank writing the first line of an incident note.

Summarise the detection below in 2-3 plain sentences for a duty officer who has
10 seconds to read it. State what the person did, why it was judged risky, and
what the system did about it. Use only the evidence given -- invent nothing, add
no recommendations, and do not soften or escalate the verdict.

Actor: {actor} ({role})
Action: {action} on {resource} from {city}
Risk score: {score}/100 ({band})
Classification: {threat_class}
Response: {taken}{policy}
Evidence:
{signals}
"""

CLASS_PHRASE: dict[ThreatClass, str] = {
    ThreatClass.BENIGN: "no insider-risk indicators",
    ThreatClass.NEGLIGENT: "careless handling rather than intent",
    ThreatClass.MALICIOUS: "deliberate misuse",
    ThreatClass.COMPROMISED: "an account under someone else's control",
    ThreatClass.PRIVILEGE_ABUSE: "abuse of granted privilege",
}

ACTION_PHRASE: dict[ActionTaken, str] = {
    ActionTaken.ALLOW: "The action was allowed and logged",
    ActionTaken.STEP_UP: "Lookout demanded a second authentication factor before continuing",
    ActionTaken.QUARANTINE: "The message was held in quarantine for review rather than delivered",
    ActionTaken.BLOCK: "The action was blocked",
    ActionTaken.BLOCK_AND_ALERT: (
        "The action was blocked, the session revoked and the SOC paged"
    ),
}


class Narrator:
    """Deterministic by default, LLM-assisted when a key is present."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float = 6.0,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.getenv("GEMINI_API_KEY", "")
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self.timeout = timeout
        #: Set when a live call has failed, so one outage does not stall every
        #: subsequent decision waiting on the same dead endpoint.
        self.degraded = False

    @property
    def live(self) -> bool:
        return bool(self.api_key) and not self.degraded

    def describe(self, decision: Decision) -> str:
        if not self.live:
            return self.template(decision)
        try:
            return self._ask_llm(decision) or self.template(decision)
        except Exception:
            self.degraded = True
            return self.template(decision)

    # -- the path that always works --------------------------------------- #

    def template(self, decision: Decision) -> str:
        """Built from the same signals the LLM would be given, so the two
        narratives never disagree about the facts."""
        event = decision.event
        risk = decision.risk

        if risk.band is Band.LOW and not risk.signals:
            return (
                f"{event.actor} performed {_verb(decision)} with no risk indicators "
                f"(score {risk.total:.0f}/100). Allowed and logged."
            )

        lead = (
            f"{event.actor} ({event.actor_role.value}) scored {risk.total:.0f}/100 "
            f"for {_verb(decision)} -- {risk.band.value} risk, consistent with "
            f"{CLASS_PHRASE[decision.threat_class]}."
        )
        top = risk.signals[:2]
        evidence = " ".join(s.explanation for s in top)
        if len(risk.signals) > 2:
            evidence += f" ({len(risk.signals) - 2} further indicators recorded.)"
        tail = f"{ACTION_PHRASE[decision.action_taken]}."
        if decision.quarantine_id:
            tail = f"{ACTION_PHRASE[decision.action_taken]} as {decision.quarantine_id}."
        if decision.policy:
            tail += f" Held by policy: {decision.policy}"
        if decision.action_taken is ActionTaken.STEP_UP:
            factor = str(event.meta.get("step_up_required", "a second factor"))
            tail = (
                f"Lookout required {factor.replace('_', ' ')} before allowing the action."
            )
        return f"{lead} {evidence} {tail}"

    # -- optional live path ----------------------------------------------- #

    def _ask_llm(self, decision: Decision) -> str:
        event = decision.event
        prompt = PROMPT.format(
            actor=event.actor,
            role=event.actor_role.value,
            action=event.action.value.replace("_", " "),
            resource=event.resource or "an internal system",
            city=f"{event.geo.city}, {event.geo.country}",
            score=f"{decision.risk.total:.0f}",
            band=decision.risk.band.value,
            threat_class=decision.threat_class.value,
            taken=decision.action_taken.value.replace("_", " "),
            policy=f" (raised by policy: {decision.policy})" if decision.policy else "",
            signals="\n".join(f"- {s.explanation}" for s in decision.risk.signals)
            or "- none",
        )
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent"
        )
        response = httpx.post(
            url,
            headers={"x-goog-api-key": self.api_key},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 200},
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        parts = response.json()["candidates"][0]["content"]["parts"]
        return " ".join(p.get("text", "") for p in parts).strip()


def _verb(decision: Decision) -> str:
    event = decision.event
    base = event.action.value.replace("_", " ")
    if event.message:
        channel = {"sms": "an SMS", "email": "an email", "push": "a push notification"}.get(
            event.message.channel, f"a {event.message.channel} message"
        )
        n = event.message.recipient_count
        return f"sending {channel} to {n:,} recipient{'' if n == 1 else 's'}"
    if event.action.value == "db_query" and event.meta.get("record_count"):
        return f"reading {int(event.meta['record_count']):,} rows from {event.resource}"
    return f"{base}{' on ' + event.resource if event.resource else ''}"
