"""The spec's message risk formula, computed from the same signals.

    Message Risk = URL + Sender Behaviour + Content + Destination + Privilege + Volume

Lookout doesn't score messages with a separate formula: a message is an event
like any other, scored by the detectors, the behavioural model and the
privilege multiplier. This module breaks that one score down into the six
components the spec names, so they always add up to the score that decided
the message's fate. Nothing is double-counted and nothing is invented.
"""

from __future__ import annotations

from .models import Decision

COMPONENTS = ("url", "sender_behaviour", "content", "destination", "privilege", "volume")

_BY_SIGNAL = {
    "suspicious_url": "url",
    "phishing_language": "content",
    "sensitive_data_leak": "content",
    "risky_attachment": "content",
    "bulk_message_blast": "volume",
    "repeated_message": "volume",
    "unauthorized_customer_comms": "privilege",
}

#: Points each detector adds when the recipient is a personal mailbox. They
#: belong to the destination, not the content.
_PERSONAL_MAILBOX_POINTS = {"sensitive_data_leak": 14.0, "risky_attachment": 10.0}


def components(decision: Decision) -> dict[str, float]:
    """Each component's share of ``decision.risk.total`` (0-100 overall)."""
    raw = dict.fromkeys(COMPONENTS, 0.0)
    for s in decision.risk.signals:
        bucket = _BY_SIGNAL.get(s.name, "sender_behaviour")
        points = s.points
        if s.name in _PERSONAL_MAILBOX_POINTS and s.detail.get("personal_mailbox"):
            moved = min(points, _PERSONAL_MAILBOX_POINTS[s.name])
            raw["destination"] += moved
            points -= moved
        raw[bucket] += points
    before = sum(raw.values())
    if before <= 0:
        return {k: 0.0 for k in COMPONENTS}
    # The privilege multiplier's extra is the privilege component's too.
    multiplier = decision.risk.privilege_multiplier
    raw["privilege"] += before * (multiplier - 1.0)
    total = decision.risk.total
    scale = total / sum(raw.values())
    out = {k: round(v * scale, 1) for k, v in raw.items()}
    # Make the rounded parts add up exactly to the displayed score.
    drift = round(total - sum(out.values()), 1)
    if drift:
        biggest = max(out, key=out.get)
        out[biggest] = round(out[biggest] + drift, 1)
    return out
