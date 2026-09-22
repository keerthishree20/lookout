"""Short-window and per-session state that rules need but baselines do not hold.

Baselines answer "what is normal for this person, ever?". Several detectors
instead need "what has this person done in the last few minutes?" -- a burst of
failed logins, a fan-out of messages, a run of escalation attempts. That lives
here as a bounded, per-actor window of recent events.

It also holds the consequences of earlier decisions, which is what turns
one-shot scoring into session monitoring: a session Lookout revoked, a source it
locked out, a session that already earned a block. Without this, an attacker
who is blocked on one request simply sends the next one.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque

from .models import Action, Event, ThreatClass


class DetectionContext:
    """Recent per-actor history plus live containment state."""

    def __init__(self, window_minutes: int = 30, max_events: int = 400) -> None:
        self.window = timedelta(minutes=window_minutes)
        self.max_events = max_events
        self._recent: dict[str, Deque[Event]] = defaultdict(
            lambda: deque(maxlen=max_events)
        )
        #: Sessions killed by an earlier decision. Any further use is a replay.
        self.revoked_sessions: set[str] = set()
        #: (actor, source IP) pairs locked out after an attack from them.
        self.locked_origins: set[tuple[str, str]] = set()
        #: Blocks, quarantines and step-ups already issued within a session.
        self.session_strikes: dict[str, int] = defaultdict(int)
        #: The most serious threat class a session has been given so far, so
        #: that follow-on activity inherits it rather than resetting to benign.
        self.session_class: dict[str, ThreatClass] = {}

    # -- recent activity -------------------------------------------------- #

    def record(self, event: Event) -> None:
        self._recent[event.actor].append(event)

    def recent(self, actor: str, now, minutes: int | None = None) -> list[Event]:
        span = timedelta(minutes=minutes) if minutes is not None else self.window
        cutoff = now - span
        return [e for e in self._recent[actor] if cutoff <= e.ts <= now]

    def session_events(self, actor: str, session_id: str, now) -> list[Event]:
        """Everything recorded for one session, plus the failed sign-ins in
        the fifteen minutes before it (they carry no session of their own)."""
        cutoff = now - timedelta(minutes=15)
        return [
            e
            for e in self._recent[actor]
            if (session_id and e.meta.get("session_id") == session_id)
            or (e.action is Action.LOGIN_FAILED and e.ts >= cutoff)
        ]

    def count(self, actor: str, action: Action, now, minutes: int | None = None) -> int:
        """Prior events of this kind in the window -- *excluding* the event
        being judged, which has not been recorded yet."""
        return sum(1 for e in self.recent(actor, now, minutes) if e.action is action)

    # -- containment ------------------------------------------------------ #

    def revoke(self, session_id: str) -> None:
        if session_id:
            self.revoked_sessions.add(session_id)

    def lock_origin(self, actor: str, source_ip: str) -> None:
        self.locked_origins.add((actor, source_ip))

    def is_revoked(self, session_id: str) -> bool:
        return bool(session_id) and session_id in self.revoked_sessions

    def is_locked(self, actor: str, source_ip: str) -> bool:
        return (actor, source_ip) in self.locked_origins

    def strike(self, session_id: str) -> None:
        if session_id:
            self.session_strikes[session_id] += 1

    def strikes(self, session_id: str) -> int:
        return self.session_strikes.get(session_id, 0) if session_id else 0

    def remember_class(self, session_id: str, cls: ThreatClass) -> None:
        """Keep the most serious class a session has shown."""
        if not session_id or cls is ThreatClass.BENIGN:
            return
        current = self.session_class.get(session_id)
        if current is None or SEVERITY[cls] > SEVERITY[current]:
            self.session_class[session_id] = cls

    def prior_class(self, session_id: str) -> ThreatClass | None:
        return self.session_class.get(session_id) if session_id else None


#: Used to break ties and to decide which class a session "keeps".
SEVERITY: dict[ThreatClass, int] = {
    ThreatClass.BENIGN: 0,
    ThreatClass.NEGLIGENT: 1,
    ThreatClass.PRIVILEGE_ABUSE: 2,
    ThreatClass.COMPROMISED: 3,
    ThreatClass.MALICIOUS: 4,
}
