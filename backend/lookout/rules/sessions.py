"""Detectors about how a signed-in session behaves over time.

* ``concurrent_sessions`` -- a second live session from a different device or
  network while the first is still open;
* ``login_frequency`` -- far more sign-ins in an hour than anyone needs;
* ``session_context_change`` -- one session's requests suddenly arriving from
  another network or device, the signature of a stolen session token;
* ``query_rate_burst`` -- hundreds of database queries in a few minutes
  (the spec's "10 per hour, then 500 in 5 minutes");
* ``failed_authorization`` -- repeated requests the access layer refused.
"""

from __future__ import annotations

from datetime import timedelta

from ..baselines import Baseline
from ..context import DetectionContext
from ..models import Action, Event, Signal, ThreatClass

#: How long a session with no logout is assumed to still be open.
SESSION_LIFETIME_HOURS = 10

#: Successful sign-ins within an hour that stop looking like a person.
LOGIN_FREQUENCY_THRESHOLD = 5

#: Database queries in five minutes that no human analyst types by hand.
QUERY_BURST_THRESHOLD = 60

#: Refused requests in thirty minutes that mean someone is probing.
DENIAL_THRESHOLD = 3


def _network(ip: str) -> str:
    """Compare /24 networks: ordinary DHCP churn changes the last octet."""
    return ip.rsplit(".", 1)[0] if ip.count(".") == 3 else ip


def _open_sessions(event: Event, ctx: DetectionContext) -> dict[str, Event]:
    """Earlier logins by this person whose session has not logged out."""
    history = ctx.recent(event.actor, event.ts, minutes=SESSION_LIFETIME_HOURS * 60)
    logins: dict[str, Event] = {}
    for e in history:
        sid = str(e.meta.get("session_id", ""))
        if not sid:
            continue
        if e.action is Action.LOGIN and e.success:
            logins[sid] = e
        elif e.action is Action.LOGOUT:
            logins.pop(sid, None)
    logins.pop(str(event.meta.get("session_id", "")), None)
    for sid in list(logins):
        if sid in ctx.revoked_sessions:
            logins.pop(sid)
    return logins


def concurrent_sessions(event: Event, baseline: Baseline, ctx: DetectionContext) -> list[Signal]:
    if event.action is not Action.LOGIN or not event.success:
        return []
    others = [
        e
        for e in _open_sessions(event, ctx).values()
        if e.device_id != event.device_id or _network(e.source_ip) != _network(event.source_ip)
    ]
    if not others:
        return []
    first = others[0]
    return [
        Signal(
            name="concurrent_sessions",
            points=round(20.0 + 6.0 * (len(others) - 1), 1),
            explanation=(
                f"{event.actor} is already signed in on {first.device_id} from {first.geo.city} "
                f"({first.source_ip}); this new session is on {event.device_id} from "
                f"{event.geo.city} ({event.source_ip}). {len(others) + 1} sessions are open at once."
            ),
            detail={
                "open_sessions": len(others) + 1,
                "other_devices": sorted({e.device_id for e in others}),
                "other_ips": sorted({e.source_ip for e in others}),
            },
            indicates=[ThreatClass.COMPROMISED],
        )
    ]


def login_frequency(event: Event, baseline: Baseline, ctx: DetectionContext) -> list[Signal]:
    if event.action is not Action.LOGIN or not event.success:
        return []
    n = sum(1 for e in ctx.recent(event.actor, event.ts, minutes=60) if e.action is Action.LOGIN and e.success) + 1
    if n < LOGIN_FREQUENCY_THRESHOLD:
        return []
    return [
        Signal(
            name="login_frequency",
            points=round(12.0 + 3.0 * (n - LOGIN_FREQUENCY_THRESHOLD), 1),
            explanation=f"{n} successful sign-ins for {event.actor} within an hour; people sign in once or twice.",
            detail={"logins_60m": n},
            indicates=[ThreatClass.COMPROMISED],
        )
    ]


def session_context_change(event: Event, baseline: Baseline, ctx: DetectionContext) -> list[Signal]:
    """A session token used from somewhere its login never came from."""
    if event.action in (Action.LOGIN, Action.LOGIN_FAILED):
        return []
    sid = str(event.meta.get("session_id", ""))
    if not sid:
        return []
    login = next(
        (
            e
            for e in reversed(ctx.recent(event.actor, event.ts, minutes=SESSION_LIFETIME_HOURS * 60))
            if e.action is Action.LOGIN and e.meta.get("session_id") == sid
        ),
        None,
    )
    if login is None:
        return []
    changed = []
    if login.device_id != event.device_id:
        changed.append(f"device {login.device_id} → {event.device_id}")
    if _network(login.source_ip) != _network(event.source_ip):
        changed.append(f"network {login.source_ip} → {event.source_ip}")
    if not changed:
        return []
    return [
        Signal(
            name="session_context_change",
            points=35.0,
            explanation=(
                f"Session {sid} began on {login.device_id} ({login.source_ip}) but this request came "
                f"from a different {' and '.join(c.split(' ')[0] for c in changed)} "
                f"({'; '.join(changed)}). That is what a stolen session token looks like."
            ),
            detail={"session_id": sid, "changes": changed},
            indicates=[ThreatClass.COMPROMISED],
        )
    ]


def query_rate_burst(event: Event, baseline: Baseline, ctx: DetectionContext) -> list[Signal]:
    if event.action is not Action.DB_QUERY:
        return []
    n = ctx.count(event.actor, Action.DB_QUERY, event.ts, minutes=5) + 1
    if n < QUERY_BURST_THRESHOLD:
        return []
    earlier = ctx.count(event.actor, Action.DB_QUERY, event.ts - timedelta(minutes=5), minutes=55)
    usual = max(1.0, earlier / 11)  # per five minutes over the hour before
    return [
        Signal(
            name="query_rate_burst",
            points=round(min(32.0, 16.0 + 4.0 * (n / QUERY_BURST_THRESHOLD - 1) * 2), 1),
            explanation=(
                f"{n} database queries by {event.actor} in 5 minutes, against about {usual:.0f} "
                f"per 5 minutes in the hour before. That is a script, not a person."
            ),
            detail={"queries_5m": n, "usual_per_5m": round(usual, 1)},
            indicates=[ThreatClass.MALICIOUS, ThreatClass.COMPROMISED],
        )
    ]


def failed_authorization(event: Event, baseline: Baseline, ctx: DetectionContext) -> list[Signal]:
    if event.action is not Action.ACCESS_DENIED:
        return []
    n = ctx.count(event.actor, Action.ACCESS_DENIED, event.ts, minutes=30) + 1
    if n < DENIAL_THRESHOLD:
        # One refusal is someone clicking the wrong thing. Still recorded.
        return [
            Signal(
                name="failed_authorization",
                points=8.0,
                explanation=f"{event.actor} was refused access to {event.resource or 'a resource'} outside their role.",
                detail={"denials_30m": n, "resource": event.resource},
                indicates=[ThreatClass.PRIVILEGE_ABUSE, ThreatClass.NEGLIGENT],
            )
        ]
    return [
        Signal(
            name="failed_authorization",
            points=round(min(34.0, 14.0 + 5.0 * (n - DENIAL_THRESHOLD)), 1),
            explanation=(
                f"{n} refused requests by {event.actor} within 30 minutes, the latest for "
                f"{event.resource or 'a resource'}: someone is testing what they can reach."
            ),
            detail={"denials_30m": n, "resource": event.resource},
            indicates=[ThreatClass.PRIVILEGE_ABUSE, ThreatClass.MALICIOUS],
        )
    ]
