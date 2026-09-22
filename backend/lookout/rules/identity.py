"""Detectors about *who* is authenticating, from where, and on what."""

from __future__ import annotations

from ..baselines import Baseline, haversine_km
from ..context import DetectionContext
from ..models import Action, Event, Signal, ThreatClass

#: Faster than any commercial aircraft including transfers. Anything above this
#: means the two logins cannot both be the same physical person.
MAX_PLAUSIBLE_KMH = 900.0

#: Below this, clock skew and coarse geolocation dominate the arithmetic.
MIN_TRAVEL_MINUTES = 3.0

#: An hour holding less than this share of an identity's history is "unusual"
#: for them. 1% of a few hundred events is a genuinely rare hour.
RARE_HOUR_SHARE = 0.01

#: Failed logins inside the context window that make a success suspicious.
BRUTE_FORCE_THRESHOLD = 5


def impossible_travel(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """Two successful logins that would require superhuman travel between them.

    Pure geometry -- distance divided by elapsed time against a speed ceiling.
    No model, no threshold to tune, and impossible to argue with in a review.
    """
    if event.action is not Action.LOGIN or not event.success:
        return []
    if baseline.last_login_geo is None or baseline.last_login_ts is None:
        return []

    hours = (event.ts - baseline.last_login_ts).total_seconds() / 3600.0
    if hours * 60 < MIN_TRAVEL_MINUTES:
        # Same-minute logins are session refreshes, not travel.
        if haversine_km(baseline.last_login_geo, (event.geo.lat, event.geo.lon)) < 50:
            return []
        hours = MIN_TRAVEL_MINUTES / 60.0

    km = haversine_km(baseline.last_login_geo, (event.geo.lat, event.geo.lon))
    if km < 100:
        return []
    speed = km / max(hours, 1e-6)
    if speed <= MAX_PLAUSIBLE_KMH:
        return []

    return [
        Signal(
            name="impossible_travel",
            # Physics, not statistics: two sessions no one person could hold.
            # Enough alone for a step-up; any corroboration makes it high.
            points=50.0,
            explanation=(
                f"Login from {event.geo.city}, {event.geo.country} is "
                f"{km:,.0f} km from the previous login in {baseline.last_login_city} "
                f"{hours * 60:,.0f} minutes earlier -- {speed:,.0f} km/h, which no "
                f"traveller can achieve. One of the two sessions is not {event.actor}."
            ),
            detail={
                "distance_km": round(km, 1),
                "elapsed_minutes": round(hours * 60, 1),
                "implied_kmh": round(speed, 1),
                "from_city": baseline.last_login_city,
                "to_city": event.geo.city,
            },
            indicates=[ThreatClass.COMPROMISED],
        )
    ]


def abnormal_login_time(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """Authentication at an hour this identity essentially never works."""
    if event.action is not Action.LOGIN or not event.success or not baseline.trained:
        return []
    share = baseline.hour_frequency(event.ts.hour)
    if share > RARE_HOUR_SHARE:
        return []
    usual = sorted(h for h in range(24) if baseline.hour_frequency(h) > 0.05)
    return [
        Signal(
            name="abnormal_login_time",
            points=12.0,
            explanation=(
                f"{event.actor} signed in at {event.ts:%H:%M}, an hour that accounts "
                f"for {share:.1%} of their {baseline.events} recorded events "
                f"(they normally work {_hour_range(usual)})."
            ),
            detail={
                "hour": event.ts.hour,
                "hour_share": round(share, 4),
                "usual_hours": usual,
            },
            indicates=[ThreatClass.COMPROMISED, ThreatClass.MALICIOUS],
        )
    ]


def new_device_or_network(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """First sighting of a device, country or network for this identity.

    Individually weak -- people get new laptops. It earns its weight by
    compounding with the signals above, which is exactly how the fusion step in
    :mod:`lookout.scoring` is meant to work.
    """
    if event.action not in (Action.LOGIN, Action.LOGIN_FAILED) or not baseline.trained:
        return []

    firsts: list[str] = []
    if baseline.is_new_country(event.geo.country):
        firsts.append(f"country {event.geo.country}")
    if baseline.is_new_device(event.device_id):
        firsts.append(f"device {event.device_id}")
    if baseline.is_new_network(event.source_ip):
        firsts.append(f"network {event.source_ip}")
    if not firsts:
        return []

    return [
        Signal(
            name="new_device_or_network",
            points=6.0 * len(firsts),
            explanation=(
                f"First time {event.actor} has been seen using "
                + ", ".join(firsts)
                + f" in {baseline.events} recorded events."
            ),
            detail={"first_seen": firsts},
            indicates=[ThreatClass.COMPROMISED],
        )
    ]


def credential_misuse(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """A successful login that follows a run of failures -- the shape of a
    guessed or stuffed credential rather than a forgotten one."""
    if event.action is not Action.LOGIN or not event.success:
        return []
    failures = ctx.count(event.actor, Action.LOGIN_FAILED, event.ts, minutes=15)
    if failures < BRUTE_FORCE_THRESHOLD:
        return []
    return [
        Signal(
            name="credential_misuse",
            points=25.0,
            explanation=(
                f"{failures} failed sign-ins for {event.actor} in the preceding "
                f"15 minutes, then a success from {event.geo.city}. That is the "
                f"signature of a guessed credential, not a forgotten one."
            ),
            detail={"failed_attempts_15m": failures, "succeeded_from": event.geo.city},
            indicates=[ThreatClass.COMPROMISED],
        )
    ]


#: Points when this many things about one sign-in are new at once.
COMPOUND_POINTS = {3: 12.0, 4: 30.0}


def compound_login_anomaly(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """Several unfamiliar things about one sign-in at the same time.

    Each on its own is ordinary: people get new laptops, travel, and sometimes
    work late. All of them together (the spec's 02:30, new device, new
    country, unknown IP) is how a stolen password looks, and it should score
    as high risk rather than merely the sum of four weak signals. Two at once
    (a new laptop at 02:30) stays a step-up.
    """
    if event.action is not Action.LOGIN or not event.success or not baseline.trained:
        return []
    novel = []
    if baseline.hour_frequency(event.ts.hour) <= RARE_HOUR_SHARE:
        novel.append(f"the hour ({event.ts:%H:%M})")
    if baseline.is_new_device(event.device_id):
        novel.append(f"the device ({event.device_id})")
    if baseline.is_new_country(event.geo.country):
        novel.append(f"the country ({event.geo.country})")
    if baseline.is_new_network(event.source_ip):
        novel.append(f"the network ({event.source_ip})")
    points = COMPOUND_POINTS.get(len(novel))
    if points is None:
        return []
    return [
        Signal(
            name="compound_login_anomaly",
            points=points,
            explanation=(
                f"{len(novel)} things about this sign-in are new for {event.actor} at once: "
                + ", ".join(novel)
                + ". Any one is ordinary; together they are how a stolen password looks."
            ),
            detail={"novel": novel, "count": len(novel)},
            indicates=[ThreatClass.COMPROMISED],
        )
    ]


def failed_login_burst(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """An attack still in progress, before anybody gets in.

    :func:`credential_misuse` fires on the success at the end. By then the
    attacker has a session. This fires on the run of failures itself, which is
    the only moment the account can still be protected rather than cleaned up
    after -- and it is why ordinary mistyped passwords are generated one or two
    at a time, well under the threshold.
    """
    if event.action is not Action.LOGIN_FAILED:
        return []
    failures = ctx.count(event.actor, Action.LOGIN_FAILED, event.ts, minutes=15) + 1
    if failures < BRUTE_FORCE_THRESHOLD:
        return []

    unfamiliar = baseline.trained and (
        baseline.is_new_country(event.geo.country)
        or baseline.is_new_device(event.device_id)
    )
    points = 18.0 + min(12.0, 2.0 * (failures - BRUTE_FORCE_THRESHOLD))
    if unfamiliar:
        points += 14.0

    origin = (
        f"an unrecognised device in {event.geo.city}, {event.geo.country}"
        if unfamiliar
        else f"{event.geo.city}"
    )
    return [
        Signal(
            name="failed_login_burst",
            points=points,
            explanation=(
                f"{failures} failed sign-ins for {event.actor} within 15 minutes from "
                f"{origin}. The account is being guessed at right now."
            ),
            detail={
                "failed_attempts_15m": failures,
                "unfamiliar_origin": unfamiliar,
                "source_ip": event.source_ip,
                "city": event.geo.city,
            },
            indicates=[ThreatClass.COMPROMISED],
        )
    ]


def containment_breach(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """Activity that continues after Lookout already acted.

    Three cases, in descending severity:

    * the session was revoked -- the token is being replayed;
    * the source was locked out after an attack from it;
    * the session already earned a block or quarantine and is still going.

    These signals raise risk but deliberately carry no threat class of their
    own. *That* an actor kept going says nothing about *what kind* of insider
    they are; the class comes from what they were doing, or is inherited from
    what the session was already judged to be.
    """
    session = str(event.meta.get("session_id", ""))

    if ctx.is_revoked(session):
        return [
            Signal(
                name="revoked_session_use",
                points=60.0,
                explanation=(
                    f"Session {session} was revoked by an earlier Lookout decision, "
                    f"yet it was used again for {event.action.value.replace('_', ' ')}. "
                    f"The token is being replayed or revocation did not propagate."
                ),
                detail={"session_id": session},
            )
        ]

    if ctx.is_locked(event.actor, event.source_ip):
        return [
            Signal(
                name="locked_origin_use",
                points=55.0,
                explanation=(
                    f"{event.source_ip} was locked out of {event.actor} after an "
                    f"earlier attack from it, and is trying again."
                ),
                detail={"source_ip": event.source_ip},
            )
        ]

    strikes = ctx.strikes(session)
    if strikes:
        return [
            Signal(
                name="persistence_after_block",
                points=min(40.0, 20.0 + 10.0 * (strikes - 1)),
                explanation=(
                    f"This session has already been blocked or held {strikes} "
                    f"time{'s' if strikes != 1 else ''} and is still issuing requests."
                ),
                detail={"session_id": session, "prior_strikes": strikes},
            )
        ]
    return []


def _hour_range(hours: list[int]) -> str:
    if not hours:
        return "no established pattern"
    return f"{min(hours):02d}:00-{max(hours) + 1:02d}:00"
