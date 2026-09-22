"""Detectors for customer fund transfers processed by staff.

Staff move customer money every day: a teller processes a withdrawal to a
payee, an officer disburses a loan. Insider transfer fraud looks like that work
with one or more things wrong -- the amount, the destination, the hour, or the
fact that this person has no mandate to move money at all.
"""

from __future__ import annotations

import math

from ..baselines import Baseline
from ..context import DetectionContext
from ..models import TRANSFER_LIMITS, Action, Event, Signal, ThreatClass

#: Z-score against this person's own transfer history that makes an amount unusual.
AMOUNT_Z_THRESHOLD = 3.0

#: Banking hours for moving money.
TRANSFER_HOURS = range(8, 20)

#: Transfers to never-seen destinations within 15 minutes that suggest draining.
VELOCITY_THRESHOLD = 3


def suspicious_transfer(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """Score one staff-initiated transfer on everything that can be wrong with it.

    One signal with an itemised explanation rather than five separate signals:
    an analyst reviewing a transfer wants the case in one place.
    """
    if event.action is not Action.FUND_TRANSFER:
        return []

    amount = float(event.meta.get("amount", 0))
    destination = str(event.meta.get("to_account", ""))
    external = bool(event.meta.get("external", False))
    limit = TRANSFER_LIMITS.get(event.actor_role)

    points = 0.0
    reasons: list[str] = []
    indicates: list[ThreatClass] = []

    if limit is None:
        points += 35.0
        reasons.append(
            f"a {event.actor_role.value} has no mandate to move customer funds at all"
        )
        indicates.append(ThreatClass.PRIVILEGE_ABUSE)
    elif amount > limit:
        over = amount / limit
        points += min(35.0, 25.0 + 10.0 * math.log10(over))
        reasons.append(
            f"₹{amount:,.0f} is {over:.1f}x the ₹{limit:,} limit for a {event.actor_role.value}"
        )
        indicates.append(ThreatClass.PRIVILEGE_ABUSE)

    stats = baseline.transfer_amount
    z = stats.z(amount)
    if stats.n >= 5 and z > AMOUNT_Z_THRESHOLD:
        points += min(20.0, 5.0 * math.log2(z / AMOUNT_Z_THRESHOLD) + 6.0)
        reasons.append(
            f"it is {amount / max(stats.mean, 1):.0f}x their average transfer of ₹{stats.mean:,.0f}"
        )

    unseen = bool(destination) and destination not in baseline.beneficiaries
    if external and unseen:
        points += 10.0 + (8.0 if z > AMOUNT_Z_THRESHOLD else 0.0)
        reasons.append(f"the destination {_mask(destination)} is outside the bank and new to them")
    elif unseen and baseline.trained:
        points += 4.0

    if event.ts.hour not in TRANSFER_HOURS:
        points += 10.0
        reasons.append(f"it was initiated at {event.ts:%H:%M}, outside banking hours")

    recent_new = sum(
        1
        for e in ctx.recent(event.actor, event.ts, minutes=15)
        if e.action is Action.FUND_TRANSFER
        and e.meta.get("external")
        and str(e.meta.get("to_account", "")) not in baseline.beneficiaries
    )
    if external and recent_new + 1 >= VELOCITY_THRESHOLD:
        points += 12.0
        reasons.append(f"it makes {recent_new + 1} transfers to new outside accounts in 15 minutes")

    if not reasons:
        return []

    indicates = [ThreatClass.MALICIOUS] + [c for c in indicates if c is not ThreatClass.MALICIOUS]
    return [
        Signal(
            name="suspicious_transfer",
            points=round(points, 1),
            explanation=(
                f"{event.actor} initiated a ₹{amount:,.0f} transfer from "
                f"{_mask(str(event.meta.get('from_account', '')))}, and "
                + "; ".join(reasons)
                + "."
            ),
            detail={
                "amount": amount,
                "role_limit": limit,
                "amount_z": round(z, 2),
                "baseline_mean": round(stats.mean, 1),
                "to_account": _mask(destination),
                "external": external,
                "new_destination": unseen,
            },
            indicates=indicates,
        )
    ]


def _mask(account: str) -> str:
    return f"•••• {account[-4:]}" if len(account) > 4 else account
