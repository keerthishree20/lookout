"""Detectors for the outbound message gateway.

Every SMS, email and push a staff member sends passes through the same pipeline
as every login and query, so a phishing blast from a compromised officer is
scored with full knowledge of how that officer normally behaves and what
privileges they hold. That context is the whole advantage of putting message
control inside the insider-threat system instead of beside it.
"""

from __future__ import annotations

import math

from ..baselines import Baseline
from ..context import DetectionContext
from ..models import (
    BULK_COMMS_ROLES,
    CUSTOMER_COMMS_ROLES,
    Action,
    Event,
    Signal,
    ThreatClass,
)
from ..urlcheck import inspect_all, worst

from ..policy import POLICY


def bulk_threshold() -> int:
    """Recipients above which a send is a campaign rather than a conversation.
    Set by the Super Admin's communication policy (default 50)."""
    return POLICY.current.bulk_threshold


#: Z-score against the sender's own history that makes a send a blast.
BLAST_Z_THRESHOLD = 4.0


def _channel(channel: str) -> str:
    return {"sms": "SMS", "push": "push notification"}.get(channel, channel)


def suspicious_url(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """A link in outbound staff mail that impersonates the bank or hides itself."""
    if event.action is not Action.SEND_MESSAGE or not event.message:
        return []
    verdicts = inspect_all(event.message.urls)
    flagged = [v for v in verdicts if v.suspicious]
    if not flagged:
        return []

    top = worst(flagged)
    assert top is not None
    reach = event.message.recipient_count
    # A hostile link is bad; a hostile link fanned out to customers is worse.
    points = 30.0 * top.score + (12.0 if reach >= bulk_threshold() else 0.0)
    if top.impersonates:
        points += 10.0

    return [
        Signal(
            name="suspicious_url",
            points=round(points, 1),
            explanation=(
                f"Outbound {_channel(event.message.channel)} to {reach:,} recipient"
                f"{'s' if reach != 1 else ''} contains {top.url} -- "
                + "; ".join(top.findings)
                + "."
            ),
            detail={
                "worst_url": top.as_dict(),
                "all_urls": [v.as_dict() for v in verdicts],
                "recipient_count": reach,
            },
            indicates=[ThreatClass.MALICIOUS, ThreatClass.COMPROMISED],
        )
    ]


def bulk_message_blast(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """Send volume far above what this sender has ever produced."""
    if event.action is not Action.SEND_MESSAGE or not event.message:
        return []
    reach = event.message.recipient_count
    if reach < bulk_threshold():
        return []

    z = baseline.recipients_per_message.z(float(reach))
    authorised = event.actor_role in BULK_COMMS_ROLES
    if z < BLAST_Z_THRESHOLD and authorised:
        return []  # a campaign manager running a campaign

    sent_30m = sum(
        e.message.recipient_count
        for e in ctx.recent(event.actor, event.ts, minutes=30)
        if e.action is Action.SEND_MESSAGE and e.message
    )
    usual = baseline.recipients_per_message.mean
    # Log-scaled on both axes, for the same reason as mass_record_access: a
    # sender who normally reaches three people produces enormous z-scores, and
    # a linear term would score 900 recipients the same as 50,000.
    z_term = min(10.0, 3.0 * math.log2(max(z, BLAST_Z_THRESHOLD) / BLAST_Z_THRESHOLD))
    reach_term = min(12.0, 4.0 * math.log10(reach / bulk_threshold()))
    points = 16.0 + z_term + reach_term
    if not authorised:
        points += 10.0

    # Volume alone says a policy was broken. Volume carrying a hostile link says
    # someone meant harm. Keeping those apart is how a careless teller ends up
    # classified as negligent rather than as a fraudster.
    hostile = any(v.suspicious for v in inspect_all(event.message.urls))
    indicates = (
        [ThreatClass.MALICIOUS, ThreatClass.PRIVILEGE_ABUSE]
        if hostile
        else [ThreatClass.NEGLIGENT, ThreatClass.PRIVILEGE_ABUSE]
    )

    return [
        Signal(
            name="bulk_message_blast",
            points=round(points, 1),
            explanation=(
                f"{event.actor} sent one {_channel(event.message.channel)} to {reach:,} recipients "
                f"(personal average {usual:,.0f}, z = {z:.1f}; {sent_30m + reach:,} "
                f"recipients in the last 30 minutes)."
                + ("" if authorised else " This role is not approved for bulk sends.")
            ),
            detail={
                "recipient_count": reach,
                "baseline_mean": round(usual, 1),
                "z_score": round(z, 2),
                "recipients_30m": sent_30m + reach,
                "role_authorised_for_bulk": authorised,
                "carries_hostile_link": hostile,
            },
            indicates=indicates,
        )
    ]


def unauthorized_customer_comms(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """Customer-facing messaging from a role with no mandate for it.

    Enforcing this is the messaging arm of privileged access management: the
    right to speak to customers in the bank's name is itself a privilege.
    """
    if event.action is not Action.SEND_MESSAGE or not event.message:
        return []
    if event.message.audience != "customer":
        return []

    reach = event.message.recipient_count
    if event.actor_role not in CUSTOMER_COMMS_ROLES:
        return [
            Signal(
                name="unauthorized_customer_comms",
                points=24.0,
                explanation=(
                    f"{event.actor} is a {event.actor_role.value} and is not authorised "
                    f"to send customer-facing messages, yet addressed {reach:,} customers."
                ),
                detail={
                    "actor_role": event.actor_role.value,
                    "permitted_roles": sorted(r.value for r in CUSTOMER_COMMS_ROLES),
                    "recipient_count": reach,
                },
                indicates=[ThreatClass.NEGLIGENT, ThreatClass.PRIVILEGE_ABUSE],
            )
        ]

    if reach >= bulk_threshold() and event.actor_role not in BULK_COMMS_ROLES:
        return [
            Signal(
                name="unauthorized_customer_comms",
                points=18.0,
                explanation=(
                    f"{event.actor} ({event.actor_role.value}) may message customers "
                    f"individually but not in bulk; this send reached {reach:,}."
                ),
                detail={
                    "actor_role": event.actor_role.value,
                    "bulk_roles": sorted(r.value for r in BULK_COMMS_ROLES),
                    "recipient_count": reach,
                },
                indicates=[ThreatClass.PRIVILEGE_ABUSE],
            )
        ]
    return []
