"""Detectors about data movement -- the exfiltration half of insider risk."""

from __future__ import annotations

import math

from ..baselines import Baseline
from ..context import DetectionContext
from ..models import PRIVILEGE_LEVEL, Action, Event, Signal, ThreatClass

#: Z-score above which a query volume stops being a busy day.
VOLUME_Z_THRESHOLD = 4.0

#: Absolute floor. A first-ever query for 80,000 customer records is alarming
#: even if the identity has no baseline to be abnormal against.
VOLUME_ABSOLUTE_FLOOR = 10_000

#: Core banking hours in branch local time.
BUSINESS_HOURS = range(8, 20)

#: Vault reads in the window that turn "doing my job" into "collecting".
VAULT_HOARD_THRESHOLD = 8

#: Bytes written to a share in one operation before it stops being a document.
#: 250 MB is far above any statement, report or loan file this bank produces.
STAGING_BYTES = 250_000_000


def mass_record_access(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """A query returning far more rows than this identity ever pulls."""
    if event.action is not Action.DB_QUERY:
        return []
    count = int(event.meta.get("record_count", 0))
    if count <= 0:
        return []

    z = baseline.records_per_query.z(float(count))
    over_floor = count >= VOLUME_ABSOLUTE_FLOOR
    if z < VOLUME_Z_THRESHOLD and not over_floor:
        return []

    usual = baseline.records_per_query.mean
    # Two terms, both logarithmic. The z term measures "unusual for this
    # person" -- log-scaled because someone whose queries are always ~40 rows
    # produces z-scores in the thousands, and a linear term would saturate on
    # any read at all. The magnitude term measures "a lot of data, full stop",
    # so that a busy afternoon and a copied customer table stay distinguishable.
    # Capped, so corroborating signals still have to do some of the work.
    z_term = min(12.0, 4.0 * math.log2(max(z, VOLUME_Z_THRESHOLD) / VOLUME_Z_THRESHOLD))
    magnitude = math.log10(max(count, 1) / VOLUME_ABSOLUTE_FLOOR)
    floor_term = 10.0 + 12.0 * max(magnitude, 0.0) if over_floor else 0.0
    points = min(46.0, 14.0 + z_term + floor_term)
    comparison = (
        f"against a personal average of {usual:,.0f} rows"
        if baseline.records_per_query.n >= 2
        else "with no established query history for this identity"
    )
    return [
        Signal(
            name="mass_record_access",
            points=points,
            explanation=(
                f"{event.actor} read {count:,} rows from {event.resource or 'a core banking table'} "
                f"{comparison} (z = {z:.1f})."
            ),
            detail={
                "record_count": count,
                "baseline_mean": round(usual, 1),
                "z_score": round(z, 2),
                "resource": event.resource,
            },
            indicates=[ThreatClass.MALICIOUS],
        )
    ]


def off_hours_data_access(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """Reading customer data outside banking hours.

    On its own this is often negligence -- someone catching up from home. It
    turns malicious when it arrives with volume, which the fusion step handles.
    """
    if event.action not in (Action.DB_QUERY, Action.FILE_ACCESS):
        return []
    if event.ts.hour in BUSINESS_HOURS:
        return []
    return [
        Signal(
            name="off_hours_data_access",
            points=10.0,
            explanation=(
                f"{event.actor} accessed {event.resource or 'customer data'} at "
                f"{event.ts:%H:%M} on {event.ts:%a %d %b}, outside the "
                f"{BUSINESS_HOURS.start:02d}:00-{BUSINESS_HOURS.stop:02d}:00 banking window."
            ),
            detail={"hour": event.ts.hour, "weekday": event.ts.strftime("%A")},
            indicates=[ThreatClass.NEGLIGENT, ThreatClass.MALICIOUS],
        )
    ]


def bulk_file_write(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """Data being staged for removal.

    Reading records is half of exfiltration; the other half is putting them
    somewhere portable. A multi-gigabyte write to a file share is the step
    between the query and the USB stick, and it is the last point at which the
    data is still inside the bank.
    """
    if event.action is not Action.FILE_ACCESS:
        return []
    written = int(event.meta.get("bytes_written", 0))
    if written < STAGING_BYTES:
        return []

    gb = written / 1_000_000_000
    return [
        Signal(
            name="bulk_file_write",
            points=min(34.0, 20.0 + 6.0 * math.log10(max(written / STAGING_BYTES, 1) + 1)),
            explanation=(
                f"{event.actor} wrote {gb:,.1f} GB to {event.resource or 'a file share'} "
                f"in a single operation. Nothing in this bank's normal document flow "
                f"is that size; this is data being staged."
            ),
            detail={
                "bytes_written": written,
                "gigabytes": round(gb, 2),
                "resource": event.resource,
            },
            indicates=[ThreatClass.MALICIOUS],
        )
    ]


def vault_hoarding(
    event: Event, baseline: Baseline, ctx: DetectionContext
) -> list[Signal]:
    """Repeated credential-vault reads in a short window.

    One vault read is an admin doing maintenance. Nine in half an hour is
    someone collecting keys.
    """
    if event.action is not Action.VAULT_READ:
        return []
    reads = ctx.count(event.actor, Action.VAULT_READ, event.ts, minutes=30) + 1
    if reads < VAULT_HOARD_THRESHOLD:
        return []
    return [
        Signal(
            name="vault_hoarding",
            points=26.0 + min(12.0, reads - VAULT_HOARD_THRESHOLD),
            explanation=(
                f"{event.actor} pulled {reads} separate secrets from the credential "
                f"vault in 30 minutes. Maintenance touches one or two; this is collection."
            ),
            detail={
                "vault_reads_30m": reads,
                "privilege_level": PRIVILEGE_LEVEL[event.actor_role],
            },
            indicates=[ThreatClass.MALICIOUS, ThreatClass.PRIVILEGE_ABUSE],
        )
    ]
