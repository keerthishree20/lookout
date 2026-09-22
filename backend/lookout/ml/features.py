"""Session-level features for the supervised insider-threat classifier.

The rules and the IsolationForest judge one event at a time. The classifier
judges a *session*: everything one identity did between signing in and now.
That is the unit an analyst actually reasons about ("this person, this
afternoon"), and it is the unit the dataset in ``datasets/`` is built from.

The same function computes features for the training set and for live
sessions at inference time. Two separate implementations would drift, and a
model scored on one and served the other would quietly be wrong.
"""

from __future__ import annotations

import math
from collections.abc import Iterable

from ..baselines import Baseline, haversine_km, ip_prefix
from ..models import Action, Event
from ..urlcheck import inspect_all

#: Column order is the model's input order. The first seventeen are the
#: features the project specification names; the last two add the money
#: movement the fund-transfer honeypot needs the model to see.
FEATURES: tuple[str, ...] = (
    "login_hour",
    "login_day",
    "location_change",
    "device_change",
    "failed_logins",
    "session_duration",
    "resource_access_count",
    "sensitive_resource_access",
    "data_volume",
    "message_count",
    "suspicious_url_count",
    "privilege_level",
    "role_change_attempt",
    "after_hours_activity",
    "ip_reputation",
    "behaviour_deviation",
    "transfer_amount",
    "new_external_payees",
)

SENSITIVE_PREFIXES: tuple[str, ...] = (
    "core.customers",
    "core.kyc_documents",
    "core.transactions",
    "vault/",
    "iam.",
    "network.firewall",
)

#: Address blocks the demo treats as known-bad (anonymising exits, prior
#: attacks). A real deployment would read a threat-intelligence feed.
BAD_PREFIXES: tuple[str, ...] = ("185.220.", "102.89.", "45.155.", "91.240.")

BUSINESS_HOURS = range(8, 20)
ACCESS_ACTIONS = (Action.DB_QUERY, Action.FILE_ACCESS, Action.VAULT_READ)


def ip_reputation(ip: str, baseline: Baseline) -> float:
    """0 = the office network this person always uses, 1 = known hostile."""
    if ip.startswith(BAD_PREFIXES):
        return 0.95
    if baseline.trained and ip_prefix(ip) in baseline.ip_prefixes:
        return 0.05
    if ip.startswith("10."):
        return 0.25  # internal, but not their usual subnet
    return 0.6


def session_features(events: Iterable[Event], baseline: Baseline) -> dict[str, float]:
    """Summarise one session against this identity's baseline."""
    events = sorted(events, key=lambda e: e.ts)
    if not events:
        raise ValueError("a session needs at least one event")

    first = next((e for e in events if e.action is Action.LOGIN), events[0])
    home = baseline.last_login_geo
    records = sum(float(e.meta.get("record_count", 0)) for e in events)
    bytes_written = sum(float(e.meta.get("bytes_written", 0)) for e in events)
    recipients = sum(e.message.recipient_count for e in events if e.message)
    urls = [u for e in events if e.message for u in e.message.urls]
    transfers = [e for e in events if e.action is Action.FUND_TRANSFER]
    amount = sum(float(e.meta.get("amount", 0)) for e in transfers)
    new_payees = {
        str(e.meta.get("to_account"))
        for e in transfers
        if e.meta.get("external") and str(e.meta.get("to_account")) not in baseline.beneficiaries
    }

    location_change = any(
        (baseline.trained and e.geo.country not in baseline.countries)
        or (home is not None and haversine_km(home, (e.geo.lat, e.geo.lon)) > 500)
        for e in events
    )
    device_change = any(baseline.is_new_device(e.device_id) for e in events)

    return {
        "login_hour": float(first.ts.hour),
        "login_day": float(first.ts.weekday()),
        "location_change": float(location_change),
        "device_change": float(device_change),
        "failed_logins": float(sum(e.action is Action.LOGIN_FAILED for e in events)),
        "session_duration": (events[-1].ts - events[0].ts).total_seconds() / 60.0,
        "resource_access_count": float(sum(e.action in ACCESS_ACTIONS for e in events)),
        "sensitive_resource_access": float(
            sum(e.resource.startswith(SENSITIVE_PREFIXES) for e in events if e.resource)
        ),
        # Records read plus megabytes written: both are "data leaving its place".
        "data_volume": records + bytes_written / 1_000_000,
        "message_count": float(recipients),
        "suspicious_url_count": float(sum(v.suspicious for v in inspect_all(urls))),
        "privilege_level": float(events[0].privilege),
        "role_change_attempt": float(sum(e.action is Action.PRIV_ESCALATE for e in events)),
        "after_hours_activity": float(sum(e.ts.hour not in BUSINESS_HOURS for e in events)),
        "ip_reputation": max(ip_reputation(e.source_ip, baseline) for e in events),
        "behaviour_deviation": behaviour_deviation(events, baseline, records, recipients, amount),
        "transfer_amount": amount,
        "new_external_payees": float(len(new_payees)),
    }


def behaviour_deviation(
    events: list[Event], baseline: Baseline, records: float, recipients: float, amount: float
) -> float:
    """How far this session sits from the person's own normal, as one number.

    The mean of log-damped z-scores on volume, reach and money, plus how rare
    the hour is for them. Log-damped because a teller whose queries are always
    40 rows produces z-scores in the thousands, which would swamp every other
    column.
    """

    def damped(z: float) -> float:
        return math.log1p(max(z, 0.0))

    n_queries = max(1, sum(e.action is Action.DB_QUERY for e in events))
    n_messages = max(1, sum(e.action is Action.SEND_MESSAGE for e in events))
    n_transfers = max(1, sum(e.action is Action.FUND_TRANSFER for e in events))
    parts = [
        damped(baseline.records_per_query.z(records / n_queries)) if records else 0.0,
        damped(baseline.recipients_per_message.z(recipients / n_messages)) if recipients else 0.0,
        damped(baseline.transfer_amount.z(amount / n_transfers)) if amount else 0.0,
        3.0 * (1.0 - baseline.hour_frequency(events[0].ts.hour)) if baseline.trained else 0.0,
    ]
    return round(sum(parts) / len(parts), 4)


def vector(features: dict[str, float]) -> list[float]:
    return [float(features[name]) for name in FEATURES]
