"""Synthetic event generator for a fictional bank.

Real privileged-access logs are the one thing a project like this cannot
obtain, and scraping something approximate would be worse than useless. So
Lookout ships its own generator, which buys two things a borrowed dataset would
not:

* **Ground truth.** Every event carries a :class:`~lookout.models.ThreatClass`
  label, so :mod:`lookout.evaluate` can report real precision and recall for
  the detectors instead of asserting that they work.
* **A deterministic demo.** Same seed, same events, same decisions, every run.

The bank is Meridian Bank: 12 staff across Chennai, Bengaluru, Mumbai and a
Singapore data centre, each with their own hours, devices and workload, so that
"abnormal" has something concrete to be abnormal against.
"""

from __future__ import annotations

import math
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache

from .customers import customer_book as _customer_book
from .models import (
    CUSTOMER_COMMS_ROLES,
    TRANSFER_LIMITS,
    Action,
    Event,
    Geo,
    MessagePayload,
    Role,
    ThreatClass,
)

CITIES: dict[str, Geo] = {
    "Chennai": Geo(city="Chennai", country="IN", lat=13.0827, lon=80.2707),
    "Bengaluru": Geo(city="Bengaluru", country="IN", lat=12.9716, lon=77.5946),
    "Mumbai": Geo(city="Mumbai", country="IN", lat=19.0760, lon=72.8777),
    "Singapore": Geo(city="Singapore", country="SG", lat=1.3521, lon=103.8198),
    "Coimbatore": Geo(city="Coimbatore", country="IN", lat=11.0168, lon=76.9558),
    # Used only by attack scenarios.
    "Kyiv": Geo(city="Kyiv", country="UA", lat=50.4501, lon=30.5234),
    "Lagos": Geo(city="Lagos", country="NG", lat=6.5244, lon=3.3792),
    "Sao Paulo": Geo(city="Sao Paulo", country="BR", lat=-23.5505, lon=-46.6333),
    "New York": Geo(city="New York", country="US", lat=40.7128, lon=-74.0060),
}


@dataclass(frozen=True)
class Staff:
    """One employee's normal working life, in parameters."""

    actor: str
    role: Role
    city: str
    start_hour: int
    end_hour: int
    device: str
    ip_prefix: str
    #: Mean rows returned by this person's queries; 0 means they do not query.
    query_rows: int = 0
    #: Mean recipients per message; 0 means they do not send.
    message_reach: int = 0
    workdays: tuple[int, ...] = (0, 1, 2, 3, 4)  # Mon-Fri


ROSTER: tuple[Staff, ...] = (
    Staff("r.krishnan", Role.TELLER, "Chennai", 9, 17, "WS-CHN-114", "10.21.4", 40, 3),
    Staff("s.iyer", Role.TELLER, "Chennai", 9, 17, "WS-CHN-118", "10.21.4", 35, 2),
    Staff("a.fernandes", Role.TELLER, "Mumbai", 9, 18, "WS-MUM-052", "10.24.8", 45, 2),
    Staff("p.nair", Role.OFFICER, "Bengaluru", 9, 18, "LT-BLR-231", "10.22.6", 180, 14),
    Staff("m.d'souza", Role.OFFICER, "Mumbai", 10, 19, "LT-MUM-087", "10.24.8", 210, 18),
    Staff("k.venkatesh", Role.ANALYST, "Chennai", 9, 18, "LT-CHN-401", "10.21.9", 2400, 1),
    Staff("d.sharma", Role.ANALYST, "Bengaluru", 10, 19, "LT-BLR-455", "10.22.6", 3100, 1),
    Staff("l.mathew", Role.MANAGER, "Chennai", 8, 19, "LT-CHN-007", "10.21.2", 320, 140),
    Staff("v.rao", Role.MANAGER, "Bengaluru", 8, 18, "LT-BLR-011", "10.22.2", 290, 95),
    Staff("t.banerjee", Role.DBA, "Singapore", 10, 20, "SRV-SIN-03", "10.31.1", 5200, 0),
    Staff(
        "h.qureshi", Role.SYSADMIN, "Singapore", 11, 21, "SRV-SIN-09", "10.31.1",
        900, 0, workdays=(0, 1, 2, 3, 4, 5, 6),
    ),
    Staff(
        "n.pillai", Role.DOMAIN_ADMIN, "Chennai", 9, 19, "LT-CHN-001", "10.21.1",
        150, 6,
    ),
)

BY_ACTOR: dict[str, Staff] = {s.actor: s for s in ROSTER}

RESOURCES: dict[Action, tuple[str, ...]] = {
    Action.DB_QUERY: (
        "core.accounts", "core.transactions", "core.customers", "crm.leads",
        "core.kyc_documents", "reporting.daily_positions",
    ),
    Action.FILE_ACCESS: (
        "/share/statements", "/share/audit", "/share/loan-files", "/share/reports",
    ),
    Action.CONFIG_CHANGE: (
        "iam.policies", "network.firewall", "app.core-banking", "iam.role-bindings",
    ),
    Action.VAULT_READ: (
        "vault/db-primary", "vault/swift-gateway", "vault/api-signing",
        "vault/backup-encryption",
    ),
}

BENIGN_URLS: tuple[str, ...] = (
    "https://secure.meridianbank.com/statements",
    "https://meridianbank.com/branch-locator",
    "https://meridianbank.in/support",
    "",
)


def make_event(
    staff: Staff,
    action: Action,
    ts: datetime,
    rng: random.Random,
    *,
    city: str | None = None,
    device: str | None = None,
    ip: str | None = None,
    success: bool = True,
    resource: str | None = None,
    message: MessagePayload | None = None,
    label: ThreatClass = ThreatClass.BENIGN,
    scenario: str | None = None,
    **meta,
) -> Event:
    """Build one event, defaulting every unspecified field to this person's normal."""
    geo = CITIES[city or staff.city]
    return Event(
        event_id=str(uuid.uuid4()),
        ts=ts,
        actor=staff.actor,
        actor_role=staff.role,
        action=action,
        resource=resource if resource is not None else _pick_resource(action, rng),
        source_ip=ip or f"{staff.ip_prefix}.{rng.randint(10, 250)}",
        device_id=device or staff.device,
        geo=geo,
        success=success,
        message=message,
        meta=meta,
        label=label,
        scenario=scenario,
    )


def generate_history(
    days: int = 30,
    seed: int = 20260921,
    end: datetime | None = None,
) -> list[Event]:
    """A month of ordinary work for the whole roster, in chronological order.

    Ordinary does not mean uniform: there is weekday-to-weekend variation,
    occasional late evenings, a genuine bulk campaign from each manager, and the
    odd mistyped password -- all labelled benign, so a detector that fires on
    them is measurably wrong rather than arguably wrong.
    """
    rng = random.Random(seed)
    end = end or datetime(2026, 9, 21, 9, 0, 0)
    start = end - timedelta(days=days)
    events: list[Event] = []

    for staff in ROSTER:
        day = start
        while day < end:
            if day.weekday() not in staff.workdays:
                # Weekends are quiet but not empty for on-call staff.
                if staff.role not in (Role.SYSADMIN, Role.DBA) or rng.random() > 0.35:
                    day += timedelta(days=1)
                    continue
            events.extend(_one_day(staff, day, rng))
            day += timedelta(days=1)

    events.sort(key=lambda e: e.ts)
    return events


def _one_day(staff: Staff, day: datetime, rng: random.Random) -> list[Event]:
    """A single working day: sign in, do the job, sign out."""
    events: list[Event] = []
    login_hour = staff.start_hour + rng.choice([-1, 0, 0, 0, 1])
    login = day.replace(hour=max(0, login_hour), minute=rng.randint(0, 55), second=0)

    # People mistype passwords; one or two failures is normal life, and the
    # brute-force detector needs a threshold above it.
    for i in range(rng.choices([0, 0, 0, 1, 2], weights=[60, 15, 10, 10, 5])[0]):
        events.append(
            make_event(
                staff, Action.LOGIN_FAILED, login - timedelta(minutes=i + 1), rng,
                success=False, resource="",
            )
        )

    events.append(make_event(staff, Action.LOGIN, login, rng, session_id=_sid(rng)))
    session = events[-1].meta["session_id"]

    hours = max(1, staff.end_hour - staff.start_hour)
    for _ in range(rng.randint(6, 18)):
        offset = timedelta(minutes=rng.randint(5, hours * 60))
        ts = login + offset
        events.append(_work_event(staff, ts, rng, session))

    events.append(
        make_event(
            staff, Action.LOGOUT, login + timedelta(hours=hours, minutes=rng.randint(0, 45)),
            rng, resource="", session_id=session,
        )
    )
    return events


def _work_event(
    staff: Staff, ts: datetime, rng: random.Random, session: str
) -> Event:
    """One unit of ordinary work, weighted by what this role actually does."""
    choices: list[Action] = [Action.DB_QUERY, Action.FILE_ACCESS]
    weights: list[float] = [5.0, 3.0]
    if staff.message_reach:
        choices.append(Action.SEND_MESSAGE)
        weights.append(3.0)
    if staff.role in (Role.SYSADMIN, Role.DOMAIN_ADMIN):
        choices += [Action.CONFIG_CHANGE, Action.VAULT_READ]
        weights += [2.0, 1.0]
    elif staff.role is Role.DBA:
        choices.append(Action.VAULT_READ)
        weights.append(1.0)
    if staff.role in TRANSFER_LIMITS:
        choices.append(Action.FUND_TRANSFER)
        weights.append(2.0)

    action = rng.choices(choices, weights=weights)[0]

    if action is Action.FUND_TRANSFER:
        return make_event(
            staff, action, ts, rng, resource="core.payments", session_id=session,
            **_benign_transfer(staff, rng),
        )

    if action is Action.DB_QUERY:
        rows = max(1, int(rng.gauss(staff.query_rows, staff.query_rows * 0.30)))
        return make_event(staff, action, ts, rng, record_count=rows, session_id=session)

    if action is Action.SEND_MESSAGE:
        return make_event(
            staff, action, ts, rng, resource="gateway.outbound",
            message=_benign_message(staff, rng), session_id=session,
        )

    return make_event(staff, action, ts, rng, session_id=session)


def _benign_message(staff: Staff, rng: random.Random) -> MessagePayload:
    """A real outbound message, including the managers' legitimate campaigns --
    the false-positive trap for the bulk detector."""
    campaign = staff.role in (Role.MANAGER, Role.DOMAIN_ADMIN) and rng.random() < 0.25
    reach = (
        rng.randint(400, 2500)
        if campaign
        else max(1, int(rng.gauss(staff.message_reach, max(1, staff.message_reach * 0.4))))
    )
    url = rng.choice(BENIGN_URLS)
    # Benign staff obey the communication policy -- that is what makes them
    # benign. Roles without a customer-comms mandate only message colleagues.
    may_reach_customers = staff.role in CUSTOMER_COMMS_ROLES
    if not may_reach_customers:
        audience = "internal"
    elif reach > 5:
        audience = "customer"
    else:
        audience = rng.choice(["internal", "customer"])
    return MessagePayload(
        channel=rng.choice(["sms", "email", "email"]),
        recipient_count=reach,
        audience=audience,
        subject="Your monthly statement" if campaign else "Account update",
        body="Your Meridian Bank statement is ready in net banking.",
        urls=[url] if url else [],
    )


@lru_cache(maxsize=1)
def customer_book():
    """The generator reads the book on every transfer; build it once."""
    return _customer_book()


#: Typical single transfer each role processes, in rupees (median of a lognormal).
TYPICAL_TRANSFER: dict[Role, float] = {
    Role.TELLER: 18_000,
    Role.OFFICER: 120_000,
    Role.MANAGER: 600_000,
}


def payee_pool(actor: str) -> list[tuple[str, bool]]:
    """The accounts this person routinely pays into: mostly customers of the
    bank, plus a few long-standing outside payees. (account, is_external)."""
    book = customer_book()
    r = random.Random(f"payees:{actor}")
    internal = [(c.account_no, False) for c in r.sample(book, 12)]
    external = [(f"91{r.randrange(10**10):010d}", True) for _ in range(3)]
    return internal + external


def _benign_transfer(staff: Staff, rng: random.Random) -> dict:
    """An ordinary transfer: a usual amount, mostly to someone paid before,
    occasionally to a new internal customer -- never over the role's limit."""
    book = customer_book()
    typical = TYPICAL_TRANSFER[staff.role]
    amount = min(
        TRANSFER_LIMITS[staff.role] * 0.9,
        round(rng.lognormvariate(math.log(typical), 0.55), -2),
    )
    if rng.random() < 0.9:
        to_account, external = rng.choice(payee_pool(staff.actor))
    else:
        to_account, external = rng.choice(book).account_no, False
    source = rng.choice(book).account_no
    return {
        "amount": max(500.0, amount),
        "from_account": source,
        "to_account": to_account,
        "external": external,
    }


def _pick_resource(action: Action, rng: random.Random) -> str:
    options = RESOURCES.get(action)
    return rng.choice(options) if options else ""


def _sid(rng: random.Random) -> str:
    return f"sess-{rng.randrange(16**8):08x}"
