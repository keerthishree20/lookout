"""Scripted insider incidents.

Six incidents, chosen so that between them they exercise every detector and
every response band. Each is a list of labelled events replayed through the
same pipeline as live traffic -- nothing about scoring knows that a scenario is
running, which is what makes the demo evidence rather than theatre.

They end in different places on purpose: the negligent teller is held for
review rather than paged, the exfiltration is blocked before data leaves, and
the attacks that reach privileged systems or customers page the SOC.

Session IDs are drawn from the scenario's RNG, so running the same scenario
twice produces two independent incidents rather than a replay of a session the
first run already revoked.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from .generator import BY_ACTOR, make_event
from .models import Action, Event, MessagePayload, Role, ThreatClass


@dataclass(frozen=True)
class Scenario:
    key: str
    title: str
    summary: str
    #: The capabilities from the brief that this incident demonstrates.
    covers: tuple[str, ...]
    build: Callable[[datetime, random.Random], list[Event]]

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "title": self.title,
            "summary": self.summary,
            "covers": list(self.covers),
        }


def _sid(rng: random.Random) -> str:
    return f"sess-{rng.randrange(16**8):08x}"


def _compromised_account(now: datetime, rng: random.Random) -> list[Event]:
    """A teller's credentials are used from Kyiv 28 minutes after Chennai."""
    staff = BY_ACTOR["r.krishnan"]
    real, stolen = _sid(rng), _sid(rng)
    return [
        make_event(
            staff, Action.LOGIN, now, rng, session_id=real,
            label=ThreatClass.BENIGN, scenario="compromised_account",
        ),
        make_event(
            staff, Action.LOGIN, now + timedelta(minutes=28), rng,
            city="Kyiv", device="UNKNOWN-7f21", ip="185.220.101.44",
            session_id=stolen, label=ThreatClass.COMPROMISED,
            scenario="compromised_account",
        ),
        make_event(
            staff, Action.DB_QUERY, now + timedelta(minutes=31), rng,
            city="Kyiv", device="UNKNOWN-7f21", ip="185.220.101.44",
            resource="core.customers", record_count=18_400,
            session_id=stolen, label=ThreatClass.COMPROMISED,
            scenario="compromised_account",
        ),
    ]


def _privilege_escalation(now: datetime, rng: random.Random) -> list[Event]:
    """A loans officer tries repeatedly to take domain admin, then edits IAM."""
    staff = BY_ACTOR["p.nair"]
    session = _sid(rng)
    events = [
        make_event(
            staff, Action.PRIV_ESCALATE, now + timedelta(minutes=i * 3), rng,
            resource="iam.role-bindings", success=False,
            target_role=Role.DOMAIN_ADMIN.value, session_id=session,
            label=ThreatClass.PRIVILEGE_ABUSE, scenario="privilege_escalation",
        )
        for i in range(3)
    ]
    events.append(
        make_event(
            staff, Action.PRIV_ESCALATE, now + timedelta(minutes=10), rng,
            resource="iam.role-bindings", success=True,
            target_role=Role.DOMAIN_ADMIN.value, session_id=session,
            label=ThreatClass.PRIVILEGE_ABUSE, scenario="privilege_escalation",
        )
    )
    events.append(
        make_event(
            staff, Action.CONFIG_CHANGE, now + timedelta(minutes=12), rng,
            resource="iam.policies", session_id=session,
            label=ThreatClass.PRIVILEGE_ABUSE, scenario="privilege_escalation",
        )
    )
    return events


def _phishing_blast(now: datetime, rng: random.Random) -> list[Event]:
    """An officer's account fans a lookalike-domain link out to 50,000 customers."""
    staff = BY_ACTOR["m.d'souza"]
    session = _sid(rng)
    phish = MessagePayload(
        channel="sms",
        recipient_count=50_000,
        audience="customer",
        subject="Urgent: account verification required",
        body=(
            "Meridian Bank: your account will be suspended in 24 hours. "
            "Re-verify your KYC now: http://meridian-bank.secure-verify.top/re-kyc"
        ),
        urls=["http://meridian-bank.secure-verify.top/re-kyc"],
    )
    return [
        make_event(
            staff, Action.SEND_MESSAGE, now, rng, resource="gateway.outbound",
            message=phish, session_id=session, label=ThreatClass.MALICIOUS,
            scenario="phishing_blast",
        ),
        make_event(
            staff, Action.SEND_MESSAGE, now + timedelta(minutes=2), rng,
            resource="gateway.outbound",
            message=phish.model_copy(update={"recipient_count": 50_000}),
            session_id=session, label=ThreatClass.MALICIOUS,
            scenario="phishing_blast",
        ),
    ]


def _data_exfiltration(now: datetime, rng: random.Random) -> list[Event]:
    """An analyst pulls the customer table at 02:00 and copies it to a share."""
    staff = BY_ACTOR["k.venkatesh"]
    at_night = now.replace(hour=2, minute=14, second=0, microsecond=0)
    if at_night <= now:
        # The *next* 02:14, never one in the past -- replaying into history
        # would scramble the baselines the detectors compare against.
        at_night += timedelta(days=1)
    session = _sid(rng)
    return [
        make_event(
            staff, Action.LOGIN, at_night, rng, session_id=session,
            label=ThreatClass.MALICIOUS, scenario="data_exfiltration",
        ),
        make_event(
            staff, Action.DB_QUERY, at_night + timedelta(minutes=4), rng,
            resource="core.customers", record_count=412_000, session_id=session,
            label=ThreatClass.MALICIOUS, scenario="data_exfiltration",
        ),
        make_event(
            staff, Action.FILE_ACCESS, at_night + timedelta(minutes=9), rng,
            resource="/share/statements", bytes_written=2_900_000_000,
            session_id=session, label=ThreatClass.MALICIOUS,
            scenario="data_exfiltration",
        ),
    ]


def _credential_stuffing(now: datetime, rng: random.Random) -> list[Event]:
    """A sysadmin account is guessed into, then used to sweep the vault."""
    staff = BY_ACTOR["h.qureshi"]
    events = [
        make_event(
            staff, Action.LOGIN_FAILED, now + timedelta(seconds=40 * i), rng,
            city="Lagos", device="UNKNOWN-c31a", ip="102.89.33.7", success=False,
            resource="", label=ThreatClass.COMPROMISED, scenario="credential_stuffing",
        )
        for i in range(7)
    ]
    session = _sid(rng)
    events.append(
        make_event(
            staff, Action.LOGIN, now + timedelta(minutes=6), rng,
            city="Lagos", device="UNKNOWN-c31a", ip="102.89.33.7",
            session_id=session, label=ThreatClass.COMPROMISED,
            scenario="credential_stuffing",
        )
    )
    for i in range(9):
        events.append(
            make_event(
                staff, Action.VAULT_READ, now + timedelta(minutes=8 + i), rng,
                city="Lagos", device="UNKNOWN-c31a", ip="102.89.33.7",
                session_id=session, label=ThreatClass.COMPROMISED,
                scenario="credential_stuffing",
            )
        )
    return events


def _negligent_insider(now: datetime, rng: random.Random) -> list[Event]:
    """Not an attack: a teller emails 900 customers a real statement link.

    Included because a detector that cannot separate careless from criminal is
    useless in a bank. This should be stepped up or quarantined, never paged.
    """
    staff = BY_ACTOR["s.iyer"]
    return [
        make_event(
            staff, Action.SEND_MESSAGE, now, rng, resource="gateway.outbound",
            message=MessagePayload(
                channel="email",
                recipient_count=900,
                audience="customer",
                subject="Statement reminder",
                body="Your statement is ready.",
                urls=["https://secure.meridianbank.com/statements"],
            ),
            session_id=_sid(rng), label=ThreatClass.NEGLIGENT,
            scenario="negligent_insider",
        )
    ]


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        "compromised_account",
        "Compromised teller account",
        "r.krishnan signs in from Chennai, then again from Kyiv 28 minutes later "
        "on an unknown device, and immediately queries the customer table.",
        ("Impossible travel", "Abnormal login", "Credential misuse", "Session monitoring"),
        _compromised_account,
    ),
    Scenario(
        "privilege_escalation",
        "Privilege escalation by a loans officer",
        "p.nair attempts to grant themselves domain admin four times in ten "
        "minutes, succeeds, and edits IAM policy.",
        ("Privilege escalation", "Privileged access management", "Out-of-scope admin action"),
        _privilege_escalation,
    ),
    Scenario(
        "phishing_blast",
        "Bulk phishing from an internal account",
        "m.d'souza's account sends 50,000 customers an SMS carrying a "
        "lookalike-domain KYC link.",
        (
            "Real-time message scanning", "Message risk score",
            "Bulk fraud message detection", "Privileged communication control",
            "Message quarantine",
        ),
        _phishing_blast,
    ),
    Scenario(
        "data_exfiltration",
        "After-hours mass data access",
        "k.venkatesh signs in at 02:14 and reads 412,000 customer records, then "
        "writes 2.9 GB to a file share.",
        ("Insider threat classification", "Behaviour analytics", "Session monitoring"),
        _data_exfiltration,
    ),
    Scenario(
        "credential_stuffing",
        "Credential stuffing into a sysadmin account",
        "Seven failed sign-ins from Lagos, then a success, then nine credential "
        "vault reads in nine minutes.",
        ("Credential misuse", "Abnormal login", "Quantum-safe credential sealing"),
        _credential_stuffing,
    ),
    Scenario(
        "negligent_insider",
        "Negligent -- not malicious",
        "s.iyer emails 900 customers a genuine statement link from a role that "
        "is not approved for bulk sends.",
        ("Insider threat classification", "Risk-based authentication"),
        _negligent_insider,
    ),
)

BY_KEY: dict[str, Scenario] = {s.key: s for s in SCENARIOS}


def build(key: str, now: datetime | None = None, seed: int = 11) -> list[Event]:
    """Materialise one scenario's events."""
    scenario = BY_KEY[key]
    return scenario.build(now or datetime(2026, 9, 21, 9, 30), random.Random(seed))


def build_all(now: datetime | None = None, seed: int = 11) -> list[Event]:
    """Every scenario, spaced an hour apart so they do not contaminate each
    other's 30-minute context windows."""
    base = now or datetime(2026, 9, 21, 9, 30)
    events: list[Event] = []
    for i, scenario in enumerate(SCENARIOS):
        events.extend(scenario.build(base + timedelta(hours=i), random.Random(seed + i)))
    return events
