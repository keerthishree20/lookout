"""Synthetic labelled insider-threat dataset (10,000+ sessions).

SYNTHETIC DATA. Every row comes from Lookout's own simulator of a fictional
bank. It exists so a supervised model can be trained and *measured* in a
project that has no access to real bank telemetry. Replace it with real
enterprise logs before trusting any number trained on it.

How it is built, so it is not trivially separable:

* Normal sessions are windows of the same simulator the rest of Lookout uses
  (one person, one working day), including its awkward-but-benign cases:
  manager campaigns, weekend on-call admin, mistyped passwords. A slice of
  them additionally get an innocent new laptop, a trip to another city or a
  late evening, labelled normal.
* Threat sessions are copies of real normal sessions with an attack spliced
  in. Every attack family draws its intensity at random, from blatant to
  barely-there, so some threats genuinely look like work.
* Class balance is deliberately skewed the way real data is: roughly 89%
  normal, and the rarest class under 2%.
"""

from __future__ import annotations

import csv
import random
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from ..baselines import Baseline
from ..generator import BY_ACTOR, CITIES, ROSTER, generate_history, make_event
from ..models import (
    CUSTOMER_COMMS_ROLES,
    PRIVILEGE_LEVEL,
    TRANSFER_LIMITS,
    Action,
    Event,
    MessagePayload,
    Role,
)
from .features import FEATURES, session_features

CLASSES: tuple[str, ...] = ("normal", "negligent", "malicious", "compromised", "privilege_abuse")

#: Threat sessions per class. Normal fills the rest.
THREAT_COUNTS: dict[str, int] = {
    "negligent": 420,
    "malicious": 330,
    "compromised": 260,
    "privilege_abuse": 190,
}

WARMUP_DAYS = 45
FOREIGN = ("Kyiv", "Lagos", "Sao Paulo")
HOSTILE_URLS = (
    "http://meridian-bank.secure-verify.top/re-kyc",
    "https://meridianbamk.com/login",
    "https://bit.ly/3kYc-verify",
    "http://185.220.101.44/netbanking",
    "https://merid1anbank.com/otp",
)
CLEAN_URLS = ("https://secure.meridianbank.com/statements", "https://meridianbank.com/offers")


@dataclass
class Row:
    session_id: str
    user_id: str
    role: str
    features: dict[str, float]
    threat_type: str


def build(
    n_normal: int = 9_400,
    seed: int = 20260922,
) -> list[Row]:
    rng = random.Random(seed)
    # ~9 working sessions a day across the roster; add warm-up and slack.
    days = WARMUP_DAYS + int(n_normal / 8.5) + 30
    history = generate_history(days=days, seed=seed, end=datetime(2026, 9, 1, 9, 0))
    start = history[0].ts

    sessions: dict[tuple[str, str], list[Event]] = defaultdict(list)
    baselines = {s.actor: Baseline(s.actor, s.role) for s in ROSTER}
    for e in history:
        if (e.ts - start).days < WARMUP_DAYS:
            baselines[e.actor].observe(e)
        else:
            sessions[(e.actor, e.ts.date().isoformat())].append(e)

    keys = sorted(sessions)
    rng.shuffle(keys)
    rows: list[Row] = []

    # Normal sessions, a slice of them made innocently odd.
    for i, key in enumerate(keys[:n_normal]):
        events = sessions[key]
        admin = PRIVILEGE_LEVEL[BY_ACTOR[events[0].actor].role] >= 4
        if rng.random() < (0.12 if admin else 0.06):
            events = _innocent_oddity(events, rng)
        rows.append(_row(f"S{i:06d}", events, baselines, "normal"))

    # Threat sessions spliced into copies of other people's ordinary days.
    pool = keys[n_normal:] or keys
    mutate = {
        "negligent": _negligent,
        "malicious": _malicious,
        "compromised": _compromised,
        "privilege_abuse": _privilege_abuse,
    }
    n = len(rows)
    for cls, count in THREAT_COUNTS.items():
        for _ in range(count):
            key = rng.choice(pool)
            events = mutate[cls](list(sessions[key]), rng)
            rows.append(_row(f"S{n:06d}", events, baselines, cls))
            n += 1

    rng.shuffle(rows)
    return rows


def write_csv(rows: list[Row], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["session_id", "user_id", "role", *FEATURES, "threat_type"])
        for r in rows:
            w.writerow([r.session_id, r.user_id, r.role, *(round(r.features[k], 4) for k in FEATURES), r.threat_type])


def read_csv(path: Path) -> tuple[list[list[float]], list[str]]:
    X, y = [], []
    with path.open() as f:
        for rec in csv.DictReader(f):
            X.append([float(rec[k]) for k in FEATURES])
            y.append(rec["threat_type"])
    return X, y


# --------------------------------------------------------------------------- #


def _row(sid: str, events: list[Event], baselines: dict[str, Baseline], cls: str) -> Row:
    actor = events[0].actor
    return Row(sid, actor, events[0].actor_role.value, session_features(events, baselines[actor]), cls)


def _anchor(events: list[Event]) -> datetime:
    login = next((e for e in events if e.action is Action.LOGIN), events[0])
    return login.ts


def _session_id(events: list[Event]) -> str:
    return next((str(e.meta["session_id"]) for e in events if e.meta.get("session_id")), "sess-x")


def _at_night(events: list[Event], rng: random.Random) -> list[Event]:
    """Shift a whole session into the small hours, keeping its shape."""
    t0 = _anchor(events)
    target = t0.replace(hour=rng.choice([0, 1, 2, 3, 22, 23]), minute=rng.randrange(60))
    shift = target - t0
    return [e.model_copy(update={"ts": e.ts + shift}) for e in events]


def _innocent_oddity(events: list[Event], rng: random.Random) -> list[Event]:
    staff = BY_ACTOR[events[0].actor]
    kinds = ["laptop", "trip", "late"]
    if PRIVILEGE_LEVEL[staff.role] >= 4:
        # Approved just-in-time elevation: admins legitimately request higher
        # rights for a change window. Without this, "any escalation request"
        # would be a perfect privilege-abuse label and the metric a lie.
        kinds += ["jit", "jit"]
    kind = rng.choice(kinds)
    if kind == "jit":
        t, sid = _anchor(events) + timedelta(hours=1), _session_id(events)
        return list(events) + [
            make_event(staff, Action.PRIV_ESCALATE, t, rng, resource="pam.checkout", success=True,
                       target_role=Role.DOMAIN_ADMIN.value, session_id=sid, approved_change="CHG-"
                       f"{rng.randrange(10**5):05d}")
        ]
    if kind == "laptop":
        dev = f"LT-NEW-{rng.randrange(1000):03d}"
        return [e.model_copy(update={"device_id": dev}) for e in events]
    if kind == "trip":
        city = rng.choice([c for c in ("Chennai", "Bengaluru", "Mumbai", "Coimbatore") if c != staff.city])
        return [e.model_copy(update={"geo": CITIES[city]}) for e in events]
    t0 = _anchor(events)
    shift = timedelta(hours=rng.choice([2, 3, 4]))
    return [e.model_copy(update={"ts": e.ts + shift}) if e.ts > t0 + timedelta(hours=3) else e for e in events]


def _negligent(events: list[Event], rng: random.Random) -> list[Event]:
    """Carelessness: policy broken, nothing hostile."""
    staff = BY_ACTOR[events[0].actor]
    t, sid = _anchor(events) + timedelta(hours=rng.uniform(1, 6)), _session_id(events)
    kind = rng.choice(["comms", "export", "late_access", "typos"])
    out = list(events)
    if kind == "comms":
        reach = rng.choice([rng.randint(60, 400), rng.randint(400, 3000)])
        audience = "customer" if staff.role not in CUSTOMER_COMMS_ROLES or reach > 50 else "internal"
        out.append(make_event(staff, Action.SEND_MESSAGE, t, rng, resource="gateway.outbound", session_id=sid,
                              message=MessagePayload(recipient_count=reach, audience=audience,
                                                     urls=[rng.choice(CLEAN_URLS)])))
    elif kind == "export":
        rows = int(max(staff.query_rows, 30) * rng.uniform(3, 12))
        out.append(make_event(staff, Action.DB_QUERY, t, rng, resource="core.customers", record_count=rows, session_id=sid))
    elif kind == "late_access":
        late = _anchor(events).replace(hour=rng.choice([20, 21, 22, 23]))
        for i in range(rng.randint(1, 4)):
            out.append(make_event(staff, Action.DB_QUERY, late + timedelta(minutes=7 * i), rng,
                                  resource="core.customers", record_count=max(1, staff.query_rows), session_id=sid))
    else:
        for i in range(rng.randint(3, 5)):
            out.insert(0, make_event(staff, Action.LOGIN_FAILED, _anchor(events) - timedelta(minutes=i + 1), rng,
                                     success=False, resource=""))
    return out


def _malicious(events: list[Event], rng: random.Random) -> list[Event]:
    """Deliberate misuse from the person's own desk and credentials."""
    staff = BY_ACTOR[events[0].actor]
    if rng.random() < 0.5:
        events = _at_night(events, rng)
    t, sid = _anchor(events) + timedelta(minutes=rng.uniform(5, 240)), _session_id(events)
    out = list(events)
    intensity = rng.choice([0.3, 1.0, 1.0, 3.0])  # some are subtle
    for kind in rng.sample(["exfil", "stage", "phish", "fraud"], k=rng.choice([1, 1, 2])):
        if kind == "exfil":
            rows = int(max(staff.query_rows, 40) * rng.uniform(15, 400) * intensity)
            out.append(make_event(staff, Action.DB_QUERY, t, rng, resource="core.customers", record_count=rows, session_id=sid))
        elif kind == "stage":
            out.append(make_event(staff, Action.FILE_ACCESS, t + timedelta(minutes=4), rng, resource="/share/statements",
                                  bytes_written=int(rng.uniform(3e8, 4e9) * intensity), session_id=sid))
        elif kind == "phish":
            out.append(make_event(staff, Action.SEND_MESSAGE, t, rng, resource="gateway.outbound", session_id=sid,
                                  message=MessagePayload(recipient_count=int(rng.choice([1, 50, 2000, 50000]) * intensity) or 1,
                                                         audience="customer", urls=[rng.choice(HOSTILE_URLS)])))
        else:
            limit = TRANSFER_LIMITS.get(staff.role, 200_000)
            for i in range(rng.randint(1, 3)):
                out.append(make_event(staff, Action.FUND_TRANSFER, t + timedelta(minutes=3 * i), rng, resource="core.payments",
                                      session_id=sid, amount=float(round(limit * rng.uniform(0.4, 3.0) * intensity, -2)),
                                      from_account="502100000000", to_account=f"77{rng.randrange(10**10):010d}", external=True))
    return out


def _compromised(events: list[Event], rng: random.Random) -> list[Event]:
    """Someone else is using this person's credentials."""
    staff = BY_ACTOR[events[0].actor]
    city = rng.choice(FOREIGN) if rng.random() < 0.75 else rng.choice(["Mumbai", "Bengaluru", "Chennai"])
    device = f"UNKNOWN-{rng.randrange(16**4):04x}"
    ip = rng.choice([f"185.220.{rng.randrange(256)}.{rng.randrange(256)}", f"102.89.{rng.randrange(256)}.{rng.randrange(256)}",
                     f"{rng.randrange(20, 220)}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}"])
    hijack = rng.random() < 0.5
    if not hijack and rng.random() < 0.5:
        events = _at_night(events, rng)
    t0, sid = _anchor(events), f"sess-c{rng.randrange(16**6):06x}"
    # Half are hijacks in the middle of the real person's working day, so the
    # session keeps its ordinary length and content. Without this, "short
    # session" alone identified every compromise -- SHAP showed the model
    # leaning on exactly that shortcut.
    out: list[Event] = list(events) if hijack else []
    if hijack:
        t0 = t0 + timedelta(hours=rng.uniform(1, 6))
    for i in range(rng.choice([0, 0, 2, 5, 8])):
        out.append(make_event(staff, Action.LOGIN_FAILED, t0 - timedelta(minutes=i + 1), rng, city=city,
                              device=device, ip=ip, success=False, resource=""))
    out.append(make_event(staff, Action.LOGIN, t0, rng, city=city, device=device, ip=ip, session_id=sid))
    for i in range(rng.randint(1, 6)):
        action = rng.choice([Action.DB_QUERY, Action.DB_QUERY, Action.VAULT_READ, Action.FILE_ACCESS])
        extra = {"record_count": int(max(staff.query_rows, 30) * rng.uniform(0.5, 60))} if action is Action.DB_QUERY else {}
        out.append(make_event(staff, action, t0 + timedelta(minutes=2 + 3 * i), rng, city=city, device=device, ip=ip,
                              session_id=sid, **extra))
    return out


def _privilege_abuse(events: list[Event], rng: random.Random) -> list[Event]:
    """Reaching past granted rights."""
    staff = BY_ACTOR[events[0].actor]
    t, sid = _anchor(events) + timedelta(hours=rng.uniform(0.5, 5)), _session_id(events)
    out = list(events)
    higher = [r for r in Role if PRIVILEGE_LEVEL[r] > PRIVILEGE_LEVEL[staff.role]] or [Role.DOMAIN_ADMIN]
    for i in range(rng.choice([1, 1, 2, 4])):
        out.append(make_event(staff, Action.PRIV_ESCALATE, t + timedelta(minutes=2 * i), rng, resource="iam.role-bindings",
                              success=rng.random() < 0.3, target_role=rng.choice(higher).value, session_id=sid))
    for _ in range(rng.choice([0, 1, 2])):
        action = rng.choice([Action.CONFIG_CHANGE, Action.VAULT_READ])
        out.append(make_event(staff, action, t + timedelta(minutes=12), rng, session_id=sid))
    return out
