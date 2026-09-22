"""Per-identity behavioural baselines.

"Abnormal" only means anything relative to a normal. A 2 a.m. login is routine
for an on-call sysadmin and alarming for a teller, so every threshold in
:mod:`lookout.rules` is expressed against the actor's own history rather than a
global constant.

Baselines update online (Welford's algorithm for mean/variance, sets for
categoricals) so the system keeps learning as it runs, the way a real UEBA
product does. :meth:`Baseline.snapshot` is what the dashboard renders.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime
from typing import Any

from .models import Action, Event, Role


class RunningStat:
    """Online mean/standard deviation (Welford)."""

    __slots__ = ("n", "mean", "_m2")

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self._m2 = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self._m2 += delta * (x - self.mean)

    @property
    def std(self) -> float:
        return math.sqrt(self._m2 / (self.n - 1)) if self.n > 1 else 0.0

    def z(self, x: float) -> float:
        """Z-score, with a floor on sigma so a perfectly constant history does
        not produce an infinite score the first time it varies."""
        if self.n < 2:
            return 0.0
        sigma = max(self.std, max(1.0, abs(self.mean) * 0.10))
        return (x - self.mean) / sigma

    def as_dict(self) -> dict[str, float]:
        return {"n": self.n, "mean": round(self.mean, 2), "std": round(self.std, 2)}


class Baseline:
    """Everything Lookout has learned about one identity."""

    def __init__(self, actor: str, role: Role) -> None:
        self.actor = actor
        self.role = role
        self.events = 0
        self.hour_counts: list[int] = [0] * 24
        self.countries: set[str] = set()
        self.cities: set[str] = set()
        self.devices: set[str] = set()
        self.ip_prefixes: set[str] = set()
        self.resources: set[str] = set()
        self.records_per_query = RunningStat()
        self.recipients_per_message = RunningStat()
        self.transfer_amount = RunningStat()
        #: Destination accounts this person has paid before.
        self.beneficiaries: set[str] = set()
        self.last_login_ts: datetime | None = None
        self.last_login_geo: tuple[float, float] | None = None
        self.last_login_city: str = ""
        self.recent_failures = 0
        self.action_counts: dict[str, int] = defaultdict(int)

    # -- learning --------------------------------------------------------- #

    def observe(self, event: Event) -> None:
        """Fold one event into the profile. Called *after* scoring, so a
        detector never sees the event it is judging inside the baseline."""
        self.events += 1
        self.hour_counts[event.ts.hour] += 1
        self.countries.add(event.geo.country)
        self.cities.add(event.geo.city)
        self.devices.add(event.device_id)
        self.ip_prefixes.add(ip_prefix(event.source_ip))
        self.action_counts[event.action.value] += 1
        if event.resource:
            self.resources.add(event.resource)

        if event.action is Action.LOGIN and event.success:
            self.last_login_ts = event.ts
            self.last_login_geo = (event.geo.lat, event.geo.lon)
            self.last_login_city = event.geo.city
            self.recent_failures = 0
        elif event.action is Action.LOGIN_FAILED:
            self.recent_failures += 1

        if event.action is Action.DB_QUERY:
            self.records_per_query.update(float(event.meta.get("record_count", 0)))
        if event.action is Action.SEND_MESSAGE and event.message:
            self.recipients_per_message.update(float(event.message.recipient_count))
        if event.action is Action.FUND_TRANSFER:
            self.transfer_amount.update(float(event.meta.get("amount", 0)))
            if event.meta.get("to_account"):
                self.beneficiaries.add(str(event.meta["to_account"]))

    # -- queries used by rules -------------------------------------------- #

    @property
    def trained(self) -> bool:
        """Below this, the profile is too thin to call anything abnormal."""
        return self.events >= 20

    def hour_frequency(self, hour: int) -> float:
        """Share of this identity's history that falls in the given hour."""
        if self.events == 0:
            return 0.0
        return self.hour_counts[hour] / self.events

    def is_new_country(self, country: str) -> bool:
        return self.trained and country not in self.countries

    def is_new_device(self, device_id: str) -> bool:
        return self.trained and device_id not in self.devices

    def is_new_network(self, ip: str) -> bool:
        return self.trained and ip_prefix(ip) not in self.ip_prefixes

    def snapshot(self) -> dict[str, Any]:
        top_hours = sorted(range(24), key=lambda h: self.hour_counts[h], reverse=True)[:4]
        return {
            "actor": self.actor,
            "role": self.role.value,
            "events": self.events,
            "trained": self.trained,
            "usual_hours": sorted(h for h in top_hours if self.hour_counts[h]),
            "countries": sorted(self.countries),
            "devices": sorted(self.devices),
            "records_per_query": self.records_per_query.as_dict(),
            "recipients_per_message": self.recipients_per_message.as_dict(),
            "transfer_amount": self.transfer_amount.as_dict(),
            "last_login": {
                "ts": self.last_login_ts.isoformat() if self.last_login_ts else None,
                "city": self.last_login_city,
            },
            "action_mix": dict(sorted(self.action_counts.items())),
        }


class BaselineStore:
    """All baselines, keyed by actor."""

    def __init__(self) -> None:
        self._by_actor: dict[str, Baseline] = {}

    def get(self, actor: str, role: Role) -> Baseline:
        b = self._by_actor.get(actor)
        if b is None:
            b = Baseline(actor, role)
            self._by_actor[actor] = b
        return b

    def observe(self, event: Event) -> None:
        self.get(event.actor, event.actor_role).observe(event)

    def all(self) -> list[Baseline]:
        return list(self._by_actor.values())

    def __len__(self) -> int:
        return len(self._by_actor)


def ip_prefix(ip: str) -> str:
    """/24 for IPv4 -- enough to tell "same office" from "somewhere else"."""
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance in kilometres."""
    r = 6371.0
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))
