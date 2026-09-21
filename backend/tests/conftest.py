from __future__ import annotations

import os
import random
from datetime import datetime, timedelta

import pytest

# Never hit a real LLM or start background traffic from the test suite.
os.environ["GEMINI_API_KEY"] = ""
os.environ["LOOKOUT_LIVE_TRAFFIC"] = "0"

from lookout.baselines import Baseline  # noqa: E402
from lookout.context import DetectionContext  # noqa: E402
from lookout.generator import BY_ACTOR, make_event  # noqa: E402
from lookout.models import Action, Role  # noqa: E402
from lookout.narrator import Narrator  # noqa: E402
from lookout.pipeline import Engine  # noqa: E402

#: A moment just after the generated history ends.
AFTER_HISTORY = datetime(2026, 9, 28, 10, 0)


@pytest.fixture
def engine() -> Engine:
    """A warmed-up engine with a month of benign history behind it."""
    return Engine(narrator=Narrator(api_key="")).warm_up()


@pytest.fixture
def rng() -> random.Random:
    return random.Random(1234)


@pytest.fixture
def ctx() -> DetectionContext:
    return DetectionContext()


@pytest.fixture
def trained_teller(rng) -> Baseline:
    """A teller baseline with 60 ordinary Chennai working-hours events."""
    staff = BY_ACTOR["r.krishnan"]
    b = Baseline(staff.actor, staff.role)
    t = datetime(2026, 9, 1, 9, 30)
    for day in range(20):
        ts = t + timedelta(days=day)
        b.observe(make_event(staff, Action.LOGIN, ts, rng, session_id=f"s{day}"))
        b.observe(
            make_event(
                staff, Action.DB_QUERY, ts + timedelta(hours=2), rng, record_count=40,
            )
        )
        b.observe(
            make_event(
                staff, Action.DB_QUERY, ts + timedelta(hours=4), rng, record_count=38,
            )
        )
    return b


def event_for(actor: str, action: Action, ts: datetime, rng, **kw):
    return make_event(BY_ACTOR[actor], action, ts, rng, **kw)


__all__ = ["AFTER_HISTORY", "event_for", "Role"]
