"""Unsupervised behavioural anomaly model.

The rules in :mod:`lookout.rules` catch the misuse we thought to describe. This
catches the rest: an IsolationForest trained only on benign history, which
learns the shape of ordinary work at this bank and flags whatever sits outside
it -- including combinations nobody wrote a rule for.

It is deliberately a *minority* of the final score. An unsupervised model that
cannot explain itself should never be the reason an employee is locked out, so
here it contributes at most :data:`MAX_MODEL_POINTS` and always alongside the
feature attributions below, which say which inputs pushed the event out.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest

from .baselines import Baseline, BaselineStore, haversine_km
from .context import DetectionContext
from .models import Action, Event
from .urlcheck import inspect_all, worst

#: Ceiling on the model's contribution to a 0-100 risk score.
MAX_MODEL_POINTS = 22.0

FEATURE_NAMES: tuple[str, ...] = (
    "hour_rarity",
    "unseen_country",
    "unseen_device",
    "unseen_network",
    "privilege_level",
    "log_records_read",
    "log_recipients",
    "log_transfer_amount",
    "worst_url_score",
    "failed_logins_15m",
    "log_km_from_last_login",
    "events_last_30m",
    "action_sensitivity",
    "failed_action",
)

#: How much damage each verb can do. Gives the model an ordinal sense of
#: "sensitive" without one-hot encoding fourteen sparse columns.
ACTION_SENSITIVITY: dict[Action, float] = {
    Action.LOGOUT: 0.0,
    Action.LOGIN: 0.2,
    Action.LOGIN_FAILED: 0.3,
    Action.FILE_ACCESS: 0.4,
    Action.DB_QUERY: 0.5,
    Action.SEND_MESSAGE: 0.6,
    Action.CONFIG_CHANGE: 0.8,
    Action.VAULT_READ: 0.9,
    Action.PRIV_ESCALATE: 1.0,
    Action.FUND_TRANSFER: 0.95,
}


@dataclass
class AnomalyVerdict:
    """The model's opinion, with the attributions that justify it."""

    score: float  # 0..1
    points: float  # contribution to the risk total
    top_features: list[tuple[str, float]]

    def explanation(self) -> str:
        if not self.top_features:
            return "Behavioural model found nothing unusual in this event."
        drivers = ", ".join(
            f"{name.replace('_', ' ')} ({value:+.2f} vs typical)"
            for name, value in self.top_features
        )
        return (
            f"Behavioural model places this event in the {self.score:.0%} most "
            f"unusual of learned activity, driven by {drivers}."
        )

    def as_dict(self) -> dict:
        return {
            "score": round(self.score, 3),
            "points": round(self.points, 2),
            "top_features": [[n, round(v, 3)] for n, v in self.top_features],
            "explanation": self.explanation(),
        }


def featurise(event: Event, baseline: Baseline, ctx: DetectionContext) -> np.ndarray:
    """Turn one event into the fixed vector the forest consumes.

    Every feature is relative to the actor's own baseline, so the model learns
    "unusual for this person", not "unusual for the bank".
    """
    records = float(event.meta.get("record_count", 0))
    recipients = float(event.message.recipient_count) if event.message else 0.0
    url_score = 0.0
    if event.message and event.message.urls:
        top = worst(inspect_all(event.message.urls))
        url_score = top.score if top else 0.0

    km = 0.0
    if baseline.last_login_geo is not None:
        km = haversine_km(baseline.last_login_geo, (event.geo.lat, event.geo.lon))

    return np.array(
        [
            1.0 - baseline.hour_frequency(event.ts.hour),
            float(baseline.is_new_country(event.geo.country)),
            float(baseline.is_new_device(event.device_id)),
            float(baseline.is_new_network(event.source_ip)),
            float(event.privilege) / 6.0,
            math.log1p(records),
            math.log1p(recipients),
            math.log1p(float(event.meta.get("amount", 0))),
            url_score,
            float(ctx.count(event.actor, Action.LOGIN_FAILED, event.ts, minutes=15)),
            math.log1p(km),
            float(len(ctx.recent(event.actor, event.ts, minutes=30))),
            ACTION_SENSITIVITY.get(event.action, 0.5),
            float(not event.success),
        ],
        dtype=float,
    )


class BehaviourModel:
    """IsolationForest wrapper that stays inert until it has been fitted."""

    def __init__(self, contamination: float = 0.02, seed: int = 7) -> None:
        self._forest = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=seed,
            n_jobs=1,
        )
        self._mean: np.ndarray | None = None
        self._std: np.ndarray | None = None
        self.fitted = False
        self.trained_on = 0

    def fit(self, vectors: list[np.ndarray]) -> "BehaviourModel":
        if len(vectors) < 50:
            # Too little history to distinguish rare from abnormal; staying
            # unfitted means the score is rules-only, which is the safe default.
            return self
        matrix = np.vstack(vectors)
        self._mean = matrix.mean(axis=0)
        self._std = matrix.std(axis=0)
        self._std[self._std < 1e-9] = 1.0
        self._forest.fit(matrix)
        self.fitted = True
        self.trained_on = len(vectors)
        return self

    def score(self, vector: np.ndarray) -> AnomalyVerdict:
        if not self.fitted:
            return AnomalyVerdict(0.0, 0.0, [])

        # decision_function: positive is inlier, negative is outlier. Squash to
        # 0..1 where 1 is maximally anomalous.
        raw = float(self._forest.decision_function(vector.reshape(1, -1))[0])
        score = 1.0 / (1.0 + math.exp(raw * 12.0))

        assert self._mean is not None and self._std is not None
        deviation = (vector - self._mean) / self._std
        ranked = sorted(
            zip(FEATURE_NAMES, deviation), key=lambda kv: abs(kv[1]), reverse=True
        )
        top = [(name, float(dev)) for name, dev in ranked[:3] if abs(dev) > 1.0]

        return AnomalyVerdict(
            score=score, points=round(MAX_MODEL_POINTS * score, 2), top_features=top
        )


def train_from_history(
    events: list[Event], store: BaselineStore, ctx: DetectionContext
) -> BehaviourModel:
    """Replay benign history to build baselines and fit the forest in one pass.

    Events carrying a non-benign ground-truth label are excluded, because a
    model trained on attacks learns to call attacks normal.
    """
    from .models import ThreatClass

    vectors: list[np.ndarray] = []
    for event in events:
        baseline = store.get(event.actor, event.actor_role)
        if event.label in (None, ThreatClass.BENIGN):
            vectors.append(featurise(event, baseline, ctx))
        ctx.record(event)
        baseline.observe(event)
    return BehaviourModel().fit(vectors)
