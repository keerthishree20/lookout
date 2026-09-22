"""Supervised insider-threat classifier with SHAP explanations.

A RandomForest over the session features in :mod:`lookout.ml.features`,
trained once on the synthetic dataset and loaded at start-up -- never retrained
per request. It is a *second opinion*: the rule-based classification in
:mod:`lookout.scoring` stays authoritative because every part of it can be
read aloud. The forest adds a calibrated-ish confidence and, through SHAP, a
per-feature account of why it leaned the way it did.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import label_binarize

from .dataset import CLASSES, Row
from .features import FEATURES

BACKEND = Path(__file__).resolve().parents[2]
MODEL_PATH = Path(os.getenv("MODEL_PATH", BACKEND / "trained_models" / "insider_rf.joblib"))
METRICS_PATH = MODEL_PATH.with_name("metrics.json")
DATASET_PATH = BACKEND / "datasets" / "insider_sessions.csv"


def new_forest(seed: int = 7) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=200,
        min_samples_leaf=3,
        # Threat classes are 2-4% each; without re-weighting the forest can
        # score 89% accuracy by calling everything normal.
        class_weight="balanced_subsample",
        random_state=seed,
        n_jobs=-1,
    )


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #


def evaluate(model: RandomForestClassifier, X: np.ndarray, y: np.ndarray) -> dict[str, Any]:
    pred = model.predict(X)
    proba = model.predict_proba(X)
    labels = [str(c) for c in model.classes_]
    p, r, f, support = precision_recall_fscore_support(y, pred, labels=labels, zero_division=0)
    y_bin = label_binarize(y, classes=labels)
    per_class = {
        cls: {
            "precision": round(float(p[i]), 4),
            "recall": round(float(r[i]), 4),
            "f1": round(float(f[i]), 4),
            "support": int(support[i]),
            "pr_auc": round(float(average_precision_score(y_bin[:, i], proba[:, i])), 4),
        }
        for i, cls in enumerate(labels)
    }
    threat = y != "normal"
    threat_pred = pred != "normal"
    return {
        "accuracy": round(float(accuracy_score(y, pred)), 4),
        "macro_f1": round(float(np.mean(f)), 4),
        "roc_auc_ovr_macro": round(float(roc_auc_score(y_bin, proba, average="macro", multi_class="ovr")), 4),
        "pr_auc_macro": round(float(np.mean([v["pr_auc"] for v in per_class.values()])), 4),
        # The number that matters most in security: of the real threats, how
        # many did the model not wave through as normal?
        "threat_recall": round(float((threat & threat_pred).sum() / max(threat.sum(), 1)), 4),
        "normal_false_alarm_rate": round(float((~threat & threat_pred).sum() / max((~threat).sum(), 1)), 4),
        "per_class": per_class,
        "confusion_matrix": {"labels": labels, "rows_true_cols_pred": confusion_matrix(y, pred, labels=labels).tolist()},
        "n": int(len(y)),
    }


def train_and_evaluate(rows: list[Row], seed: int = 7) -> tuple[RandomForestClassifier, dict[str, Any]]:
    X = np.array([[r.features[k] for k in FEATURES] for r in rows])
    y = np.array([r.threat_type for r in rows])
    users = np.array([r.user_id for r in rows])

    # 1. Stratified random split.
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, stratify=y, random_state=seed)
    model = new_forest(seed).fit(X_tr, y_tr)
    random_split = evaluate(model, X_te, y_te)

    # 2. Harder: three employees the model never saw. With only twelve people
    #    in the bank, this is what shows whether it learned behaviour or people.
    held_out = sorted(set(users))[::4][:3]
    mask = np.isin(users, held_out)
    unseen_model = new_forest(seed).fit(X[~mask], y[~mask])
    unseen_split = evaluate(unseen_model, X[mask], y[mask])
    unseen_split["held_out_users"] = held_out

    # Importance from the model that will actually be served.
    final = new_forest(seed).fit(X, y)
    importance = sorted(
        zip(FEATURES, final.feature_importances_), key=lambda kv: kv[1], reverse=True
    )
    metrics = {
        "model": "RandomForestClassifier(n_estimators=200, min_samples_leaf=3, class_weight=balanced_subsample)",
        "dataset": {
            "rows": int(len(y)),
            "synthetic": True,
            "class_counts": {c: int((y == c).sum()) for c in CLASSES},
        },
        "random_split_25pct": random_split,
        "unseen_employees": unseen_split,
        "feature_importance": [[k, round(float(v), 4)] for k, v in importance],
    }
    return final, metrics


def save(model: RandomForestClassifier, metrics: dict[str, Any]) -> None:
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH, compress=3)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))


# --------------------------------------------------------------------------- #
# Serving
# --------------------------------------------------------------------------- #


@dataclass
class Opinion:
    classification: str
    confidence: float
    probabilities: dict[str, float]
    #: (feature, feature value, SHAP contribution toward the predicted class)
    shap: list[tuple[str, float, float]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "confidence": round(self.confidence, 4),
            "probabilities": {k: round(v, 4) for k, v in self.probabilities.items()},
            "shap": [
                {"feature": n, "value": round(v, 4), "contribution": round(c, 4)} for n, v, c in self.shap
            ],
        }


class ThreatClassifier:
    """Loaded once; answers per session. SHAP explainer built lazily because
    it is only needed for sessions someone actually looks at."""

    def __init__(self, model: RandomForestClassifier) -> None:
        self.model = model
        self._explainer = None

    @classmethod
    def load_or_train(cls) -> "ThreatClassifier":
        if MODEL_PATH.exists():
            model = joblib.load(MODEL_PATH)
            # One session at a time: thread start-up would cost more than
            # it saves.
            model.n_jobs = 1
            return cls(model)
        # Train from the committed dataset through the same cleaning step as
        # ml/train.py; regenerate it only if the file is missing.
        if DATASET_PATH.exists():
            from .cleaning import load_clean, to_rows

            rows = to_rows(load_clean(DATASET_PATH)[0])
        else:
            from .dataset import build

            rows = build()
        model, metrics = train_and_evaluate(rows)
        save(model, metrics)
        model.n_jobs = 1
        return cls(model)

    def opinion(self, features: dict[str, float], explain: bool = True, top: int = 6) -> Opinion:
        x = np.array([[features[k] for k in FEATURES]])
        proba = self.model.predict_proba(x)[0]
        labels = [str(c) for c in self.model.classes_]
        idx = int(np.argmax(proba))
        contributions: list[tuple[str, float, float]] = []
        if explain:
            values = self._shap(x)[:, idx]
            ranked = sorted(zip(FEATURES, x[0], values), key=lambda t: abs(t[2]), reverse=True)
            contributions = [(n, float(v), float(c)) for n, v, c in ranked[:top] if abs(c) > 1e-4]
        return Opinion(
            classification=labels[idx],
            confidence=float(proba[idx]),
            probabilities={lab: float(p) for lab, p in zip(labels, proba)},
            shap=contributions,
        )

    def _shap(self, x: np.ndarray) -> np.ndarray:
        """SHAP values for one row, shaped (features, classes)."""
        if self._explainer is None:
            import shap

            self._explainer = shap.TreeExplainer(self.model)
        values = self._explainer.shap_values(x)
        if isinstance(values, list):  # older shap: one array per class
            return np.stack([v[0] for v in values], axis=-1)
        return np.asarray(values)[0]


def load_metrics() -> dict[str, Any] | None:
    return json.loads(METRICS_PATH.read_text()) if METRICS_PATH.exists() else None
