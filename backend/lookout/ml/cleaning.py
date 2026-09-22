"""Data cleaning for the classifier's dataset (spec §32: raw data -> cleaning).

The synthetic generator produces clean rows, but a pipeline that will one day
read real telemetry can't assume that, so every training run goes through the
same checks:

* duplicate session ids are dropped (a replayed export would double-count);
* rows with a missing or non-numeric feature, or an unknown label, are dropped;
* infinities become missing and are dropped with them;
* values outside their physical range are clipped (an hour of 25, a negative
  row count, an IP reputation above 1);
* labels are normalised (case, whitespace).

The report says how many rows each step removed or changed, so a cleaning
step that suddenly discards half the data is visible rather than silent.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .dataset import CLASSES, Row
from .features import FEATURES as _FEATURES

#: A list, not a tuple: pandas reads a tuple as one multi-level column key.
FEATURES = list(_FEATURES)

#: Physical bounds per feature; anything outside is clipped.
BOUNDS: dict[str, tuple[float, float | None]] = {
    "login_hour": (0, 23),
    "login_day": (0, 6),
    "location_change": (0, 1),
    "device_change": (0, 1),
    "ip_reputation": (0, 1),
}


def load_clean(path: Path) -> tuple[pd.DataFrame, dict[str, Any]]:
    raw = pd.read_csv(path)
    report: dict[str, Any] = {"raw_rows": int(len(raw))}

    df = raw.drop_duplicates(subset="session_id", keep="first")
    report["duplicate_sessions_dropped"] = int(len(raw) - len(df))

    df = df.copy()
    df["threat_type"] = df["threat_type"].astype(str).str.strip().str.lower()
    for col in FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df[FEATURES] = df[FEATURES].replace([np.inf, -np.inf], np.nan)

    before = len(df)
    df = df.dropna(subset=FEATURES)
    report["incomplete_rows_dropped"] = int(before - len(df))

    before = len(df)
    df = df[df["threat_type"].isin(CLASSES)]
    report["unknown_label_rows_dropped"] = int(before - len(df))

    clipped = 0
    for col in FEATURES:
        low, high = BOUNDS.get(col, (0, None))
        out = (df[col] < low) | ((df[col] > high) if high is not None else False)
        clipped += int(out.sum())
        df[col] = df[col].clip(lower=low, upper=high)
    report["values_clipped"] = clipped
    report["clean_rows"] = int(len(df))
    report["class_counts"] = {c: int(n) for c, n in df["threat_type"].value_counts().items()}
    return df.reset_index(drop=True), report


def to_rows(df: pd.DataFrame) -> list[Row]:
    return [
        Row(r.session_id, r.user_id, r.role, {k: float(getattr(r, k)) for k in FEATURES}, r.threat_type)
        for r in df.itertuples(index=False)
    ]


def describe(df: pd.DataFrame) -> pd.DataFrame:
    """Per-class feature means: the quickest check that the classes differ
    in the ways the generator intended, and overlap where real life does."""
    return df.groupby("threat_type")[FEATURES].mean().T.round(2)
