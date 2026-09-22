"""Train the classifier on the dataset CSV and serialise it with joblib."""

import _path  # noqa: F401

from lookout.ml.dataset import Row
from lookout.ml.features import FEATURES
from lookout.ml.model import DATASET_PATH, MODEL_PATH, save, train_and_evaluate

if __name__ == "__main__":
    import csv

    with DATASET_PATH.open() as f:
        rows = [
            Row(r["session_id"], r["user_id"], r["role"], {k: float(r[k]) for k in FEATURES}, r["threat_type"])
            for r in csv.DictReader(f)
        ]
    model, metrics = train_and_evaluate(rows)
    save(model, metrics)
    print(f"trained on {len(rows):,} rows -> {MODEL_PATH}")
    s = metrics["random_split_25pct"]
    print(f"accuracy {s['accuracy']}  macro-F1 {s['macro_f1']}  threat recall {s['threat_recall']}")
