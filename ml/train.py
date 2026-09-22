"""Clean the dataset, train the classifier, evaluate it, serialise it with joblib."""

import _path  # noqa: F401

from lookout.ml.cleaning import load_clean, to_rows
from lookout.ml.model import DATASET_PATH, MODEL_PATH, save, train_and_evaluate

if __name__ == "__main__":
    df, report = load_clean(DATASET_PATH)
    print("cleaning:", report)
    model, metrics = train_and_evaluate(to_rows(df))
    metrics["cleaning"] = report
    save(model, metrics)
    print(f"trained on {len(df):,} rows -> {MODEL_PATH}")
    s = metrics["random_split_25pct"]
    print(f"accuracy {s['accuracy']}  macro-F1 {s['macro_f1']}  threat recall {s['threat_recall']}")
