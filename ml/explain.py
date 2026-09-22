"""Explain one session per threat class with SHAP."""

import _path  # noqa: F401
import csv

from lookout.ml.dataset import CLASSES
from lookout.ml.features import FEATURES
from lookout.ml.model import DATASET_PATH, ThreatClassifier

if __name__ == "__main__":
    clf = ThreatClassifier.load_or_train()
    seen: set[str] = set()
    with DATASET_PATH.open() as f:
        for r in csv.DictReader(f):
            if r["threat_type"] in seen:
                continue
            seen.add(r["threat_type"])
            o = clf.opinion({k: float(r[k]) for k in FEATURES})
            print(f"{r['session_id']} truth={r['threat_type']:<16} model={o.classification} ({o.confidence:.0%})")
            for item in o.as_dict()["shap"]:
                print(f"    {item['feature']:<26} = {item['value']:<12} SHAP {item['contribution']:+.3f}")
            if len(seen) == len(CLASSES):
                break
