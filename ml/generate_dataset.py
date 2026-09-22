"""Generate the synthetic insider-threat dataset (10,000+ labelled sessions)."""

import _path  # noqa: F401
from collections import Counter

from lookout.ml.dataset import build, write_csv
from lookout.ml.model import DATASET_PATH

if __name__ == "__main__":
    rows = build()
    write_csv(rows, DATASET_PATH)
    print(f"wrote {len(rows):,} SYNTHETIC sessions to {DATASET_PATH}")
    for cls, n in Counter(r.threat_type for r in rows).most_common():
        print(f"  {cls:<16} {n:>6}  {n / len(rows):6.1%}")
