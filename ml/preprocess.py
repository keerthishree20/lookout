"""Load the dataset, check it, and print per-class feature means.

The features are already numeric and bounded by construction, so preprocessing
is validation rather than transformation: no missing values, no infinities,
every label known. Tree models need no scaling.
"""

import _path  # noqa: F401
import math
from collections import defaultdict

from lookout.ml.dataset import CLASSES, read_csv
from lookout.ml.features import FEATURES
from lookout.ml.model import DATASET_PATH

if __name__ == "__main__":
    X, y = read_csv(DATASET_PATH)
    bad = [i for i, row in enumerate(X) if any(math.isnan(v) or math.isinf(v) for v in row)]
    unknown = sorted(set(y) - set(CLASSES))
    print(f"{len(X):,} rows x {len(FEATURES)} features; bad rows: {len(bad)}; unknown labels: {unknown or 'none'}")
    sums: dict[str, list[float]] = defaultdict(lambda: [0.0] * len(FEATURES))
    counts: dict[str, int] = defaultdict(int)
    for row, label in zip(X, y):
        counts[label] += 1
        for i, v in enumerate(row):
            sums[label][i] += v
    print(f"{'feature':<26}" + "".join(f"{c[:11]:>12}" for c in CLASSES))
    for i, name in enumerate(FEATURES):
        print(f"{name:<26}" + "".join(f"{sums[c][i] / max(counts[c], 1):>12.2f}" for c in CLASSES))
