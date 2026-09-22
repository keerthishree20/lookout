"""Load the dataset with pandas, clean it, and show what cleaning did.

Prints the cleaning report (duplicates, incomplete rows, unknown labels,
out-of-range values clipped), the class balance, and the per-class feature
means. Tree models need no scaling, so cleaning is the whole preprocessing
step; feature engineering happens upstream in ``lookout.ml.features``.
"""

import _path  # noqa: F401

import pandas as pd

from lookout.ml.cleaning import describe, load_clean
from lookout.ml.model import DATASET_PATH

if __name__ == "__main__":
    df, report = load_clean(DATASET_PATH)
    for k, v in report.items():
        print(f"{k:<28} {v}")
    print()
    with pd.option_context("display.width", 140, "display.max_rows", 40):
        print(describe(df))
