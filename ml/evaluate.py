"""Print the evaluation written by train.py: every metric, both splits."""

import _path  # noqa: F401

from lookout.ml.model import load_metrics

if __name__ == "__main__":
    m = load_metrics()
    if m is None:
        raise SystemExit("no metrics yet: run ml/train.py first")
    print(f"model: {m['model']}")
    print(f"dataset: {m['dataset']['rows']:,} rows (SYNTHETIC)  {m['dataset']['class_counts']}\n")
    for split in ("random_split_25pct", "unseen_employees"):
        s = m[split]
        title = split if split != "unseen_employees" else f"unseen employees {s['held_out_users']}"
        print(f"== {title}  (n={s['n']})")
        for k in ("accuracy", "macro_f1", "roc_auc_ovr_macro", "pr_auc_macro", "threat_recall", "normal_false_alarm_rate"):
            print(f"  {k:<24} {s[k]}")
        print(f"  {'class':<16}{'precision':>10}{'recall':>8}{'f1':>8}{'pr_auc':>8}{'n':>6}")
        for cls, v in s["per_class"].items():
            print(f"  {cls:<16}{v['precision']:>10}{v['recall']:>8}{v['f1']:>8}{v['pr_auc']:>8}{v['support']:>6}")
        cm = s["confusion_matrix"]
        print("  confusion (rows = true, cols = predicted):", cm["labels"])
        for label, row in zip(cm["labels"], cm["rows_true_cols_pred"]):
            print(f"    {label:<16}{row}")
        print()
    print("top features:", m["feature_importance"][:8])
