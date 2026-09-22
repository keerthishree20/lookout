# ML pipeline

Thin entry points over `backend/lookout/ml/`. Run from the repository root with the backend venv:

| Step | Command |
|---|---|
| Generate the synthetic dataset (10,600 sessions) | `backend/.venv/bin/python ml/generate_dataset.py` |
| Preprocess (summary + sanity checks) | `backend/.venv/bin/python ml/preprocess.py` |
| Train and serialise the classifier | `backend/.venv/bin/python ml/train.py` |
| Evaluate (writes `backend/trained_models/metrics.json`) | `backend/.venv/bin/python ml/evaluate.py` |
| Explain one session with SHAP | `backend/.venv/bin/python ml/explain.py` |

The data is **synthetic**. See `docs/ml.md`.
