# Machine learning

Lookout uses three models. None of them decides on its own.

| | IsolationForest | RandomForest classifier |
|---|---|---|
| Kind | unsupervised anomaly detector | supervised, 5 classes |
| Unit | one event | one session (a person's afternoon) |
| Trained on | benign history from the start-up replay | `datasets/insider_sessions.csv` |
| Role | adds up to 22 of 100 points to the score | second opinion shown beside the rules' classification, with SHAP |
| Code | `lookout/anomaly.py` | `lookout/ml/` |

The third, the **message-content model**, is described at the end.

The rules make the decision because each rule can say in a sentence why it fired. A model that
can't explain itself shouldn't be the reason an employee is locked out. The classifier is there
so an analyst can see when a statistical model disagrees with the rules.

## Dataset

`ml/generate_dataset.py` → `backend/datasets/insider_sessions.csv`: **10,600 synthetic sessions**,
imbalanced like real logs.

| class | rows |
|---|---|
| normal | 9,400 (88.7%) |
| negligent | 420 |
| malicious | 330 |
| compromised | 260 |
| privilege_abuse | 190 |

18 features (`ml/features.py`): login_hour, login_day, location_change, device_change,
failed_logins, session_duration, resource_access_count, sensitive_resource_access, data_volume,
message_count, suspicious_url_count, privilege_level, role_change_attempt, after_hours_activity,
ip_reputation, behaviour_deviation, transfer_amount, new_external_payees.

The generator deliberately overlaps the classes where real life does, so the classes can't be
told apart by one feature:

- admins do legitimate just-in-time elevations, so a role change isn't enough on its own to mean
  privilege abuse;
- some compromised sessions are session hijacks, which look like normal hours on a known device;
- negligent sessions look like ordinary work that happened to include a bad link or a
  mis-addressed bulk message.

## Pipeline

Raw data → cleaning → features → split → train → evaluate → serialise → inference. Cleaning uses
pandas (`lookout/ml/cleaning.py`): it drops duplicate sessions, incomplete rows and unknown labels,
clips out-of-range values, and reports how many rows each step touched. On the current dataset it
changes nothing (0 rows dropped, 0 values clipped), and the report says so rather than assuming it.

```bash
cd ml
python generate_dataset.py   # writes backend/datasets/insider_sessions.csv
python preprocess.py         # validates, summarises, shows class balance
python train.py              # fits, evaluates, saves model + metrics.json
python evaluate.py           # prints the saved metrics
python explain.py            # SHAP for a few example sessions
```

The API loads `trained_models/insider_rf.joblib` (or `MODEL_PATH`), training it from the CSV on
first start if it's missing. The Docker image trains it at build time. The `.joblib` file is not
committed; `metrics.json` is.

Model: `RandomForestClassifier(n_estimators=200, min_samples_leaf=3,
class_weight="balanced_subsample")`. The class weighting stops the classifier from simply
predicting "normal" and being 89% accurate.

## Results

Two evaluations, because the first alone would flatter the model.

**Stratified 25% split** (2,650 sessions):

| | |
|---|---|
| accuracy | 0.973 |
| macro F1 | 0.903 |
| ROC-AUC (one-vs-rest, macro) | 0.993 |
| PR-AUC (macro) | 0.950 |
| threat recall (any threat class caught as some threat) | 0.837 |
| false alarms on normal sessions | 0.98% |

| class | precision | recall | F1 |
|---|---|---|---|
| compromised | 1.000 | 1.000 | 1.000 |
| malicious | 0.987 | 0.915 | 0.949 |
| negligent | 0.827 | **0.638** | 0.720 |
| privilege_abuse | 0.827 | 0.896 | 0.860 |
| normal | 0.979 | 0.990 | 0.985 |

**Unseen employees** (trained on some employees, tested on others): accuracy 0.923, macro F1
0.867, but **negligent precision falls to 0.297** and the false-alarm rate on normal sessions
rises to 7.0%. Without a history for that person, careless-but-innocent looks like ordinary
work. That's why per-person baselines matter, and why the model doesn't decide.

Accuracy isn't the headline number here: a model that always says "normal" scores 0.887.

**All of these are measured on synthetic data from Lookout's own generator.** They show the
pipeline works and where it is weak. They say nothing about accuracy on a real bank's logs.

## Explanations (SHAP)

`ThreatClassifier.opinion()` runs SHAP's `TreeExplainer` on the session and returns the top
features pushing towards the predicted class, each with its value and signed contribution. The
decision detail panel in the console shows them next to the rule signals, and they are also
returned by `GET /api/risk/{event_id}/explanation`.

## Message-content model

`lookout/nlp.py`: TF-IDF over word 1-2 grams, then logistic regression. It answers "does this
text read like a scam?", so a message with no link at all ("reply with the OTP you received") is
still caught, and detection isn't a keyword list.

- **Corpus:** 3,000 messages generated from templates in `nlp.py`, about 30% scams, the rest bank
  notices and ordinary staff chat. **Synthetic.**
- **Held-out result:** precision, recall and F1 of 1.0 on 750 messages. That only shows the
  pipeline works: the test messages come from the same templates as the training ones. It says
  nothing about real phishing.
- **Use:** the `phishing_language` detector fires at a probability of 0.7 or more and adds 10-24
  points. Its explanation names the phrases that pushed the score up.
- **Training:** once, on first use, cached for the life of the process; never per request.
