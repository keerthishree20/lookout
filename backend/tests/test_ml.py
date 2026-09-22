"""Supervised classifier: dataset shape, features, training, SHAP, serving."""

from collections import Counter
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from lookout.baselines import Baseline
from lookout.generator import BY_ACTOR, make_event
from lookout.ml.dataset import CLASSES, THREAT_COUNTS, build, read_csv, write_csv
from lookout.ml.features import FEATURES, session_features
from lookout.ml.model import DATASET_PATH, ThreatClassifier, evaluate, load_metrics, train_and_evaluate
from lookout.models import Action

SPEC_FEATURES = (
    "login_hour", "login_day", "location_change", "device_change", "failed_logins",
    "session_duration", "resource_access_count", "sensitive_resource_access", "data_volume",
    "message_count", "suspicious_url_count", "privilege_level", "role_change_attempt",
    "after_hours_activity", "ip_reputation", "behaviour_deviation",
)


@pytest.fixture(scope="module")
def small():
    """A reduced dataset: same generator, fewer normal rows, fast to train."""
    return build(n_normal=1_500, seed=5)


def test_feature_set_covers_the_specification():
    assert set(SPEC_FEATURES) <= set(FEATURES)


def test_committed_dataset_is_ten_thousand_plus_and_imbalanced():
    X, y = read_csv(DATASET_PATH)
    counts = Counter(y)
    assert len(y) >= 10_000
    assert set(counts) == set(CLASSES)
    assert counts["normal"] / len(y) > 0.85
    assert min(counts[c] for c in THREAT_COUNTS) / len(y) < 0.02  # rarest class under 2%
    assert all(len(row) == len(FEATURES) for row in X)


def test_dataset_generation_is_deterministic(small):
    again = build(n_normal=1_500, seed=5)
    assert [r.features for r in small[:20]] == [r.features for r in again[:20]]


def test_csv_roundtrip(tmp_path, small):
    path = tmp_path / "d.csv"
    write_csv(small[:50], path)
    X, y = read_csv(path)
    assert len(X) == 50 and y == [r.threat_type for r in small[:50]]


def test_admins_have_legitimate_escalations_in_normal_data():
    """Otherwise 'any escalation request' would be a perfect label."""
    rows = build(n_normal=3_000, seed=9)
    normal_escalations = [r for r in rows if r.threat_type == "normal" and r.features["role_change_attempt"] > 0]
    assert normal_escalations
    assert all(r.role in ("dba", "sysadmin", "domain_admin") for r in normal_escalations)


def test_session_features_on_a_compromised_session():
    staff = BY_ACTOR["r.krishnan"]
    b = Baseline(staff.actor, staff.role)
    import random

    r = random.Random(1)
    t = datetime(2026, 9, 1, 9, 30)
    for d in range(25):
        b.observe(make_event(staff, Action.LOGIN, t + timedelta(days=d), r))
    attack = [
        make_event(staff, Action.LOGIN_FAILED, t + timedelta(days=30, minutes=i), r, city="Kyiv",
                   device="UNKNOWN-1", ip="185.220.1.1", success=False)
        for i in range(4)
    ] + [make_event(staff, Action.LOGIN, t + timedelta(days=30, minutes=5), r, city="Kyiv",
                    device="UNKNOWN-1", ip="185.220.1.1", session_id="s")]
    f = session_features(attack, b)
    assert f["location_change"] == 1 and f["device_change"] == 1
    assert f["failed_logins"] == 4
    assert f["ip_reputation"] >= 0.9


def test_training_reports_every_required_metric(small):
    _, metrics = train_and_evaluate(small)
    for split in ("random_split_25pct", "unseen_employees"):
        s = metrics[split]
        for key in ("accuracy", "macro_f1", "roc_auc_ovr_macro", "pr_auc_macro", "threat_recall", "confusion_matrix", "per_class"):
            assert key in s
        assert set(s["per_class"]) == set(CLASSES)
    assert metrics["dataset"]["synthetic"] is True


def test_model_beats_the_all_normal_baseline(small):
    """A model that calls everything normal scores ~85% accuracy on this data
    and catches nothing. Threat recall is the honest bar."""
    _, metrics = train_and_evaluate(small)
    assert metrics["random_split_25pct"]["threat_recall"] > 0.6


def test_published_metrics_are_the_real_ones():
    m = load_metrics()
    assert m is not None
    assert m["dataset"]["rows"] >= 10_000
    # The weak class is reported, not hidden.
    assert m["unseen_employees"]["per_class"]["negligent"]["precision"] < 0.9


def test_shap_explains_the_predicted_class(small):
    model, _ = train_and_evaluate(small)
    clf = ThreatClassifier(model)
    compromised = next(r for r in small if r.threat_type == "compromised")
    o = clf.opinion(compromised.features)
    assert o.classification == "compromised"
    assert 0 < o.confidence <= 1
    assert abs(sum(o.probabilities.values()) - 1) < 1e-6
    names = [n for n, _, _ in o.shap]
    assert names and set(names) <= set(FEATURES)
    assert any(n in ("ip_reputation", "device_change", "location_change", "failed_logins") for n in names[:3])


def test_evaluate_handles_a_perfect_split(small):
    model, _ = train_and_evaluate(small)
    import numpy as np

    X = np.array([[r.features[k] for k in FEATURES] for r in small[:200]])
    y = np.array([r.threat_type for r in small[:200]])
    assert evaluate(model, X, y)["accuracy"] > 0.8


# -- served through the API -------------------------------------------------- #


@pytest.fixture(scope="module")
def client():
    from lookout.api import app

    with TestClient(app) as c:
        token = c.post("/api/auth/login", json={"username": "soc.analyst", "password": "SocWatch@2026"}).json()["token"]
        c.headers.update({"Authorization": f"Bearer {token}"})
        yield c


def test_flagged_decisions_carry_a_second_opinion(client):
    client.post("/api/reset")
    r = client.post("/api/scenarios/credential_stuffing/run").json()
    flagged = [d for d in r["decisions"] if d["action_taken"] != "allow"]
    assert flagged and all(d["ml"] for d in flagged)
    assert flagged[-1]["ml"]["classification"] in CLASSES
    assert set(flagged[-1]["ml"]["features"]) == set(FEATURES)


def test_explanation_endpoint(client):
    client.post("/api/reset")
    r = client.post("/api/scenarios/compromised_account/run").json()
    eid = r["peak"]["event"]["event_id"]
    e = client.get(f"/api/risk/{eid}/explanation").json()
    assert e["risk_level"] in ("HIGH", "CRITICAL")
    assert e["reasons"]
    ml = e["ml_second_opinion"]
    assert ml["available"] and ml["shap"]
    assert client.get("/api/risk/nope/explanation").status_code == 404


def test_metrics_endpoint(client):
    m = client.get("/api/ml/metrics").json()
    assert m["random_split_25pct"]["accuracy"] > 0
