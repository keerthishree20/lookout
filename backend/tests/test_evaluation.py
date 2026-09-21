"""Regression guard on detection quality.

These floors sit below today's measured numbers on purpose -- they exist to
fail loudly if a change quietly trades recall for fewer alerts, or starts
paging on ordinary work. They say nothing about performance on real bank data;
see the README for why.
"""

import pytest

from lookout.evaluate import ConfusionMatrix, run_evaluation


@pytest.fixture(scope="module")
def report():
    return run_evaluation()


def test_recall_floor(report):
    assert report.matrix.recall >= 0.90, report.summary()


def test_precision_floor(report):
    assert report.matrix.precision >= 0.90, report.summary()


def test_false_positive_rate_on_held_out_benign_traffic(report):
    assert report.matrix.false_positive_rate <= 0.01, report.summary()
    assert report.benign_events > 500


def test_threat_classification_accuracy(report):
    assert report.classification_accuracy >= 0.85, report.summary()


def test_every_scenario_is_detected_at_least_once(report):
    for key, row in report.per_scenario.items():
        assert row["detected"] >= 1, key


def test_known_miss_is_the_lone_night_login(report):
    """The one incident event Lookout lets through is the 02:14 login that opens
    the exfiltration scenario: an unusual hour alone is not enough to block, and
    the query four minutes later is blocked before any data leaves. If this
    changes, the README's stated miss needs updating too."""
    row = report.per_scenario["data_exfiltration"]
    assert row["events"] - row["detected"] <= 1


def test_confusion_matrix_arithmetic():
    m = ConfusionMatrix(true_positive=8, false_positive=2, true_negative=88, false_negative=2)
    assert m.precision == 0.8
    assert m.recall == 0.8
    assert m.f1 == pytest.approx(0.8)
    assert m.false_positive_rate == pytest.approx(2 / 90)
    assert ConfusionMatrix().precision == 0.0
