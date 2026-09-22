"""Measure the detectors instead of asserting that they work.

Because every generated event carries a ground-truth label, Lookout can score
itself the way any classifier is scored. This matters more than it looks: the
easy way to make an insider-threat demo impressive is to tune thresholds until
the five scripted attacks light up, which also makes the system alert on every
manager running a marketing campaign. Running this evaluation against held-out
benign traffic is what stops that.

"Flagged" means Lookout did anything other than allow. False positives are
counted against held-out benign days the model never trained on, including the
deliberately awkward cases: legitimate bulk campaigns, on-call weekend admin
work and ordinary mistyped passwords.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .generator import generate_history
from .models import ActionTaken, Band, Decision, Event, ThreatClass
from .narrator import Narrator
from .pipeline import Engine
from .scenarios import SCENARIOS
from .scoring import PRIVILEGED_COMMS_POLICY


@dataclass
class ConfusionMatrix:
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0

    @property
    def precision(self) -> float:
        d = self.true_positive + self.false_positive
        return self.true_positive / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.true_positive + self.false_negative
        return self.true_positive / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        d = self.false_positive + self.true_negative
        return self.false_positive / d if d else 0.0

    def as_dict(self) -> dict:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


@dataclass
class EvaluationReport:
    matrix: ConfusionMatrix
    benign_events: int
    incident_events: int
    #: Of the incident events Lookout flagged, how many it also named correctly
    #: (negligent / malicious / compromised / privilege abuse).
    classified_correctly: int = 0
    classified_total: int = 0
    per_scenario: dict[str, dict] = field(default_factory=dict)
    worst_false_positives: list[dict] = field(default_factory=list)
    #: Low-score events given a second factor only because policy requires it
    #: (privileged staff messaging customers). A mandatory control, not a
    #: detection, so they count as neither true nor false positives.
    policy_step_ups: int = 0

    @property
    def classification_accuracy(self) -> float:
        return self.classified_correctly / self.classified_total if self.classified_total else 0.0

    def as_dict(self) -> dict:
        return {
            "overall": self.matrix.as_dict(),
            "benign_events": self.benign_events,
            "incident_events": self.incident_events,
            "classification": {
                "correct": self.classified_correctly,
                "total": self.classified_total,
                "accuracy": round(self.classification_accuracy, 3),
            },
            "per_scenario": self.per_scenario,
            "worst_false_positives": self.worst_false_positives,
            "policy_step_ups": self.policy_step_ups,
        }

    def summary(self) -> str:
        m = self.matrix
        lines = [
            "Lookout detector evaluation",
            "=" * 48,
            f"held-out benign events : {self.benign_events}",
            f"incident events        : {self.incident_events}",
            "",
            f"precision              : {m.precision:.3f}",
            f"recall                 : {m.recall:.3f}",
            f"F1                     : {m.f1:.3f}",
            f"false positive rate    : {m.false_positive_rate:.4f}"
            f"  ({m.false_positive} of {m.false_positive + m.true_negative} benign)",
            f"threat classification  : {self.classification_accuracy:.3f}"
            f"  ({self.classified_correctly} of {self.classified_total} detected incidents named correctly)",
            f"policy step-ups        : {self.policy_step_ups}"
            "  (low-score events given MFA because policy requires it; not counted as detections)",
            "",
            "per scenario (incident events only):",
        ]
        for key, row in self.per_scenario.items():
            lines.append(
                f"  {key:<22} detected {row['detected']:>2}/{row['events']:<2}"
                f"  peak {row['peak_score']:>5.1f}  -> {row['strongest_action']:<16}"
                f" class {row['classified_as']}"
            )
        if self.worst_false_positives:
            lines += ["", "loudest false positives:"]
            for fp in self.worst_false_positives:
                lines.append(
                    f"  {fp['actor']:<14} {fp['action']:<14} {fp['score']:>5.1f}"
                    f"  {fp['signals']}"
                )
        return "\n".join(lines)


def run_evaluation(
    train_days: int = 30,
    holdout_days: int = 7,
    seed: int = 20260921,
) -> EvaluationReport:
    """Train on one month, then judge held-out benign days plus every scenario."""
    engine = Engine(narrator=Narrator(api_key="")).warm_up(days=train_days, seed=seed)

    train_end = datetime(2026, 9, 21, 9, 0)
    holdout = generate_history(
        days=holdout_days,
        seed=seed + 1,
        end=train_end + timedelta(days=holdout_days),
    )
    holdout = [e for e in holdout if e.ts >= train_end]

    incidents: list[Event] = []
    base = train_end + timedelta(days=holdout_days, hours=1)
    for i, scenario in enumerate(SCENARIOS):
        import random

        incidents.extend(
            scenario.build(base + timedelta(hours=i * 3), random.Random(seed + i))
        )

    matrix = ConfusionMatrix()
    per_scenario: dict[str, dict] = {}
    false_positives: list[dict] = []
    classified_correctly = classified_total = 0
    policy_step_ups = 0

    for event in holdout + incidents:
        decision = engine.ingest(event)
        policy_only = decision.policy == PRIVILEGED_COMMS_POLICY and decision.risk.band is Band.LOW
        policy_step_ups += policy_only
        flagged = decision.action_taken is not ActionTaken.ALLOW and not policy_only
        actually_bad = event.label not in (None, ThreatClass.BENIGN)

        if actually_bad and flagged:
            matrix.true_positive += 1
            classified_total += 1
            if decision.threat_class is event.label:
                classified_correctly += 1
        elif actually_bad:
            matrix.false_negative += 1
        elif flagged:
            matrix.false_positive += 1
            false_positives.append(_fp_row(decision))
        else:
            matrix.true_negative += 1

        # A scenario may open with a legitimate event (the real login before
        # the hijack); only the labelled incident events count toward its row.
        if event.scenario and actually_bad:
            row = per_scenario.setdefault(
                event.scenario,
                {
                    "events": 0,
                    "detected": 0,
                    "peak_score": 0.0,
                    "strongest_action": "allow",
                    "classified_as": "-",
                },
            )
            row["events"] += 1
            if flagged:
                row["detected"] += 1
            if decision.risk.total > row["peak_score"]:
                row["peak_score"] = decision.risk.total
                row["strongest_action"] = decision.action_taken.value
                row["classified_as"] = decision.threat_class.value

    false_positives.sort(key=lambda r: r["score"], reverse=True)
    return EvaluationReport(
        matrix=matrix,
        benign_events=matrix.true_negative + matrix.false_positive,
        incident_events=matrix.true_positive + matrix.false_negative,
        classified_correctly=classified_correctly,
        classified_total=classified_total,
        per_scenario=per_scenario,
        worst_false_positives=false_positives[:8],
        policy_step_ups=policy_step_ups,
    )


def _fp_row(decision: Decision) -> dict:
    return {
        "actor": decision.event.actor,
        "action": decision.event.action.value,
        "score": decision.risk.total,
        "taken": decision.action_taken.value,
        "signals": ", ".join(s.name for s in decision.risk.signals) or "-",
    }


if __name__ == "__main__":  # pragma: no cover
    print(run_evaluation().summary())
