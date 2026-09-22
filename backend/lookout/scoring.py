"""Risk fusion, insider classification and the graded response.

One number comes out of here, and every part of it is traceable:

    total = min(100, (rule_points + model_points) x privilege_multiplier)

Rule points come from named detectors, each of which carries the sentence
explaining itself. Model points are the IsolationForest's capped contribution.
The privilege multiplier exists because identical behaviour is not identically
dangerous: a domain admin reading 50,000 rows can do more with them than a
teller can.

The band then selects a *graded* response rather than a binary one. Blocking
everything suspicious trains staff to route around the control; asking for a
second factor when the evidence is mid-strength is what makes risk-based
authentication worth having.
"""

from __future__ import annotations

from collections import Counter

from .anomaly import AnomalyVerdict
from .context import SEVERITY
from .models import (
    TRANSFER_LIMITS,
    Action,
    ActionTaken,
    Band,
    Event,
    RiskScore,
    Signal,
    ThreatClass,
)

#: Default score thresholds (see :mod:`lookout.policy` for the live ones).
#: Ordered, non-overlapping, and deliberately conservative at the top:
#: BLOCK_AND_ALERT pages a human, so it must be rare and right.
BAND_THRESHOLDS: tuple[tuple[float, Band], ...] = (
    (80.0, Band.CRITICAL),
    (60.0, Band.HIGH),
    (30.0, Band.MEDIUM),
    (0.0, Band.LOW),
)

#: Extra risk per privilege level above the lowest.
PRIVILEGE_STEP = 0.07


def fuse(
    event: Event, signals: list[Signal], anomaly: AnomalyVerdict
) -> RiskScore:
    """Combine detectors and model into one explainable score."""
    rule_points = sum(s.points for s in signals)
    multiplier = 1.0 + PRIVILEGE_STEP * (event.privilege - 1)
    total = min(100.0, (rule_points + anomaly.points) * multiplier)

    ordered = sorted(signals, key=lambda s: s.points, reverse=True)
    if anomaly.points > 0:
        ordered.append(
            Signal(
                name="behavioural_model",
                points=anomaly.points,
                explanation=anomaly.explanation(),
                detail=anomaly.as_dict(),
            )
        )

    # Band the number the analyst will actually see. Banding the unrounded
    # value once showed "60" beside a medium-risk response.
    total = round(total, 1)
    return RiskScore(
        total=total,
        band=band_for(total),
        rule_points=round(rule_points, 1),
        model_points=round(anomaly.points, 1),
        privilege_multiplier=round(multiplier, 2),
        signals=ordered,
    )


def band_for(total: float) -> Band:
    """Thresholds come from the live policy, so an admin change applies to
    the next decision. :data:`BAND_THRESHOLDS` records the defaults."""
    from .policy import POLICY

    p = POLICY.current
    for threshold, band in ((p.critical, Band.CRITICAL), (p.high, Band.HIGH), (p.medium, Band.MEDIUM)):
        if total >= threshold:
            return band
    return Band.LOW


#: Weight given to a signal's first-listed class versus each class after it.
#: A privilege-escalation attempt is primarily privilege abuse and only
#: secondarily evidence of malice; weighting them equally lets the tie-break
#: toward severity mislabel it.
PRIMARY_WEIGHT = 1.0
SECONDARY_WEIGHT = 0.5


def classify(
    signals: list[Signal],
    event: Event,
    prior: ThreatClass | None = None,
) -> ThreatClass:
    """Name the kind of insider problem this looks like.

    Each detector declares which classes it is evidence for, primary first. The
    winner is the class with the most weighted evidence, where each signal
    contributes its points at full weight to its primary class and half weight
    to the rest. Ties break toward the more serious reading, because an
    under-called incident costs more than an over-called one.

    Signals that carry no class (containment, the behavioural model) add risk
    without voting. If they are all there is, the event inherits ``prior`` --
    the class its session was already given -- so follow-on activity from a
    hijacked session stays "compromised" instead of resetting to benign.

    "Compromised" is also *sticky*. These classes describe the employee, not
    the act: once a session is judged to be under someone else's control,
    everything done in it -- however malicious -- is the intruder's, and
    relabelling the employee "malicious" for it would be exactly wrong.
    """
    if prior is ThreatClass.COMPROMISED:
        return ThreatClass.COMPROMISED

    weights: Counter[ThreatClass] = Counter()
    for signal in signals:
        for i, cls in enumerate(signal.indicates):
            weights[cls] += signal.points * (PRIMARY_WEIGHT if i == 0 else SECONDARY_WEIGHT)

    if not weights:
        return prior or ThreatClass.BENIGN
    return max(weights.items(), key=lambda kv: (kv[1], SEVERITY[kv[0]]))[0]


#: Response severity, least to most disruptive, for applying policy floors.
SEVERITY_ORDER: tuple[ActionTaken, ...] = (
    ActionTaken.ALLOW,
    ActionTaken.STEP_UP,
    ActionTaken.QUARANTINE,
    ActionTaken.BLOCK,
    ActionTaken.BLOCK_AND_ALERT,
)

NO_TRANSFER_MANDATE_POLICY = (
    "This role has no mandate to move customer funds; transfers from it are "
    "blocked whatever the risk score."
)

PRIVILEGED_COMMS_POLICY = (
    "Customer-facing messages from a privileged administrator need a second "
    "factor and are monitored, whatever the risk score."
)

HOSTILE_LINK_POLICY = (
    "Customer-facing messages carrying a suspicious link are never delivered "
    "without human review, whatever the sender's risk score."
)


def decide(risk: RiskScore, event: Event) -> tuple[ActionTaken, str | None]:
    """Map band to response, then apply hard policy floors.

    Returns the action and, if a policy raised it above what the score alone
    would have done, the policy's wording -- so the console can say "held by
    policy" rather than leaving an analyst to wonder why a score of 30 was
    quarantined.

    A fund transfer from a role with no transfer mandate is blocked outright:
    that is an authorisation rule, not a question of degree.

    Two message-specific rules. A held message can be released by a reviewer;
    a blocked login cannot be un-blocked after the fact. So HIGH-band messages
    are quarantined rather than destroyed. And a customer-facing message with a
    suspicious link is quarantined *at minimum*: step-up authentication cannot
    be the control here, because a malicious insider passes their own MFA.
    """
    is_message = event.action is Action.SEND_MESSAGE

    if risk.band is Band.CRITICAL:
        action = ActionTaken.BLOCK_AND_ALERT
    elif risk.band is Band.HIGH:
        action = ActionTaken.QUARANTINE if is_message else ActionTaken.BLOCK
    elif risk.band is Band.MEDIUM:
        action = ActionTaken.STEP_UP
    else:
        action = ActionTaken.ALLOW

    if (
        event.action is Action.FUND_TRANSFER
        and event.actor_role not in TRANSFER_LIMITS
        and _below(action, ActionTaken.BLOCK)
    ):
        return ActionTaken.BLOCK, NO_TRANSFER_MANDATE_POLICY

    to_customers = is_message and event.message is not None and event.message.audience == "customer"
    hostile_link = any(s.name == "suspicious_url" for s in risk.signals)
    if to_customers and hostile_link and _below(action, ActionTaken.QUARANTINE):
        return ActionTaken.QUARANTINE, HOSTILE_LINK_POLICY

    from .policy import POLICY

    if (
        to_customers
        and event.privilege >= 4
        and POLICY.current.privileged_comms_step_up
        and _below(action, ActionTaken.STEP_UP)
    ):
        return ActionTaken.STEP_UP, PRIVILEGED_COMMS_POLICY

    return action, None


def _below(a: ActionTaken, b: ActionTaken) -> bool:
    return SEVERITY_ORDER.index(a) < SEVERITY_ORDER.index(b)


def step_up_requirement(risk: RiskScore, event: Event) -> str:
    """Which second factor risk-based authentication should demand.

    Strength scales with both the score and what the account can reach, so a
    marginal teller login costs one push and a marginal admin action costs a
    hardware key.
    """
    if event.privilege >= 5 or risk.total >= 50:
        return "hardware_security_key"
    if event.privilege >= 3 or risk.total >= 40:
        return "totp_and_manager_approval"
    return "push_notification"


def should_revoke_session(action: ActionTaken, event: Event) -> bool:
    """Kill the session on anything critical -- and on a blocked login, because
    a login that was refused must not leave behind a session that works."""
    if action is ActionTaken.BLOCK_AND_ALERT:
        return True
    return action is ActionTaken.BLOCK and event.action is Action.LOGIN


def should_lock_origin(action: ActionTaken, event: Event) -> bool:
    """Lock the source out when an attack on the front door turns critical --
    otherwise the attacker simply keeps guessing from the same address."""
    return action is ActionTaken.BLOCK_AND_ALERT and event.action in (
        Action.LOGIN,
        Action.LOGIN_FAILED,
    )


def is_strike(action: ActionTaken) -> bool:
    """Responses that count against a session for persistence detection."""
    return action in (
        ActionTaken.BLOCK,
        ActionTaken.QUARANTINE,
        ActionTaken.BLOCK_AND_ALERT,
    )
