from datetime import datetime

from lookout.anomaly import AnomalyVerdict
from lookout.generator import BY_ACTOR, make_event
from lookout.models import Action, ActionTaken, Band, MessagePayload, Signal, ThreatClass
from lookout.scoring import (
    band_for,
    classify,
    decide,
    fuse,
    should_lock_origin,
    should_revoke_session,
    step_up_requirement,
)

T = datetime(2026, 9, 22, 10, 0)
NO_MODEL = AnomalyVerdict(0.0, 0.0, [])


def _ev(actor, action=Action.DB_QUERY, **kw):
    import random

    return make_event(BY_ACTOR[actor], action, T, random.Random(0), **kw)


def _sig(points, *classes, name="x"):
    return Signal(name=name, points=points, explanation="e", indicates=list(classes))


def test_bands():
    assert band_for(0) is Band.LOW
    assert band_for(29.9) is Band.LOW
    assert band_for(30) is Band.MEDIUM
    assert band_for(60) is Band.HIGH
    assert band_for(85) is Band.CRITICAL


def test_privilege_multiplier_makes_admins_riskier():
    s = [_sig(40, ThreatClass.MALICIOUS)]
    teller = fuse(_ev("r.krishnan"), s, NO_MODEL)
    admin = fuse(_ev("n.pillai"), s, NO_MODEL)
    assert teller.privilege_multiplier == 1.0
    assert admin.privilege_multiplier == 1.35
    assert admin.total > teller.total


def test_total_is_capped_at_100():
    assert fuse(_ev("n.pillai"), [_sig(500)], NO_MODEL).total == 100.0


def test_model_contribution_is_listed_as_its_own_signal():
    risk = fuse(_ev("r.krishnan"), [_sig(10)], AnomalyVerdict(0.5, 11.0, [("hour_rarity", 3.0)]))
    assert risk.model_points == 11.0
    assert risk.signals[-1].name == "behavioural_model"
    assert "hour rarity" in risk.signals[-1].explanation


def test_signals_are_ordered_by_weight():
    risk = fuse(_ev("r.krishnan"), [_sig(5, name="a"), _sig(30, name="b")], NO_MODEL)
    assert [s.name for s in risk.signals] == ["b", "a"]


def test_classify_benign_with_no_signals():
    assert classify([], _ev("r.krishnan")) is ThreatClass.BENIGN


def test_classify_primary_class_outweighs_secondary():
    """Escalation lists PRIVILEGE_ABUSE first and MALICIOUS second; it must
    not be relabelled malicious by the severity tie-break."""
    s = [_sig(50, ThreatClass.PRIVILEGE_ABUSE, ThreatClass.MALICIOUS)]
    assert classify(s, _ev("p.nair")) is ThreatClass.PRIVILEGE_ABUSE


def test_classify_ties_break_toward_severity():
    s = [_sig(20, ThreatClass.NEGLIGENT), _sig(20, ThreatClass.MALICIOUS)]
    assert classify(s, _ev("r.krishnan")) is ThreatClass.MALICIOUS


def test_classless_signals_inherit_session_class():
    s = [_sig(60)]  # e.g. revoked_session_use
    assert classify(s, _ev("r.krishnan"), prior=ThreatClass.PRIVILEGE_ABUSE) is ThreatClass.PRIVILEGE_ABUSE
    assert classify(s, _ev("r.krishnan")) is ThreatClass.BENIGN


def test_compromised_is_sticky():
    """Anything done in a hijacked session is the intruder's, not the employee's."""
    s = [_sig(80, ThreatClass.MALICIOUS)]
    assert classify(s, _ev("r.krishnan"), prior=ThreatClass.COMPROMISED) is ThreatClass.COMPROMISED


def _risk(total):
    return fuse(_ev("r.krishnan"), [_sig(total)], NO_MODEL)


def test_decide_graded_response():
    login = _ev("r.krishnan", Action.LOGIN)
    assert decide(_risk(10), login) == (ActionTaken.ALLOW, None)
    assert decide(_risk(40), login) == (ActionTaken.STEP_UP, None)
    assert decide(_risk(70), login) == (ActionTaken.BLOCK, None)
    assert decide(_risk(90), login) == (ActionTaken.BLOCK_AND_ALERT, None)


def test_high_risk_messages_are_quarantined_not_destroyed():
    msg = _ev("r.krishnan", Action.SEND_MESSAGE, message=MessagePayload())
    assert decide(_risk(70), msg)[0] is ActionTaken.QUARANTINE
    assert decide(_risk(90), msg)[0] is ActionTaken.BLOCK_AND_ALERT


def _link_risk(total):
    return fuse(_ev("p.nair"), [_sig(total, name="suspicious_url")], NO_MODEL)


def test_customer_message_with_hostile_link_is_never_merely_stepped_up():
    """Step-up cannot stop a malicious insider -- they pass their own MFA. So a
    suspicious link to customers is held for review however low the score."""
    to_customer = _ev("p.nair", Action.SEND_MESSAGE, message=MessagePayload(audience="customer"))
    action, policy = decide(_link_risk(10), to_customer)
    assert action is ActionTaken.QUARANTINE
    assert policy and "never delivered" in policy


def test_hostile_link_floor_does_not_lower_a_stronger_response():
    to_customer = _ev("p.nair", Action.SEND_MESSAGE, message=MessagePayload(audience="customer"))
    assert decide(_link_risk(95), to_customer) == (ActionTaken.BLOCK_AND_ALERT, None)


def test_hostile_link_floor_is_for_customer_traffic_only():
    internal = _ev("p.nair", Action.SEND_MESSAGE, message=MessagePayload(audience="internal"))
    assert decide(_link_risk(40), internal) == (ActionTaken.STEP_UP, None)


def test_step_up_strength_scales_with_privilege_and_score():
    assert step_up_requirement(_risk(32), _ev("r.krishnan")) == "push_notification"
    assert step_up_requirement(_risk(32), _ev("l.mathew")) == "totp_and_manager_approval"
    assert step_up_requirement(_risk(32), _ev("h.qureshi")) == "hardware_security_key"


def test_blocked_login_revokes_but_blocked_query_does_not():
    assert should_revoke_session(ActionTaken.BLOCK, _ev("r.krishnan", Action.LOGIN))
    assert not should_revoke_session(ActionTaken.BLOCK, _ev("r.krishnan", Action.DB_QUERY))
    assert should_revoke_session(ActionTaken.BLOCK_AND_ALERT, _ev("r.krishnan", Action.DB_QUERY))


def test_origin_lock_only_for_critical_front_door_attacks():
    assert should_lock_origin(ActionTaken.BLOCK_AND_ALERT, _ev("r.krishnan", Action.LOGIN_FAILED))
    assert not should_lock_origin(ActionTaken.BLOCK, _ev("r.krishnan", Action.LOGIN_FAILED))
    assert not should_lock_origin(ActionTaken.BLOCK_AND_ALERT, _ev("r.krishnan", Action.DB_QUERY))


def test_transfer_from_role_without_mandate_is_blocked_by_policy():
    transfer = _ev("t.banerjee", Action.FUND_TRANSFER, amount=5_000.0)
    action, policy = decide(_risk(20), transfer)
    assert action is ActionTaken.BLOCK
    assert policy and "no mandate" in policy
    teller = _ev("r.krishnan", Action.FUND_TRANSFER, amount=5_000.0)
    assert decide(_risk(20), teller) == (ActionTaken.ALLOW, None)


def test_band_uses_the_rounded_score_the_analyst_sees():
    """Regression: 59.97 was shown as 60.0 beside a medium-risk response."""
    risk = fuse(_ev("r.krishnan"), [_sig(59.96)], NO_MODEL)
    assert risk.total == 60.0 and risk.band is Band.HIGH
