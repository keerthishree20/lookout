"""End-to-end: scenarios through a warmed-up engine."""

from datetime import timedelta

import pytest

from lookout.models import Action, ActionTaken, Band, ThreatClass
from lookout.scenarios import BY_KEY, SCENARIOS, build

from .conftest import AFTER_HISTORY, event_for


def run(engine, key):
    return engine.ingest_many(build(key, now=AFTER_HISTORY))


def peak(decisions):
    return max(decisions, key=lambda d: d.risk.total)


def test_warm_up_builds_baselines_and_fits_model(engine):
    assert len(engine.store) == 12
    assert engine.model.fitted
    assert engine.history_size > 3000
    assert engine.audit.entries[0].kind == "engine.warm_up"


def test_ordinary_work_is_allowed(engine, rng):
    d = engine.ingest(
        event_for("r.krishnan", Action.DB_QUERY, AFTER_HISTORY, rng, record_count=41)
    )
    assert d.action_taken is ActionTaken.ALLOW
    assert d.threat_class is ThreatClass.BENIGN


@pytest.mark.parametrize(
    "key, expected_class, strongest",
    [
        ("compromised_account", ThreatClass.COMPROMISED, {ActionTaken.BLOCK, ActionTaken.BLOCK_AND_ALERT}),
        ("privilege_escalation", ThreatClass.PRIVILEGE_ABUSE, {ActionTaken.BLOCK_AND_ALERT}),
        ("phishing_blast", ThreatClass.MALICIOUS, {ActionTaken.BLOCK_AND_ALERT}),
        ("data_exfiltration", ThreatClass.MALICIOUS, {ActionTaken.BLOCK, ActionTaken.BLOCK_AND_ALERT}),
        ("credential_stuffing", ThreatClass.COMPROMISED, {ActionTaken.BLOCK_AND_ALERT}),
        ("negligent_insider", ThreatClass.NEGLIGENT, {ActionTaken.STEP_UP, ActionTaken.QUARANTINE}),
        ("transfer_fraud", ThreatClass.MALICIOUS, {ActionTaken.BLOCK_AND_ALERT}),
    ],
)
def test_each_scenario_ends_in_the_right_place(engine, key, expected_class, strongest):
    top = peak(run(engine, key))
    assert top.action_taken in strongest, top.narrative
    assert top.threat_class is expected_class, [s.name for s in top.risk.signals]


def test_negligent_insider_is_never_paged(engine):
    """The test that separates a useful system from an alarm cannon."""
    for d in run(engine, "negligent_insider"):
        assert d.action_taken is not ActionTaken.BLOCK_AND_ALERT


def test_impossible_travel_is_the_named_reason(engine):
    decisions = run(engine, "compromised_account")
    kyiv = next(d for d in decisions if d.event.geo.city == "Kyiv")
    assert "impossible_travel" in [s.name for s in kyiv.risk.signals]
    assert decisions[0].action_taken is ActionTaken.ALLOW  # the real login


def test_blocked_login_leaves_no_usable_session(engine):
    """Regression: a refused login used to leave its session alive, so every
    vault read after it was allowed."""
    decisions = run(engine, "credential_stuffing")
    login = next(d for d in decisions if d.event.action is Action.LOGIN)
    assert login.action_taken in (ActionTaken.BLOCK, ActionTaken.BLOCK_AND_ALERT)
    reads = [d for d in decisions if d.event.action is Action.VAULT_READ]
    assert reads and all(d.action_taken is not ActionTaken.ALLOW for d in reads)
    assert all(d.threat_class is ThreatClass.COMPROMISED for d in reads)


def test_failed_logins_lock_the_origin(engine):
    run(engine, "credential_stuffing")
    assert ("h.qureshi", "102.89.33.7") in engine.ctx.locked_origins


def test_phishing_is_blocked_and_session_revoked(engine):
    decisions = run(engine, "phishing_blast")
    session = decisions[0].event.meta["session_id"]
    assert decisions[0].action_taken is ActionTaken.BLOCK_AND_ALERT
    assert engine.ctx.is_revoked(session)
    assert "revoked_session_use" in [s.name for s in decisions[1].risk.signals]
    # The first message is judged on what it *is*, not on a stale session.
    assert decisions[0].risk.signals[0].name != "revoked_session_use"


def test_rerunning_a_scenario_tells_the_same_story(engine):
    """Regression: fixed session IDs meant a second run hit the session the
    first run revoked, and the explanation led with 'token replayed' instead
    of the phishing link."""
    first = engine.ingest_many(build("phishing_blast", now=AFTER_HISTORY, seed=1))
    second = engine.ingest_many(
        build("phishing_blast", now=AFTER_HISTORY + timedelta(hours=2), seed=2)
    )
    assert first[0].event.meta["session_id"] != second[0].event.meta["session_id"]
    lead = lambda d: [s.name for s in d.risk.signals if s.name != "behavioural_model"][:2]  # noqa: E731
    assert "revoked_session_use" not in lead(second[0])
    assert "suspicious_url" in lead(second[0])


def test_single_lookalike_link_to_one_customer_is_held_by_policy(engine, rng):
    from lookout.models import MessagePayload

    d = engine.ingest(
        event_for(
            "p.nair", Action.SEND_MESSAGE, AFTER_HISTORY, rng,
            message=MessagePayload(
                recipient_count=1, audience="customer",
                urls=["https://meridianbamk.com/login"],
            ),
            session_id="sess-one",
        )
    )
    assert d.action_taken is ActionTaken.QUARANTINE
    assert d.policy is not None
    assert "Held by policy" in d.narrative
    assert "to 1 recipient " in d.narrative or "to 1 recipient." in d.narrative


def test_attacks_do_not_poison_the_baseline(engine):
    from lookout.models import Role

    baseline = engine.store.get("k.venkatesh", Role.ANALYST)
    before = baseline.records_per_query.mean
    run(engine, "data_exfiltration")
    # The 412,000-row read was blocked, so it must not become part of "normal".
    assert baseline.records_per_query.mean == pytest.approx(before)
    assert baseline.records_per_query.mean < 10_000


def test_every_decision_is_audited_and_chain_verifies(engine):
    n_before = len(engine.audit.entries)
    decisions = run(engine, "privilege_escalation")
    assert len(engine.audit.entries) == n_before + len(decisions)
    assert all(d.audit_seq is not None for d in decisions)
    assert engine.audit.verify().ok


def test_critical_decisions_are_checkpointed_immediately(engine):
    before = len(engine.audit.checkpoints)
    run(engine, "phishing_blast")
    assert len(engine.audit.checkpoints) > before
    assert engine.audit.checkpoints[-1].algorithm == "ML-DSA-65"


def test_quarantine_and_release_are_audited(engine, rng):
    from lookout.models import MessagePayload

    # A clean-link bulk send from an officer: over their bulk mandate, but no
    # hostile link -- the canonical "hold it and ask a human" case.
    d = engine.ingest(
        event_for(
            "p.nair", Action.SEND_MESSAGE, AFTER_HISTORY, rng,
            message=MessagePayload(
                recipient_count=4_000, audience="customer",
                urls=["https://meridianbank.com/offers"],
            ),
            session_id="sess-q",
        )
    )
    assert d.action_taken is ActionTaken.QUARANTINE, (d.risk.total, d.narrative)
    assert d.quarantine_id in engine.quarantine
    engine.release(d.quarantine_id, reviewer="soc.lead")
    assert d.quarantine_id not in engine.quarantine
    assert engine.audit.entries[-1].kind == "quarantine.release"
    assert engine.audit.entries[-1].payload["reviewer"] == "soc.lead"


def test_early_attack_attempts_are_stepped_up_with_a_named_factor(engine):
    """The first failed sign-ins from Lagos are not yet a burst, but come from
    an unknown device, network and country: medium risk, so risk-based auth
    demands a stronger factor instead of blocking or waving them through."""
    decisions = run(engine, "credential_stuffing")
    first = decisions[0]
    assert first.risk.band is Band.MEDIUM
    assert first.action_taken is ActionTaken.STEP_UP
    # h.qureshi is a sysadmin (level 5), so nothing short of a hardware key.
    assert first.event.meta["step_up_required"] == "hardware_security_key"
    assert "hardware security key" in first.narrative


def test_every_flagged_decision_explains_itself(engine):
    for s in SCENARIOS:
        for d in engine.ingest_many(build(s.key, now=AFTER_HISTORY + timedelta(days=SCENARIOS.index(s)))):
            if d.action_taken is not ActionTaken.ALLOW:
                assert d.risk.signals, s.key
                assert all(sig.explanation.endswith((".", ")")) for sig in d.risk.signals)
                assert d.event.actor in d.narrative


def test_credential_sealing_roundtrip_and_audit(engine):
    sealed = engine.seal_credential("vault/swift-gateway", "sk_live_abc123")
    assert sealed["algorithm"].startswith("ML-KEM-768")
    blob = {k: sealed[k] for k in ("kem_ciphertext", "nonce", "ciphertext", "algorithm")}
    assert engine.unseal_credential("vault/swift-gateway", blob) == "sk_live_abc123"
    entry = engine.audit.entries[sealed["audit_seq"]]
    assert entry.kind == "credential.sealed"
    assert "sk_live" not in str(entry.payload)


def test_scenario_catalogue_is_complete():
    assert set(BY_KEY) == {
        "compromised_account", "privilege_escalation", "phishing_blast",
        "data_exfiltration", "credential_stuffing", "negligent_insider",
        "transfer_fraud",
    }
