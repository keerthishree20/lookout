"""Each detector: one case where it must fire, one where it must stay quiet."""

from datetime import datetime, timedelta

from lookout.baselines import Baseline
from lookout.generator import BY_ACTOR, make_event
from lookout.models import Action, MessagePayload, Role, ThreatClass
from lookout.rules import (
    abnormal_login_time,
    bulk_file_write,
    bulk_message_blast,
    containment_breach,
    credential_misuse,
    dormant_privileged_account,
    failed_login_burst,
    impossible_travel,
    mass_record_access,
    new_device_or_network,
    off_hours_data_access,
    out_of_scope_admin_action,
    privilege_escalation,
    suspicious_url,
    unauthorized_customer_comms,
    vault_hoarding,
)

from .conftest import event_for

T = datetime(2026, 9, 22, 10, 0)


def names(signals):
    return [s.name for s in signals]


# -- identity -------------------------------------------------------------- #


def test_impossible_travel_fires_chennai_to_kyiv_in_28_minutes(trained_teller, ctx, rng):
    trained_teller.observe(event_for("r.krishnan", Action.LOGIN, T, rng))
    kyiv = event_for("r.krishnan", Action.LOGIN, T + timedelta(minutes=28), rng, city="Kyiv")
    [sig] = impossible_travel(kyiv, trained_teller, ctx)
    assert sig.detail["implied_kmh"] > 10_000
    assert "Kyiv" in sig.explanation and "Chennai" in sig.explanation
    assert sig.indicates == [ThreatClass.COMPROMISED]


def test_impossible_travel_allows_a_real_flight(trained_teller, ctx, rng):
    trained_teller.observe(event_for("r.krishnan", Action.LOGIN, T, rng))
    # Chennai -> Mumbai is ~1,030 km; three hours later is an ordinary flight.
    mumbai = event_for("r.krishnan", Action.LOGIN, T + timedelta(hours=3), rng, city="Mumbai")
    assert impossible_travel(mumbai, trained_teller, ctx) == []


def test_impossible_travel_ignores_same_city_refresh(trained_teller, ctx, rng):
    trained_teller.observe(event_for("r.krishnan", Action.LOGIN, T, rng))
    again = event_for("r.krishnan", Action.LOGIN, T + timedelta(seconds=40), rng)
    assert impossible_travel(again, trained_teller, ctx) == []


def test_abnormal_login_time_fires_at_3am_for_a_day_worker(trained_teller, ctx, rng):
    night = event_for("r.krishnan", Action.LOGIN, T.replace(hour=3), rng)
    [sig] = abnormal_login_time(night, trained_teller, ctx)
    assert sig.detail["hour"] == 3


def test_abnormal_login_time_quiet_in_usual_hours(trained_teller, ctx, rng):
    assert abnormal_login_time(event_for("r.krishnan", Action.LOGIN, T.replace(hour=9), rng), trained_teller, ctx) == []


def test_abnormal_login_time_needs_a_trained_baseline(ctx, rng):
    fresh = Baseline("r.krishnan", Role.TELLER)
    assert abnormal_login_time(event_for("r.krishnan", Action.LOGIN, T.replace(hour=3), rng), fresh, ctx) == []


def test_new_device_network_and_country_each_count(trained_teller, ctx, rng):
    e = event_for(
        "r.krishnan", Action.LOGIN, T, rng, city="Lagos", device="UNKNOWN-1", ip="102.1.1.1"
    )
    [sig] = new_device_or_network(e, trained_teller, ctx)
    assert len(sig.detail["first_seen"]) == 3
    assert sig.points == 18.0


def test_known_device_and_network_are_quiet(trained_teller, ctx, rng):
    assert new_device_or_network(event_for("r.krishnan", Action.LOGIN, T, rng), trained_teller, ctx) == []


def test_failed_login_burst_waits_for_the_threshold(trained_teller, ctx, rng):
    """Four mistyped passwords is a bad morning, not an attack."""
    for i in range(3):
        ctx.record(event_for("r.krishnan", Action.LOGIN_FAILED, T + timedelta(seconds=i), rng, success=False))
    fourth = event_for("r.krishnan", Action.LOGIN_FAILED, T + timedelta(seconds=5), rng, success=False)
    assert failed_login_burst(fourth, trained_teller, ctx) == []
    ctx.record(fourth)
    fifth = event_for("r.krishnan", Action.LOGIN_FAILED, T + timedelta(seconds=6), rng, success=False)
    [sig] = failed_login_burst(fifth, trained_teller, ctx)
    assert sig.detail["failed_attempts_15m"] == 5


def test_failed_login_burst_weighs_unfamiliar_origin(trained_teller, ctx, rng):
    for i in range(5):
        ctx.record(event_for("r.krishnan", Action.LOGIN_FAILED, T + timedelta(seconds=i), rng, success=False))
    home = event_for("r.krishnan", Action.LOGIN_FAILED, T + timedelta(seconds=9), rng, success=False)
    away = event_for(
        "r.krishnan", Action.LOGIN_FAILED, T + timedelta(seconds=9), rng,
        success=False, city="Lagos", device="UNKNOWN-2",
    )
    assert failed_login_burst(away, trained_teller, ctx)[0].points > failed_login_burst(home, trained_teller, ctx)[0].points


def test_credential_misuse_is_success_after_failures(trained_teller, ctx, rng):
    for i in range(6):
        ctx.record(event_for("r.krishnan", Action.LOGIN_FAILED, T + timedelta(seconds=i * 20), rng, success=False))
    ok = event_for("r.krishnan", Action.LOGIN, T + timedelta(minutes=3), rng)
    assert names(credential_misuse(ok, trained_teller, ctx)) == ["credential_misuse"]


def test_credential_misuse_ignores_a_single_typo(trained_teller, ctx, rng):
    ctx.record(event_for("r.krishnan", Action.LOGIN_FAILED, T, rng, success=False))
    assert credential_misuse(event_for("r.krishnan", Action.LOGIN, T + timedelta(minutes=1), rng), trained_teller, ctx) == []


def test_containment_revoked_session(trained_teller, ctx, rng):
    ctx.revoke("sess-x")
    e = event_for("r.krishnan", Action.DB_QUERY, T, rng, session_id="sess-x")
    [sig] = containment_breach(e, trained_teller, ctx)
    assert sig.name == "revoked_session_use"
    assert sig.indicates == []  # raises risk, never votes on class


def test_containment_locked_origin(trained_teller, ctx, rng):
    ctx.lock_origin("r.krishnan", "102.1.1.1")
    e = event_for("r.krishnan", Action.LOGIN, T, rng, ip="102.1.1.1")
    assert names(containment_breach(e, trained_teller, ctx)) == ["locked_origin_use"]


def test_containment_persistence_after_block(trained_teller, ctx, rng):
    ctx.strike("sess-y")
    ctx.strike("sess-y")
    e = event_for("r.krishnan", Action.DB_QUERY, T, rng, session_id="sess-y")
    [sig] = containment_breach(e, trained_teller, ctx)
    assert sig.name == "persistence_after_block"
    assert sig.detail["prior_strikes"] == 2


def test_containment_quiet_for_clean_session(trained_teller, ctx, rng):
    assert containment_breach(event_for("r.krishnan", Action.DB_QUERY, T, rng, session_id="s-ok"), trained_teller, ctx) == []


# -- privilege ------------------------------------------------------------- #


def test_privilege_escalation_scales_with_jump(ctx, rng):
    b = Baseline("p.nair", Role.OFFICER)
    small = event_for("p.nair", Action.PRIV_ESCALATE, T, rng, target_role="manager")
    big = event_for("p.nair", Action.PRIV_ESCALATE, T, rng, target_role="domain_admin")
    assert privilege_escalation(big, b, ctx)[0].points > privilege_escalation(small, b, ctx)[0].points
    assert privilege_escalation(big, b, ctx)[0].indicates[0] is ThreatClass.PRIVILEGE_ABUSE


def test_privilege_escalation_ignores_downward_or_same_level(ctx, rng):
    b = Baseline("n.pillai", Role.DOMAIN_ADMIN)
    e = event_for("n.pillai", Action.PRIV_ESCALATE, T, rng, target_role="sysadmin")
    assert privilege_escalation(e, b, ctx) == []


def test_privilege_escalation_counts_the_current_attempt(ctx, rng):
    b = Baseline("p.nair", Role.OFFICER)
    for i in range(2):
        ctx.record(event_for("p.nair", Action.PRIV_ESCALATE, T + timedelta(minutes=i), rng, target_role="domain_admin"))
    third = event_for("p.nair", Action.PRIV_ESCALATE, T + timedelta(minutes=3), rng, target_role="domain_admin")
    [sig] = privilege_escalation(third, b, ctx)
    assert sig.detail["attempts_15m"] == 3
    assert "attempt 3" in sig.explanation


def test_out_of_scope_admin_action(ctx, rng):
    b = Baseline("p.nair", Role.OFFICER)
    e = event_for("p.nair", Action.CONFIG_CHANGE, T, rng, resource="iam.policies")
    assert names(out_of_scope_admin_action(e, b, ctx)) == ["out_of_scope_admin_action"]
    admin = event_for("h.qureshi", Action.CONFIG_CHANGE, T, rng)
    assert out_of_scope_admin_action(admin, Baseline("h.qureshi", Role.SYSADMIN), ctx) == []


def test_dormant_privileged_account(ctx, rng):
    b = Baseline("t.banerjee", Role.DBA)
    b.observe(event_for("t.banerjee", Action.LOGIN, T - timedelta(days=60), rng))
    e = event_for("t.banerjee", Action.VAULT_READ, T, rng)
    [sig] = dormant_privileged_account(e, b, ctx)
    assert sig.detail["idle_days"] >= 59


def test_dormant_does_not_apply_to_low_privilege(ctx, rng):
    b = Baseline("r.krishnan", Role.TELLER)
    b.observe(event_for("r.krishnan", Action.LOGIN, T - timedelta(days=90), rng))
    assert dormant_privileged_account(event_for("r.krishnan", Action.LOGIN, T, rng), b, ctx) == []


# -- data ------------------------------------------------------------------ #


def test_mass_record_access_against_personal_baseline(trained_teller, ctx, rng):
    e = event_for("r.krishnan", Action.DB_QUERY, T, rng, record_count=2_000)
    [sig] = mass_record_access(e, trained_teller, ctx)
    assert sig.detail["z_score"] > 4


def test_mass_record_access_quiet_for_normal_volume(trained_teller, ctx, rng):
    assert mass_record_access(event_for("r.krishnan", Action.DB_QUERY, T, rng, record_count=45), trained_teller, ctx) == []


def test_mass_record_access_absolute_floor_without_history(ctx, rng):
    fresh = Baseline("k.venkatesh", Role.ANALYST)
    e = event_for("k.venkatesh", Action.DB_QUERY, T, rng, record_count=80_000)
    [sig] = mass_record_access(e, fresh, ctx)
    assert "no established query history" in sig.explanation


def test_bigger_reads_score_higher(trained_teller, ctx, rng):
    a = mass_record_access(event_for("r.krishnan", Action.DB_QUERY, T, rng, record_count=12_000), trained_teller, ctx)[0]
    b = mass_record_access(event_for("r.krishnan", Action.DB_QUERY, T, rng, record_count=400_000), trained_teller, ctx)[0]
    assert b.points > a.points


def test_off_hours_data_access(ctx, rng, trained_teller):
    assert names(off_hours_data_access(event_for("r.krishnan", Action.DB_QUERY, T.replace(hour=23), rng), trained_teller, ctx)) == ["off_hours_data_access"]
    assert off_hours_data_access(event_for("r.krishnan", Action.DB_QUERY, T.replace(hour=11), rng), trained_teller, ctx) == []


def test_bulk_file_write(ctx, rng, trained_teller):
    big = event_for("r.krishnan", Action.FILE_ACCESS, T, rng, bytes_written=2_900_000_000)
    [sig] = bulk_file_write(big, trained_teller, ctx)
    assert sig.detail["gigabytes"] == 2.9
    small = event_for("r.krishnan", Action.FILE_ACCESS, T, rng, bytes_written=4_000_000)
    assert bulk_file_write(small, trained_teller, ctx) == []


def test_vault_hoarding_counts_current_read(ctx, rng):
    b = Baseline("h.qureshi", Role.SYSADMIN)
    for i in range(7):
        ctx.record(event_for("h.qureshi", Action.VAULT_READ, T + timedelta(minutes=i), rng))
    eighth = event_for("h.qureshi", Action.VAULT_READ, T + timedelta(minutes=8), rng)
    [sig] = vault_hoarding(eighth, b, ctx)
    assert sig.detail["vault_reads_30m"] == 8


def test_one_vault_read_is_maintenance(ctx, rng):
    assert vault_hoarding(event_for("h.qureshi", Action.VAULT_READ, T, rng), Baseline("h.qureshi", Role.SYSADMIN), ctx) == []


# -- messaging ------------------------------------------------------------- #


def _msg(actor, reach, urls=(), audience="customer"):
    return make_event(
        BY_ACTOR[actor], Action.SEND_MESSAGE, T, __import__("random").Random(1),
        message=MessagePayload(recipient_count=reach, audience=audience, urls=list(urls)),
    )


def _sender_baseline(actor, reach):
    staff = BY_ACTOR[actor]
    b = Baseline(actor, staff.role)
    import random

    r = random.Random(2)
    for i in range(30):
        b.observe(
            make_event(
                staff, Action.SEND_MESSAGE, T - timedelta(days=i), r,
                message=MessagePayload(recipient_count=reach + (i % 3)),
            )
        )
    return b


def test_suspicious_url_fires_on_lookalike(ctx):
    b = _sender_baseline("m.d'souza", 15)
    [sig] = suspicious_url(_msg("m.d'souza", 10, ["https://meridianbamk.com/kyc"]), b, ctx)
    assert sig.detail["worst_url"]["impersonates"] == "meridianbank.com"


def test_suspicious_url_quiet_on_corporate_link(ctx):
    b = _sender_baseline("m.d'souza", 15)
    assert suspicious_url(_msg("m.d'souza", 10, ["https://meridianbank.com/x"]), b, ctx) == []


def test_bulk_blast_from_unauthorised_role(ctx):
    b = _sender_baseline("m.d'souza", 15)
    [sig] = bulk_message_blast(_msg("m.d'souza", 50_000), b, ctx)
    assert not sig.detail["role_authorised_for_bulk"]
    assert sig.detail["z_score"] > 100


def test_bigger_blasts_score_higher(ctx):
    """Regression: a linear z term saturated, scoring 900 and 50,000 equally."""
    b = _sender_baseline("s.iyer", 2)
    small = bulk_message_blast(_msg("s.iyer", 900), b, ctx)[0]
    huge = bulk_message_blast(_msg("s.iyer", 50_000), b, ctx)[0]
    assert huge.points > small.points


def test_bulk_blast_class_depends_on_link(ctx):
    """Same volume: a clean link is negligence, a hostile link is malice."""
    b = _sender_baseline("s.iyer", 2)
    clean = bulk_message_blast(_msg("s.iyer", 900, ["https://meridianbank.com/s"]), b, ctx)[0]
    hostile = bulk_message_blast(_msg("s.iyer", 900, ["http://meridian-bank.verify.top/kyc"]), b, ctx)[0]
    assert clean.indicates[0] is ThreatClass.NEGLIGENT
    assert hostile.indicates[0] is ThreatClass.MALICIOUS


def test_manager_campaign_within_their_normal_is_quiet(ctx):
    b = _sender_baseline("l.mathew", 1500)
    assert bulk_message_blast(_msg("l.mathew", 1600), b, ctx) == []


def test_teller_may_not_message_customers(ctx):
    b = _sender_baseline("r.krishnan", 2)
    assert names(unauthorized_customer_comms(_msg("r.krishnan", 1), b, ctx)) == ["unauthorized_customer_comms"]
    assert unauthorized_customer_comms(_msg("r.krishnan", 1, audience="internal"), b, ctx) == []


def test_officer_may_message_one_customer_but_not_a_campaign(ctx):
    b = _sender_baseline("p.nair", 10)
    assert unauthorized_customer_comms(_msg("p.nair", 3), b, ctx) == []
    assert names(unauthorized_customer_comms(_msg("p.nair", 400), b, ctx)) == ["unauthorized_customer_comms"]
