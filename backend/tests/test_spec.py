"""Coverage for the spec-completion pass: content and session detectors, URL
features, message risk breakdown, login risk + MFA, quarantine actions, the
section 31 routes, the post-quantum store, privileged administrators, the
Super Admin's roles/config, and the simulation buttons."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from lookout.api import app
from lookout.auth import DEMO_ACCOUNTS
from lookout.generator import BY_ACTOR, make_event
from lookout.message_risk import COMPONENTS, components
from lookout.models import Action, Attachment, MessagePayload
from lookout.policy import POLICY, PolicyError
from lookout.rules.content import find_sensitive, phishing_language, repeated_message, risky_attachment
from lookout.rules.sessions import (
    concurrent_sessions,
    failed_authorization,
    query_rate_burst,
    session_context_change,
)
from lookout.runtime import CONFIG
from lookout.urlcheck import inspect_url

from .conftest import AFTER_HISTORY

PASSWORDS = {u: p for u, p, _ in DEMO_ACCOUNTS}


# --------------------------------------------------------------------------- #
# Detectors (no API)
# --------------------------------------------------------------------------- #


def _msg(staff, rng, ts=AFTER_HISTORY, **kw):
    return make_event(staff, Action.SEND_MESSAGE, ts, rng, resource="gateway.outbound",
                      message=MessagePayload(**kw), session_id="s-msg")


def test_find_sensitive_counts_kinds_and_ignores_amounts():
    text = (
        "Card 4111 1111 1111 1111, Aadhaar 2345 6789 0123, PAN ABCDE1234F, "
        "account no 502128842312, IFSC MERI0001234, password: hunter2. Amount Rs 4,80,000."
    )
    found = find_sensitive(text)
    assert found == {
        "card number": 1, "Aadhaar number": 1, "PAN": 1, "IFSC code": 1,
        "account number": 1, "credential": 1,
    }
    # 16 digits that fail the Luhn check are not a card; money is not PII.
    assert find_sensitive("ref 1234 5678 9012 3456, Rs 4,80,000 credited") == {}


def test_phishing_language_fires_on_scam_text_not_on_a_notice(rng, ctx, trained_teller):
    staff = BY_ACTOR["p.nair"]
    scam = _msg(staff, rng, body="Please reply with the OTP you received so we can stop the fraudulent debit.")
    notice = _msg(staff, rng, body="Your Meridian Bank statement is ready in net banking.")
    assert phishing_language(scam, trained_teller, ctx)[0].name == "phishing_language"
    assert phishing_language(notice, trained_teller, ctx) == []


def test_risky_attachment_double_extension_and_personal_mailbox(rng, ctx, trained_teller):
    staff = BY_ACTOR["k.venkatesh"]
    e = _msg(staff, rng, body="see attached", recipient="me.personal@gmail.com",
             attachments=[Attachment(name="invoice.pdf.exe", size_kb=120)])
    sig = risky_attachment(e, trained_teller, ctx)[0]
    assert "double extension" in sig.explanation and sig.detail["personal_mailbox"]
    harmless = _msg(staff, rng, body="minutes", attachments=[Attachment(name="minutes.pdf", size_kb=90)])
    assert risky_attachment(harmless, trained_teller, ctx) == []


def test_repeated_message_needs_suspicious_content(rng, ctx, trained_teller):
    staff = BY_ACTOR["m.d'souza"]
    bad = "Your KYC expired. Verify at meridian-bank.secure-verify.top/kyc now"
    for i in range(2):
        ctx.record(_msg(staff, rng, ts=AFTER_HISTORY + timedelta(minutes=i), body=bad, urls=["meridian-bank.secure-verify.top/kyc"]))
    third = _msg(staff, rng, ts=AFTER_HISTORY + timedelta(minutes=3), body=bad, urls=["meridian-bank.secure-verify.top/kyc"])
    assert repeated_message(third, trained_teller, ctx)[0].detail["sends_60m"] == 3
    # The same harmless notice sent all day is not a campaign.
    ok = "Your Meridian Bank statement is ready in net banking."
    for i in range(5):
        ctx.record(_msg(staff, rng, ts=AFTER_HISTORY + timedelta(minutes=10 + i), body=ok))
    assert repeated_message(_msg(staff, rng, ts=AFTER_HISTORY + timedelta(minutes=20), body=ok), trained_teller, ctx) == []


def test_session_detectors(rng, ctx, trained_teller):
    staff = BY_ACTOR["r.krishnan"]
    t = AFTER_HISTORY
    ctx.record(make_event(staff, Action.LOGIN, t, rng, session_id="a"))
    # Second live session from another device and network.
    second = make_event(staff, Action.LOGIN, t + timedelta(minutes=5), rng, session_id="b",
                        device="LT-UNKNOWN-1", ip="203.0.113.5")
    assert concurrent_sessions(second, trained_teller, ctx)[0].detail["open_sessions"] == 2
    # Session "a" suddenly used from elsewhere: a stolen token.
    hijack = make_event(staff, Action.DB_QUERY, t + timedelta(minutes=6), rng, session_id="a",
                        ip="198.51.100.9", record_count=10)
    assert session_context_change(hijack, trained_teller, ctx)[0].name == "session_context_change"
    # Same session, same network: nothing.
    fine = make_event(staff, Action.DB_QUERY, t + timedelta(minutes=7), rng, session_id="a", record_count=10)
    assert session_context_change(fine, trained_teller, ctx) == []


def test_query_burst_and_failed_authorization(rng, ctx, trained_teller):
    staff = BY_ACTOR["k.venkatesh"]
    t = AFTER_HISTORY
    for i in range(70):
        ctx.record(make_event(staff, Action.DB_QUERY, t + timedelta(seconds=3 * i), rng, record_count=5))
    burst = make_event(staff, Action.DB_QUERY, t + timedelta(minutes=4), rng, record_count=5)
    assert query_rate_burst(burst, trained_teller, ctx)[0].detail["queries_5m"] == 71
    for i in range(2):
        ctx.record(make_event(staff, Action.ACCESS_DENIED, t + timedelta(minutes=i), rng, resource="admin_console"))
    third = make_event(staff, Action.ACCESS_DENIED, t + timedelta(minutes=3), rng, resource="admin_console")
    assert failed_authorization(third, trained_teller, ctx)[0].points >= 14


def test_url_lexical_features():
    at = inspect_url("https://meridianbank.com@login-verify.top/kyc").as_dict()
    assert at["host"] == "login-verify.top" and at["features"]["userinfo_trick"]
    redirect = inspect_url("http://bit.ly/x?url=https%3A%2F%2Fevil.top%2Fotp").as_dict()
    assert redirect["features"]["redirect_param"] and redirect["risk_score"] >= 80
    # No scheme written: the link must not be reported as plain HTTP.
    bare = inspect_url("meridian-bank.secure-verify.top/re-kyc").as_dict()
    assert not any("plain HTTP" in f for f in bare["findings"])
    assert inspect_url("https://secure.meridianbank.com/loans").as_dict()["risk_score"] == 0


def test_message_components_add_up(engine, rng):
    staff = BY_ACTOR["m.d'souza"]
    e = _msg(staff, rng, recipient_count=50_000, audience="customer",
             body="Your KYC expired. Verify at meridian-bank.secure-verify.top/kyc now",
             urls=["meridian-bank.secure-verify.top/kyc"])
    d = engine.ingest(e)
    parts = components(d)
    assert set(parts) == set(COMPONENTS)
    assert abs(sum(parts.values()) - d.risk.total) < 0.05
    assert parts["url"] > 0 and parts["volume"] > 0


def test_policy_defaults_and_comms_validation():
    assert POLICY.current.critical == 80.0
    with pytest.raises(PolicyError):
        POLICY.update({"bulk_comms_roles": ["teller"]})  # bulk must be a subset of customer comms
    POLICY.reset()


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def login(client, user, **ctx):
    return client.post("/api/auth/login", json={"username": user, "password": PASSWORDS[user], **ctx})


def h(client, user, **ctx):
    r = login(client, user, **ctx)
    assert r.status_code == 200, r.text
    body = r.json()
    if body.get("mfa_required"):
        body = client.post("/api/auth/mfa/verify", json={"challenge_id": body["challenge_id"], "otp": body["demo_otp"]}).json()
    return {"Authorization": f"Bearer {body['token']}"}


@pytest.fixture
def soc(client):
    return h(client, "soc.analyst")


@pytest.fixture
def admin(client):
    return h(client, "super.admin")


@pytest.fixture(autouse=True)
def fresh(client, soc):
    client.post("/api/reset", headers=soc)
    for u in PASSWORDS:
        client.post(f"/api/accounts/{u}/enable", headers=soc)
    yield
    POLICY.reset()


def test_login_returns_risk_and_accepts_email(client):
    r = login(client, "v.rao")
    assert r.status_code == 200
    risk = r.json()["risk"]
    assert set(risk) >= {"risk_score", "risk_level", "reason"} and risk["risk_level"] == "LOW"
    by_email = client.post("/api/auth/login", json={"username": "v.rao@meridianbank.example", "password": PASSWORDS["v.rao"]})
    assert by_email.status_code == 200


def test_unusual_sign_in_context_raises_risk(client):
    """The spec's example: 02:30, a new device, a new country, an unknown IP."""
    r = login(client, "d.sharma", device_id="LT-UNKNOWN-9", city="New York", ip="198.51.100.40", at_hour=2).json()
    risk = r["risk"]
    assert risk["risk_level"] in ("HIGH", "CRITICAL"), risk
    assert any("device" in x.lower() or "hour" in x.lower() or "new york" in x.lower() for x in risk["reason"])


def test_medium_risk_sign_in_needs_the_second_factor(client):
    # The spec's step 2: a new device at 02:30 (on a new network) is MEDIUM,
    # so it gets a second factor rather than a block.
    r = login(client, "d.sharma", at_hour=2, device_id="LT-NEW-1", ip="203.0.113.9").json()
    assert r["risk"]["risk_level"] == "MEDIUM" and r["mfa_required"] and "token" not in r
    wrong = client.post("/api/auth/mfa/verify", json={"challenge_id": r["challenge_id"], "otp": "000000" if r["demo_otp"] != "000000" else "111111"})
    assert wrong.status_code == 401
    ok = client.post("/api/auth/mfa/verify", json={"challenge_id": r["challenge_id"], "otp": r["demo_otp"]})
    assert ok.status_code == 200 and ok.json()["token"]


def _held_message(client, soc):
    r = client.post("/api/messages/scan", headers=soc, json={
        "sender": "p.nair", "channel": "email", "recipient_count": 1, "audience": "customer",
        "recipient": "customer.1@example.com",
        "body": "Dear customer, your KYC expired. Verify your password at meridianbank-kyc.top/verify now",
    }).json()
    assert r["held"], r["decision"]["action_taken"]
    return r


def test_scan_reports_components_and_url_risk(client, soc):
    r = _held_message(client, soc)
    comp = r["message_risk"]["components"]
    assert abs(sum(comp.values()) - r["message_risk"]["score"]) < 0.05
    assert r["urls"][0]["risk_score"] >= 60


def test_quarantine_block_delete_investigate(client, soc):
    q1 = _held_message(client, soc)["decision"]["quarantine_id"]
    q2 = _held_message(client, soc)["decision"]["quarantine_id"]
    q3 = _held_message(client, soc)["decision"]["quarantine_id"]
    inv = client.post(f"/api/quarantine/{q3}/investigate", headers=soc).json()
    assert inv["incident_id"].startswith("INC-")
    held = {x["quarantine_id"]: x for x in client.get("/api/quarantine", headers=soc).json()}
    assert held[q3]["review"]["status"] == "INVESTIGATING" and held[q3]["message"]["sender"] == "p.nair"
    assert client.post(f"/api/quarantine/{q1}/block", headers=soc).json()["blocked"] == q1
    assert client.post(f"/api/quarantine/{q2}/delete", headers=soc).json()["deleted"] == q2
    left = {x["quarantine_id"] for x in client.get("/api/quarantine", headers=soc).json()}
    assert q1 not in left and q2 not in left and q3 in left
    kinds = [e["kind"] for e in client.get("/api/audit-logs?action=quarantine.", headers=soc).json()["entries"]]
    assert {"quarantine.block", "quarantine.delete", "quarantine.investigate"} <= set(kinds)


def test_messages_routes_and_risk_calculate(client, soc):
    msg = _held_message(client, soc)
    listed = client.get("/api/messages?status=QUARANTINED", headers=soc).json()
    assert any(m["message_id"] == msg["decision"]["event"]["event_id"] for m in listed)
    one = client.get(f"/api/messages/{msg['decision']['event']['event_id']}", headers=soc).json()
    assert one["status"] == "QUARANTINED" and one["urls"]
    before = client.get("/api/stats", headers=soc).json()["decisions"]
    ev = msg["decision"]["event"]
    ev = {**ev, "event_id": "dry-run-1"}
    calc = client.post("/api/risk/calculate", headers=soc, json={"event": ev}).json()
    assert calc["recorded"] is False and calc["risk_level"] in ("HIGH", "CRITICAL", "MEDIUM")
    assert client.get("/api/stats", headers=soc).json()["decisions"] == before


def test_protected_store_and_quantum_alert(client, soc):
    arts = client.get("/api/crypto/artefacts", headers=soc).json()
    cats = {a["category"] for a in arts["artefacts"]}
    assert {"sensitive_configuration", "credential", "key_material", "security_artefact"} <= cats
    assert "ML-KEM-768" in arts["algorithm"]
    assert client.post("/api/crypto/artefacts/verify", headers=soc).json()["ok"]
    client.post("/api/crypto/artefacts/tamper?name=vault/hsm/operator-pin", headers=soc)
    bad = client.post("/api/crypto/artefacts/verify", headers=soc).json()
    assert not bad["ok"] and bad["alert"]["alert_type"] == "Quantum-Safe Key/Artefact Security Event"
    again = client.post("/api/crypto/artefacts/verify", headers=soc).json()
    assert again["alert"]["id"] == bad["alert"]["id"]  # no second page for the same problem
    layers = client.get("/api/crypto", headers=soc).json()["layers"]
    assert {l["family"] for l in layers} >= {"classical", "post-quantum"}


def test_audit_tamper_raises_quantum_alert(client, soc):
    # Forge a blocked decision into an "allow", as a rogue admin would.
    seq = client.post("/api/scenarios/privilege_escalation/run", headers=soc).json()["peak"]["audit_seq"]
    assert client.post(f"/api/audit/tamper/{seq}", headers=soc).status_code == 200
    v = client.get("/api/audit/verify", headers=soc).json()
    assert not v["ok"] and v["alert"]["alert_type"] == "Quantum-Safe Key/Artefact Security Event"


def test_employee_self_service_and_pam(client):
    teller = h(client, "r.krishnan")
    me = client.get("/api/portal/me", headers=teller).json()
    assert me["role"] == "teller" and not me["privileged_administrator"]
    assert client.get("/api/portal/activity", headers=teller).json()[0]["activity"].startswith("Signed in")
    denied = client.post("/api/portal/resources/admin_console/open", headers=teller)
    assert denied.status_code == 403 and denied.json()["detail"]["decision"] == "DENIED"
    ok = client.post("/api/portal/resources/customer_database/open", headers=teller)
    assert ok.status_code == 403 or ok.json()["decision"] in ("ALLOWED", "RESTRICTED", "MFA_REQUIRED")


def test_privileged_admin_operations_and_escalation(client, soc):
    teller = h(client, "r.krishnan")
    r = client.get("/api/portal/admin/users", headers=teller)
    assert r.status_code == 403 and r.json()["detail"]["logged_as"] == "PRIVILEGE_ESCALATION_ATTEMPT"
    last = client.get("/api/users/r.krishnan/activity?limit=1", headers=soc).json()[0]
    assert last["event"]["action"] == "priv_escalate"

    pillai = h(client, "n.pillai")  # domain admin
    users = client.get("/api/portal/admin/users", headers=pillai).json()
    assert any(u["username"] == "s.iyer" for u in users)
    changed = client.post("/api/portal/admin/users/s.iyer/role", headers=pillai, json={"role": "officer"}).json()
    assert changed["to"] == "officer" and "risk" in changed["monitored"]
    # Cannot grant a role at or above their own level.
    assert client.post("/api/portal/admin/users/s.iyer/role", headers=pillai, json={"role": "domain_admin"}).status_code == 403
    assert client.post("/api/portal/admin/users/s.iyer/disable", headers=pillai, json={"reason": "left the bank"}).status_code == 200
    assert login(client, "s.iyer").status_code == 403


def test_super_admin_roles_and_config(client, admin, soc):
    roles = client.get("/api/admin/roles", headers=admin).json()
    assert {r["role"] for r in roles["roles"]} >= {"teller", "domain_admin"}
    upd = client.put("/api/admin/roles", headers=admin, json={"resource_min_level": {"payroll_system": 4}}).json()
    assert upd["changed"]["payroll_system"] == {"from": 3, "to": 4}
    assert client.get("/api/admin/roles", headers=soc).status_code == 403
    try:
        client.put("/api/admin/config", headers=admin, json={"show_demo_accounts": False})
        assert client.get("/api/auth/demo-accounts").json() == []
    finally:
        client.put("/api/admin/config", headers=admin, json={"show_demo_accounts": True})
    assert CONFIG["show_demo_accounts"] is True


def test_simulation_has_the_spec_buttons(client, soc):
    buttons = {s["button"] for s in client.get("/api/scenarios", headers=soc).json()}
    assert {
        "Simulate Normal Login", "Simulate Abnormal Login", "Simulate Impossible Travel",
        "Simulate Privilege Escalation", "Simulate Credential Misuse", "Simulate Phishing Message",
        "Simulate Bulk Fraud Messages", "Simulate Insider Threat", "Simulate Compromised Account",
    } <= buttons


def test_dashboard_and_user_profile_additions(client, soc):
    client.post("/api/scenarios/phishing_blast/run", headers=soc)
    stats = client.get("/api/dashboard/statistics", headers=soc).json()
    assert stats["message_outcomes"]["blocked"] >= 1
    prof = client.get("/api/users/m.d'souza/risk", headers=soc).json()
    assert prof["message_activity"] and prof["sessions"] and prof["daily_risk"]
    assert prof["sudden_changes"], "a jump to 100 should be highlighted"
    trend = client.get("/api/dashboard/risk-trends", headers=soc).json()["buckets"]
    assert "login_anomalies" in trend[0] and "privilege_escalations" in trend[0]
