import pytest
from fastapi.testclient import TestClient

from lookout.api import app


@pytest.fixture(scope="module")
def client():
    """Signed in as the SOC analyst: every console route requires it."""
    with TestClient(app) as c:
        token = c.post(
            "/api/auth/login", json={"username": "soc.analyst", "password": "SocWatch@2026"}
        ).json()["token"]
        c.headers.update({"Authorization": f"Bearer {token}"})
        yield c


@pytest.fixture(autouse=True)
def fresh(client):
    client.post("/api/reset")


def test_health(client):
    body = client.get("/api/health").json()
    assert body["ok"] and body["model_fitted"]
    assert body["narrator"] == "template"
    assert body["signing"] == "ML-DSA-65"


def test_stats_after_warm_up(client):
    s = client.get("/api/stats").json()
    assert s["identities"] == 12
    assert s["decisions"] == 0
    assert s["audit_entries"] == 1


def test_crypto_is_fully_quantum_safe(client):
    c = client.get("/api/crypto").json()
    assert c["fully_quantum_safe"]
    assert c["signing"]["standard"] == "NIST FIPS 204"
    assert c["sealing"]["standard"] == "NIST FIPS 203"


def test_scenarios_listed(client):
    keys = {s["key"] for s in client.get("/api/scenarios").json()}
    assert "phishing_blast" in keys and len(keys) == 7


def test_run_scenario(client):
    r = client.post("/api/scenarios/phishing_blast/run").json()
    assert r["peak"]["action_taken"] == "block_and_alert"
    assert r["peak"]["threat_class"] == "malicious"
    assert r["peak"]["narrative"]
    flagged = client.get("/api/decisions?flagged_only=true").json()
    assert len(flagged) == 2


def test_unknown_scenario_404(client):
    assert client.post("/api/scenarios/nope/run").status_code == 404


def test_gateway_blocks_phishing_and_extracts_the_link_from_the_body(client):
    r = client.post(
        "/api/messages/scan",
        json={
            "sender": "m.d'souza",
            "recipient_count": 20000,
            "body": "Your account is locked. Verify now: http://meridian-bank.secure-verify.top/kyc",
        },
    ).json()
    assert not r["delivered"]
    assert r["decision"]["action_taken"] in ("quarantine", "block_and_alert")
    assert r["urls"][0]["suspicious"]
    assert r["urls"][0]["impersonates"]


def test_gateway_delivers_ordinary_message(client):
    r = client.post(
        "/api/messages/scan",
        json={
            "sender": "p.nair",
            "recipient_count": 1,
            "body": "Hi, your loan documents are ready: https://secure.meridianbank.com/loans",
        },
    ).json()
    assert r["delivered"], r["decision"]["narrative"]
    assert r["decision"]["action_taken"] == "allow"


def test_gateway_holds_single_lookalike_link(client):
    """The brief's core requirement: staff cannot send fraud links, even one."""
    r = client.post(
        "/api/messages/scan",
        json={
            "sender": "p.nair",
            "recipient_count": 1,
            "body": "Please log in to confirm your loan: https://meridianbamk.com/login",
        },
    ).json()
    assert not r["delivered"]
    assert r["held"]
    assert r["decision"]["policy"]


def test_gateway_unknown_sender(client):
    assert client.post("/api/messages/scan", json={"sender": "x", "body": "hi"}).status_code == 404


def test_url_inspect(client):
    r = client.post("/api/urls/inspect", json={"url": "https://bit.ly/abc"}).json()
    assert r["suspicious"]
    assert client.post("/api/urls/inspect", json={"url": ""}).status_code == 400


def test_quarantine_list_and_release(client):
    client.post(
        "/api/messages/scan",
        json={
            "sender": "p.nair",
            "recipient_count": 4000,
            "body": "Festive offers: https://meridianbank.com/offers",
        },
    )
    q = client.get("/api/quarantine").json()
    assert len(q) == 1
    qid = q[0]["quarantine_id"]
    assert client.post(f"/api/quarantine/{qid}/release", json={"reviewer": "soc"}).status_code == 200
    assert client.get("/api/quarantine").json() == []
    assert client.post(f"/api/quarantine/{qid}/release", json={"reviewer": "soc"}).status_code == 404


def test_users(client):
    users = client.get("/api/users").json()
    assert len(users) == 12
    detail = client.get("/api/users/h.qureshi").json()
    assert detail["baseline"]["role"] == "sysadmin"
    assert client.get("/api/users/nobody").status_code == 404


def test_audit_tamper_is_detected_and_reset_restores(client):
    client.post("/api/scenarios/privilege_escalation/run")
    assert client.get("/api/audit/verify").json()["ok"]
    r = client.post("/api/audit/tamper/2").json()
    assert not r["verify"]["ok"]
    assert r["verify"]["broken_at"] == 2
    client.post("/api/reset")
    assert client.get("/api/audit/verify").json()["ok"]


def test_audit_listing(client):
    client.post("/api/scenarios/compromised_account/run")
    a = client.get("/api/audit?limit=5").json()
    assert a["total"] >= 4
    assert len(a["entries"]) <= 5
    assert a["checkpoints"]


def test_seal_credential(client):
    r = client.post(
        "/api/credentials/seal", json={"name": "vault/db-primary", "secret": "p@ss"}
    ).json()
    assert r["roundtrip_ok"]
    assert r["algorithm"].startswith("ML-KEM-768")
    assert "p@ss" not in r["ciphertext"]


def test_ground_truth_label_never_leaves_the_server(client):
    r = client.post("/api/scenarios/phishing_blast/run").json()
    assert all("label" not in d["event"] for d in r["decisions"])
    assert "label" not in client.get("/api/decisions").json()[0]["event"]


def test_narrative_reads_naturally(client):
    r = client.post("/api/scenarios/phishing_blast/run").json()
    assert "sending an SMS to 50,000 recipients" in r["peak"]["narrative"]


def test_decision_lookup(client):
    r = client.post("/api/scenarios/negligent_insider/run").json()
    eid = r["decisions"][0]["event"]["event_id"]
    assert client.get(f"/api/decisions/{eid}").json()["threat_class"] == "negligent"
    assert client.get("/api/decisions/missing").status_code == 404


def test_traffic_toggle(client):
    assert client.post("/api/traffic/pause").json()["traffic_paused"]
    assert not client.post("/api/traffic/resume").json()["traffic_paused"]
    assert client.post("/api/traffic/sideways").status_code == 400


def test_ingest_arbitrary_event(client):
    event = {
        "event_id": "manual-1",
        "ts": "2026-09-21T11:00:00",
        "actor": "r.krishnan",
        "actor_role": "teller",
        "action": "config_change",
        "resource": "iam.policies",
        "geo": {"city": "Chennai", "country": "IN", "lat": 13.08, "lon": 80.27},
    }
    r = client.post("/api/events", json={"event": event}).json()
    assert "out_of_scope_admin_action" in [s["name"] for s in r["risk"]["signals"]]
