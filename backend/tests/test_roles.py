"""Manager, Super Admin, alerts, incidents, sessions, policy, access checks."""

import pytest
from fastapi.testclient import TestClient

from lookout.api import app
from lookout.auth import DEMO_ACCOUNTS
from lookout.policy import POLICY

PASSWORDS = {u: p for u, p, _ in DEMO_ACCOUNTS}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def h(client, user):
    r = client.post("/api/auth/login", json={"username": user, "password": PASSWORDS[user]})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


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


# -- route access ------------------------------------------------------------- #


def test_role_map(client, soc, admin):
    emp, mgr = h(client, "r.krishnan"), h(client, "l.mathew")
    assert client.get("/api/admin/policies", headers=admin).status_code == 200
    assert client.get("/api/admin/policies", headers=soc).status_code == 403
    assert client.get("/api/admin/policies", headers=emp).status_code == 403
    assert client.get("/api/incidents", headers=admin).status_code == 200  # super admin sees the console
    assert client.get("/api/team/overview", headers=mgr).status_code == 200
    assert client.get("/api/team/overview", headers=emp).status_code == 403  # not a manager
    assert client.get("/api/team/overview", headers=soc).status_code == 403
    assert client.get("/api/incidents").status_code == 401


# -- manager ------------------------------------------------------------------ #


def test_manager_sees_only_their_branch_team(client):
    body = client.get("/api/team/overview", headers=h(client, "l.mathew")).json()
    users = {m["user"] for m in body["members"]}
    assert users == {"r.krishnan", "s.iyer", "k.venkatesh"}
    assert "n.pillai" not in users  # the domain admin is not their report


def test_team_view_never_reveals_the_honeypot(client, soc):
    client.post("/api/scenarios/data_exfiltration/run", headers=soc)  # k.venkatesh -> honeypot
    body = client.get("/api/team/overview", headers=h(client, "l.mathew")).json()
    assert "honeypot" not in str(body).lower()
    assert next(m for m in body["members"] if m["user"] == "k.venkatesh")["peak_risk"] > 60


def test_access_request_flow(client):
    emp = h(client, "r.krishnan")
    req = client.post(
        "/api/portal/access-requests",
        json={"resource": "core.transactions:read", "reason": "month-end reconciliation"},
        headers=emp,
    ).json()
    assert req["status"] == "PENDING" and req["approver"] == "l.mathew"
    assert client.post(f"/api/team/access-requests/{req['id']}/decide", json={"approve": True}, headers=h(client, "v.rao")).status_code == 403
    done = client.post(
        f"/api/team/access-requests/{req['id']}/decide", json={"approve": True, "note": "ok"}, headers=h(client, "l.mathew")
    ).json()
    assert done["status"] == "APPROVED" and done["decided_by"] == "l.mathew"
    mine = client.get("/api/portal/access-requests", headers=emp).json()["requests"]
    assert mine[0]["status"] == "APPROVED"
    again = client.post(f"/api/team/access-requests/{req['id']}/decide", json={"approve": False}, headers=h(client, "l.mathew"))
    assert again.status_code == 409


def test_staff_without_a_branch_manager_go_to_super_admin(client, admin):
    req = client.post(
        "/api/portal/access-requests",
        json={"resource": "admin.console", "reason": "patch window tonight"},
        headers=h(client, "h.qureshi"),
    ).json()
    assert req["approver"] == "super.admin"
    decided = client.post(f"/api/admin/access-requests/{req['id']}/decide", json={"approve": False}, headers=admin).json()
    assert decided["status"] == "DENIED"


def test_unknown_resource_request_rejected(client):
    r = client.post("/api/portal/access-requests", json={"resource": "x", "reason": "because"}, headers=h(client, "s.iyer"))
    assert r.status_code == 400


# -- super admin policy ---------------------------------------------------------- #


def test_policy_change_applies_to_the_next_decision(client, soc, admin):
    before = client.get("/api/admin/policies", headers=admin).json()
    assert before["high"] == 60
    r = client.put("/api/admin/policies", json={"honeypot_export_threshold": 20}, headers=admin).json()
    assert r["changed"] == {"honeypot_export_threshold": {"from": 100, "to": 20}}
    client.post("/api/portal/export", json={"count": 25}, headers=h(client, "s.iyer"))
    assert len(client.get("/api/honeypots", headers=soc).json()["served"]) == 1
    kinds = [e["kind"] for e in client.get("/api/audit?limit=10", headers=soc).json()["entries"]]
    assert "policy.changed" in kinds


def test_incoherent_policy_rejected(client, admin):
    assert client.put("/api/admin/policies", json={"medium": 70, "high": 60}, headers=admin).status_code == 400
    assert client.put("/api/admin/policies", json={"transfer_limits": {"wizard": 5}}, headers=admin).status_code == 400
    assert client.put("/api/admin/policies", json={"honeypot_export_threshold": 0}, headers=admin).status_code == 400


def test_transfer_limit_change_is_used_by_the_detector(client, admin):
    client.put("/api/admin/policies", json={"transfer_limits": {"teller": 5000, "officer": 1000000, "manager": 5000000}}, headers=admin)
    from lookout.models import TRANSFER_LIMITS, Role

    assert TRANSFER_LIMITS[Role.TELLER] == 5000


def test_reset_restores_default_policy(client, soc, admin):
    client.put("/api/admin/policies", json={"high": 55}, headers=admin)
    client.post("/api/reset", headers=soc)
    assert client.get("/api/admin/policies", headers=admin).json()["high"] == 60


# -- accounts and sessions --------------------------------------------------------- #


def test_disable_account_signs_out_and_refuses_login(client, soc):
    emp = h(client, "p.nair")
    r = client.post("/api/accounts/p.nair/disable", json={"reason": "under investigation"}, headers=soc).json()
    assert r["sessions_signed_out"] >= 1
    assert client.get("/api/auth/me", headers=emp).status_code == 401
    login = client.post("/api/auth/login", json={"username": "p.nair", "password": PASSWORDS["p.nair"]})
    assert login.status_code == 403 and "disabled" in login.json()["detail"]
    client.post("/api/accounts/p.nair/enable", headers=soc)
    assert client.post("/api/auth/login", json={"username": "p.nair", "password": PASSWORDS["p.nair"]}).status_code == 200


def test_cannot_disable_yourself(client, soc):
    assert client.post("/api/accounts/soc.analyst/disable", json={"reason": "oops"}, headers=soc).status_code == 400


def test_session_list_and_revoke(client, soc):
    emp = h(client, "d.sharma")
    # Other test modules may have left older d.sharma sessions open; the one
    # just created expires last.
    mine = [x for x in client.get("/api/sessions", headers=soc).json() if x["username"] == "d.sharma"]
    sess = max(mine, key=lambda x: x["expires"])
    assert client.post(f"/api/sessions/{sess['session_id']}/revoke", headers=soc).json()["user"] == "d.sharma"
    assert client.get("/api/auth/me", headers=emp).status_code == 401
    assert client.post(f"/api/sessions/{sess['session_id']}/revoke", headers=soc).status_code == 404


def test_accounts_listing(client, soc):
    accts = client.get("/api/accounts", headers=soc).json()
    assert len(accts) == 14
    admin_row = next(a for a in accts if a["username"] == "n.pillai")
    assert admin_row["privilege_level"] == 6


# -- alerts and incidents -------------------------------------------------------------- #


def test_high_risk_decisions_raise_alerts_grouped_into_one_incident(client, soc):
    client.post("/api/scenarios/credential_stuffing/run", headers=soc)
    alerts = client.get("/api/alerts", headers=soc).json()
    assert alerts and all(a["user"] == "h.qureshi" for a in alerts)
    assert {a["severity"] for a in alerts} <= {"HIGH", "CRITICAL"}
    assert all(a["recommended_action"] and a["reasons"] for a in alerts)
    incidents = client.get("/api/incidents", headers=soc).json()
    assert len(incidents) == 1  # many alerts, one person, one incident
    assert incidents[0]["alert_count"] == len(alerts)
    assert incidents[0]["severity"] == "CRITICAL"


def test_alert_types_follow_the_specification(client, soc):
    client.post("/api/scenarios/compromised_account/run", headers=soc)
    client.post("/api/scenarios/phishing_blast/run", headers=soc)
    client.post("/api/scenarios/privilege_escalation/run", headers=soc)
    types = {a["alert_type"] for a in client.get("/api/alerts", headers=soc).json()}
    assert {"Impossible Travel", "Phishing URL", "Privilege Escalation"} <= types


def test_incident_workflow(client, soc):
    client.post("/api/scenarios/transfer_fraud/run", headers=soc)
    inc_id = client.get("/api/incidents", headers=soc).json()[0]["id"]
    inc = client.post(f"/api/incidents/{inc_id}/assign", json={"analyst": "soc.analyst"}, headers=soc).json()
    assert inc["status"] == "INVESTIGATING" and inc["assigned_to"] == "soc.analyst"
    client.post(f"/api/incidents/{inc_id}/notes", json={"text": "Called the branch."}, headers=soc)
    act = client.post(f"/api/incidents/{inc_id}/actions", json={"action": "disable_account"}, headers=soc).json()
    assert any(a["action"] == "disable_account" for a in act["actions_taken"])
    assert client.post("/api/auth/login", json={"username": "a.fernandes", "password": PASSWORDS["a.fernandes"]}).status_code == 403
    done = client.post(f"/api/incidents/{inc_id}/status", json={"status": "resolved"}, headers=soc).json()
    assert done["status"] == "RESOLVED" and done["resolved_at"]
    full = client.get(f"/api/incidents/{inc_id}", headers=soc).json()
    kinds = [t["kind"] for t in full["timeline"]]
    assert kinds[0] == "opened" and "note" in kinds and "action" in kinds and "status" in kinds
    assert full["ai_explanation"] and full["evidence"]
    assert all(a["status"] == "RESOLVED" for a in full["alerts"])
    assert full["honeypot"] is not None  # the transfer put her in the honeypot


def test_new_incident_after_resolution(client, soc):
    client.post("/api/scenarios/phishing_blast/run", headers=soc)
    first = client.get("/api/incidents", headers=soc).json()[0]["id"]
    client.post(f"/api/incidents/{first}/status", json={"status": "FALSE_POSITIVE"}, headers=soc)
    client.post("/api/scenarios/phishing_blast/run", headers=soc)
    assert len(client.get("/api/incidents", headers=soc).json()) == 2


def test_manual_incident_and_bad_status(client, soc):
    inc = client.post("/api/incidents", json={"title": "Tip-off from branch", "user": "s.iyer", "severity": "medium"}, headers=soc).json()
    assert inc["severity"] == "MEDIUM"
    assert client.post(f"/api/incidents/{inc['id']}/status", json={"status": "maybe"}, headers=soc).status_code == 400
    assert client.get("/api/incidents/INC-9999", headers=soc).status_code == 404


def test_alert_status_update(client, soc):
    client.post("/api/scenarios/phishing_blast/run", headers=soc)
    aid = client.get("/api/alerts", headers=soc).json()[0]["id"]
    assert client.post(f"/api/alerts/{aid}/status", json={"status": "investigating"}, headers=soc).json()["status"] == "INVESTIGATING"
    assert client.get("/api/alerts?status=INVESTIGATING", headers=soc).json()[0]["id"] == aid


# -- risk-based access control ------------------------------------------------------------ #


def test_access_check_combines_role_and_risk(client, soc):
    check = lambda u, r: client.post("/api/access/check", json={"user": u, "resource": r}, headers=soc).json()  # noqa: E731
    assert check("r.krishnan", "customer_database")["decision"] == "DENIED"  # teller, below minimum
    assert check("p.nair", "customer_database")["decision"] == "ALLOWED"
    admin_console = check("h.qureshi", "admin_console")
    assert admin_console["decision"] == "MFA_REQUIRED" and admin_console["monitoring"] == "enhanced"
    client.post("/api/scenarios/data_exfiltration/run", headers=soc)  # k.venkatesh now high risk
    assert check("k.venkatesh", "customer_database")["decision"] in ("RESTRICTED", "BLOCK_AND_REVOKE")


def test_access_check_honours_approved_requests(client, soc):
    emp = h(client, "r.krishnan")
    req = client.post("/api/portal/access-requests", json={"resource": "core.customers:export", "reason": "audit sample"}, headers=emp).json()
    client.post(f"/api/team/access-requests/{req['id']}/decide", json={"approve": True}, headers=h(client, "l.mathew"))
    r = client.post("/api/access/check", json={"user": "r.krishnan", "resource": "customer_database"}, headers=soc).json()
    assert r["decision"] == "ALLOWED"


# -- dashboard and user risk -------------------------------------------------------------- #


def test_dashboard_statistics_and_trends(client, soc):
    client.post("/api/scenarios/phishing_blast/run", headers=soc)
    stats = client.get("/api/dashboard/statistics", headers=soc).json()
    for key in ("total_users", "active_sessions", "high_risk_users", "critical_alerts", "blocked_messages",
                "quarantined_messages", "privileged_accounts"):
        assert key in stats
    assert stats["blocked_messages"] >= 1 and stats["privileged_accounts"] == 3
    trends = client.get("/api/dashboard/risk-trends?buckets=6", headers=soc).json()["buckets"]
    assert len(trends) == 6 and sum(b["count"] for b in trends) >= 2


def test_user_risk_profile(client, soc):
    client.post("/api/scenarios/compromised_account/run", headers=soc)
    r = client.get("/api/users/r.krishnan/risk", headers=soc).json()
    assert r["peak_risk"] >= 60 and r["classification"] == "compromised"
    assert "Kyiv" in r["locations"] and r["alerts"]
    assert client.get("/api/users/r.krishnan/activity?limit=3", headers=soc).json()


# -- websocket ------------------------------------------------------------------------------ #


def test_websocket_pushes_decisions_and_alerts(client, soc):
    token = soc["Authorization"].split()[1]
    with client.websocket_connect(f"/api/ws?token={token}") as ws:
        client.post("/api/scenarios/phishing_blast/run", headers=soc)
        kinds = {ws.receive_json()["type"] for _ in range(4)}
    assert {"decision", "alert"} <= kinds


def test_websocket_refuses_without_console_token(client):
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/ws?token=nope") as ws:
            ws.receive_json()


# -- JWT, rate limiting, headers ------------------------------------------------------------ #


def test_tokens_are_signed_jwts_and_tampering_fails(client):
    import jwt as pyjwt

    token = client.post("/api/auth/login", json={"username": "s.iyer", "password": PASSWORDS["s.iyer"]}).json()["token"]
    claims = pyjwt.decode(token, options={"verify_signature": False})
    assert claims["sub"] == "s.iyer" and claims["kind"] == "employee" and "exp" in claims and claims["sid"]
    forged = pyjwt.encode({**claims, "kind": "soc"}, "not-the-secret", algorithm="HS256")
    assert client.get("/api/stats", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_valid_jwt_stops_working_once_the_session_is_revoked(client, soc):
    token = client.post("/api/auth/login", json={"username": "v.rao", "password": PASSWORDS["v.rao"]}).json()["token"]
    hdr = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/auth/me", headers=hdr).status_code == 200
    sid = __import__("jwt").decode(token, options={"verify_signature": False})["sid"]
    client.post(f"/api/sessions/{sid}/revoke", headers=soc)
    assert client.get("/api/auth/me", headers=hdr).status_code == 401


def test_login_rate_limit_after_ten_failures(client, soc):
    codes = [client.post("/api/auth/login", json={"username": "m.d'souza", "password": "x"}).status_code for _ in range(11)]
    assert codes[:10] == [401] * 10 and codes[10] == 429
    right = client.post("/api/auth/login", json={"username": "m.d'souza", "password": PASSWORDS["m.d'souza"]})
    assert right.status_code == 429 and "Retry-After" in right.headers
    client.post("/api/reset", headers=soc)  # clears the limiter for the other tests
    assert client.post("/api/auth/login", json={"username": "m.d'souza", "password": PASSWORDS["m.d'souza"]}).status_code == 200


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]


def test_api_docs_are_served(client):
    assert client.get("/swagger").status_code == 200
    assert client.get("/redoc").status_code == 200
    assert "Content-Security-Policy" not in client.get("/swagger").headers
    assert client.get("/openapi.json").json()["info"]["title"] == "Lookout"


def test_browser_may_send_put_for_policy_updates(client):
    """Regression: CORS allowed only GET and POST, so the Super Admin's
    policy save (a PUT) was blocked by the browser before reaching the API."""
    r = client.options(
        "/api/admin/policies",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "PUT",
                 "Access-Control-Request-Headers": "authorization,content-type"},
    )
    assert r.status_code == 200
    assert "PUT" in r.headers["access-control-allow-methods"]
