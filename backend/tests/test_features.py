"""Incident PDF reports and outbound alert notifications."""

from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from lookout.api import app
from lookout.auth import DEMO_ACCOUNTS
from lookout.notify import Notifier, NotifySettings

PASSWORDS = {u: p for u, p, _ in DEMO_ACCOUNTS}


# --------------------------------------------------------------------------- #
# Notifier (no API)
# --------------------------------------------------------------------------- #


class FakeAlert:
    def __init__(self, severity="CRITICAL", user="t.banerjee", alert_type="Privilege Escalation"):
        self.id, self.severity, self.user, self.alert_type = "AL-00001", severity, user, alert_type
        self.risk_score, self.event, self.incident_id = 100.0, "priv_escalate", "INC-0001"
        self.reasons = ["requested domain_admin", "no change ticket"]
        self.recommended_action = "Revoke the rights and interview the employee."


class Recorder:
    """Stands in for httpx: records calls, answers with a status."""

    def __init__(self, status=200):
        self.status, self.calls = status, []

    def __call__(self, url, payload, headers):
        self.calls.append({"url": url, "payload": payload, "headers": headers})
        if isinstance(self.status, Exception):
            raise self.status
        return self.status


def _notifier(post, **kw) -> Notifier:
    settings = NotifySettings(webhook_url="https://hooks.example.com/services/T/B/xyz", **kw)
    return Notifier(settings=settings, transport=post)


def test_critical_alert_is_sent_high_is_not():
    post = Recorder()
    n = _notifier(post)
    n.on_alert(FakeAlert(severity="HIGH"))
    n.on_alert(FakeAlert())
    n._queue.join()
    assert len(post.calls) == 1
    text = post.calls[0]["payload"]["text"]
    assert "Privilege Escalation" in text and "t.banerjee" in text and "AL-00001" in text
    assert n.status()["recent"][0]["ok"] is True


def test_same_alert_twice_is_held_back_and_the_hourly_cap_applies():
    post = Recorder()
    n = _notifier(post, cooldown_seconds=300)
    n.on_alert(FakeAlert())
    n.on_alert(FakeAlert())  # same person and type, inside the cooldown
    n._queue.join()
    assert len(post.calls) == 1 and n.skipped == 1

    capped = _notifier(Recorder(), cooldown_seconds=0, max_per_hour=2)
    for i in range(5):
        capped.on_alert(FakeAlert(user=f"user{i}"))
    capped._queue.join()
    assert capped.status()["sent_last_hour"] == 2 and capped.skipped == 3


def test_a_failing_channel_is_recorded_not_raised():
    n = _notifier(Recorder(status=RuntimeError("connection refused")))
    n.on_alert(FakeAlert())
    n._queue.join()
    last = n.status()["recent"][0]
    assert last["ok"] is False and "connection refused" in last["detail"]


def test_telegram_gets_its_own_payload_and_secrets_are_redacted():
    post = Recorder()
    n = Notifier(
        settings=NotifySettings(
            webhook_url="https://api.telegram.org/bot12345:SECRET-TOKEN/sendMessage",
            telegram_chat_id="99",
        ),
        transport=post,
    )
    n.on_alert(FakeAlert())
    n._queue.join()
    assert post.calls[0]["payload"]["chat_id"] == "99"
    shown = n.status()["settings"]["webhook_url"]
    assert "SECRET-TOKEN" not in shown and shown.startswith("https://api.telegram.org")


def test_email_needs_a_key_a_sender_and_a_recipient():
    assert NotifySettings(email_to="soc@example.com").channels() == []
    full = NotifySettings(email_to="soc@example.com", email_from="lookout@example.com", brevo_api_key="k")
    assert full.channels() == ["email"]
    post = Recorder()
    n = Notifier(settings=full, transport=post)
    n.on_alert(FakeAlert())
    n._queue.join()
    body = post.calls[0]
    assert body["headers"]["api-key"] == "k"
    assert body["payload"]["to"] == [{"email": "soc@example.com"}]
    assert "CRITICAL" in body["payload"]["subject"]


def test_nothing_configured_means_nothing_sent():
    post = Recorder()
    n = Notifier(settings=NotifySettings(), transport=post)
    n.on_alert(FakeAlert())
    n._queue.join()
    assert post.calls == [] and n.status()["active"] is False


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def h(client, user):
    r = client.post("/api/auth/login", json={"username": user, "password": PASSWORDS[user]})
    body = r.json()
    if body.get("mfa_required"):
        body = client.post(
            "/api/auth/mfa/verify",
            json={"challenge_id": body["challenge_id"], "otp": body["demo_otp"]},
        ).json()
    return {"Authorization": f"Bearer {body['token']}"}


@pytest.fixture
def soc(client):
    return h(client, "soc.analyst")


@pytest.fixture
def admin(client):
    return h(client, "super.admin")


def test_incident_report_pdf(client, soc):
    client.post("/api/reset", headers=soc)
    client.post("/api/scenarios/privilege_escalation/run", headers=soc)
    incidents = client.get("/api/incidents", headers=soc).json()
    assert incidents, "the scenario should have opened an incident"
    inc = incidents[0]

    r = client.get(f"/api/incidents/{inc['id']}/report", headers=soc)
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert inc["id"] in r.headers["content-disposition"]
    assert r.content.startswith(b"%PDF")

    text = "\n".join(page.extract_text() for page in PdfReader(io.BytesIO(r.content)).pages)
    for expected in (inc["id"], inc["user"], "Summary", "Evidence", "Timeline", "How to verify"):
        assert expected in text, expected
    # The evidence section quotes real signals, not a template.
    assert "risk" in text.lower() and "simulated" in text.lower()
    # Exporting is itself audited, and noted on the incident.
    kinds = [e["kind"] for e in client.get("/api/audit-logs?action=incident.", headers=soc).json()["entries"]]
    assert "incident.report_exported" in kinds
    assert any(t["kind"] == "report" for t in client.get(f"/api/incidents/{inc['id']}", headers=soc).json()["timeline"])


def test_report_is_console_only(client, soc):
    inc = client.get("/api/incidents", headers=soc).json()[0]
    employee = h(client, "r.krishnan")
    assert client.get(f"/api/incidents/{inc['id']}/report", headers=employee).status_code == 403
    assert client.get(f"/api/incidents/{inc['id']}/report").status_code == 401
    assert client.get("/api/incidents/INC-9999/report", headers=soc).status_code == 404


def test_notification_settings_are_super_admin_only(client, soc, admin):
    assert client.get("/api/admin/notifications", headers=soc).status_code == 403

    before = client.get("/api/admin/notifications", headers=admin).json()
    assert before["active"] is False  # nothing configured in tests

    updated = client.put(
        "/api/admin/notifications",
        headers=admin,
        json={"webhook_url": "https://hooks.example.com/services/T/B/secret-part", "min_severity": "HIGH"},
    ).json()
    assert updated["active"] is True
    assert "secret-part" not in updated["settings"]["webhook_url"]
    assert updated["settings"]["min_severity"] == "HIGH"
    assert client.get("/api/admin/notifications", headers=admin).json()["settings"]["channels"] == ["webhook"]

    # Changing where alerts go is a critical audit entry.
    kinds = [e["kind"] for e in client.get("/api/audit-logs?action=notifications.", headers=soc).json()["entries"]]
    assert "notifications.changed" in kinds

    client.put("/api/admin/notifications", headers=admin, json={"webhook_url": "", "min_severity": "CRITICAL"})
    assert client.get("/api/admin/notifications", headers=admin).json()["active"] is False


def test_test_send_reports_each_channel(client, admin):
    client.put("/api/admin/notifications", headers=admin, json={"webhook_url": "", "email_to": ""})
    assert client.post("/api/admin/notifications/test", headers=admin).status_code == 400
    client.put(
        "/api/admin/notifications",
        headers=admin,
        json={"webhook_url": "http://127.0.0.1:9/never-listening"},
    )
    results = client.post("/api/admin/notifications/test", headers=admin).json()["results"]
    assert results and results[0]["ok"] is False  # reported, not raised
    client.put("/api/admin/notifications", headers=admin, json={"webhook_url": ""})
