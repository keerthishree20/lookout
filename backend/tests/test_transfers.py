"""Fund transfers: the detector, the shadow ledger, and the honeypot page."""

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

import lookout.api as api_mod
from lookout.api import app
from lookout.auth import DEMO_ACCOUNTS
from lookout.banking import Bank
from lookout.baselines import Baseline
from lookout.context import DetectionContext
from lookout.customers import customer_book
from lookout.generator import BY_ACTOR, make_event
from lookout.models import Action, Role, ThreatClass
from lookout.rules import suspicious_transfer

PASSWORDS = {u: p for u, p, _ in DEMO_ACCOUNTS}
T = datetime(2026, 9, 22, 11, 0)


# -- detector ---------------------------------------------------------------- #


def _teller_with_history(n=30, amount=20_000):
    import random

    staff = BY_ACTOR["r.krishnan"]
    b = Baseline(staff.actor, staff.role)
    r = random.Random(3)
    for i in range(n):
        b.observe(
            make_event(
                staff, Action.FUND_TRANSFER, T - timedelta(days=i), r,
                amount=float(amount + (i % 5) * 1000), to_account="502100000001", external=False,
            )
        )
    return b


def _transfer(actor, amount, to="776655443322", external=True, ts=T):
    import random

    return make_event(
        BY_ACTOR[actor], Action.FUND_TRANSFER, ts, random.Random(1),
        amount=float(amount), from_account="502100009999", to_account=to, external=external,
    )


def test_ordinary_transfer_is_quiet():
    b = _teller_with_history()
    assert suspicious_transfer(_transfer("r.krishnan", 21_000, "502100000001", False), b, DetectionContext()) == []


def test_over_role_limit():
    [sig] = suspicious_transfer(_transfer("r.krishnan", 450_000), _teller_with_history(), DetectionContext())
    assert "limit for a teller" in sig.explanation
    assert sig.indicates[0] is ThreatClass.MALICIOUS
    assert ThreatClass.PRIVILEGE_ABUSE in sig.indicates


def test_role_with_no_transfer_mandate():
    b = Baseline("t.banerjee", Role.DBA)
    [sig] = suspicious_transfer(_transfer("t.banerjee", 5_000), b, DetectionContext())
    assert "no mandate to move customer funds" in sig.explanation
    assert sig.points >= 35


def test_bigger_and_stranger_scores_higher():
    b, ctx = _teller_with_history(), DetectionContext()
    known = suspicious_transfer(_transfer("r.krishnan", 150_000, "502100000001", False), b, ctx)[0]
    new_ext = suspicious_transfer(_transfer("r.krishnan", 150_000), b, ctx)[0]
    at_night = suspicious_transfer(_transfer("r.krishnan", 150_000, ts=T.replace(hour=23)), b, ctx)[0]
    assert known.points < new_ext.points < at_night.points


def test_velocity_to_new_outside_accounts():
    b, ctx = _teller_with_history(), DetectionContext()
    for i in range(2):
        ctx.record(_transfer("r.krishnan", 30_000, to=f"7700000000{i:02d}", ts=T + timedelta(minutes=i)))
    [sig] = suspicious_transfer(_transfer("r.krishnan", 30_000, to="770000000099", ts=T + timedelta(minutes=3)), b, ctx)
    assert "3 transfers to new outside accounts" in sig.explanation


# -- shadow ledger ----------------------------------------------------------- #


def test_shadow_transfer_never_touches_real_balances():
    book = customer_book()
    bank = Bank(book)
    src, dst = book[0].account_no, book[1].account_no
    real_src, real_dst = bank.balances[src], bank.balances[dst]
    txn = bank.transfer(
        actor="x", from_account=src, to_account=dst, to_name="", to_ifsc="MERB0000001",
        amount=10_000, remarks="", shadow=True,
    )
    assert bank.balances[src] == real_src and bank.balances[dst] == real_dst
    assert bank.balance(src, "x") == real_src - 10_000
    assert bank.balance(dst, "x") == real_dst + 10_000
    assert bank.balance(src, "someone-else") == real_src
    assert txn.balance_after == real_src - 10_000
    assert bank.transactions == []  # nothing in the genuine ledger


def test_shadow_history_merges_with_real_history():
    book = customer_book()
    bank = Bank(book)
    a = dict(actor="x", to_account=book[2].account_no, to_name="", to_ifsc="MERB0000001", remarks="")
    bank.transfer(from_account=book[0].account_no, amount=100, shadow=False, **a)
    bank.transfer(from_account=book[0].account_no, amount=200, shadow=True, **a)
    assert [t.amount for t in bank.history("x")] == [200, 100]
    assert [t.amount for t in bank.history("y")] == []
    discarded = bank.leave_shadow("x")
    assert [t.amount for t in discarded] == [200]
    assert [t.amount for t in bank.history("x")] == [100]


def test_real_and_shadow_references_share_a_format():
    import re

    book = customer_book()
    bank = Bank(book)
    a = dict(actor="x", from_account=book[0].account_no, to_account="918877665544",
             to_name="A", to_ifsc="HDFC0001234", amount=10, remarks="")
    real = bank.transfer(shadow=False, **a)
    fake = bank.transfer(shadow=True, **a)
    for t in (real, fake):
        assert re.fullmatch(r"MBTXN\d{10}", t.reference)
        assert re.fullmatch(r"MERB\d{13}", t.utr)


# -- API: the honeypot transfer page ----------------------------------------- #


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def h(client, user):
    token = client.post("/api/auth/login", json={"username": user, "password": PASSWORDS[user]}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def soc(client):
    return h(client, "soc.analyst")


@pytest.fixture(autouse=True)
def fresh(client, soc):
    client.post("/api/reset", headers=soc)


@pytest.fixture
def rich():
    bank = api_mod.get_state().bank
    return max(bank.balances, key=bank.balances.get)


def send(client, headers, src, amount, to="918877665544", ifsc="HDFC0001234"):
    return client.post(
        "/api/portal/transfers",
        json={"from_account": src, "to_account": to, "to_name": "Test Payee", "to_ifsc": ifsc, "amount": amount},
        headers=headers,
    )


def test_small_transfer_is_real(client, soc, rich):
    bank = api_mod.get_state().bank
    before = bank.balances[rich]
    dst = customer_book()[9].account_no
    r = send(client, h(client, "a.fernandes"), rich, 12_000, to=dst, ifsc="MERB0000001").json()
    assert r["status"] == "SUCCESS"
    assert bank.balances[rich] == before - 12_000
    assert client.get("/api/honeypots", headers=soc).json()["transfer_decoys"] == []


def test_medium_risk_asks_for_a_code_then_completes(client, rich):
    emp = h(client, "a.fernandes")
    bank = api_mod.get_state().bank
    before = bank.balances[rich]
    r = send(client, emp, rich, 150_000).json()
    assert r["status"] == "VERIFICATION_REQUIRED"
    wrong = client.post("/api/portal/transfers/verify", json={"challenge_id": r["challenge_id"], "code": "000000"}, headers=emp)
    assert wrong.status_code == 400
    ok = client.post("/api/portal/transfers/verify", json={"challenge_id": r["challenge_id"], "code": r["demo_code"]}, headers=emp).json()
    assert ok["status"] == "SUCCESS"
    assert bank.balances[rich] == before - 150_000


def test_three_wrong_codes_cancel_the_transfer(client, rich):
    emp = h(client, "a.fernandes")
    r = send(client, emp, rich, 150_000).json()
    codes = [client.post("/api/portal/transfers/verify", json={"challenge_id": r["challenge_id"], "code": "x"}, headers=emp).status_code for _ in range(3)]
    assert codes == [400, 400, 403]


def test_high_risk_transfer_gets_the_honeypot(client, soc, rich):
    """The employee sees success, a receipt and a debited balance. No money moves."""
    emp = h(client, "a.fernandes")
    bank = api_mod.get_state().bank
    real_before = bank.balances[rich]

    r = send(client, emp, rich, 480_000, to="776655443322", ifsc="ICIC0004321").json()
    assert r["status"] == "SUCCESS"
    receipt = r["receipt"]
    assert receipt["amount"] == 480_000
    assert receipt["balance_after"] == pytest.approx(real_before - 480_000)

    # Real money: untouched. Employee's view: debited, consistently.
    assert bank.balances[rich] == real_before
    view = client.get(f"/api/portal/accounts/{rich}", headers=emp).json()
    assert view["balance"] == pytest.approx(real_before - 480_000)
    history = client.get("/api/portal/transfers", headers=emp).json()
    assert history[0]["reference"] == receipt["reference"]
    # Everyone else sees the truth.
    other = client.get(f"/api/portal/accounts/{rich}", headers=h(client, "s.iyer")).json()
    assert other["balance"] == real_before

    hp = client.get("/api/honeypots", headers=soc).json()
    [decoy] = hp["transfer_decoys"]
    assert decoy["actor"] == "a.fernandes" and decoy["real_funds_moved"] is False
    assert decoy["shown_balance_after"] == pytest.approx(real_before - 480_000)
    assert hp["watchlist"] == ["a.fernandes"]


def test_genuine_and_decoy_receipts_have_identical_shape(client, rich):
    emp = h(client, "l.mathew")
    dst = customer_book()[9].account_no
    real = send(client, emp, rich, 5_000, to=dst, ifsc="MERB0000001").json()
    fake = send(client, h(client, "t.banerjee"), rich, 5_000, to=dst, ifsc="MERB0000001").json()
    # t.banerjee is a DBA: no transfer mandate, so blocked by policy, so the honeypot.
    assert api_mod.get_state().ledger.caught("t.banerjee")
    assert real["status"] == fake["status"] == "SUCCESS"
    assert set(real["receipt"]) == set(fake["receipt"])


def test_once_caught_every_transfer_is_fake(client, rich):
    emp = h(client, "a.fernandes")
    bank = api_mod.get_state().bank
    send(client, emp, rich, 480_000, to="776655443322", ifsc="ICIC0004321")
    real = bank.balances[rich]
    dst = customer_book()[9].account_no
    r = send(client, h(client, "a.fernandes"), rich, 2_000, to=dst, ifsc="MERB0000001").json()
    if r["status"] == "VERIFICATION_REQUIRED":
        r = client.post("/api/portal/transfers/verify", json={"challenge_id": r["challenge_id"], "code": r["demo_code"]}, headers=emp).json()
    assert r["status"] == "SUCCESS"
    assert bank.balances[rich] == real  # still nothing real moved


def test_caught_by_pdf_export_means_transfers_are_fake_too(client, rich):
    emp = h(client, "p.nair")
    client.post("/api/portal/export", json={"count": 120}, headers=emp)
    bank = api_mod.get_state().bank
    before = bank.balances[rich]
    dst = customer_book()[9].account_no
    r = send(client, emp, rich, 3_000, to=dst, ifsc="MERB0000001").json()
    if r["status"] == "VERIFICATION_REQUIRED":
        r = client.post("/api/portal/transfers/verify", json={"challenge_id": r["challenge_id"], "code": r["demo_code"]}, headers=emp).json()
    assert r["status"] == "SUCCESS"
    assert bank.balances[rich] == before


def test_high_risk_anywhere_activates_the_honeypot(client, soc):
    """A scenario run from the console -- not the portal -- still puts the
    employee in the honeypot for their next portal visit."""
    client.post("/api/scenarios/data_exfiltration/run", headers=soc)
    hp = client.get("/api/honeypots", headers=soc).json()
    assert "k.venkatesh" in hp["watchlist"]
    kinds = [e["kind"] for e in client.get("/api/audit?limit=20", headers=soc).json()["entries"]]
    assert "honeypot.activated" in kinds


def test_everything_a_caught_employee_does_is_recorded(client, soc, rich):
    emp = h(client, "a.fernandes")
    send(client, emp, rich, 480_000, to="776655443322", ifsc="ICIC0004321")
    client.get(f"/api/portal/accounts/{rich}", headers=emp)
    client.get("/api/portal/transfers", headers=emp)
    client.get("/api/portal/customers", headers=emp)
    [watch] = client.get("/api/honeypots", headers=soc).json()["watch"]
    whats = [a["what"] for a in watch["activity"]]
    assert "made a transfer (fake -- no money moved)" in whats
    assert {"looked up account", "viewed transfer history", "viewed customer directory"} <= set(whats)


def test_decoy_transfer_is_audited_as_no_money_moved(client, soc, rich):
    send(client, h(client, "a.fernandes"), rich, 480_000, to="776655443322", ifsc="ICIC0004321")
    entries = client.get("/api/audit?limit=15", headers=soc).json()["entries"]
    decoy = next(e for e in entries if e["kind"] == "transfer.decoy_executed")
    assert decoy["payload"]["real_funds_moved"] is False
    assert client.get("/api/audit/verify", headers=soc).json()["ok"]


def test_trace_by_transaction_reference_and_utr(client, soc, rich):
    r = send(client, h(client, "a.fernandes"), rich, 480_000, to="776655443322", ifsc="ICIC0004321").json()
    for needle in (r["receipt"]["reference"], r["receipt"]["utr"]):
        t = client.get(f"/api/honeypots/trace?q={needle}", headers=soc).json()
        assert t["found"] and t["kind"] == "transfer" and t["record"]["actor"] == "a.fernandes"


def test_clearing_restores_the_real_view(client, soc, rich):
    emp = h(client, "a.fernandes")
    real = api_mod.get_state().bank.balances[rich]
    send(client, emp, rich, 480_000, to="776655443322", ifsc="ICIC0004321")
    client.post("/api/honeypots/watchlist/a.fernandes/clear", json={"reviewer": "soc.analyst"}, headers=soc)
    assert client.get(f"/api/portal/accounts/{rich}", headers=emp).json()["balance"] == real


def test_caught_employee_can_still_sign_in_and_lands_in_the_honeypot(client, soc):
    """Refusing the sign-in would tell an intruder they were seen. Instead
    they get in, and everything they do from then on is fake and recorded."""
    client.post("/api/scenarios/compromised_account/run", headers=soc)
    assert "r.krishnan" in client.get("/api/honeypots", headers=soc).json()["watchlist"]
    r = client.post("/api/auth/login", json={"username": "r.krishnan", "password": PASSWORDS["r.krishnan"]})
    assert r.status_code == 200
    watch = next(w for w in client.get("/api/honeypots", headers=soc).json()["watch"] if w["actor"] == "r.krishnan")
    assert watch["activity"][0]["what"] == "signed in"


def test_forgotten_password_then_success_is_not_the_honeypot(client, soc):
    """Six wrong passwords from your own desk, then the right one, is a bad
    morning -- a step-up, not a trap."""
    for _ in range(6):
        client.post("/api/auth/login", json={"username": "s.iyer", "password": "wrong"})
    assert client.post("/api/auth/login", json={"username": "s.iyer", "password": PASSWORDS["s.iyer"]}).status_code == 200
    assert "s.iyer" not in client.get("/api/honeypots", headers=soc).json()["watchlist"]


@pytest.mark.parametrize(
    "body, detail",
    [
        ({"to_account": "12"}, "9-18 digits"),
        ({"to_ifsc": "BAD"}, "IFSC"),
        ({"amount": 10**12}, None),
        ({"from_account": "000000000000"}, "not found"),
    ],
)
def test_transfer_validation(client, rich, body, detail):
    payload = {"from_account": rich, "to_account": "918877665544", "to_name": "A", "to_ifsc": "HDFC0001234", "amount": 10}
    payload.update(body)
    r = client.post("/api/portal/transfers", json=payload, headers=h(client, "a.fernandes"))
    assert r.status_code in (400, 422)
    if detail:
        assert detail in r.json()["detail"]


def test_insufficient_balance(client):
    bank = api_mod.get_state().bank
    poorest = min(bank.balances, key=bank.balances.get)
    r = send(client, h(client, "a.fernandes"), poorest, bank.balances[poorest] + 1)
    assert r.status_code == 400 and "insufficient" in r.json()["detail"]


def test_accounts_can_be_given_by_customer_id(client):
    book = customer_book()
    rich = max(book, key=lambda c: c.balance_inr)
    emp = h(client, "l.mathew")
    view = client.get(f"/api/portal/accounts/{rich.customer_id}", headers=emp).json()
    assert view["customer_id"] == rich.customer_id and view["name"] == rich.name
    assert "account_no" not in view  # the page never needs the full number
    r = client.post(
        "/api/portal/transfers",
        json={"from_account": rich.customer_id, "to_account": book[9].customer_id,
              "to_name": "", "to_ifsc": "MERB0000001", "amount": 1_000},
        headers=emp,
    ).json()
    assert r["status"] == "SUCCESS"
    assert r["receipt"]["to_name"] == book[9].name


def test_stats_count_transfer_decoys(client, soc, rich):
    send(client, h(client, "a.fernandes"), rich, 480_000, to="776655443322", ifsc="ICIC0004321")
    s = client.get("/api/stats", headers=soc).json()
    assert s["transfer_decoys"] == 1 and s["honeypots_served"] == 1 and s["in_honeypot"] == 1
