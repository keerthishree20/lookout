"""Employee portal, SOC access control, and the honeypot export."""

import io
import re

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from lookout.api import app
from lookout.auth import DEMO_ACCOUNTS
from lookout.customers import customer_book, decoy_of, masked

PASSWORDS = {u: p for u, p, _ in DEMO_ACCOUNTS}


@pytest.fixture(scope="module")
def raw():
    with TestClient(app) as c:
        yield c


def login(client, username, password=None):
    r = client.post(
        "/api/auth/login",
        json={"username": username, "password": password or PASSWORDS[username]},
    )
    return r


def bearer(client, username):
    return {"Authorization": f"Bearer {login(client, username).json()['token']}"}


@pytest.fixture
def soc(raw):
    return bearer(raw, "soc.analyst")


@pytest.fixture(autouse=True)
def fresh(raw, soc):
    raw.post("/api/reset", headers=soc)


def pdf_rows(content: bytes) -> list[str]:
    reader = PdfReader(io.BytesIO(content))
    lines = []
    for page in reader.pages:
        lines += [l for l in page.extract_text().splitlines() if re.match(r"^C\d{6} ", l)]
    return lines


def footer_ref(content: bytes) -> str:
    text = PdfReader(io.BytesIO(content)).pages[-1].extract_text()
    return re.search(r"MB-DOC-[0-9A-F]{8}", text).group(0)


# -- accounts ---------------------------------------------------------------- #


def test_every_demo_account_can_sign_in(raw):
    for username, _, kind in DEMO_ACCOUNTS:
        r = login(raw, username)
        assert r.status_code == 200, username
        assert r.json()["kind"] == kind


def test_twelve_employees_and_one_soc_analyst():
    kinds = [k for _, _, k in DEMO_ACCOUNTS]
    assert kinds.count("employee") == 12 and kinds.count("soc") == 1


def test_wrong_password_rejected_and_scored(raw, soc):
    assert login(raw, "p.nair", "nope").status_code == 401
    feed = raw.get("/api/decisions?limit=5", headers=soc).json()
    assert feed[0]["event"]["action"] == "login_failed"
    assert feed[0]["event"]["actor"] == "p.nair"


def test_unknown_user_rejected(raw):
    assert login(raw, "nobody", "x").status_code == 401


def test_password_guessing_trips_the_burst_detector(raw, soc):
    for _ in range(6):
        login(raw, "a.fernandes", "guess")
    feed = raw.get("/api/decisions?limit=1", headers=soc).json()
    assert "failed_login_burst" in [s["name"] for s in feed[0]["risk"]["signals"]]


def test_demo_accounts_listed_for_sign_in_page(raw):
    accounts = raw.get("/api/auth/demo-accounts").json()
    assert len(accounts) == 13
    assert {"username", "password", "kind", "role"} <= set(accounts[0])


def test_me(raw):
    h = bearer(raw, "k.venkatesh")
    me = raw.get("/api/auth/me", headers=h).json()
    assert me["kind"] == "employee"
    assert me["profile"]["role"] == "analyst"


def test_logout_invalidates_token(raw):
    h = bearer(raw, "v.rao")
    raw.post("/api/auth/logout", headers=h)
    assert raw.get("/api/auth/me", headers=h).status_code == 401


# -- access control ---------------------------------------------------------- #


def test_console_requires_sign_in(raw):
    assert raw.get("/api/stats").status_code == 401
    assert raw.post("/api/audit/tamper/1").status_code == 401


def test_employee_cannot_reach_console(raw):
    h = bearer(raw, "n.pillai")  # even the domain admin
    assert raw.get("/api/stats", headers=h).status_code == 403
    assert raw.get("/api/honeypots", headers=h).status_code == 403
    assert raw.post("/api/audit/tamper/1", headers=h).status_code == 403


def test_soc_cannot_use_employee_portal(raw, soc):
    assert raw.get("/api/portal/customers", headers=soc).status_code == 403


def test_stream_accepts_token_in_query(raw):
    token = login(raw, "soc.analyst").json()["token"]
    assert raw.get("/api/stats?token=" + token).status_code == 200


def test_health_is_public(raw):
    assert raw.get("/api/health").status_code == 200


# -- customer view ----------------------------------------------------------- #


def test_customers_are_masked_on_screen(raw):
    h = bearer(raw, "r.krishnan")
    body = raw.get("/api/portal/customers?limit=5", headers=h).json()
    assert body["total"] == 500
    row = body["rows"][0]
    assert row["account_no"].startswith("••••")
    assert "•" in row["phone"] and "•" in row["email"]
    assert "balance_inr" not in row


def test_customer_search(raw):
    h = bearer(raw, "r.krishnan")
    body = raw.get("/api/portal/customers?q=chennai", headers=h).json()
    assert 0 < body["total"] < 500
    assert all(r["city"] == "Chennai" for r in body["rows"])


# -- exports ----------------------------------------------------------------- #


def export(raw, h, **body):
    return raw.post("/api/portal/export", json=body, headers=h)


def test_small_export_is_genuine(raw, soc):
    h = bearer(raw, "r.krishnan")
    r = export(raw, h, count=10)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    rows = pdf_rows(r.content)
    book = customer_book()
    assert len(rows) == 10
    assert book[0].account_no in rows[0]  # the real, unmasked account number

    hp = raw.get("/api/honeypots", headers=soc).json()
    assert hp["served"] == []
    assert hp["exports"][0]["decoy"] is False


def test_hundred_record_export_gets_the_decoy(raw, soc):
    h = bearer(raw, "r.krishnan")
    r = export(raw, h, count=100)
    assert r.status_code == 200
    rows = pdf_rows(r.content)
    book = customer_book()[:100]
    assert len(rows) == 100
    real_accounts = {c.account_no for c in customer_book()}
    for line, real in zip(rows, book):
        # Same person the employee saw on screen...
        assert line.startswith(f"{real.customer_id} {real.name} ")
        # ...but not their real account number, and not anyone else's either.
        acct = line.split()[3] if len(real.name.split()) == 2 else None
        assert real.account_no not in line
        if acct:
            assert acct not in real_accounts
            assert acct.endswith(real.account_no[-4:])  # matches the masked •••• 1234

    hp = raw.get("/api/honeypots", headers=soc).json()
    [served] = hp["served"]
    assert served["actor"] == "r.krishnan"
    assert served["requested"] == 100
    assert served["canary_count"] == 100
    assert "threshold" in served["reason"]
    assert served["doc_ref"] == footer_ref(r.content)


def test_decoy_and_genuine_responses_look_the_same(raw):
    h = bearer(raw, "d.sharma")
    real = export(raw, h, count=5)
    h2 = bearer(raw, "d.sharma")
    decoy = export(raw, h2, count=150)
    assert real.status_code == decoy.status_code == 200
    assert set(real.headers) == set(decoy.headers)
    pattern = r'attachment; filename="customers_d\.sharma_\d{8}_\d{6}\.pdf"'
    assert re.fullmatch(pattern, real.headers["content-disposition"])
    assert re.fullmatch(pattern, decoy.headers["content-disposition"])
    r_meta = PdfReader(io.BytesIO(real.content)).metadata
    d_meta = PdfReader(io.BytesIO(decoy.content)).metadata
    assert set(r_meta) == set(d_meta)
    assert r_meta["/Creator"] == d_meta["/Creator"]
    # Both carry a document reference, so its presence is not a tell.
    assert footer_ref(real.content) and footer_ref(decoy.content)


def test_once_caught_every_export_is_a_decoy_even_after_signing_in_again(raw, soc):
    """Regression: a 3-row export after a decoy used to be genuine, handing the
    insider the comparison that exposes the trap."""
    real_first = customer_book()[0].account_no
    h = bearer(raw, "s.iyer")
    export(raw, h, count=120)
    assert real_first not in pdf_rows(export(raw, h, count=3).content)[0]

    raw.post("/api/auth/logout", headers=h)
    fresh_session = bearer(raw, "s.iyer")
    assert real_first not in pdf_rows(export(raw, fresh_session, count=3).content)[0]

    hp = raw.get("/api/honeypots", headers=soc).json()
    assert len(hp["served"]) == 3
    assert hp["watchlist"] == ["s.iyer"]
    # Other employees are unaffected.
    assert real_first in pdf_rows(export(raw, bearer(raw, "p.nair"), count=3).content)[0]


def test_soc_can_clear_the_watchlist(raw, soc):
    h = bearer(raw, "v.rao")
    export(raw, h, count=100)
    r = raw.post("/api/honeypots/watchlist/v.rao/clear", json={"reviewer": "soc.analyst"}, headers=soc)
    assert r.status_code == 200
    assert customer_book()[0].account_no in pdf_rows(export(raw, h, count=2).content)[0]
    kinds = [e["kind"] for e in raw.get("/api/audit?limit=10", headers=soc).json()["entries"]]
    assert "honeypot.watchlist_cleared" in kinds
    assert raw.post("/api/honeypots/watchlist/v.rao/clear", json={"reviewer": "x"}, headers=soc).status_code == 404


def test_selected_customers_export(raw):
    h = bearer(raw, "p.nair")
    ids = ["C100005", "C100007"]
    rows = pdf_rows(export(raw, h, customer_ids=ids).content)
    assert [r.split()[0] for r in rows] == ids


def test_trace_by_doc_ref_and_by_leaked_account(raw, soc):
    h = bearer(raw, "m.d'souza")
    r = export(raw, h, count=100)
    ref = footer_ref(r.content)
    by_ref = raw.get(f"/api/honeypots/trace?q={ref}", headers=soc).json()
    assert by_ref["found"] and by_ref["export"]["actor"] == "m.d'souza"
    assert by_ref["matched_by"] == "doc_ref"

    leaked = raw.get("/api/honeypots", headers=soc).json()["served"][0]["canaries"][42]
    spaced = f"{leaked[:4]} {leaked[4:8]} {leaked[8:]}"  # as it might appear in a dump
    by_acct = raw.get(f"/api/honeypots/trace?q={spaced}", headers=soc).json()
    assert by_acct["found"] and by_acct["matched_by"] == "canary_account"
    assert by_acct["export"]["actor"] == "m.d'souza"


def test_trace_miss(raw, soc):
    assert raw.get("/api/honeypots/trace?q=MB-DOC-00000000", headers=soc).json()["found"] is False


def test_decoy_is_audited_and_checkpointed(raw, soc):
    h = bearer(raw, "t.banerjee")
    export(raw, h, count=200)
    audit = raw.get("/api/audit?limit=5", headers=soc).json()
    kinds = [e["kind"] for e in audit["entries"]]
    assert "export.decoy_served" in kinds
    entry = next(e for e in audit["entries"] if e["kind"] == "export.decoy_served")
    # The audit log records that canaries were planted, not what they are.
    assert entry["payload"]["canary_accounts"] == 200
    assert "canaries" not in entry["payload"]
    assert audit["checkpoints"][0]["seq"] >= entry["seq"]
    assert raw.get("/api/audit/verify", headers=soc).json()["ok"]


def test_export_is_scored_by_the_engine(raw, soc):
    h = bearer(raw, "r.krishnan")
    export(raw, h, count=300)
    d = raw.get("/api/decisions?limit=1", headers=soc).json()[0]
    assert d["event"]["meta"]["export"] == "pdf"
    assert "mass_record_access" in [s["name"] for s in d["risk"]["signals"]]


def test_stats_count_honeypots(raw, soc):
    export(raw, bearer(raw, "a.fernandes"), count=100)
    s = raw.get("/api/stats", headers=soc).json()
    assert s["honeypots_served"] == 1 and s["exports"] == 1


# -- decoy generation -------------------------------------------------------- #


def test_decoy_matches_what_the_screen_shows():
    book = customer_book()
    rows = book[:50]
    for real, fake in zip(rows, decoy_of(rows, seed=3, real=book)):
        assert masked(real) == masked(fake)  # identical on screen
        assert fake.account_no != real.account_no
        assert fake.phone != real.phone
        assert len(fake.account_no) == len(real.account_no)
        assert len(fake.phone) == len(real.phone)


def test_decoy_accounts_never_collide_with_real_ones():
    book = customer_book()
    real = {c.account_no for c in book}
    fakes = decoy_of(book, seed=9, real=book)
    assert not real & {c.account_no for c in fakes}
    assert len({c.account_no for c in fakes}) == len(fakes)
