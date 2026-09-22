# Lookout

[![ci](https://github.com/keerthishree20/lookout/actions/workflows/ci.yml/badge.svg)](https://github.com/keerthishree20/lookout/actions/workflows/ci.yml)

**Privileged-access misuse and insider-threat detection for banking.** Lookout watches every
login, query, admin action, fund transfer and outbound staff message. It scores each one against
that person's own behavioural baseline, explains the score in plain sentences, and responds in
proportion: allow, step-up auth, quarantine, block, or block and page the SOC. Anyone caught doing
something high-risk is silently moved into a **honeypot**, where their exports are decoy PDFs and
their transfers move no real money. Every decision goes into an audit log signed with
**ML-DSA-65 (NIST FIPS 204)**, and credentials are sealed with **ML-KEM-768 (FIPS 203)**.

```
event ─► baseline ─► 17 detectors + IsolationForest ─► fused, explained score ─► graded response
      ─► session containment ─► RandomForest second opinion + SHAP ─► alerts, incidents, honeypot
      ─► hash-chained audit, ML-DSA signed ─► PostgreSQL + live console over WebSocket
```

**Stack:** FastAPI · SQLAlchemy 2 + PostgreSQL 16 · scikit-learn + SHAP · dilithium-py / kyber-py ·
React 19 + Vite + React Router + Tailwind 4 + Recharts · Docker Compose + nginx.

## Run it

### Docker (recommended)

```bash
cp .env.example .env
# set JWT_SECRET, POST_QUANTUM_KEY and POSTGRES_PASSWORD in .env, e.g.
#   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
docker compose up -d --build
```

Open **http://localhost:3000**. Three containers start: PostgreSQL, the API (which trains the
classifier while the image builds), and nginx, which serves the app and proxies `/api` and the
WebSocket. All three restart automatically, including after a reboot. The database port is not
published. API docs are at http://localhost:3000/swagger.

### Without Docker

```bash
# backend: Python 3.12
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
export DATABASE_URL=postgresql://lookout:lookout@localhost:5432/lookout   # optional
uvicorn lookout.api:app --port 8077

# frontend, in another terminal
cd frontend
npm ci
npm run dev          # http://localhost:3000
```

Without `DATABASE_URL`, Lookout runs in memory. Without `GEMINI_API_KEY`, incident narratives
come from a template. If the API is not on `localhost:8077`, set `VITE_API_URL` for the frontend.
Every variable is described in `.env.example`.

Tests: `cd backend && python -m pytest` (275 tests; set `LOOKOUT_TEST_DATABASE_URL` to also run
the database tests against PostgreSQL). Detection report: `python -m lookout.evaluate`.

## Sign-in

| Page | Who | What it does |
|---|---|---|
| `/login` | everyone | sign in; lists the demo accounts |
| `/employee` | the 12 employees | customer book (PII masked), PDF export, fund transfers, access requests; managers also get **My team** |
| `/dashboard` and the rest of the console | SOC analyst, super admin | 17 pages: dashboard, simulation, live activity, alerts, incidents, honeypot, users, sessions, access control, privileged access, messages, message scanner, quarantine, audit & quantum-safe, ML insights, security policies, settings |

Demo credentials (a simulated bank; passwords are stored as salted PBKDF2 hashes):

| # | Username | Password | Role |
|---|---|---|---|
| — | `super.admin` | `SuperAdmin@2026` | super admin: the console, plus editing policy and final access approval |
| — | `soc.analyst` | `SocWatch@2026` | SOC analyst |
| 1 | `r.krishnan` | `Teller@Krishnan1` | teller, Chennai |
| 2 | `s.iyer` | `Teller@Iyer2` | teller, Chennai |
| 3 | `a.fernandes` | `Teller@Fernandes3` | teller, Mumbai |
| 4 | `p.nair` | `Officer@Nair4` | officer, Bengaluru |
| 5 | `m.d'souza` | `Officer@Dsouza5` | officer, Mumbai |
| 6 | `k.venkatesh` | `Analyst@Venkatesh6` | analyst, Chennai |
| 7 | `d.sharma` | `Analyst@Sharma7` | analyst, Bengaluru |
| 8 | `l.mathew` | `Manager@Mathew8` | **manager**, Chennai |
| 9 | `v.rao` | `Manager@Rao9` | **manager**, Bengaluru |
| 10 | `t.banerjee` | `Dba@Banerjee10` | DBA, Singapore |
| 11 | `h.qureshi` | `Sysadmin@Qureshi11` | sysadmin, Singapore |
| 12 | `n.pillai` | `Admin@Pillai12` | domain admin, Chennai |

Every sign-in, including wrong passwords, is scored by the engine. Guessing at an account trips
the password-guessing detector and the rate limiter (429). Employees can't reach any console
route; this is enforced in one middleware. Managers see their team's risk and approve access
requests, but are never told that someone is in the honeypot.

## The honeypot

When an employee does anything **high-risk**, they are silently moved into the honeypot. That
covers a transfer scored high, a role with no transfer mandate trying to move money, exporting
100 or more customers (`LOOKOUT_HONEYPOT_THRESHOLD`, editable by the super admin), or any other
HIGH/CRITICAL or BLOCK decision about them. From then on the **same pages** run on fake data;
there is no separate "decoy" page, because a different page would give it away.

- **Transfers** complete as normal: the same OTP step for medium risk, then "Transfer
  successful", with a reference number, UTR and a debited balance that stays debited on refresh.
  **No real money moves.** A per-employee shadow ledger holds the fake balances, and everyone
  else still sees the real ones.
- **Exports** are decoy PDFs. Everything visible on screen matches (names, IDs, the last four
  digits of the account and phone), and every field the screen masked is fabricated. The
  filename, layout and footer reference are the same as a genuine export's.
- **Everything they do** is recorded on a timeline in the SOC **Honeypot** page and in the signed
  audit log (`real_funds_moved: false`). The decision that triggered the honeypot raises an alert
  and an incident for the monitoring team, and later honeypot activity is added to that
  incident's timeline.
- Fake account numbers, document references, transaction references and UTRs are **canaries**.
  Paste one into **Trace** and it names the employee who received it.
- Signing out doesn't get them out. Only the SOC's **Clear** ends it, and that is audited too.

To demo it: sign in as `a.fernandes`, open **Fund transfer**, and send ₹10,000 to "Another
Meridian customer" (real). Then send ₹4,80,000 to "Outside account (ICICI)" (fake). In a second
tab, sign in as `soc.analyst` and open **Honeypot**.

## Spec coverage

| Spec section | Where it lives |
|---|---|
| 4 User roles | `auth.py` accounts; `ROUTE_ACCESS` in `api.py`; employee, manager, SOC analyst, super admin |
| 5 Authentication | PBKDF2 hashes, HS256 JWT + server-side session registry, `LoginLimiter`, risk-scored sign-in |
| 6–7 Abnormal login, impossible travel | `rules/identity.py` |
| 8–9 PAM, privilege escalation | `rules/privilege.py`; access requests (employee → manager → super admin); Privileged access page |
| 10 Session monitoring | `context.py` containment; Sessions page with revoke |
| 11 Credential misuse | `rules/identity.py` (failed-login bursts, success after a run of failures) and `rules/data.py` (vault hoarding) |
| 12 Insider classification | `scoring.classify`: normal / negligent / malicious / compromised / privilege abuse, plus the ML second opinion |
| 13 Behavioural analytics | `baselines.py` per-person profiles + `anomaly.py` IsolationForest |
| 14–21 Message gateway, content, URL risk, message risk score, actions, quarantine, privileged comms, bulk fraud | `urlcheck.py`, `rules/messaging.py`, `POST /api/messages/scan`; Message scanner and Quarantine pages |
| 22 Risk-based access control | score bands → allow / step-up (factor strength scales with privilege) / block; `POST /api/access/check` |
| 23 Explainable AI | every signal carries a sentence and its points; SHAP for the classifier |
| 24 Alerts | `incidents.py` alert book; live over WebSocket |
| 25–26 Dashboard, user risk profile | Dashboard, Users and user detail pages |
| 27 Incident management | `incidents.py`; assign, notes, status, response actions |
| 28 Audit logging | `audit.py` hash chain; `audit_logs` table re-verified from the database |
| 29 Quantum-safe module | `crypto.py`; [docs/quantum_safe.md](docs/quantum_safe.md) |
| 30 Database design | 15 tables; [docs/database.md](docs/database.md) |
| 31 API design | [docs/api.md](docs/api.md); `/swagger`, `/redoc` |
| 32–34 ML pipeline, dataset, evaluation | `ml/`, `backend/lookout/ml/`; [docs/ml.md](docs/ml.md) |
| 35–37 Frontend pages, UI, real-time | React + Vite, 17 console pages, WebSocket live feed |
| 38–39 Demo mode, example scenario | Simulation page; the `attack_story` scenario replays the spec's example |
| Honeypot transfer page | `portal.py`, `banking.py` (see above) |

## Scenarios

On start-up the API replays a month of synthetic activity for 12 staff at a fictional bank to
build baselines and train the anomaly model, then keeps a trickle of ordinary work flowing. These
scenarios can be run from the **Simulation** page:

| Scenario | What happens | Lookout's response |
|---|---|---|
| Abnormal login | known analyst, 02:30, unseen laptop, new country | step-up; classed *compromised* |
| Compromised account | Chennai login, then Kyiv 28 minutes later on an unknown device, then an 18,400-row query | impossible travel; blocked, session killed; classed *compromised* |
| Privilege escalation | loans officer tries to become domain admin four times, then edits IAM | blocked and paged; *privilege abuse* |
| Bulk phishing | 50,000 customers get an SMS with `meridian-bank.secure-verify.top/re-kyc` | blocked and paged; lookalike domain named |
| After-hours exfiltration | 02:14 login, 412,000-row read, 2.9 GB written to a share | read blocked before data leaves |
| Credential stuffing | 7 failures from Lagos, a success, 9 vault reads | burst detected, origin locked, every vault read refused |
| Transfer fraud | teller sends ₹1.9L, ₹4.8L and ₹4.95L to new outside accounts at 21:40 | stepped up, then blocked and paged; *malicious*; honeypot |
| Negligent insider | teller emails 900 customers a *genuine* statement link | quarantined, classed *negligent*, never paged |
| Attack story | the spec's example on one DBA: normal login, new device at 02:30, sensitive DB, escalation, phishing link | 2 allow → 32 step-up → 73 block → 100 block and page. Same order of responses as the spec, though the scores differ from its illustrative 68 and 78 |

## Detection quality, and what it means

`python -m lookout.evaluate` trains on 30 days, then scores a held-out week plus every scenario:

| | |
|---|---|
| precision | 1.000 |
| recall | 0.974 (38 of 39 incident events) |
| false positives | 0 of 872 held-out benign events |
| threat classification | 38 of 38 detected incidents named correctly |

The supervised classifier, on 10,600 synthetic sessions: accuracy 0.973 and macro F1 0.903 on a
stratified split. It is weakest on **negligent** insiders (recall 0.64), and on employees it has
never seen, negligent precision falls to 0.30. Details in [docs/ml.md](docs/ml.md).

**These are numbers on synthetic data from Lookout's own generator.** They show the detectors are
consistent and don't fire on ordinary work, including legitimate manager campaigns, weekend
on-call admin work and mistyped passwords. They are not a claim about accuracy on a real bank's
logs; nobody can make that claim without those logs.

The one miss is on purpose: the 02:14 login that opens the exfiltration scenario is allowed. An
unusual hour alone isn't enough to lock someone out, and the query four minutes later is blocked.

## Design decisions

- **Rules decide; the models assist.** The IsolationForest adds at most 22 of 100 points, and the
  RandomForest only gives a second opinion. A model that can't explain itself shouldn't be the
  reason an employee is locked out.
- **The LLM narrates, never judges.** With `GEMINI_API_KEY` set, Gemini writes the incident
  summary from evidence that has already been decided.
- **Baselines never learn from incidents.** Only allowed events update a profile, so an attack
  never becomes "normal".
- **Policy floors.** A customer message with a hostile link is at least quarantined, whatever the
  score, because step-up auth can't stop an insider who holds their own second factor.
- **Checkpoint signing.** ML-DSA signing takes about 90 ms, so every entry is hash-linked and the
  chain head is signed every 25 entries and after anything critical.
- **The ground-truth label never leaves the server.** Detectors never read it, and the API
  strips it.

## Limitations

- **Synthetic data only.** Nothing here has seen a real bank's logs.
- **Engine state is in memory.** PostgreSQL keeps a durable record of every decision, alert,
  incident and audit entry across restarts. The engine itself rebuilds from the synthetic replay
  on start and doesn't reload baselines, open incidents or the honeypot watchlist from the
  database.
- **Step-up is simulated.** The OTP is displayed; there's no real second factor.
- **One process.** Sessions, rate limits and the live feed are per process, so several API
  replicas would need Redis or similar.
- **Pure-Python PQC** is not constant-time. Use liboqs or an HSM in production; see
  [docs/quantum_safe.md](docs/quantum_safe.md).
- **Not deployed publicly.** It runs locally with Docker Compose. Hosting it needs a provider
  account, which this repo doesn't include.

## Docs

[Architecture](docs/architecture.md) · [Database](docs/database.md) · [API](docs/api.md) ·
[ML](docs/ml.md) · [Security](docs/security.md) · [Quantum-safe](docs/quantum_safe.md) ·
[GUIDE.md](GUIDE.md) (how it was built)

## Layout

```
backend/lookout/
  api.py           FastAPI: REST, WebSocket, SSE, auth middleware
  pipeline.py      the engine
  models.py        events, signals, decisions, roles and privilege levels
  generator.py     synthetic bank: 12 staff, hours, devices, workloads, transfers
  scenarios.py     labelled incidents, including the spec's attack story
  baselines.py     per-identity online profiles
  context.py       short-window history + session containment
  rules/           identity, privilege, data, messaging and transfer detectors
  anomaly.py       IsolationForest + feature attributions
  scoring.py       fusion, bands, classification, graded response, policy floors
  policy.py        live, super-admin-editable policy
  urlcheck.py      offline URL reputation and link extraction
  portal.py        employee portal, honeypot ledger, decoy PDFs
  banking.py       real and shadow ledgers
  incidents.py     alerts and incidents
  auth.py          accounts, JWT sessions, rate limiting
  crypto.py        ML-DSA / ML-KEM with Ed25519 / X25519 fallback
  audit.py         hash chain + signed checkpoints
  narrator.py      template or Gemini summaries
  evaluate.py      precision / recall against labels
  ml/              session features, dataset, RandomForest + SHAP
  db/              SQLAlchemy schema and write-through persistence
backend/datasets/  insider_sessions.csv (10,600 rows)
ml/                generate, preprocess, train, evaluate, explain
frontend/src/      React + Vite app: pages/, components/, hooks/, lib/
docs/              design documentation
docker-compose.yml PostgreSQL + API + nginx
```

## License

MIT
