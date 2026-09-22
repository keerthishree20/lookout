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
event ─► baseline ─► 27 detectors + IsolationForest + NLP content model ─► fused, explained score ─► graded response
      ─► session containment ─► RandomForest second opinion + SHAP ─► alerts, incidents, honeypot
      ─► hash-chained audit, ML-DSA signed ─► PostgreSQL + live console over WebSocket
```

**Stack:** FastAPI · SQLAlchemy 2 + PostgreSQL 16 · scikit-learn + SHAP + pandas · dilithium-py / kyber-py ·
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

### Online, on Render (free)

The repository includes a Render Blueprint (`render.yaml`) and a single-service `Dockerfile` that
serves the site and the API from one URL.

1. Sign in at https://dashboard.render.com (the GitHub account that can see this repo).
2. **New → Blueprint**, pick `keerthishree20/lookout`, and click **Apply**.
3. Render creates the `lookout` web service and a free `lookout-db` PostgreSQL database, and
   generates `JWT_SECRET` and `POST_QUANTUM_KEY`. The first build takes about 10 minutes.
4. Open the service's `https://….onrender.com` URL.

On the free tier the service sleeps after 15 idle minutes, and the first visit after that takes
about a minute. The demo state starts fresh on each wake-up; the database keeps the history. A free
database expires after 30 days; Lookout then keeps running in memory. The demo accounts are shown
on the sign-in page, so anyone with the URL can sign in. That's fine for a demo, and the Super
Admin can hide them under Settings → System configuration.

#### Keeping the database past 30 days

Render's free PostgreSQL expires after 30 days. To keep the history, point the service at a free
database elsewhere (Neon and Supabase don't expire):

1. Create a free project at https://neon.com (or https://supabase.com) and copy its PostgreSQL
   connection string. It looks like
   `postgresql://user:password@ep-something.aws.neon.tech/neondb?sslmode=require`.
2. In Render: the **lookout** service → **Environment** → edit **`DATABASE_URL`** → paste it → **Save**.
   The service restarts and creates its tables on the new database.
3. Check it worked: sign in as the Super Admin and open **Settings**, or call `/api/db/status`.
   It should say `enabled: true` and that the stored audit chain verifies.

Lookout accepts `postgres://` or `postgresql://` URLs with their query parameters, waits up to
`LOOKOUT_DB_CONNECT_TIMEOUT` seconds (default 10) for a sleeping database to wake, and falls back
to running in memory if the database can't be reached at all.

If you later press **Sync** on the Blueprint page, Render restores `DATABASE_URL` to its own
database. Re-paste the external one, or delete the `databases:` block from `render.yaml` first.

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

Tests: `cd backend && python -m pytest` (299 tests; set `LOOKOUT_TEST_DATABASE_URL` to also run
the database tests against PostgreSQL). Detection report: `python -m lookout.evaluate`.

## Sign-in

| Page | Who | What it does |
|---|---|---|
| `/login` | everyone | sign in; lists the demo accounts |
| `/employee` | the 12 employees | customer book (PII masked), PDF export, fund transfers, access requests, **My profile** (own profile, own activity, protected systems); managers also get **My team**; privileged administrators (DBA, sysadmin, domain admin) get the **Admin console** |
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

Every sign-in, including wrong passwords, is scored by the engine and the response carries the login
risk (`risk_score`, `risk_level`, `reason`). A MEDIUM sign-in must pass a simulated one-time code
first; a HIGH one silently lands in the honeypot. The sign-in page's **Sign-in context** selector
simulates where a sign-in comes from (a new laptop at 02:30; 02:30 from a new country on an unknown
device and IP; New York), since the demo can't really change your device or city. You can also sign
in with the work email (`v.rao@meridianbank.example`). Guessing at an account trips the
password-guessing detector and the rate limiter (429). Employees can't reach any console
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

Every section of the project specification (39 sections plus the honeypot requirement) is listed,
with its status and where it's built, in **[docs/spec-coverage.md](docs/spec-coverage.md)**. In
short: all 39 are done. Section 39's example scenario matches the spec's *statuses* but not its
illustrative scores, and public deployment isn't done. Highlights:

- **27 detectors**: sign-in (unusual time, new device/network/country, compound novelty, impossible
  travel, failed-login bursts, credential misuse, concurrent sessions, sign-in frequency), session
  (hijacked token, query bursts, failed authorisation, replay after revocation), privilege
  (escalation, out-of-scope admin work, dormant accounts), data (mass reads, off-hours access, bulk
  writes, vault hoarding), messages (phishing links, bulk blasts, unauthorised customer messages,
  scam language, PII leaks, risky attachments, repeated campaigns) and transfers.
- **Three models**: an IsolationForest for "is this unusual for them", a RandomForest with SHAP for
  "what kind of insider is this", and a TF-IDF + logistic-regression content model for "does this
  message read like a scam". None of them decides alone.
- **Message risk** is broken into the spec's six parts (URL, sender behaviour, content,
  destination, privilege, volume), which always add up to the score. **URL risk** is 0-100.
- **Quarantine**: Release, Block, Delete, Investigate. **Communication policy** (who may message
  customers or run bulk campaigns) is configurable.
- **Post-quantum protected store**: sensitive configuration, credentials and the audit-signing key
  itself (key wrapping) sealed with ML-KEM-768; a failed check raises a "Quantum-Safe Key/Artefact
  Security Event".
- **Roles**: employee, manager, privileged administrator, SOC analyst, super admin.

## Scenarios

On start-up the API replays a month of synthetic activity for 12 staff at a fictional bank to
build baselines and train the anomaly model, then keeps a trickle of ordinary work flowing. These
scenarios can be run from the **Simulation** page. The first nine are the spec's §38 buttons
("Simulate Normal Login", "Simulate Impossible Travel", and so on):

| Scenario | What happens | Lookout's response |
|---|---|---|
| Abnormal login | known analyst, 02:30, unseen laptop, new country, unknown IP (the spec's §5 example) | HIGH, blocked; classed *compromised* |
| Impossible travel | Bengaluru at 10:00, New York at 10:20 (the spec's §7 example) | blocked and paged; *compromised* |
| Phishing email | one customer gets a KYC scam with a lookalike link, asking for their password | quarantined; *malicious* |
| Compromised account | Chennai login, then Kyiv 28 minutes later on an unknown device, then an 18,400-row query | impossible travel; blocked, session killed; classed *compromised* |
| Privilege escalation | loans officer tries to become domain admin four times, then edits IAM | blocked and paged; *privilege abuse* |
| Bulk phishing | 50,000 customers get an SMS with `meridian-bank.secure-verify.top/re-kyc` | blocked and paged; lookalike domain named |
| After-hours exfiltration | 02:14 login, 412,000-row read, 2.9 GB written to a share | read blocked before data leaves |
| Credential stuffing | 7 failures from Lagos, a success, 9 vault reads | burst detected, origin locked, every vault read refused |
| Transfer fraud | teller sends ₹1.9L, ₹4.8L and ₹4.95L to new outside accounts at 21:40 | stepped up, then blocked and paged; *malicious*; honeypot |
| Negligent insider | teller emails 900 customers a *genuine* statement link | quarantined, classed *negligent*, never paged |
| Attack story | the spec's §39 example on one DBA: normal login, new device at 02:30, sensitive DB, escalation, phishing link | 2.5 allow → 46.9 step-up → 73.2 block → 100 block and page. Same statuses as the spec; its example scores (12, 68, 78, 92) are illustrative and Lookout's differ |

## Detection quality, and what it means

`python -m lookout.evaluate` trains on 30 days, then scores a held-out week plus every scenario:

| | |
|---|---|
| precision | 1.000 |
| recall | 0.976 (40 of 41 incident events) |
| false positives | 0 of 873 held-out benign events |
| threat classification | 40 of 40 detected incidents named correctly |
| policy step-ups | 8 (a privileged administrator's ordinary customer messages, which policy says need MFA: a mandatory control, reported separately and not counted as a detection) |

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
- **Bands follow the spec**: 0-29 low, 30-59 medium, 60-79 high, 80-100 critical. The Super Admin
  can move them.
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
- **The message-content model** is trained on template messages Lookout wrote itself. It shows the
  pipeline works; it has never seen a real phishing campaign.
- **Pure-Python PQC** is not constant-time. Use liboqs or an HSM in production; see
  [docs/quantum_safe.md](docs/quantum_safe.md).
- **Hosting is ready, not live.** `render.yaml` deploys it to Render in a few clicks (above), but
  that needs the owner's Render account, so it hasn't been done from here.

## Docs

[Spec coverage](docs/spec-coverage.md) · [Architecture](docs/architecture.md) · [Database](docs/database.md) · [API](docs/api.md) ·
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
  rules/           identity, session, privilege, data, messaging, content and transfer detectors
  nlp.py           message-content model (TF-IDF + logistic regression, synthetic corpus)
  message_risk.py  the spec's six-part message risk breakdown
  pq_vault.py      post-quantum protected store; classical vs PQ table
  routes_spec.py   the rest of the spec's routes (admin console, quarantine actions, ...)
  runtime.py       Super Admin system configuration
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
  ml/              session features, dataset, pandas cleaning, RandomForest + SHAP
  db/              SQLAlchemy schema and write-through persistence
backend/datasets/  insider_sessions.csv (10,600 rows)
ml/                generate, preprocess, train, evaluate, explain
frontend/src/      React + Vite app: pages/, components/, hooks/, lib/
docs/              design documentation
docker-compose.yml PostgreSQL + API + nginx
```

## License

MIT
