# Lookout

[![ci](https://github.com/keerthishree20/lookout/actions/workflows/ci.yml/badge.svg)](https://github.com/keerthishree20/lookout/actions/workflows/ci.yml)

**Privileged-access misuse and insider-threat detection for banking.** Lookout watches every
login, query, admin action and outbound staff message, scores each one against that person's own
behavioural baseline, explains the score in plain sentences, responds in proportion (allow, step-up
auth, quarantine, block, block and page the SOC), and writes every decision to an audit log signed
with **ML-DSA-65 (NIST FIPS 204)**. Credentials are sealed with **ML-KEM-768 (FIPS 203)**.

```
event ─► baseline lookup ─► 16 detectors + IsolationForest ─► fused, explained score
      ─► graded response + session containment ─► hash-chained audit, ML-DSA signed ─► live console
```

## What it covers

| Brief requirement | Where it lives |
|---|---|
| Misuse of privileged accounts | `rules/privilege.py`: escalation scored by the size of the jump, out-of-scope admin actions, dormant admin accounts waking up |
| Real-time insider detection | `pipeline.py` scores each event as it arrives; the console streams decisions over SSE |
| AI-driven behavioural analysis | `baselines.py` (per-person online profiles) + `anomaly.py` (IsolationForest trained only on benign history) |
| Risk-based access control | `scoring.py`: MEDIUM band demands a second factor whose strength scales with privilege (push → TOTP + approval → hardware key) |
| Protect critical admin systems | vault-hoarding detection, session revocation, source lock-out after an attack |
| Quantum-safe cryptography | `crypto.py` + `audit.py`: ML-DSA-signed audit checkpoints, ML-KEM-sealed credentials, classical fallback that says so |
| Impossible travel, abnormal login, credential misuse | `rules/identity.py` |
| Session monitoring | `context.py`: revoked sessions, locked origins and "still going after a block" feed back into scoring |
| Insider classification | `scoring.classify`: negligent / malicious / compromised / privilege abuse, with "compromised" sticky per session |
| Explainable AI | every signal carries a sentence and its points; the console shows the arithmetic |
| Message scanning, risk score, bulk fraud, privileged comms, quarantine | `urlcheck.py` + `rules/messaging.py` + `POST /api/messages/scan` |

## Run it

```bash
# backend (Python 3.10+)
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn lookout.api:app --port 8077

# frontend, in another terminal
cd frontend
npm install
npm run dev          # http://localhost:3000
```

No API key, database or compiler is needed. The post-quantum libraries are pure Python.
Optional settings are listed in `backend/.env.example`; export them before starting uvicorn.
If the API runs somewhere other than `localhost:8077`, set `NEXT_PUBLIC_API_URL` for the frontend.

Tests: `cd backend && python -m pytest` (145 tests). Detection report: `python -m lookout.evaluate`.

## The demo

On start-up the API replays a month of synthetic activity for 12 staff at a fictional bank to build
baselines and train the model, then keeps a trickle of ordinary work flowing. Six scenarios can be
injected from the console:

| Scenario | What happens | Lookout's response |
|---|---|---|
| Compromised teller account | Chennai login, then Kyiv 28 minutes later on an unknown device, then an 18,400-row query | impossible travel; login blocked, session killed; query classed as *compromised*, not malicious |
| Privilege escalation | Loans officer tries to become domain admin four times, then edits IAM | blocked and paged; *privilege abuse* |
| Bulk phishing | 50,000 customers get an SMS with `meridian-bank.secure-verify.top/re-kyc` | blocked and paged; lookalike domain named in the explanation |
| After-hours exfiltration | 02:14 login, 412,000-row read, 2.9 GB written to a share | read blocked before data leaves |
| Credential stuffing | 7 failures from Lagos, a success, 9 vault reads | burst detected, origin locked, every vault read refused |
| Negligent insider | Teller emails 900 customers a *genuine* statement link | quarantined for review, classed *negligent*, never paged |

The **Message gateway** tab takes any text. Links are extracted from the body, and a customer-facing
message carrying a suspicious link is always held for human review whatever the score, because
step-up auth cannot stop an insider who owns their own second factor.

The **Audit & QPC** tab can forge a past decision the way a rogue admin would. Verification finds
the exact entry. Recomputing every hash doesn't help either: the ML-DSA checkpoint no longer
verifies.

## Detection quality, and what it means

`python -m lookout.evaluate` trains on 30 days, then scores a held-out week plus every scenario:

| | |
|---|---|
| precision | 1.000 |
| recall | 0.967 (29 of 30 incident events) |
| false-positive rate | 0 of 940 held-out benign events |
| threat classification | 29 of 29 detected incidents named correctly |

Across five other random seeds the worst case was 1 false positive in 896 benign events.

**These are numbers on synthetic data from Lookout's own generator.** They show the detectors are
consistent and don't fire on ordinary work, including legitimate manager campaigns, weekend on-call
admin and mistyped passwords. They are not a claim about accuracy on a real bank's logs. Nobody
can make that claim without those logs.

The one miss is on purpose: the 02:14 login that opens the exfiltration scenario is allowed.
An unusual hour on its own is not enough to lock someone out, and the query four minutes later is
blocked.

## Design decisions

- **Rules score, the model assists.** The IsolationForest adds at most 22 of 100 points. An
  unsupervised model that can't explain itself should not be the reason an employee is locked out.
- **The LLM narrates, never judges.** With `GEMINI_API_KEY` set, Gemini writes the incident
  summary from the evidence that has already been decided. Without it, a deterministic template does.
- **Baselines never learn from incidents.** Only allowed events update a profile, so an attack
  never becomes "normal".
- **Checkpoint signing.** ML-DSA signing takes about 90 ms, so every entry is hash-linked and the chain
  head is signed every 25 entries and immediately after anything critical, the way
  transparency logs work.
- **The ground-truth label never leaves the server.** Detectors never read it, and the API strips it.

## Layout

```
backend/lookout/
  models.py        events, signals, decisions, roles and privilege levels
  generator.py     synthetic bank: 12 staff, hours, devices, workloads
  scenarios.py     six labelled incidents
  baselines.py     per-identity online profiles
  context.py       short-window history + session containment state
  rules/           identity, privilege, data, messaging detectors
  urlcheck.py      offline URL reputation (lookalikes, homoglyphs, shorteners, punycode)
  anomaly.py       IsolationForest + feature attributions
  scoring.py       fusion, bands, classification, graded response, policy floors
  crypto.py        ML-DSA / ML-KEM with Ed25519 / X25519 fallback
  audit.py         hash chain + signed checkpoints
  narrator.py      template or Gemini summaries
  pipeline.py      the engine
  evaluate.py      precision / recall against labels
  api.py           FastAPI + SSE
frontend/src/      Next.js console
```

## License

MIT
