# Architecture

```
                         ┌──────────────────────── browser ────────────────────────┐
                         │  React 19 + Vite: /login, /employee, /soc/* (17 pages)   │
                         └───────────────┬───────────────────────────┬─────────────┘
                                   REST (Axios)              WebSocket /api/ws
                                         │                           │
┌────────────────────────────────── nginx (web container) ──────────────────────────────────┐
│  serves dist/, SPA fallback, proxies /api/* and the WebSocket upgrade to the api container  │
└──────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                           │
┌─────────────────────────────────── FastAPI (api container) ────────────────────────────────┐
│ middleware: JWT → session registry → role→route map → security headers                      │
│                                                                                             │
│  event ─► baselines ─► 27 rule detectors + NLP ─► IsolationForest ─► fusion + policy floors  │
│        ─► graded response (allow / step_up / quarantine / block / block_and_alert)           │
│        ─► session containment ─► RandomForest second opinion + SHAP                          │
│        ─► alerts / incidents ─► honeypot watchlist + shadow ledger                          │
│        ─► hash-chained audit, ML-DSA-65 checkpoints                                          │
│        ─► listeners: WebSocket/SSE broadcast, PostgreSQL write-through                        │
└──────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                           │ SQLAlchemy 2 + psycopg 3
                                  ┌────────┴────────┐
                                  │ PostgreSQL 16   │  15 tables, see database.md
                                  └─────────────────┘
```

## Request path

1. **Auth middleware** reads the bearer token (or `?token=` for the WebSocket and SSE, which
   cannot send headers), verifies the HS256 JWT, and checks the session ID against the
   server-side registry. A revoked session fails here even though its JWT hasn't expired.
2. **Route map** (`ROUTE_ACCESS` in `api.py`) decides which account kinds may call the path:
   `/api/portal/*` and `/api/team/*` are employee-only, `/api/admin/*` is super admin only, and
   everything else is the SOC console (SOC analyst or super admin). The check sits in one place
   instead of being repeated on every handler.
3. **The handler** turns the request into an `Event`, where there is one, and hands it to the
   engine.

## The engine (`lookout/pipeline.py`)

The engine is the single place that decides. For each event it:

- looks up the person's **baseline** (`baselines.py`): their usual hours, devices, locations,
  query sizes, transfer amounts and payees, learned online from allowed events only;
- runs **27 detectors** (`rules/`), each returning points plus a sentence explaining why. They cover
  sign-in, session behaviour, privilege, data access, message links, message content (including the
  NLP scam-language model in `nlp.py`, PII leaks and attachments) and transfers;
- adds up to 22 points from an **IsolationForest** trained on benign history (`anomaly.py`);
- fuses these, weighted by the actor's privilege level, into a 0-100 score. The score is banded
  by the live `POLICY` (medium 30, high 60, critical 80, the spec's bands) and turned into a graded
  response;
- applies **policy floors**, which set the minimum response however low the score. A customer
  message carrying a hostile link is at least quarantined; a transfer by a role with no
  mandate is blocked; a privileged administrator messaging customers needs a second factor;
- updates **session containment** (`context.py`): revoked sessions, locked origins and strikes
  feed back into later scores;
- asks the **supervised classifier** (`ml/model.py`) for a second opinion on the session, with
  SHAP attributions. The rules decide; the model only annotates;
- writes an **audit entry** and notifies listeners.

Listeners are how everything else hooks in without the engine knowing about it: the live feed,
the database, the alert and incident book, and the honeypot (which watchlists anyone with a
HIGH or CRITICAL decision, or a BLOCK).

## Sign-in

`POST /api/auth/login` scores the sign-in as an event before handing out a working session:

- **LOW**: a session and the login risk (`risk_score`, `risk_level`, `reason`);
- **MEDIUM**: no session yet; a simulated one-time code must be confirmed at
  `POST /api/auth/mfa/verify`, and each wrong code is scored as a failed sign-in;
- **HIGH / CRITICAL**: a session, but the employee is now in the honeypot.

## Messages

`POST /api/messages/scan` extracts links from the text (with or without a scheme), sanitises the
input, and scores the message like any other event. The response breaks the score into the spec's
six components (`message_risk.py`). Held messages wait in the quarantine queue for Release, Block,
Delete or Investigate.

## Protected store

At start-up `AppState` seals sensitive configuration (the JWT secret, the database URL, any API
key), synthetic vault credentials, a snapshot of the detection policy, and the audit-signing seed
(key wrapping) into `pq_vault.ProtectedStore`. `POST /api/crypto/artefacts/verify` reopens every
artefact. A failure, or a failed audit verification, raises a "Quantum-Safe Key/Artefact Security
Event" alert through `IncidentBook.system_alert`.

## Honeypot

`portal.py` holds the `HoneypotLedger`. Once an employee is watchlisted:

- customer exports return a decoy PDF. Everything the screen showed is kept, and the fields it
  masked are fabricated. The fake account numbers are canaries recorded against that export;
- transfers go to a per-employee **shadow ledger** (`banking.py`) instead of the real one. The
  page, OTP step, success message, reference and UTR are the same as the real ones, and the
  balances are fake. No money moves;
- every action is added to a timeline the SOC sees on the Honeypot page.

The employee's pages don't change, because a different page would give it away.

## State and restarts

The engine is in memory and rebuilds itself on start by replaying a month of synthetic activity,
so the demo always starts from a known state. With `DATABASE_URL` set, every decision, audit
entry, alert, incident, login, session and message is also written to PostgreSQL, tagged with a
`run_id`. The database is the durable record across restarts and the thing to query for
reporting. The engine does not reload its working state from it; see the limitations in the
README.

## Frontend

`frontend/src/`:

- `hooks/useLive.tsx`: one WebSocket per tab. Event types: `decision`, `alert`, `incident` (a
  critical one pops up in the corner), `risk` (a person's latest score), `message` (a scan
  result) and `session` (sign-in, sign-out, MFA challenge, revocation).
- `lib/api.ts`: Axios client. `VITE_API_URL` is the API origin; it is empty in the Docker build,
  so requests are same-origin through nginx.
- `lib/session.ts`: the token is kept in `sessionStorage`, one per tab, so an employee and the
  SOC can be signed in side by side in two tabs.
- `layouts/SocLayout.tsx` and `pages/soc/*`: the console. `pages/EmployeePortal.tsx`: the
  employee side, with Customers, Fund transfer, Access requests, My profile, My team (managers)
  and Admin console (privileged administrators).
