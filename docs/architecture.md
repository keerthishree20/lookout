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
│  event ─► baselines ─► 17 rule detectors ─► IsolationForest ─► fusion + policy floors        │
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
- runs **17 detectors** (`rules/`), each returning points plus a sentence explaining why;
- adds up to 22 points from an **IsolationForest** trained on benign history (`anomaly.py`);
- fuses these, weighted by the actor's privilege level, into a 0-100 score. The score is banded
  by the live `POLICY` (medium 30, high 60, critical 85) and turned into a graded response;
- applies **policy floors**, which set the minimum response however low the score. A customer
  message carrying a hostile link is at least quarantined; a transfer by a role with no
  mandate is blocked;
- updates **session containment** (`context.py`): revoked sessions, locked origins and strikes
  feed back into later scores;
- asks the **supervised classifier** (`ml/model.py`) for a second opinion on the session, with
  SHAP attributions. The rules decide; the model only annotates;
- writes an **audit entry** and notifies listeners.

Listeners are how everything else hooks in without the engine knowing about it: the live feed,
the database, the alert and incident book, and the honeypot (which watchlists anyone with a
HIGH or CRITICAL decision, or a BLOCK).

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

- `hooks/useLive.tsx`: one WebSocket per tab, carrying decisions, stats and alerts to every page.
- `lib/api.ts`: Axios client. `VITE_API_URL` is the API origin; it is empty in the Docker build,
  so requests are same-origin through nginx.
- `lib/session.ts`: the token is kept in `sessionStorage`, one per tab, so an employee and the
  SOC can be signed in side by side in two tabs.
- `layouts/SocLayout.tsx` and `pages/soc/*`: the console. `pages/EmployeePortal.tsx`: the
  employee side, with Customers, Fund transfer, Access requests, and My team (managers only).
