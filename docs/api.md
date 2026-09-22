# API

Interactive docs: `/swagger` (Swagger UI) and `/redoc`. Every route except `/api/health` and
`/api/auth/*` needs `Authorization: Bearer <token>` from `POST /api/auth/login`.

Who may call what is decided by path prefix in one middleware (`ROUTE_ACCESS` in `api.py`):

| Prefix | Allowed |
|---|---|
| `/api/health`, `/api/auth/` | anyone |
| `/api/portal/` | employees |
| `/api/team/` | employees; the handler also requires the manager role |
| `/api/admin/` | super admin |
| everything else | SOC analyst and super admin |

## Auth

| Method | Path | |
|---|---|---|
| POST | `/api/auth/login` | `{username (or work email), password, device_id?, city?, ip?, at_hour?}` → `{token, kind, profile, risk}`, where `risk` is `{risk_score, risk_level, reason[], action}`. The optional fields simulate where the sign-in comes from. A MEDIUM sign-in returns `{mfa_required, challenge_id, factor, demo_otp, risk}` instead of a token. Rate-limited per account and per IP (429). |
| POST | `/api/auth/mfa/verify` | `{challenge_id, otp}` → the session. Three wrong codes end the challenge; each is scored as a failed sign-in. |
| POST | `/api/auth/logout` | revokes the session server-side |
| GET | `/api/auth/me` | current account |
| GET | `/api/auth/demo-accounts` | demo credentials for the sign-in page (turn off with `LOOKOUT_SHOW_DEMO_ACCOUNTS=0`) |

## Employee portal

| Method | Path | |
|---|---|---|
| GET | `/api/portal/customers` | customer book, PII masked |
| POST | `/api/portal/export` | PDF export of `{count}` customers. The response is a real or decoy PDF; the two can't be told apart. |
| GET | `/api/portal/accounts/{account}` | payee lookup |
| GET/POST | `/api/portal/transfers` | history / new transfer. Returns `completed`, `otp_required` or 403, and runs on the shadow ledger if the employee is watchlisted. |
| POST | `/api/portal/transfers/verify` | OTP step |
| GET/POST | `/api/portal/access-requests` | request elevated access |
| GET | `/api/portal/me` · `/api/portal/activity` | own profile · own recent activity (no scores) |
| GET | `/api/portal/resources` · POST `/api/portal/resources/{resource}/open` | protected systems and a PAM request for one: `DENIED` (logged as a failed authorisation), `MFA_REQUIRED`, `RESTRICTED` or `ALLOWED` |
| GET | `/api/portal/admin/users` | privileged administrators (level 4+) only; anyone else gets 403 **and** is scored for a privilege-escalation attempt |
| POST | `/api/portal/admin/users/{u}/disable` · `/enable` · `/role` | manage accounts and roles below your own level; each is a monitored admin operation |
| GET/PUT | `/api/portal/admin/comms-policy` | who may message customers and run bulk campaigns |
| GET | `/api/team/overview` | manager: team members and their risk |
| GET | `/api/team/access-requests` · POST `/api/team/access-requests/{id}/decide` | manager approval |

## SOC console

| Area | Routes |
|---|---|
| Dashboard | `GET /api/stats`, `/api/dashboard/statistics`, `/api/dashboard/risk-trends` |
| Live feed | `WS /api/ws?token=`: `decision`, `alert`, `incident`, `risk`, `message`, `session` events. `GET /api/stream` (SSE) carries the same. |
| Decisions | `GET /api/decisions`, `/api/decisions/{event_id}`, `/api/risk/{event_id}/explanation` (signals + SHAP) |
| Events and simulation | `POST /api/events` (= `POST /api/activity/analyze`), `POST /api/risk/calculate` (scores without recording anything), `GET /api/scenarios`, `POST /api/scenarios/{key}/run`, `POST /api/traffic/{mode}`, `POST /api/reset` |
| Messages | `POST /api/messages/scan` (returns `message_risk.components`), `GET /api/messages?status=&q=`, `GET /api/messages/{id}`, `POST /api/urls/inspect` (URL `risk_score` 0-100 and lexical `features`) |
| Quarantine | `GET /api/quarantine`, `POST /api/quarantine/{id}/release`, `/block`, `/delete`, `/investigate` |
| Users | `GET /api/users`, `/api/users/{actor}`, `/api/users/{actor}/risk`, `/api/users/{actor}/activity` |
| Accounts and sessions | `GET /api/accounts`, `POST /api/accounts/{u}/disable` / `enable`, `GET /api/sessions`, `POST /api/sessions/{id}/revoke` |
| Alerts | `GET /api/alerts`, `/api/alerts/{id}`, `POST /api/alerts/{id}/status` |
| Incidents | `GET/POST /api/incidents`, `GET /api/incidents/{id}`, `POST .../assign`, `.../notes`, `.../status`, `.../actions` |
| Honeypot | `GET /api/honeypots`, `GET /api/honeypots/trace?q=`, `POST /api/honeypots/watchlist/{actor}/clear` |
| Access control | `POST /api/access/check` (risk-based decision for a resource), `GET /api/policy` |
| Audit and crypto | `GET /api/audit`, `GET /api/audit-logs?action=`, `/api/audit/verify` (a failure raises a quantum-safe alert), `GET /api/crypto/artefacts`, `POST /api/crypto/artefacts/verify`, `POST /api/crypto/artefacts/tamper?name=` (demo), `POST /api/audit/tamper/{seq}` (demo; `LOOKOUT_ALLOW_TAMPER=0` disables), `GET /api/crypto`, `POST /api/credentials/seal` |
| ML | `GET /api/ml/metrics`, `GET /api/evaluation` |
| Database | `GET /api/db/status` |

## Super admin

| Method | Path | |
|---|---|---|
| GET/PUT | `/api/admin/policies` | risk bands, honeypot export threshold, transfer limits, communication policy |
| GET/PUT | `/api/admin/roles` | every role, its members and reach; the minimum privilege for each protected system |
| GET/PUT | `/api/admin/config` | system configuration: demo traffic, sign-in MFA, demo accounts on the sign-in page, tamper demos |
| GET | `/api/admin/access-requests` · POST `/api/admin/access-requests/{id}/decide` | final approval |

## Example

```bash
T=$(curl -s localhost:3000/api/auth/login -H 'content-type: application/json' \
      -d '{"username":"soc.analyst","password":"SocWatch@2026"}' | jq -r .token)

curl -s localhost:3000/api/messages/scan -H "Authorization: Bearer $T" \
  -H 'content-type: application/json' \
  -d '{"sender":"r.krishnan","channel":"sms","recipient_count":50000,"audience":"customer",
       "body":"Your KYC expires today. Update at meridian-bank.secure-verify.top/re-kyc"}'
```
