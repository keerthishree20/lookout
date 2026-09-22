# Security

What protects Lookout itself, as opposed to what it detects.

## Authentication

- Passwords are stored as PBKDF2-HMAC-SHA256 hashes with a per-account random salt
  (`auth.py`). Demo passwords are in the README because this is a demo bank; they are never
  stored in plain text.
- Tokens are HS256 JWTs signed with `JWT_SECRET`, lasting 8 hours (`JWT_EXPIRES_HOURS`). If
  `JWT_SECRET` is unset or shorter than 32 characters, a random secret is generated per process and every restart signs
  everyone out. Compose refuses to start without one.
- Every token carries a session ID that is checked against a **server-side registry**. Sign-out,
  a SOC revocation, or the engine blocking the session invalidates it immediately, so a stolen
  but unexpired token is useless.
- The sign-in itself is an event: the engine scores it (time, device, network, country, impossible
  travel, concurrent sessions, password guessing). A MEDIUM sign-in gets no session until a
  simulated one-time code is confirmed (`/api/auth/mfa/verify`; three wrong codes end the
  challenge, and each is scored). A HIGH one is let in, but only to the honeypot.
- **Rate limiting** (`LoginLimiter`): 10 failures in 5 minutes locks an account, and more than 60
  attempts a minute from one IP is refused with 429. Wrong passwords are also scored, so
  guessing trips the credential-misuse detector.

## Authorisation

- Five roles: employee, manager (an employee with the manager role), privileged administrator
  (DBA, sysadmin, domain admin: privilege level 4 or more), SOC analyst, and super admin.
- Privileged administrators work in the portal's Admin console. They can only manage accounts and
  grant roles *below* their own level, and every operation is a scored admin event, so the same
  detectors watch the administrators. Anyone else who calls those routes gets a 403 **and** a
  privilege-escalation attempt on their record.
- Path-prefix access is enforced in one middleware (see `api.md`), so a new route is
  console-only unless it is deliberately put under an employee prefix.
- Employee handlers act on the signed-in employee only; the actor is never read from the
  request body.
- The ground-truth "is this an attack" label on synthetic events is stripped from every API
  response and is never read by a detector.

## Input handling

- Every request body is a Pydantic model with types, lengths and patterns (message channel,
  audience, recipient count, OTP format, IP format, known cities).
- Free text (message body, subject, recipient, attachment names, admin reasons) goes through
  `sanitize()`: Unicode NFKC normalisation, and control and bidi-override characters stripped. Those
  characters are how a link or a filename is made to display as something else
  (`invoice‮fdp.exe`).
- The console renders all of it as text through React, never as HTML.

## Transport and browser

- Security headers on every response: `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`,
  `Cache-Control: no-store`. The API sends `Content-Security-Policy: default-src 'none'`,
  because it returns only JSON and PDFs.
- CORS allows only the configured origins (`FRONTEND_URL`, `CORS_ORIGINS`) and the methods the
  app uses (GET, POST, PUT). In Docker the app and the API share an origin through nginx, so
  CORS isn't involved at all.
- The session token is kept in `sessionStorage`: it's scoped to one tab and cleared when the
  tab closes.

## Audit

Every decision, sign-in, honeypot activation, policy change, clearance and incident action is
written to a SHA-256 hash chain with ML-DSA-65 signed checkpoints (see `quantum_safe.md`), and
persisted to `audit_logs` with its hashes. `GET /api/audit/verify` checks the signatures;
`GET /api/db/status` recomputes the chain from the database rows.

## Honeypot safety

- A decoy never contains real data beyond what the employee was already shown on screen.
- A fake transfer never touches the real ledger; each one is audited with
  `real_funds_moved: false`.
- Managers' team views never reveal that someone is in the honeypot. Only the SOC sees it.

## Secrets

`.env` is gitignored. `.env.example` lists every variable with no values. Never commit
`JWT_SECRET`, `POST_QUANTUM_KEY`, database passwords or `GEMINI_API_KEY`.

## Known gaps

- There is no real MFA: step-up is simulated with a one-time code shown on screen.
- Demo credentials are public. Before any real use, change them (or set
  `LOOKOUT_SHOW_DEMO_ACCOUNTS=0` and replace `DEMO_ACCOUNTS`).
- `POST /api/audit/tamper` exists for the demo. Set `LOOKOUT_ALLOW_TAMPER=0` outside a demo.
- Rate-limit and session state is per process; several API replicas would need a shared store.
