# Database

PostgreSQL 16 in Docker; any SQLAlchemy URL works for development. Set `DATABASE_URL`:
`postgresql://...` is rewritten to the psycopg 3 driver automatically. If `DATABASE_URL` is unset,
Lookout runs in memory only and `/api/db/status` reports `enabled: false`.

Tables are created on start (`Base.metadata.create_all`). Roles, permissions and users are seeded
idempotently from `auth.DEMO_ACCOUNTS` and the role model in `models.py`.

## Tables

| Table | Key columns | Written when |
|---|---|---|
| `roles` | name, privilege_level | seed |
| `permissions` | name, resource, action | seed |
| `role_permissions` | role_id → roles, permission_id → permissions | seed |
| `users` | username, email, password_hash (PBKDF2), role_id, department, status | seed; disable/enable |
| `login_events` | user_id, timestamp, ip_address, device_id, lat/long, location, success, risk_score, risk_level | every login decision |
| `sessions` | user_id, device_id, ip_address, start_time, last_activity, status, risk_score | login; revocation |
| `activity_logs` | user_id, event_id, activity_type, resource, action, metadata (JSON), risk_score | every decision |
| `risk_scores` | user_id, event_id, score, risk_level, explanation (JSON signals) | every decision |
| `threat_events` | user_id, event_id, event_type, classification, confidence, ml_classification | decisions classified as a threat |
| `messages` | sender_id, recipient, message_type, content, recipient_count, status, risk_score | every scanned message |
| `url_analysis` | message_id → messages, url, risk_score, classification, reason | each link in a message |
| `quarantined_messages` | run_id, message_id, reason, status, reviewed_by, reviewed_at | quarantine; release |
| `alerts` | run_id, user_id, severity, alert_type, risk_score, status, detail (JSON) | alert opened or updated |
| `incidents` | run_id, title, severity, user_id, status, assigned_to, resolved_at, detail (JSON) | incident opened, assigned, noted, resolved |
| `audit_logs` | run_id, seq, action, resource, timestamp, integrity_hash, prev_hash, payload (JSON) | every audit entry |

Indexes are on every `user_id`, every `event_id` and the time columns used for dashboards
(`activity_logs.timestamp`, `login_events.timestamp`, `risk_scores.timestamp`).

## Runs

Each API start is a **run** with a fresh `run_id` (UUID). The in-memory audit chain starts again
at sequence 0 on each run, so `audit_logs`, `alerts`, `incidents` and `quarantined_messages` carry
`run_id`: their IDs and chain are only unique within a run. Nothing is deleted, so earlier runs
remain queryable.

## Integrity check

`GET /api/db/status` recomputes the SHA-256 chain of the current run's `audit_logs` rows from the
database: each row's `integrity_hash` must equal the hash of its payload and `prev_hash`. It
reports `ok`, the row count, and `broken_at` for the first row that doesn't match. This catches
someone editing the table directly, not only the in-memory log. The ML-DSA checkpoint
signatures are checked by `GET /api/audit/verify`.

## Tests

`tests/test_db.py` runs against SQLite by default. To run the same tests against PostgreSQL:

```bash
LOOKOUT_TEST_DATABASE_URL=postgresql://lookout:lookout@localhost:5432/lookout_test python -m pytest tests/test_db.py
```

CI does this with a Postgres service container.
