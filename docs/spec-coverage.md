# Spec coverage

Section by section against the project specification ("Build a Complete AI-Based Privileged Access
Misuse & Insider Threat Detection Platform", 39 sections plus the honeypot transfer requirement).

**Done** means built and exercised by a test or the browser check. **Partly** says what is missing.
Every number below comes from Lookout's own synthetic data; see the README for what that does and
doesn't prove.

| § | Requirement | Status | Where |
|---|---|---|---|
| 1 | Continuous monitoring; dynamic risk score; Low → allow, Medium → verify, High → block/quarantine, Critical → block + revoke + alert; ML combined with deterministic rules | Done | `pipeline.py`, `scoring.decide`; IsolationForest, RandomForest and an NLP model alongside 27 rule detectors |
| 2 | Architecture: auth → risk-based auth → session monitoring → behaviour analysis → ML → risk → policy → allow/verify/block → dashboard → SOC; message gateway path | Done | [architecture.md](architecture.md) |
| 3 | Stack: React, TypeScript, Vite, Tailwind, Recharts, Axios, React Router, WebSockets; FastAPI, SQLAlchemy, Pydantic, JWT, Pandas, NumPy, scikit-learn, SHAP; PostgreSQL; Isolation Forest + Random Forest/XGBoost | Done | Random Forest chosen (the spec allows either); pandas cleans the dataset (`ml/cleaning.py`) |
| 3 | Security: hashing, JWT, RBAC, MFA simulation, risk-based auth, sessions, rate limiting, audit, validation, input sanitisation | Done | `auth.py`, `api.py` (`sanitize`, Pydantic limits), [security.md](security.md) |
| 3 | Quantum-safe protection of credentials, security/audit artefacts, config, key wrapping; classical and PQ clearly separated | Done | `pq_vault.py`, `crypto.py`, [quantum_safe.md](quantum_safe.md) |
| 4 | Employee: login, own profile, permitted resources, messages, own activity, request access, answer MFA | Done | portal tabs: Customers, Fund transfer, Access requests, My profile |
| 4 | Manager: team activity, approve requests, risk summaries | Done | My team tab (`/api/team/*`) |
| 4 | Privileged Administrator: admin operations, sensitive resources, manage users, roles, policies, stronger monitoring | Done | Admin console tab for level 4+ (`/api/portal/admin/*`); every operation is a scored CONFIG_CHANGE; anyone else trying is a privilege-escalation attempt |
| 4 | SOC: dashboard, alerts, incidents, risk, explanations, quarantine, review, revoke sessions, disable accounts | Done | the 17-page console |
| 4 | Super Admin: platform, security policies, roles, system configuration | Done | Security policies; Settings → Roles and permissions, System configuration |
| 5 | Login with username/email, password, device, IP, location, timestamp; login risk score from time, history, IP, device, geo, failures, privilege, travel | Done | `POST /api/auth/login` returns `risk`; sign-in context selector on `/login`. The role is taken from the account, not typed in |
| 5 | 02:30 + new device + new country + unknown IP → high-risk login | Done | `compound_login_anomaly`; the `abnormal_login` scenario scores 66.5 HIGH |
| 6 | Unusual time, new device/IP/location, failed logins, simultaneous sessions, suspicious frequency; `{risk_score, risk_level, reason[]}` | Done | `rules/identity.py`, `rules/sessions.py` (`concurrent_sessions`, `login_frequency`) |
| 7 | Impossible travel (distance ÷ time) | Done | `impossible_travel`; "Simulate Impossible Travel" (Bengaluru 10:00 → New York 10:20) |
| 8 | PAM: user, role, privilege, resource, action, time, device, IP, session; customer DB etc.; deny / allow / allow + enhanced monitoring | Done | `access_decision`, My profile → Protected systems, Access control page |
| 9 | Privilege escalation: admin resources, role/permission/policy changes; block, log, alert, revoke | Done | `privilege_escalation`, `out_of_scope_admin_action`, admin-console attempts by non-admins |
| 10 | Session monitoring incl. query rate (10/h → 500 in 5 min), IP/device change, failed authorisation | Done | `query_rate_burst`, `session_context_change`, `failed_authorization`, `containment_breach` |
| 11 | Credential misuse → COMPROMISED | Done | `credential_misuse`, `failed_login_burst`, compound login anomaly |
| 12 | ML classification NORMAL/NEGLIGENT/MALICIOUS/COMPROMISED/PRIVILEGE_ABUSE with confidence | Done | `lookout/ml/model.py`; `decision.ml` |
| 13 | Per-employee baseline and deviation score; ML, not only thresholds | Done | `baselines.py`, `anomaly.py`, `behaviour_deviation` feature |
| 14 | Message gateway for simulated SMS / email / notification; nothing really sent | Done | Message scanner page, `POST /api/messages/scan` |
| 15 | Content analysis: text, URLs, attachment metadata, sender, recipient, destination, volume, privilege; phishing, credential harvesting, leakage, repeated fraud; ML/NLP, not only keywords | Done | `rules/content.py`, `nlp.py` (TF-IDF + logistic regression, trained on a **synthetic** corpus) |
| 16 | URL extraction and risk: domain, length, suspicious characters, IP host, HTTPS, shortener, TLD, obfuscation; URL risk 0-100 | Done | `urlcheck.py` (`risk_score`, `features`). Domain age and live redirect chains are not looked up (no external service), which the spec allows |
| 17 | Message risk = URL + sender + content + destination + privilege + volume, 0-100; bands 0-29/30-59/60-79/80-100; admin-configurable | Done | `message_risk.py` breakdown; bands in `policy.py` (critical from 80), editable by the Super Admin |
| 18 | Low allow, Medium verify, High quarantine, Critical block + alert + audit | Done | `scoring.decide` |
| 19 | Quarantine with ID, sender, recipient, time, risk, reasons, URLs, classification; Release / Block / Delete / Investigate; only security staff | Done | Quarantine page; `/api/quarantine/{id}/release|block|delete|investigate` |
| 20 | Privileged communication control: normal staff no bulk, authorised staff approved comms, admins need MFA + monitoring; configurable | Done | communication policy (`policy.py`), `unauthorized_customer_comms`, privileged-comms step-up floor |
| 21 | Bulk fraud: detect volume, raise risk, block further messages, revoke session, critical alert, incident, dashboard | Done | `bulk_message_blast`, `repeated_message`, containment; "Simulate Bulk Fraud Messages" |
| 22 | Risk-based access control: role + behaviour + risk policy engine | Done | `access_decision` |
| 23 | XAI with SHAP; `GET /api/risk/{id}/explanation` | Done | every signal carries its sentence; SHAP for the classifier |
| 24 | Real-time alerts of every listed type incl. Quantum-Safe Key/Artefact Security Event; fields; OPEN/INVESTIGATING/RESOLVED/FALSE_POSITIVE | Done | `incidents.py`; the quantum-safe event is raised when an audit or artefact check fails |
| 25 | Dashboard stats and charts (risk over time, classes, score distribution, message results, login anomalies, escalations); live alerts over WebSocket | Done | Dashboard page |
| 26 | User risk page: history of logins, devices, locations, sessions, resources, messages, alerts; risk trend; sudden changes highlighted | Done | Users → user page (daily peak risk, sudden-change list) |
| 27 | Incidents: ID, type, user, severity, score, timeline, evidence, AI explanation, actions, analyst, status; assign, notes, block user, revoke session, resolve | Done | Incidents page |
| 28 | Audit every sensitive action; immutable as far as practical; hashing; quantum-safe protection | Done | `audit.py`: SHA-256 chain + ML-DSA-65 checkpoints; the DB copy is re-verified from its rows |
| 29 | Quantum-safe module with the seven documented points; no false claims about SHA/AES | Done | [quantum_safe.md](quantum_safe.md), Audit & quantum-safe page |
| 30 | PostgreSQL tables as listed | Done | 15 tables, [database.md](database.md) |
| 31 | REST routes as listed, with schemas | Done | all 24 listed routes exist; [api.md](api.md), `/swagger` |
| 32 | ML pipeline: raw → cleaning → features → split → train → evaluate → serialise → inference; no retraining per request | Done | `ml/`, `lookout/ml/`; joblib; trained once at start-up or image build |
| 33 | Synthetic dataset, 10,000+ rows, listed features, realistic imbalance, marked synthetic | Done | `backend/datasets/insider_sessions.csv` (10,600 rows, 88.7% normal) |
| 34 | Accuracy, precision, recall, F1, confusion matrix, ROC-AUC, PR-AUC; honest; recall on malicious/compromised | Done | [ml.md](ml.md); ML insights page shows the real numbers, including the weak negligent class |
| 35 | The 17 pages | Done | all 17 routes |
| 36 | Dark SOC UI; sidebar, cards, tables, charts, risk badges, alert panels, modals, search, filtering, pagination; green/yellow/orange/red; responsive | Done | modals on Quarantine and Messages; search, filters and pagination on the long tables; no horizontal scroll at 390 px |
| 37 | WebSockets for alerts, risk changes, message results, session changes, critical incidents | Done | `/api/ws` event types `decision`, `alert`, `risk`, `message`, `session`, `incident` |
| 38 | Simulation page with the nine named buttons | Done | Simulation page, plus three extra scenarios |
| 39 | Example scenario: allowed → additional verification → high risk → blocked → suspicious message | Done (statuses) | `attack_story`: 2.5 allow → 46.9 step-up → 73.2 block → 100 block and alert → phishing SMS blocked. The statuses match; the spec's example numbers (12, 68, 78, 92) are illustrative and Lookout's scores differ |
| — | Honeypot: on high-risk activity, the same transfer page runs on fake values, nothing really moves, everything recorded and sent to the monitoring team | Done | `portal.py`, `banking.py`; Honeypot page |

## Not done

- **Public deployment** is prepared, not live: `render.yaml` plus the root `Dockerfile` deploy it to
  Render as one service with a free PostgreSQL database, but someone has to click "Apply" in their
  Render account. The image was tested locally under Render's 512 MB limit: it peaked at 281 MB
  through both browser test runs.
- **Real data.** Every model is trained, and every number is measured, on synthetic data.
