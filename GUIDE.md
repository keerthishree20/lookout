# Lookout — Complete Project Guide

> This guide stands on its own. It explains what Lookout is, how every part works, and why it was
> built this way, with enough real code that you can follow it without opening the repository.
> Repository: https://github.com/keerthishree20/lookout

## Table of Contents

1. Overview
2. Tech Stack & Why
3. Setup from Scratch
4. The Event Model
5. Behavioural Baselines
6. The Detectors
7. The Behavioural Model (IsolationForest)
8. Risk Fusion, Bands and the Graded Response
9. Insider Threat Classification
10. Session Monitoring and Containment
11. The Outbound Message Gateway
12. Quantum-Safe Cryptography
13. The Tamper-Evident Audit Log
14. The Narrator (Explainability in Prose)
15. Synthetic Data and Evaluation
16. The API
17. The Console
18. Configuration & Troubleshooting
19. Complete Feature Summary

---

## 1. Overview

Banks already guard the front door against outsiders. Insiders are harder: employees, contractors
and administrators hold legitimate credentials, and their misuse looks like work. A teller whose
password was phished, an analyst copying the customer table at 2 a.m., a loans officer granting
themselves domain admin, a compromised account texting 50,000 customers a fake KYC link all
arrive with valid credentials.

Lookout watches every action by every identity and asks one question: **is this normal for this
person, given what they are allowed to do?** It answers with a score from 0 to 100, the sentences
that justify the score, and a proportionate response:

| Band | Score | Response |
|---|---|---|
| 🟢 Low | 0–29 | Allow and log |
| 🟡 Medium | 30–59 | Demand a second factor (risk-based authentication) |
| 🔴 High | 60–84 | Block (messages: quarantine for review) |
| ⚫ Critical | 85–100 | Block, revoke the session, page the SOC |

Every decision goes into an audit log that is hash-chained and signed with a post-quantum
signature scheme, so nobody can quietly rewrite it later, and the signatures will still hold once
quantum computers can break today's schemes.

---

## 2. Tech Stack & Why

| Layer | Choice | Why |
|---|---|---|
| API | FastAPI | Typed request models via Pydantic, async SSE support, auto docs at `/docs` |
| Live feed | Server-Sent Events (`sse-starlette`) | One-way server→browser is all a feed needs; simpler than WebSockets, auto-reconnects |
| Models | Pydantic v2 | One definition validates API input *and* serialises decisions |
| Anomaly detection | scikit-learn IsolationForest | Unsupervised, trains only on benign data, fast, no labels needed |
| Signatures | `dilithium-py` (ML-DSA-65, FIPS 204) | Real NIST standard, pure Python, no compiler or liboqs build |
| Key encapsulation | `kyber-py` (ML-KEM-768, FIPS 203) | Same reasons; pairs with AES-256-GCM from `cryptography` |
| Classical fallback | `cryptography` (Ed25519, X25519, AES-GCM, HKDF) | Keeps the system running if PQC is unavailable, and it says so |
| Narrator | Gemini over HTTPS (optional) | Prose summaries; a deterministic template is the default |
| Frontend | Next.js 16 + React 19 + Tailwind 4 | Same stack as the other projects; one client page |
| Icons | lucide-react | Consistent, tree-shaken |
| Tests | pytest (145) | Unit, end-to-end pipeline, API, and a detection-quality floor |

---

## 3. Setup from Scratch

```bash
git clone https://github.com/keerthishree20/lookout
cd lookout/backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q                      # 145 passed
python -m lookout.evaluate               # precision / recall report
uvicorn lookout.api:app --port 8077      # API + live traffic
```

```bash
cd ../frontend
npm install
npm run dev                              # http://localhost:3000
```

The API uses port **8077** rather than 8000, which is usually already taken by another local
FastAPI project. If you change it, set `NEXT_PUBLIC_API_URL` for the frontend.

---

## 4. The Event Model

Everything that enters Lookout is an `Event`, and everything that leaves is a `Decision`
(`backend/lookout/models.py`):

```python
class Event(BaseModel):
    event_id: str
    ts: datetime
    actor: str
    actor_role: Role
    action: Action           # login, login_failed, priv_escalate, db_query, file_access,
                             # config_change, send_message, vault_read, logout
    resource: str = ""
    source_ip: str = "0.0.0.0"
    device_id: str = "unknown"
    geo: Geo
    success: bool = True
    message: MessagePayload | None = None
    meta: dict[str, Any]     # record_count, target_role, session_id, bytes_written ...
    label: ThreatClass | None = None   # ground truth, generated data only
```

Roles map to privilege levels 1–6, from teller to domain admin. Two frozensets define who may speak to
customers at all, and who may do it in bulk:

```python
CUSTOMER_COMMS_ROLES = frozenset({Role.OFFICER, Role.MANAGER, Role.DOMAIN_ADMIN})
BULK_COMMS_ROLES     = frozenset({Role.MANAGER, Role.DOMAIN_ADMIN})
```

**Why a `label` field that detectors never read?** It makes evaluation possible (section 15). The
API strips it from every response so nobody inspecting the console's traffic has to take that on
trust.

---

## 5. Behavioural Baselines

A 2 a.m. login is routine for the on-call sysadmin and alarming for a teller. So every threshold is
measured against the actor's own history (`baselines.py`):

```python
class Baseline:
    hour_counts: list[int]          # 24-bin activity histogram
    countries, devices, ip_prefixes # categorical "seen before" sets
    records_per_query: RunningStat  # Welford online mean / std
    recipients_per_message: RunningStat
    last_login_ts, last_login_geo   # for impossible travel
```

`RunningStat` uses Welford's algorithm, so the profile updates one event at a time with no stored
history. Its z-score floors sigma at `max(1, 10% of mean)`. Without the floor, a teller whose queries are
always exactly 40 rows would get an infinite z-score the first time they read 41.

**Why only learn from allowed events?** In `pipeline.py`:

```python
if action is ActionTaken.ALLOW:
    baseline.observe(event)
```

If a blocked 412,000-row read fed into the baseline, the next exfiltration would look less
unusual. A test checks the baseline mean is unchanged after the exfiltration scenario.

---

## 6. The Detectors

Sixteen detectors, each a function `(event, baseline, ctx) -> list[Signal]`. A `Signal` carries its
points, a complete sentence, and which threat classes it is evidence for:

```python
Signal(
    name="impossible_travel",
    points=40.0,
    explanation="Login from Kyiv, UA is 6,102 km from the previous login in Chennai "
                "28 minutes earlier -- 13,076 km/h, which no traveller can achieve. ...",
    indicates=[ThreatClass.COMPROMISED],
)
```

| Group | Detector | Fires when |
|---|---|---|
| Identity | `impossible_travel` | great-circle distance ÷ elapsed time > 900 km/h |
| | `abnormal_login_time` | the hour holds < 1% of this person's history |
| | `new_device_or_network` | first sighting of a device, country or /24 network |
| | `failed_login_burst` | ≥ 5 failures in 15 min (more points from an unfamiliar origin) |
| | `credential_misuse` | a success after ≥ 5 failures |
| | `containment_breach` | revoked session reused, locked origin retrying, or persisting after a block |
| Privilege | `privilege_escalation` | requested role above held role; scored by levels jumped + burst |
| | `out_of_scope_admin_action` | config change / vault read / escalation by a role without the mandate |
| | `dormant_privileged_account` | level ≥ 4 account active after 45+ idle days |
| Data | `mass_record_access` | rows read far above personal norm, or ≥ 10,000 absolute |
| | `off_hours_data_access` | data access outside 08:00–20:00 |
| | `bulk_file_write` | ≥ 250 MB written in one operation (data staging) |
| | `vault_hoarding` | ≥ 8 vault reads in 30 minutes |
| Messaging | `suspicious_url` | a link impersonates the bank or hides its destination |
| | `bulk_message_blast` | recipients far above sender's norm, or from an unauthorised role |
| | `unauthorized_customer_comms` | customer messaging from a role without the mandate |

### Why logarithmic volume scoring

An early version scored volume linearly in z. A test caught the flaw: a teller whose queries are
always about 40 rows produces z ≈ 3,000 on *any* big read, so 12,000 rows and 400,000 rows both hit the
cap and scored the same. The fix uses two log-scaled terms:

```python
z_term = min(12.0, 4.0 * math.log2(max(z, 4.0) / 4.0))           # unusual for *them*
magnitude = math.log10(max(count, 1) / VOLUME_ABSOLUTE_FLOOR)
floor_term = 10.0 + 12.0 * max(magnitude, 0.0) if over_floor else 0.0  # a lot, full stop
points = min(46.0, 14.0 + z_term + floor_term)
```

`bulk_message_blast` had the same bug and got the same fix, so 900 and 50,000 recipients now
score differently. Both have regression tests.

---

## 7. The Behavioural Model (IsolationForest)

Rules catch the misuse someone thought to describe. `anomaly.py` catches the rest. Each event
becomes a 13-number vector, every feature *relative to the actor's baseline*: hour rarity,
unseen country/device/network, privilege level, log rows, log recipients, worst URL score, recent
failures, log km from last login, events in 30 min, action sensitivity, failed flag.

```python
raw = float(self._forest.decision_function(vector.reshape(1, -1))[0])
score = 1.0 / (1.0 + math.exp(raw * 12.0))          # 0..1, 1 = most anomalous
points = MAX_MODEL_POINTS * score                   # capped at 22 of 100
```

Attributions are the three features furthest from the training mean in standard deviations, so the
model's contribution also carries a sentence: *"driven by log recipients (+8.80 vs typical)"*.

**Why cap the model at 22 points?** An unsupervised model that cannot fully explain itself should
never be the sole reason an employee is locked out. It can tip a borderline case; it cannot create
one.

**Why train only on benign data?** A model trained on attacks learns to call attacks normal.
`train_from_history` skips any event with a non-benign label.

---

## 8. Risk Fusion, Bands and the Graded Response

```
total = min(100, (rule_points + model_points) × (1 + 0.07 × (privilege_level − 1)))
```

The privilege multiplier runs from 1.00 for a teller to 1.35 for a domain admin. The same behaviour
is not equally dangerous: a domain admin can do more with 50,000 rows than a teller can.

`decide()` maps the band to a response, then applies **policy floors**:

```python
if to_customers and hostile_link and _below(action, ActionTaken.QUARANTINE):
    return ActionTaken.QUARANTINE, HOSTILE_LINK_POLICY
```

**Why a floor for hostile links?** A browser test found the gap: one lookalike-domain link to one
customer scored 30, which meant step-up auth. If the sender passed MFA, the link went out. A
malicious insider passes their own MFA without effort, so step-up can't be the control here. Any
customer-facing message with a suspicious link is now held for human review, and the decision
carries the policy text so the analyst can see why a score of 30 was quarantined.

**Risk-based authentication.** The strength of the step-up scales with privilege and score:

```python
if event.privilege >= 5 or risk.total >= 50:  return "hardware_security_key"
if event.privilege >= 3 or risk.total >= 40:  return "totp_and_manager_approval"
return "push_notification"
```

---

## 9. Insider Threat Classification

Each signal lists the classes it supports, **primary first**. The primary class gets the signal's
full points and each secondary class gets half:

```python
for i, cls in enumerate(signal.indicates):
    weights[cls] += signal.points * (1.0 if i == 0 else 0.5)
```

Without the weighting, an escalation attempt (`[PRIVILEGE_ABUSE, MALICIOUS]`) tied and the
severity tie-break labelled it malicious.

Two more rules:

- **Containment signals don't vote.** "They kept going after being blocked" raises risk but says
  nothing about *what kind* of insider this is. Those events inherit the class their session
  already has.
- **"Compromised" is sticky.** The classes describe the employee, not the act. Once a session is
  under someone else's control, everything done in it belongs to the intruder. Labelling the
  employee "malicious" for the intruder's query would be wrong.

The negligent-insider scenario tests the distinction. A teller emails 900 customers a
*genuine* link. `bulk_message_blast` classes volume with a clean link as `NEGLIGENT` and
volume with a hostile link as `MALICIOUS`. The result is quarantine, never a SOC page.

---

## 10. Session Monitoring and Containment

`context.py` holds the consequences of earlier decisions:

```python
self.revoked_sessions: set[str]
self.locked_origins: set[tuple[str, str]]      # (actor, source_ip)
self.session_strikes: dict[str, int]           # blocks/holds already issued
self.session_class: dict[str, ThreatClass]
```

`pipeline._respond()` updates it after each decision:

- BLOCK_AND_ALERT, or BLOCK on a *login*, revokes the session
- BLOCK_AND_ALERT on a login attempt locks the source IP out of that account
- any block or quarantine is a strike against the session

**The bug this fixed.** In the credential-stuffing scenario the Lagos login was blocked, but only
BLOCK_AND_ALERT revoked sessions, so the nine vault reads that followed on the same session were
*allowed*. A refused login now leaves no usable session, and a regression test covers it.

---

## 11. The Outbound Message Gateway

`POST /api/messages/scan` is where every staff SMS, email or push is checked before it leaves. URLs
are extracted from the **body** with a regex rather than taken from a separate field, because a
sender hiding a link would simply leave the field empty.

`urlcheck.py` decides offline whether a link is hostile. With no threat-intel feed, it asks the question that
matters for internal phishing, **does this link claim to be us when it isn't?**:

```python
HOMOGLYPHS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", ...}

def _fold(text):   # visual twins become string twins
    folded = "".join(HOMOGLYPHS.get(c, c) for c in text.lower())
    return folded.replace("rn", "m").replace("vv", "w").replace("-", "")
```

After folding, `levenshtein(host, corporate) ≤ 2` flags lookalikes such as `meridianbamk.com`,
`merid1anbank.com`, `rneridianbank.com` and `meridian-bank.com`. Other findings: brand embedded under a
foreign domain, shorteners, bare IPs, punycode, abuse-heavy TLDs, credential bait (`kyc`, `otp`,
`verify` ...), plain HTTP, deep subdomain chains.

Message risk combines URL reputation, sender behaviour (z against their own send history), content,
audience and privilege, which is the formula from the brief. The graded outcomes: deliver, hold for
step-up, quarantine (a reviewer can release it, and the release is audited), or block and page.

---

## 12. Quantum-Safe Cryptography

Two jobs, two NIST standards (`crypto.py`):

| Job | Algorithm | Threat it answers |
|---|---|---|
| Sign the audit log | ML-DSA-65 (FIPS 204) | Ed25519/ECDSA signatures become forgeable once a large quantum computer exists, which retroactively destroys a log's evidential value |
| Seal credentials | ML-KEM-768 (FIPS 203) + AES-256-GCM | Harvest now, decrypt later: vault blobs stolen today must stay unreadable |

```python
def seal(self, plaintext, aad=b""):
    shared, kem_ct = ML_KEM_768.encaps(self._ek)
    nonce = os.urandom(12)
    ct = AESGCM(_derive_key(shared)).encrypt(nonce, plaintext, aad)
    return SealedBlob(b64(kem_ct), b64(nonce), b64(ct), self.algorithm)
```

The vault path is the AES-GCM associated data, so a sealed blob moved to a different path won't
decrypt (tested). Both schemes sit behind small interfaces with classical fallbacks. On a host
without the PQC libraries the dashboard shows "classical" rather than claiming quantum safety.

**Why pure-Python implementations?** `liboqs-python` compiles liboqs from source at import time.
`dilithium-py` and `kyber-py` install with pip in seconds and implement the same standards. The
cost is speed (about 90 ms per ML-DSA signature), which is why the audit log signs checkpoints rather than every entry.

---

## 13. The Tamper-Evident Audit Log

```python
entry_hash = sha256(canonical({"seq", "ts", "kind", "payload", "prev": prev_hash}))
```

Each entry links to the one before. Every 25 entries, and immediately after anything critical, the
chain head is **signed with ML-DSA**. Verification recomputes the chain and checks every
signature. Three attacks are tested:

| Attack | Caught by |
|---|---|
| Edit a payload, leave the hash | content no longer matches its hash, reported at that entry |
| Edit a payload and recompute its hash | the next entry's `prev_hash` no longer links |
| Rewrite the whole chain consistently | the signed checkpoint no longer verifies without the private key |

The console's **Forge entry** button runs the first attack live. **Reset demo** restores state.

---

## 14. The Narrator (Explainability in Prose)

The score, class and action are all fixed before `narrator.py` runs. The narrator only writes them
up. With no key it builds the summary from the top two signals:

> p.nair (officer) scored 30/100 for sending an SMS to 1 recipient -- medium risk, consistent with
> deliberate misuse. Outbound SMS to 1 recipient contains https://meridianbamk.com/login -- host
> resembles the corporate domain meridianbank.com ... Held by policy: Customer-facing messages
> carrying a suspicious link are never delivered without human review, whatever the sender's risk score.

With `GEMINI_API_KEY` set, Gemini receives the same evidence and is told to invent nothing and
neither soften nor escalate. If a call fails once, the narrator marks itself degraded and uses the
template from then on, so a network outage never stalls decisions.

---

## 15. Synthetic Data and Evaluation

Real privileged-access logs from a bank can't be obtained, and an approximation scraped from
elsewhere would be worse than none. `generator.py` simulates **Meridian Bank**: 12 staff across
Chennai, Bengaluru, Mumbai and Singapore, each with their own hours, devices, query volumes and
messaging habits. The simulation includes the awkward benign cases: managers running 400–2,500-recipient
campaigns, weekend on-call admins, one or two mistyped passwords a day.

`evaluate.py` trains on 30 days and scores a held-out week plus the six scenarios:

```
precision              : 1.000
recall                 : 0.967
false positive rate    : 0.0000  (0 of 940 benign)
threat classification  : 1.000  (29 of 29 detected incidents named correctly)
```

Across five other seeds the worst case was one false positive in 896.

**What this does and doesn't prove.** Lookout generated both the attacks and the normal traffic,
so these numbers show internal consistency and that ordinary work doesn't trigger alerts. They are
**not** a claim about a real bank. `tests/test_evaluation.py` sets floors below today's numbers so
that a later change can't quietly trade recall for fewer alerts.

The generator also had a bug of its own: simulated tellers sent customer messages, which the
policy forbids, so "benign" data broke the rules it was scored against. That was the only
false positive. Fixing the simulation, not the detector, was the right call.

---

## 16. The API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health`, `/api/stats`, `/api/crypto` | status, counters, crypto status |
| GET | `/api/decisions?limit&flagged_only` | recent decisions |
| GET | `/api/stream` | SSE live feed (`event: decision`) |
| POST | `/api/events` | score an arbitrary event |
| GET / POST | `/api/scenarios`, `/api/scenarios/{key}/run` | list / inject incidents |
| POST | `/api/messages/scan` | the message gateway |
| POST | `/api/urls/inspect` | URL reputation alone |
| GET / POST | `/api/quarantine`, `/api/quarantine/{id}/release` | held messages |
| GET | `/api/users`, `/api/users/{actor}` | baselines |
| GET | `/api/audit`, `/api/audit/verify` | chain and verification |
| POST | `/api/audit/tamper/{seq}` | demo forgery (disable with `LOOKOUT_ALLOW_TAMPER=0`) |
| POST | `/api/credentials/seal` | ML-KEM sealing round-trip |
| GET | `/api/evaluation` | cached precision/recall |
| POST | `/api/traffic/{pause,resume}`, `/api/reset` | demo controls |

Interactive docs: `http://localhost:8077/docs`.

---

## 17. The Console

One client page (`frontend/src/app/page.tsx`) with five tabs:

- **Console**: scenario launcher, live feed over `EventSource`, and the **Why?** panel with the score
  arithmetic, each signal's points and sentence, and the event's details.
- **Message gateway**: presets (phishing blast, lookalike, shortener, legitimate), verdict, per-URL
  findings, quarantine queue with release.
- **Identities**: every baseline: privilege bars, usual hours, rows/query, reach, countries, peak risk.
- **Audit & QPC**: algorithm status, credential sealing, chain listing, verify / forge / reset.
- **Evaluation**: the metrics above with the synthetic-data caveat shown first.

It was checked in headless Chromium: every tab, scenario injection, forgery detection, no console
errors, and no horizontal scroll at 390 px wide. `networkidle` never fires on this page because the
SSE connection stays open. Browser tests must wait on `domcontentloaded`.

---

## 18. Configuration & Troubleshooting

| Variable | Default | Effect |
|---|---|---|
| `GEMINI_API_KEY` | empty | enables LLM narratives |
| `GEMINI_MODEL` | `gemini-2.5-flash` | narrator model |
| `LOOKOUT_AUDIT_SEED` | demo seed | stable ML-DSA key across restarts; change for anything real |
| `LOOKOUT_LIVE_TRAFFIC` | `1` | background benign activity |
| `LOOKOUT_TRAFFIC_INTERVAL` | `1.5` | seconds between background events |
| `LOOKOUT_ALLOW_TAMPER` | `1` | demo forgery endpoint |
| `CORS_ORIGINS` | empty | extra origins; localhost is always allowed |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8077` | frontend → API (set at build time) |

| Symptom | Cause / fix |
|---|---|
| Red "Cannot reach the Lookout API" banner | API not running, or on another port: set `NEXT_PUBLIC_API_URL` and rebuild |
| `address already in use` on start | another app holds the port; pick another with `--port` |
| Feed says "reconnecting" | SSE dropped; the browser retries automatically |
| Dashboard shows "classical" crypto | `dilithium-py` / `kyber-py` not installed in this venv |
| Re-running credential stuffing looks different | intended: the attacker's IP is still locked from the first run. Use **Reset** |

---

## 19. Complete Feature Summary

### All Features Built

| Feature | File |
|---|---|
| Per-identity online baselines | `baselines.py` |
| 16 explainable detectors | `rules/` |
| IsolationForest with attributions, capped contribution | `anomaly.py` |
| Privilege-weighted fusion, 4 bands, graded response | `scoring.py` |
| Policy floor: hostile links to customers always reviewed | `scoring.decide` |
| Risk-based step-up scaled by privilege | `scoring.step_up_requirement` |
| Insider classification with primary weighting, sticky compromise | `scoring.classify` |
| Session revocation, origin lock-out, persistence detection | `context.py`, `pipeline._respond` |
| Offline URL reputation with homoglyph folding | `urlcheck.py` |
| Message gateway + quarantine with audited release | `api.py`, `pipeline.release` |
| ML-DSA-65 signed audit checkpoints | `crypto.py`, `audit.py` |
| ML-KEM-768 credential sealing bound to vault path | `crypto.py` |
| Tamper demo with exact-entry detection | `audit.tamper`, `/api/audit/tamper` |
| Template / Gemini narrator | `narrator.py` |
| Synthetic bank + 6 labelled scenarios | `generator.py`, `scenarios.py` |
| Precision / recall / classification evaluation | `evaluate.py` |
| SSE live console, 5 tabs | `frontend/` |
| 145 tests, CI for backend and frontend | `backend/tests/`, `.github/workflows/ci.yml` |

### Data Flow

```
             ┌────────────── live traffic / scenario / gateway / POST /api/events
             ▼
         Event ──► Baseline (read) ──► 16 detectors ─┐
                         │                           ├─► fuse × privilege ─► band
                         └──► 13 features ─► Forest ─┘                        │
                                                                              ▼
            classify (primary-weighted, session-aware) ◄──── decide + policy floors
                         │                                                    │
                         ▼                                                    ▼
                  narrator (template | Gemini)                 respond: revoke / lock / strike / quarantine
                         │                                                    │
                         └──────────────► AuditLog.append (SHA-256 chain, ML-DSA checkpoint)
                                                        │
                              Baseline.observe (only if allowed) ◄─┘──► SSE ─► console
```

### Tech Stack at a Glance

```
Backend   Python 3.12 · FastAPI · Pydantic v2 · sse-starlette · scikit-learn · numpy
Crypto    ML-DSA-65 (dilithium-py) · ML-KEM-768 (kyber-py) · AES-256-GCM · HKDF · Ed25519/X25519 fallback
Frontend  Next.js 16 · React 19 · Tailwind CSS 4 · lucide-react
Testing   pytest (145) · GitHub Actions
          (the browser checks in section 17 used Playwright from outside this repo; they are not part of the suite)
```
