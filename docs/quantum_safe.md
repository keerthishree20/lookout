# Quantum-safe security module

Code: `backend/lookout/crypto.py` (primitives) and `backend/lookout/audit.py` (the signed log).
Console page: **Audit & quantum-safe**.

## 1. Algorithms used

| Job | Algorithm | Standard | Library |
|---|---|---|---|
| Signing audit checkpoints | **ML-DSA-65** (formerly CRYSTALS-Dilithium) | NIST FIPS 204 | `dilithium-py` 1.4 |
| Sealing credentials | **ML-KEM-768** (formerly CRYSTALS-Kyber) key encapsulation + AES-256-GCM | NIST FIPS 203 | `kyber-py` 1.2, `cryptography` |
| Chaining audit entries | SHA-256 | FIPS 180-4 | stdlib |

Both PQC libraries are pure Python, so no compiler or liboqs is needed.

## 2. Why these are post-quantum

ECDSA, Ed25519, RSA and X25519 are all broken by Shor's algorithm on a large enough quantum
computer. ML-DSA and ML-KEM rest on the hardness of the Module Learning With Errors problem over
lattices, for which no efficient quantum algorithm is known. NIST standardised both in August
2024 for exactly this reason.

**SHA-256 and AES-256 are not post-quantum cryptography** and Lookout doesn't claim they are.
They are symmetric primitives that Grover's algorithm weakens but doesn't break (roughly
halving the security level, which 256 bits allows for). They are used here alongside the PQC
algorithms, not instead of them.

## 3. What it protects

- **Audit artefacts.** A regulator must be able to prove, years from now, that a recorded
  decision is the one Lookout made. A signature made today with Ed25519 could be forged
  retroactively by whoever owns a quantum computer later, destroying the log's value. ML-DSA
  signatures can't be.
- **Credentials, configuration and key material.** The protected store (`pq_vault.py`) seals, at
  start-up:
  - sensitive configuration (`JWT_SECRET`, `DATABASE_URL` with its password, any API key);
  - synthetic stand-ins for a PAM vault (a core-banking service account, a payment-gateway API key,
    an HSM operator PIN);
  - a snapshot of the detection policy (a security artefact);
  - the ML-DSA **audit signing seed itself**. This is key wrapping: the key that protects the audit
    log is protected too.

  This covers the "harvest now, decrypt later" case: a blob stolen today stays unreadable after
  quantum computers arrive. The API lists what is sealed, never the plaintexts.

## 4. Key generation

- **ML-DSA:** `ML_DSA_65.key_derive(seed)` from a 32-byte seed. The seed comes from
  `POST_QUANTUM_KEY` (or `LOOKOUT_AUDIT_SEED`), so the verification key is the same after a
  restart. With neither set, a fixed demo seed is used, and it is labelled as such.
- **ML-KEM:** `ML_KEM_768.keygen()` once per process.

## 5. Workflow

**Signing.** Every audit entry is hashed as `SHA-256(canonical_json(payload) ‖ prev_hash)`, so
changing any entry breaks every entry after it. Signing each entry would cost about 90 ms, so
the chain head is signed every 25 entries and immediately after anything critical (a block-and-alert, a
honeypot activation, a policy change, a revoked session or disabled account). Transparency logs work the same way. Verification
recomputes the chain and checks every checkpoint signature. The console's tamper button shows
both failures: the edited entry is found, and even if an attacker recomputes every hash, the
signed checkpoint no longer matches.

**Sealing.**

```
(ciphertext_kem, shared_secret) = ML-KEM-768.Encaps(public_key)
key   = HKDF-SHA256(shared_secret, info="lookout/credential-seal/v1")
blob  = AES-256-GCM(key, nonce, plaintext, aad=credential name)
store = {kem_ciphertext, nonce, ciphertext, algorithm}
```

Unsealing decapsulates with the private key and decrypts. Binding the credential name as
associated data means a blob moved to another name fails to decrypt.

**Checking.** `POST /api/crypto/artefacts/verify` reopens every artefact and compares it with the
SHA-256 digest taken when it was sealed. A blob that won't open (wrong key, edited ciphertext) or
opens to something else fails. A failure raises a **"Quantum-Safe Key/Artefact Security Event"**
alert and incident. So does an audit log that no longer verifies. The console's "Corrupt" button
flips one ciphertext byte to demonstrate it; set `allow_tamper_demo` off outside a demo.

## 6. Key storage

In this demo, keys live in process memory; the signing seed comes from an environment variable.
In production:

- the ML-DSA seed and ML-KEM private key would live in an HSM or cloud KMS, never in env vars;
- public keys would be published so auditors can verify the log without trusting Lookout;
- keys would be rotated, with old public keys kept so historical checkpoints still verify.

## 7. Limitations

- The ML-KEM key pair is regenerated on every start, so a blob sealed in one run can't be
  unsealed after a restart. That's fine for the demo; a real deployment needs a persisted,
  KMS-held key.
- The environment-variable seed is padded or truncated to 32 bytes, not stretched through a
  KDF. Use a random value of 32+ characters.
- The pure-Python implementations are meant for education and prototypes: they are
  **not constant-time** and not hardened against side channels. Production should use a vetted
  native implementation such as liboqs or an HSM.
- Only the checkpoints are signed. An entry after the last checkpoint is protected by the hash
  chain alone until the next checkpoint (at most 24 entries, and never across a critical event).
- If the PQC libraries fail to import, Lookout falls back to Ed25519/X25519 and reports
  `quantum_safe: false` on the dashboard, rather than pretending.
