"""Post-quantum protection of stored artefacts.

The spec asks for quantum-safe protection of sensitive credentials, security
artefacts, audit artefacts, key material and sensitive configuration, kept
clearly apart from the classical crypto that authenticates users. This is that
store:

* every artefact is sealed with ML-KEM-768 + AES-256-GCM, with its name bound
  as associated data so a blob can't be swapped onto another name;
* the store keeps a SHA-256 digest of each plaintext, so a periodic check can
  prove every artefact still opens to exactly what was sealed;
* key material is *wrapped*: the audit log's ML-DSA signing seed is sealed
  here, so the key that signs the log is itself protected against
  harvest-now-decrypt-later.

Plaintexts are never returned by the API. A failed check raises a
"Quantum-Safe Key/Artefact Security Event" alert.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .crypto import SealedBlob, unb64

CATEGORIES = (
    "sensitive_configuration",
    "credential",
    "key_material",
    "security_artefact",
    "audit_artefact",
)


@dataclass
class Artefact:
    name: str
    category: str
    description: str
    blob: SealedBlob
    digest: str
    sealed_at: datetime
    plaintext_bytes: int
    last_check: str = "never"

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "algorithm": self.blob.algorithm,
            "plaintext_bytes": self.plaintext_bytes,
            "ciphertext_bytes": len(unb64(self.blob.ciphertext)),
            "kem_ciphertext_bytes": len(unb64(self.blob.kem_ciphertext)),
            "sha256_prefix": self.digest[:16],
            "sealed_at": self.sealed_at.isoformat(),
            "last_check": self.last_check,
        }


class ProtectedStore:
    def __init__(self, sealer) -> None:
        self.sealer = sealer
        self._items: dict[str, Artefact] = {}
        self._lock = threading.Lock()

    def protect(self, name: str, category: str, secret: bytes | str, description: str) -> Artefact:
        if category not in CATEGORIES:
            raise ValueError(f"category must be one of {CATEGORIES}")
        raw = secret.encode() if isinstance(secret, str) else secret
        blob = self.sealer.seal(raw, aad=name.encode())
        art = Artefact(
            name=name,
            category=category,
            description=description,
            blob=blob,
            digest=hashlib.sha256(raw).hexdigest(),
            sealed_at=datetime.now(timezone.utc),
            plaintext_bytes=len(raw),
        )
        with self._lock:
            self._items[name] = art
        return art

    def list(self) -> list[dict[str, Any]]:
        return [a.as_dict() for a in self._items.values()]

    def verify(self) -> list[dict[str, Any]]:
        """Open every artefact and compare it with the digest taken at sealing."""
        results = []
        for art in list(self._items.values()):
            try:
                ok = hashlib.sha256(self.sealer.unseal(art.blob, aad=art.name.encode())).hexdigest() == art.digest
                reason = "opens and matches its digest" if ok else "opened, but the contents changed"
            except Exception as e:  # noqa: BLE001 -- any failure to open is the finding
                ok, reason = False, f"cannot be opened ({type(e).__name__}): ciphertext or key tampered with"
            art.last_check = "ok" if ok else "FAILED"
            results.append({"name": art.name, "category": art.category, "ok": ok, "reason": reason})
        return results

    def tamper(self, name: str) -> bool:
        """Demo only: flip one ciphertext byte, as an attacker editing the store would."""
        art = self._items.get(name)
        if art is None:
            return False
        import base64

        ct = bytearray(base64.b64decode(art.blob.ciphertext))
        ct[0] ^= 0x01
        art.blob = SealedBlob(
            kem_ciphertext=art.blob.kem_ciphertext,
            nonce=art.blob.nonce,
            ciphertext=base64.b64encode(bytes(ct)).decode(),
            algorithm=art.blob.algorithm,
        )
        return True


#: Which cryptography protects what, and whether it is quantum-safe. The spec
#: asks for classical authentication to be kept clearly apart from the
#: post-quantum protection of artefacts; this is that table.
CRYPTO_LAYERS: list[dict[str, str]] = [
    {"protects": "Session tokens (JWT)", "algorithm": "HMAC-SHA256 (HS256)", "family": "classical",
     "note": "Symmetric and short-lived (8 h), and revocable server-side; Grover's algorithm only halves its margin."},
    {"protects": "Stored passwords", "algorithm": "PBKDF2-HMAC-SHA256, per-account salt", "family": "classical",
     "note": "A slow hash, not encryption. It is not post-quantum cryptography and isn't claimed to be."},
    {"protects": "Browser to server transport", "algorithm": "TLS, terminated in front of nginx when deployed", "family": "classical",
     "note": "Not configured in the local demo (plain HTTP on localhost)."},
    {"protects": "Audit log chaining", "algorithm": "SHA-256 hash chain", "family": "classical hash",
     "note": "Tamper evidence only. The signatures below are what make it quantum-safe."},
    {"protects": "Audit log signatures", "algorithm": "ML-DSA-65 (FIPS 204)", "family": "post-quantum",
     "note": "Checkpoints signed every 25 entries and after every critical event."},
    {"protects": "Credentials, configuration, security artefacts", "algorithm": "ML-KEM-768 (FIPS 203) + AES-256-GCM", "family": "post-quantum",
     "note": "Each artefact sealed under its own encapsulated key, name bound as associated data."},
    {"protects": "Key material", "algorithm": "ML-KEM-768 key wrapping", "family": "post-quantum",
     "note": "The ML-DSA signing seed is itself sealed in the protected store."},
]
