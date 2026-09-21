"""Quantum-safe cryptography for audit signing and credential sealing.

Two jobs, two NIST algorithms:

* **Signing the audit log** -- ML-DSA-65 (FIPS 204, formerly CRYSTALS-Dilithium).
  A regulator needs to be able to prove that a recorded decision is the one
  Lookout actually made, years from now. A signature made today with ECDSA or
  Ed25519 is forgeable by anyone who later owns a cryptographically relevant
  quantum computer, which retroactively destroys the value of the log. ML-DSA
  is not.

* **Sealing credential artefacts** -- ML-KEM-768 (FIPS 203, formerly
  CRYSTALS-Kyber) to establish a key, AES-256-GCM to encrypt under it. This is
  the "harvest now, decrypt later" case: a vault blob stolen today must still
  be unreadable after quantum computers arrive.

Both are behind small interfaces with classical fallbacks (Ed25519, X25519), so
the system still runs if the PQC dependency is unavailable -- it just reports
``quantum_safe=False`` and says so on the dashboard rather than pretending.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:  # pragma: no cover - exercised by whichever branch the host supports
    from dilithium_py.ml_dsa import ML_DSA_65

    _HAVE_ML_DSA = True
except Exception:  # pragma: no cover
    _HAVE_ML_DSA = False

try:  # pragma: no cover
    from kyber_py.ml_kem import ML_KEM_768

    _HAVE_ML_KEM = True
except Exception:  # pragma: no cover
    _HAVE_ML_KEM = False


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# --------------------------------------------------------------------------- #
# Signing
# --------------------------------------------------------------------------- #


@runtime_checkable
class Signer(Protocol):
    """Anything that can sign the audit log."""

    algorithm: str
    standard: str
    quantum_safe: bool

    def sign(self, data: bytes) -> bytes: ...

    def verify(self, data: bytes, signature: bytes) -> bool: ...

    @property
    def public_key(self) -> bytes: ...


class MLDSASigner:
    """ML-DSA-65 -- NIST FIPS 204, security category 3."""

    algorithm = "ML-DSA-65"
    standard = "NIST FIPS 204"
    quantum_safe = True

    def __init__(self, seed: bytes | None = None) -> None:
        if not _HAVE_ML_DSA:  # pragma: no cover
            raise RuntimeError("dilithium-py is not installed")
        # ML-DSA keygen is deterministic given a 32-byte seed, which lets the
        # demo reproduce the same verification key on every restart.
        self._pk, self._sk = (
            ML_DSA_65.key_derive(seed) if seed else ML_DSA_65.keygen()
        )

    def sign(self, data: bytes) -> bytes:
        return ML_DSA_65.sign(self._sk, data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            return bool(ML_DSA_65.verify(self._pk, data, signature))
        except Exception:
            return False

    @property
    def public_key(self) -> bytes:
        return self._pk


class Ed25519Signer:
    """Classical fallback. Fast, small, and not quantum-safe -- we say so."""

    algorithm = "Ed25519"
    standard = "RFC 8032 (classical)"
    quantum_safe = False

    def __init__(self, seed: bytes | None = None) -> None:
        self._sk = (
            ed25519.Ed25519PrivateKey.from_private_bytes(seed[:32])
            if seed
            else ed25519.Ed25519PrivateKey.generate()
        )
        self._pk = self._sk.public_key()

    def sign(self, data: bytes) -> bytes:
        return self._sk.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._pk.verify(signature, data)
            return True
        except Exception:
            return False

    @property
    def public_key(self) -> bytes:
        return self._pk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )


def build_signer(prefer_pqc: bool = True, seed: bytes | None = None) -> Signer:
    """Return the strongest signer available on this host."""
    if prefer_pqc and _HAVE_ML_DSA:
        return MLDSASigner(seed)
    return Ed25519Signer(seed)


# --------------------------------------------------------------------------- #
# Sealing (credential artefacts at rest)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SealedBlob:
    """An encrypted artefact plus the KEM ciphertext needed to reopen it."""

    kem_ciphertext: str
    nonce: str
    ciphertext: str
    algorithm: str

    def to_dict(self) -> dict[str, str]:
        return {
            "kem_ciphertext": self.kem_ciphertext,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "algorithm": self.algorithm,
        }


class MLKEMSealer:
    """ML-KEM-768 (FIPS 203) key encapsulation + AES-256-GCM."""

    algorithm = "ML-KEM-768 + AES-256-GCM"
    standard = "NIST FIPS 203"
    quantum_safe = True

    def __init__(self) -> None:
        if not _HAVE_ML_KEM:  # pragma: no cover
            raise RuntimeError("kyber-py is not installed")
        self._ek, self._dk = ML_KEM_768.keygen()

    @property
    def public_key(self) -> bytes:
        return self._ek

    def seal(self, plaintext: bytes, aad: bytes = b"") -> SealedBlob:
        shared, kem_ct = ML_KEM_768.encaps(self._ek)
        nonce = os.urandom(12)
        ct = AESGCM(_derive_key(shared)).encrypt(nonce, plaintext, aad)
        return SealedBlob(b64(kem_ct), b64(nonce), b64(ct), self.algorithm)

    def unseal(self, blob: SealedBlob, aad: bytes = b"") -> bytes:
        shared = ML_KEM_768.decaps(self._dk, unb64(blob.kem_ciphertext))
        return AESGCM(_derive_key(shared)).decrypt(
            unb64(blob.nonce), unb64(blob.ciphertext), aad
        )


class X25519Sealer:
    """Classical fallback sealer: ephemeral X25519 ECDH + AES-256-GCM."""

    algorithm = "X25519 + AES-256-GCM"
    standard = "RFC 7748 (classical)"
    quantum_safe = False

    def __init__(self) -> None:
        self._dk = x25519.X25519PrivateKey.generate()
        self._ek = self._dk.public_key()

    @property
    def public_key(self) -> bytes:
        return self._ek.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def seal(self, plaintext: bytes, aad: bytes = b"") -> SealedBlob:
        eph = x25519.X25519PrivateKey.generate()
        shared = eph.exchange(self._ek)
        nonce = os.urandom(12)
        ct = AESGCM(_derive_key(shared)).encrypt(nonce, plaintext, aad)
        eph_pub = eph.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return SealedBlob(b64(eph_pub), b64(nonce), b64(ct), self.algorithm)

    def unseal(self, blob: SealedBlob, aad: bytes = b"") -> bytes:
        eph_pub = x25519.X25519PublicKey.from_public_bytes(
            unb64(blob.kem_ciphertext)
        )
        shared = self._dk.exchange(eph_pub)
        return AESGCM(_derive_key(shared)).decrypt(
            unb64(blob.nonce), unb64(blob.ciphertext), aad
        )


def build_sealer(prefer_pqc: bool = True):
    """Return the strongest sealer available on this host."""
    if prefer_pqc and _HAVE_ML_KEM:
        return MLKEMSealer()
    return X25519Sealer()


def _derive_key(shared: bytes) -> bytes:
    """HKDF the KEM/ECDH shared secret down to a 32-byte AES key."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"lookout/credential-seal/v1",
    ).derive(shared)


def crypto_status(signer: Signer, sealer) -> dict:
    """Machine-readable summary for ``GET /api/crypto`` and the dashboard."""
    return {
        "signing": {
            "algorithm": signer.algorithm,
            "standard": signer.standard,
            "quantum_safe": signer.quantum_safe,
            "public_key_bytes": len(signer.public_key),
            "public_key": b64(signer.public_key)[:64] + "...",
        },
        "sealing": {
            "algorithm": sealer.algorithm,
            "standard": sealer.standard,
            "quantum_safe": sealer.quantum_safe,
            "public_key_bytes": len(sealer.public_key),
        },
        "fully_quantum_safe": signer.quantum_safe and sealer.quantum_safe,
    }
