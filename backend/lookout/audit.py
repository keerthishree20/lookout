"""Tamper-evident audit log.

Every decision Lookout makes is appended here. Two properties matter:

1. **Tamper-evident.** Each entry carries the SHA-256 of the previous entry, so
   changing entry 4 invalidates 5, 6, 7 and every one after it. You cannot
   quietly edit history; you can only make the chain fail to verify.
2. **Attributable, durably.** Chaining alone proves internal consistency, not
   origin -- whoever rewrites entry 4 can recompute the whole chain. So the
   chain head is *signed* with ML-DSA-65. A rewrite cannot be re-signed without
   the private key, and a signature made today stays meaningful after quantum
   computers exist.

Signing every entry would be wasteful (ML-DSA signing is ~90 ms, versus ~5 us
for a SHA-256 link), so this follows the checkpoint pattern used by transparency
logs: hash-link every entry, sign the head every ``checkpoint_every`` entries
and immediately for anything critical.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from .crypto import Signer, b64, build_signer

GENESIS = "0" * 64


def canonical(payload: dict[str, Any]) -> bytes:
    """Stable byte encoding, so the same content always hashes the same."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


class AuditEntry(BaseModel):
    seq: int
    ts: datetime
    kind: str
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str


class Checkpoint(BaseModel):
    """A signed commitment to the chain head at a point in time."""

    seq: int
    head_hash: str
    ts: datetime
    algorithm: str
    quantum_safe: bool
    signature: str


class VerificationResult(BaseModel):
    ok: bool
    entries_checked: int
    checkpoints_checked: int
    broken_at: int | None = None
    reason: str = ""


class AuditLog:
    """Append-only, hash-chained, signed at checkpoints. In-memory by design:
    the demo must start from a known state every run."""

    def __init__(self, signer: Signer | None = None, checkpoint_every: int = 25) -> None:
        self.signer = signer or build_signer()
        self.checkpoint_every = checkpoint_every
        self.entries: list[AuditEntry] = []
        self.checkpoints: list[Checkpoint] = []
        self._lock = threading.Lock()

    # -- writing ---------------------------------------------------------- #

    def append(self, kind: str, payload: dict[str, Any], critical: bool = False) -> AuditEntry:
        with self._lock:
            seq = len(self.entries)
            prev = self.entries[-1].entry_hash if self.entries else GENESIS
            ts = datetime.now(timezone.utc)
            entry = AuditEntry(
                seq=seq,
                ts=ts,
                kind=kind,
                payload=payload,
                prev_hash=prev,
                entry_hash=_hash_entry(seq, ts, kind, payload, prev),
            )
            self.entries.append(entry)
            due = (seq + 1) % self.checkpoint_every == 0
            if critical or due:
                self._checkpoint_locked()
            return entry

    def checkpoint(self) -> Checkpoint:
        """Sign the current head on demand (also used before a shutdown)."""
        with self._lock:
            return self._checkpoint_locked()

    def _checkpoint_locked(self) -> Checkpoint:
        head = self.entries[-1].entry_hash if self.entries else GENESIS
        seq = len(self.entries) - 1
        ts = datetime.now(timezone.utc)
        body = canonical({"seq": seq, "head": head, "ts": ts.isoformat()})
        cp = Checkpoint(
            seq=seq,
            head_hash=head,
            ts=ts,
            algorithm=self.signer.algorithm,
            quantum_safe=self.signer.quantum_safe,
            signature=b64(self.signer.sign(body)),
        )
        self.checkpoints.append(cp)
        return cp

    # -- reading ---------------------------------------------------------- #

    def tail(self, limit: int = 50) -> list[AuditEntry]:
        return self.entries[-limit:][::-1]

    def verify(self) -> VerificationResult:
        """Recompute the chain and check every signed checkpoint."""
        prev = GENESIS
        for entry in self.entries:
            if entry.prev_hash != prev:
                return VerificationResult(
                    ok=False,
                    entries_checked=entry.seq,
                    checkpoints_checked=0,
                    broken_at=entry.seq,
                    reason=f"entry {entry.seq} does not link to entry {entry.seq - 1}",
                )
            recomputed = _hash_entry(
                entry.seq, entry.ts, entry.kind, entry.payload, entry.prev_hash
            )
            if recomputed != entry.entry_hash:
                return VerificationResult(
                    ok=False,
                    entries_checked=entry.seq,
                    checkpoints_checked=0,
                    broken_at=entry.seq,
                    reason=f"entry {entry.seq} content does not match its hash",
                )
            prev = entry.entry_hash

        for cp in self.checkpoints:
            expected = self.entries[cp.seq].entry_hash if cp.seq >= 0 else GENESIS
            body = canonical(
                {"seq": cp.seq, "head": expected, "ts": cp.ts.isoformat()}
            )
            from .crypto import unb64

            if not self.signer.verify(body, unb64(cp.signature)):
                return VerificationResult(
                    ok=False,
                    entries_checked=len(self.entries),
                    checkpoints_checked=0,
                    broken_at=cp.seq,
                    reason=f"checkpoint at seq {cp.seq} fails {self.signer.algorithm} verification",
                )

        return VerificationResult(
            ok=True,
            entries_checked=len(self.entries),
            checkpoints_checked=len(self.checkpoints),
            reason="chain intact and all checkpoints verify",
        )

    # -- demo ------------------------------------------------------------- #

    def tamper(self, seq: int, field: str = "action_taken", value: Any = "allow") -> bool:
        """Forge an entry *the way an insider would* -- edit the payload and
        leave the stored hash alone. Used by the demo to prove detection works.
        Not reachable in production builds."""
        if not 0 <= seq < len(self.entries):
            return False
        self.entries[seq].payload[field] = value
        return True


def _hash_entry(
    seq: int, ts: datetime, kind: str, payload: dict[str, Any], prev: str
) -> str:
    return hashlib.sha256(
        canonical(
            {"seq": seq, "ts": ts.isoformat(), "kind": kind, "payload": payload, "prev": prev}
        )
    ).hexdigest()
