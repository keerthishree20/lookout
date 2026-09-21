from lookout.audit import GENESIS, AuditLog
from lookout.crypto import Ed25519Signer, MLDSASigner


def _log(n: int, every: int = 5) -> AuditLog:
    log = AuditLog(MLDSASigner(b"a" * 32), checkpoint_every=every)
    for i in range(n):
        log.append("decision", {"i": i, "action_taken": "block"})
    return log


def test_entries_link_back_to_genesis():
    log = _log(3)
    assert log.entries[0].prev_hash == GENESIS
    assert log.entries[1].prev_hash == log.entries[0].entry_hash
    assert log.entries[2].prev_hash == log.entries[1].entry_hash


def test_untouched_chain_verifies():
    result = _log(12).verify()
    assert result.ok
    assert result.entries_checked == 12
    assert result.checkpoints_checked == 2  # after entries 5 and 10


def test_editing_a_payload_is_caught_at_that_entry():
    log = _log(12)
    log.tamper(4, "action_taken", "allow")
    result = log.verify()
    assert not result.ok
    assert result.broken_at == 4
    assert "content" in result.reason


def test_rewriting_an_entry_and_its_hash_breaks_the_next_link():
    """An insider who recomputes entry 4's hash still breaks entry 5."""
    from lookout.audit import _hash_entry

    log = _log(8)
    e = log.entries[4]
    e.payload["action_taken"] = "allow"
    e.entry_hash = _hash_entry(e.seq, e.ts, e.kind, e.payload, e.prev_hash)
    result = log.verify()
    assert not result.ok
    assert result.broken_at == 5


def test_rewriting_the_whole_chain_fails_the_signed_checkpoint():
    """Recomputing every hash makes the chain consistent -- but the ML-DSA
    checkpoint was signed over the old head, and cannot be re-signed without
    the key."""
    from lookout.audit import _hash_entry

    log = _log(10, every=10)
    log.entries[2].payload["action_taken"] = "allow"
    prev = GENESIS
    for e in log.entries:
        e.prev_hash = prev
        e.entry_hash = _hash_entry(e.seq, e.ts, e.kind, e.payload, prev)
        prev = e.entry_hash
    result = log.verify()
    assert not result.ok
    assert "checkpoint" in result.reason
    assert "ML-DSA-65" in result.reason


def test_critical_entries_are_checkpointed_immediately():
    log = AuditLog(Ed25519Signer(), checkpoint_every=100)
    log.append("decision", {"a": 1})
    assert log.checkpoints == []
    log.append("decision", {"a": 2}, critical=True)
    assert len(log.checkpoints) == 1
    assert log.checkpoints[0].seq == 1


def test_checkpoint_records_whether_it_is_quantum_safe():
    assert _log(5).checkpoints[0].quantum_safe
    classical = AuditLog(Ed25519Signer(), checkpoint_every=1)
    classical.append("x", {})
    assert not classical.checkpoints[0].quantum_safe


def test_tail_is_newest_first():
    log = _log(6)
    assert [e.seq for e in log.tail(3)] == [5, 4, 3]


def test_tamper_rejects_out_of_range():
    assert not _log(2).tamper(9)
