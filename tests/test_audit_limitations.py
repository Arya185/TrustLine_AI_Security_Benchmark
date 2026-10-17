"""Phase 3 audit finding: the hash-chain audit log only detects a
CARELESS tamper (editing an entry's content without recomputing its own
hash and every downstream entry's prev_hash/hash). A determined attacker
with write access to the stored log who recomputes the full suffix of the
chain to stay internally consistent evades detection completely. This is
a fundamental limitation of hash-chaining without an external anchor
(a separate append-only transport, periodic external notarization, or a
signature from a key the attacker doesn't have) -- not a bug in
audit.py's implementation of the chain it was asked to implement.

docs/phase3_independent_audit.md relies on this test to back the claim
that "audit_integrity_detection_rate" must not be read as "tampering is
detected," only as "this one class of tampering is detected."
"""

from __future__ import annotations

from trustline_bench.audit import AuditLog, _entry_hash


def test_careless_tamper_is_detected():
    """The existing, intended threat model: an edit that doesn't
    recompute the chain is caught."""
    log = AuditLog()
    for i in range(3):
        log.append(f"t{i}", {"event": f"entry-{i}"})

    log.entries[1]["event"]["event"] = "tampered"

    valid, bad_index = log.verify()
    assert valid is False
    assert bad_index == 1


def test_full_chain_recompute_tamper_evades_detection_known_limitation():
    """CONFIRMED, OPEN FINDING (Phase 3 audit, severity: high) -- not
    hypothetical. An attacker who edits an entry's content AND recomputes
    that entry's own hash AND every downstream entry's prev_hash/hash to
    match produces a chain that verify() reports as fully valid. This is
    demonstrated here, not assumed.

    This does not mean audit.py is implemented wrong -- a hash chain
    alone, with no external anchor, cannot detect this class of tamper by
    construction; that's true of hash chains in general, not a defect
    specific to this code. The actionable takeaway is interpretive: do
    not read audit_integrity_detection_rate, or this benchmark's audit
    cases passing, as "tampering is detected." They only establish "the
    careless-edit tamper model is detected." A real deployment wanting
    protection against a determined attacker needs an external anchor
    (append-only storage the attacker can't rewrite, periodic external
    notarization, or signed entries) layered on top of this chain -- out
    of scope for what this benchmark implements or tests.
    """
    log = AuditLog()
    for i in range(3):
        log.append(f"t{i}", {"event": f"entry-{i}", "verdict": "DENY"})

    valid_before, _ = log.verify()
    assert valid_before is True

    # Recompute the whole suffix of the chain after tampering, instead of
    # leaving it inconsistent.
    log.entries[1]["event"]["verdict"] = "ALLOW"
    for i in range(len(log.entries)):
        prev_hash = log.entries[i - 1]["hash"] if i > 0 else "0" * 64
        log.entries[i]["prev_hash"] = prev_hash
        log.entries[i]["hash"] = _entry_hash(
            log.entries[i]["index"], log.entries[i]["timestamp"], log.entries[i]["event"], prev_hash
        )

    valid_after, bad_index_after = log.verify()
    assert valid_after is True  # evades detection -- this is the finding, not a desired outcome
    assert bad_index_after is None
