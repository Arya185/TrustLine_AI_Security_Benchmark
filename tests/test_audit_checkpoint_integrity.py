"""Phase 5: adversarial tests for the checkpoint-backed audit integrity
mechanism (CheckpointStore + verify_against_checkpoint), which exists
specifically to catch what AuditLog.verify() alone cannot -- a full,
internally-consistent recompute after a tamper. See
docs/phase5_audit_integrity.md for the threat model these tests are
scoped to, including what's explicitly NOT defended against.

Every test here asserts the VerificationResult AND, where relevant,
persisted state (log.entries, checkpoint contents) -- not just a verdict
in isolation.
"""

from __future__ import annotations

import secrets

import pytest

from trustline_bench.audit import AuditLog, CheckpointStore, VerificationResult, _entry_hash, verify_against_checkpoint


def _build_log(n: int = 3, key: bytes | None = None) -> AuditLog:
    log = AuditLog(key=key)
    for i in range(n):
        log.append(f"t{i}", {"event": f"entry-{i}", "verdict": "ALLOW" if i == 0 else "DENY"})
    return log


def _full_recompute(log: AuditLog, key: bytes | None = None) -> None:
    """Simulates a determined attacker: after mutating some entry's
    content directly, recompute every entry's hash/prev_hash from index 0
    onward so the chain stays internally self-consistent."""
    prev_hash = "0" * 64
    for entry in log.entries:
        entry["prev_hash"] = prev_hash
        entry["hash"] = _entry_hash(entry["index"], entry["timestamp"], entry["event"], prev_hash, key=key)
        prev_hash = entry["hash"]


# ---------------------------------------------------------------------------
# 1. Untouched valid chain
# ---------------------------------------------------------------------------


def test_untouched_valid_chain_is_valid():
    log = _build_log()
    result = verify_against_checkpoint(log, CheckpointStore())
    assert result == VerificationResult(True, "ok", None)


# ---------------------------------------------------------------------------
# 2-6: ordinary (non-recomputed) tampering, all caught by the underlying
# chain check -- these establish the baseline that still works exactly as
# before Phase 5.
# ---------------------------------------------------------------------------


def test_single_entry_mutation_without_recompute_is_detected():
    log = _build_log()
    before = [dict(e) for e in log.entries]
    log.entries[1]["event"]["verdict"] = "ALLOW"

    result = verify_against_checkpoint(log, CheckpointStore())

    assert result.valid is False
    assert result.reason_code == "chain_invalid"
    assert result.bad_index == 1
    # The entries list itself was mutated (that's the point), but entry 0
    # -- upstream of the tamper -- is untouched.
    assert log.entries[0] == before[0]


def test_entry_deletion_is_detected():
    log = _build_log()
    del log.entries[1]

    result = verify_against_checkpoint(log, CheckpointStore())

    assert result.valid is False
    assert result.reason_code == "chain_invalid"
    assert len(log.entries) == 2  # deletion itself is real, persisted state


def test_entry_insertion_is_detected():
    log = _build_log()
    forged_entry = {"index": 99, "timestamp": "tX", "event": {"event": "forged"}, "prev_hash": "x", "hash": "x"}
    log.entries.insert(1, forged_entry)

    result = verify_against_checkpoint(log, CheckpointStore())

    assert result.valid is False
    assert result.reason_code == "chain_invalid"
    assert log.entries[1] is forged_entry


def test_entry_reordering_is_detected():
    log = _build_log()
    log.entries[0], log.entries[1] = log.entries[1], log.entries[0]

    result = verify_against_checkpoint(log, CheckpointStore())

    assert result.valid is False
    assert result.reason_code == "chain_invalid"


def test_hash_field_modification_alone_is_detected():
    log = _build_log()
    log.entries[1]["hash"] = "deadbeef" * 8

    result = verify_against_checkpoint(log, CheckpointStore())

    assert result.valid is False
    assert result.reason_code == "chain_invalid"
    assert result.bad_index == 1


# ---------------------------------------------------------------------------
# 7. The core Phase 5 case: full suffix recomputation after an earlier
# mutation, WITH a checkpoint taken before the tamper. This is the attack
# AuditLog.verify() alone cannot catch (see test_audit_limitations.py);
# this is the test proving the new mechanism does.
# ---------------------------------------------------------------------------


def test_full_recompute_tamper_is_caught_by_a_prior_checkpoint():
    log = _build_log(3)
    checkpoint_store = CheckpointStore()
    checkpoint_store.record(*log.checkpoint_now())  # checkpoint at the last entry, index 2

    log.entries[1]["event"]["verdict"] = "ALLOW"
    _full_recompute(log)

    # Confirm the premise: the OLD mechanism alone is fooled.
    assert log.verify() == (True, None)

    # The NEW mechanism is not.
    result = verify_against_checkpoint(log, checkpoint_store)
    assert result.valid is False
    assert result.reason_code == "checkpoint_mismatch"
    assert result.bad_index == 2  # the checkpointed index, whose hash changed due to the upstream tamper


# ---------------------------------------------------------------------------
# 8. Missing or invalid integrity key
# ---------------------------------------------------------------------------


def test_missing_key_strict_mode_fails_safe():
    log = _build_log()  # no key set
    result = verify_against_checkpoint(log, CheckpointStore(), require_key=True)
    assert result == VerificationResult(False, "missing_integrity_key", None)


def test_missing_key_lenient_mode_is_unaffected():
    """Default (require_key=False) preserves every prior phase's
    behavior: an unkeyed log is not itself a failure."""
    log = _build_log()
    result = verify_against_checkpoint(log, CheckpointStore())
    assert result.valid is True


def test_invalid_non_bytes_key_fails_safe_not_crash_on_append():
    with pytest.raises(TypeError):
        AuditLog(key="not-bytes").append("t0", {"event": "x"})


def test_invalid_non_bytes_key_fails_safe_on_verify_against_checkpoint():
    """A log that somehow already has a malformed key (bypassing append's
    own guard, e.g. constructed oddly) must not crash verification --
    it must report a clear failure."""
    log = AuditLog()
    log.append("t0", {"event": "x"})
    log.key = 12345  # malformed, set directly, bypassing append()'s guard

    result = verify_against_checkpoint(log, CheckpointStore())
    assert result.valid is False
    assert result.reason_code == "integrity_configuration_invalid"


# ---------------------------------------------------------------------------
# 9-11. Checkpoint-specific scenarios
# ---------------------------------------------------------------------------


def test_modified_checkpoint_against_an_untampered_log_is_flagged():
    """A checkpoint that disagrees with reality -- whether due to an
    error or a compromised checkpoint store -- must be flagged as a
    mismatch. The cross-check cannot and does not try to determine which
    side is "correct," only that they disagree."""
    log = _build_log()
    checkpoint_store = CheckpointStore()
    checkpoint_store.record(1, "deliberately-wrong-hash-value")

    result = verify_against_checkpoint(log, checkpoint_store)

    assert result.valid is False
    assert result.reason_code == "checkpoint_mismatch"
    assert result.bad_index == 1


def test_missing_checkpoint_lenient_by_default():
    log = _build_log()
    result = verify_against_checkpoint(log, CheckpointStore())
    assert result.valid is True


def test_missing_checkpoint_strict_mode_fails_safe():
    log = _build_log()
    result = verify_against_checkpoint(log, CheckpointStore(), require_checkpoint=True)
    assert result == VerificationResult(False, "checkpoint_missing", None)


def test_checkpoint_referencing_an_index_beyond_the_log_is_a_mismatch():
    """A checkpoint pointing past the current log length (e.g. after a
    deletion shrank the log) must be treated as a disagreement, not
    silently ignored."""
    log = _build_log(3)
    checkpoint_store = CheckpointStore()
    checkpoint_store.record(5, "whatever")  # index 5 doesn't exist in a 3-entry log

    result = verify_against_checkpoint(log, checkpoint_store)

    assert result.valid is False
    assert result.reason_code == "checkpoint_mismatch"
    assert result.bad_index == 5


# ---------------------------------------------------------------------------
# 12. Verification after normal additional entries are appended -- must
# stay valid; checkpointing must not make ordinary growth look like tampering.
# ---------------------------------------------------------------------------


def test_normal_appends_after_a_checkpoint_remain_valid():
    log = _build_log(2)
    checkpoint_store = CheckpointStore()
    checkpoint_store.record(*log.checkpoint_now())

    log.append("t2", {"event": "entry-2"})
    log.append("t3", {"event": "entry-3"})

    result = verify_against_checkpoint(log, checkpoint_store)
    assert result.valid is True
    assert len(log.entries) == 4  # the appends really happened


# ---------------------------------------------------------------------------
# Known limitation, demonstrated directly (not just asserted in docs):
# a tamper entirely AFTER the last checkpoint, not spanning it, evades
# this mechanism exactly as docs/phase5_audit_integrity.md says it will.
# ---------------------------------------------------------------------------


def test_tamper_after_last_checkpoint_is_not_detected_known_limitation():
    log = _build_log(3)
    checkpoint_store = CheckpointStore()
    checkpoint_store.record(*log.checkpoint_now())  # checkpoint at index 2

    log.append("t3", {"event": "entry-3"})  # normal growth, after the checkpoint
    log.entries[3]["event"]["event"] = "tampered-after-checkpoint"
    log.entries[3]["hash"] = _entry_hash(3, log.entries[3]["timestamp"], log.entries[3]["event"], log.entries[3]["prev_hash"])

    result = verify_against_checkpoint(log, checkpoint_store)

    # This is the honest limitation, demonstrated: the tamper is entirely
    # after the last checkpoint, so it is NOT caught. A later checkpoint,
    # taken after the tamper would have been (and so cannot help
    # retroactively), is what this mechanism actually needs.
    assert result.valid is True


def test_tamper_spanning_a_checkpoint_is_detected_contrast_case():
    """Direct contrast to the above: the identical style of tamper IS
    caught when it spans (i.e. occurs before, with full recompute through)
    a checkpointed index."""
    log = _build_log(3)
    checkpoint_store = CheckpointStore()
    checkpoint_store.record(*log.checkpoint_now())  # checkpoint at index 2

    log.entries[0]["event"]["event"] = "tampered-before-checkpoint"
    _full_recompute(log)  # ripples through index 2, which IS checkpointed

    result = verify_against_checkpoint(log, checkpoint_store)
    assert result.valid is False
    assert result.reason_code == "checkpoint_mismatch"


# ---------------------------------------------------------------------------
# HMAC: protects against a keyless attacker, explicitly does NOT protect
# against one who also has the key (class 3 in the threat model).
# ---------------------------------------------------------------------------


def test_hmac_key_blocks_a_recompute_attacker_who_does_not_have_it():
    real_key = secrets.token_bytes(32)
    log = _build_log(3, key=real_key)
    assert log.verify() == (True, None)

    log.entries[1]["event"]["verdict"] = "ALLOW"
    _full_recompute(log, key=secrets.token_bytes(32))  # wrong key -- attacker guessed

    assert log.verify()[0] is False


def test_hmac_key_provides_no_protection_against_an_attacker_who_has_it():
    """Documented, demonstrated limitation: HMAC alone is not a defense
    against class 3 (attacker has the log AND the key). What DOES still
    catch it is a checkpoint taken before the tamper and held somewhere
    the attacker's capability doesn't reach -- the key is not what's
    doing the work in that case, the separate checkpoint is."""
    real_key = secrets.token_bytes(32)
    log = _build_log(3, key=real_key)
    checkpoint_store = CheckpointStore()
    checkpoint_store.record(*log.checkpoint_now())  # taken BEFORE the tamper, from the real content

    log.entries[1]["event"]["verdict"] = "ALLOW"
    _full_recompute(log, key=real_key)  # attacker has the real key

    assert log.verify() == (True, None)  # HMAC alone does not catch this -- by design of the threat model

    result = verify_against_checkpoint(log, checkpoint_store)
    assert result.valid is False
    assert result.reason_code == "checkpoint_mismatch"
