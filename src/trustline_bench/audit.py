"""Append-only, hash-chained audit log used to test audit integrity.

Each entry's hash covers its own content plus the previous entry's hash, so
mutating any past entry in place (without recomputing the whole chain from
that point forward) is detectable by `verify()`.

Phase 5 adds two things ON TOP of this, without changing `verify()`'s
existing signature or behavior (so everything that relied on it before
keeps working exactly as before, including the regression test that
documents its known weakness):

1. An optional HMAC key on AuditLog (`key: bytes | None`, default None --
   identical behavior to every prior phase when unset).
2. `CheckpointStore` + `verify_against_checkpoint()`, a second,
   independent check that catches the "fully recomputed, internally
   consistent, but doesn't match what was checkpointed earlier" attack
   that `verify()` alone cannot. See docs/phase5_audit_integrity.md for
   the full threat model, design rationale, and -- just as importantly --
   what this still does NOT protect against.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any

GENESIS_HASH = "0" * 64


def _entry_hash(
    index: int, timestamp: str, event: dict[str, Any], prev_hash: str, key: bytes | None = None
) -> str:
    """Unkeyed (key=None, the default) is bit-for-bit identical to every
    prior phase's behavior. Keyed (HMAC-SHA256) raises TypeError
    immediately for a non-bytes key, rather than silently falling back to
    unkeyed hashing or producing a hash that looks valid but authenticates
    nothing."""
    payload = json.dumps(
        {"index": index, "timestamp": timestamp, "event": event, "prev_hash": prev_hash},
        sort_keys=True,
    ).encode("utf-8")

    if key is None:
        return hashlib.sha256(payload).hexdigest()

    if not isinstance(key, bytes):
        raise TypeError(f"AuditLog.key must be bytes, got {type(key).__name__}")

    return hmac.new(key, payload, hashlib.sha256).hexdigest()


@dataclass
class AuditLog:
    entries: list[dict[str, Any]] = field(default_factory=list)
    key: bytes | None = field(default=None, repr=False)
    """Optional HMAC key. None (default) preserves every prior phase's
    plain-SHA256 behavior exactly. Never log or repr this field's value --
    repr=False keeps it out of default dataclass __repr__ output."""

    def append(self, timestamp: str, event: dict[str, Any]) -> dict[str, Any]:
        index = len(self.entries)
        prev_hash = self.entries[-1]["hash"] if self.entries else GENESIS_HASH
        entry = {
            "index": index,
            "timestamp": timestamp,
            "event": event,
            "prev_hash": prev_hash,
            "hash": _entry_hash(index, timestamp, event, prev_hash, key=self.key),
        }
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """Walk the chain recomputing hashes. Returns (valid, first_bad_index).

        Unchanged from every prior phase: this checks only internal
        self-consistency (does each entry's stored hash match a
        recomputation from its own stored content, and does the prev_hash
        linkage hold). It has no way to tell a legitimate chain from one
        an attacker tampered with and then fully, consistently
        recomputed -- see verify_against_checkpoint() below for the check
        that catches that specifically, and docs/phase5_audit_integrity.md
        for why this method's contract is deliberately left as-is rather
        than quietly strengthened in place.
        """
        expected_prev = GENESIS_HASH
        for entry in self.entries:
            if entry["prev_hash"] != expected_prev:
                return False, entry["index"]
            recomputed = _entry_hash(entry["index"], entry["timestamp"], entry["event"], entry["prev_hash"], key=self.key)
            if recomputed != entry["hash"]:
                return False, entry["index"]
            expected_prev = entry["hash"]
        return True, None

    def checkpoint_now(self) -> tuple[int, str] | None:
        """Returns (index, hash) of the current last entry, for a caller
        to hand to a CheckpointStore. Returns None for an empty log.
        AuditLog does not decide checkpoint policy or storage -- that is
        the caller's responsibility, by design (see
        docs/phase5_audit_integrity.md's point about this not modeling a
        real separate-storage boundary on its own)."""
        if not self.entries:
            return None
        last = self.entries[-1]
        return last["index"], last["hash"]


@dataclass
class CheckpointStore:
    """A witness to audit-log state, held as a distinct object from the
    mutable AuditLog itself. This models the architectural separation a
    real deployment would need (a different service, a write-once store,
    a different permission boundary) -- it does NOT itself enforce any
    real access-control boundary; in this process, anything with access
    to one object has access to the other. See docs/phase5_audit_integrity.md.
    """

    _checkpoints: dict[int, str] = field(default_factory=dict)

    def record(self, index: int, hash_: str) -> None:
        self._checkpoints[index] = hash_

    def get(self, index: int) -> str | None:
        return self._checkpoints.get(index)

    def indices(self) -> list[int]:
        return sorted(self._checkpoints)

    def is_empty(self) -> bool:
        return not self._checkpoints


@dataclass
class VerificationResult:
    valid: bool
    reason_code: str
    bad_index: int | None = None


def verify_against_checkpoint(
    log: AuditLog,
    checkpoint_store: CheckpointStore,
    *,
    require_key: bool = False,
    require_checkpoint: bool = False,
) -> VerificationResult:
    """The check that defeats a full-chain-recompute attacker, as long as
    the attacker's capability doesn't extend to rewriting
    `checkpoint_store` too (see docs/phase5_audit_integrity.md's threat
    model -- this is the class-5 boundary, not a universal guarantee).

    Checks, in order:
      1. If require_key and log.key is None -> missing_integrity_key.
      2. Ordinary chain self-consistency (log.verify()) -> chain_invalid
         if that fails. A malformed (non-bytes) key surfaces here as
         integrity_configuration_invalid rather than an uncaught
         exception.
      3. If require_checkpoint and no checkpoints exist -> checkpoint_missing.
      4. EVERY recorded checkpoint (not just the latest) must match the
         log's current hash at that index -- checking all of them, not
         only the most recent, narrows the "gap between checkpoints"
         window described in the design doc.
    """
    if require_key and log.key is None:
        return VerificationResult(False, "missing_integrity_key")

    try:
        valid, bad_index = log.verify()
    except TypeError:
        return VerificationResult(False, "integrity_configuration_invalid")

    if not valid:
        return VerificationResult(False, "chain_invalid", bad_index)

    if checkpoint_store.is_empty():
        if require_checkpoint:
            return VerificationResult(False, "checkpoint_missing")
        return VerificationResult(True, "ok")

    for index in checkpoint_store.indices():
        recorded_hash = checkpoint_store.get(index)
        if index >= len(log.entries) or log.entries[index]["hash"] != recorded_hash:
            return VerificationResult(False, "checkpoint_mismatch", index)

    return VerificationResult(True, "ok")
