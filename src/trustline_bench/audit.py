"""Append-only, hash-chained audit log used to test audit integrity.

Each entry's hash covers its own content plus the previous entry's hash, so
mutating any past entry in place (without recomputing the whole chain from
that point forward) is detectable by `verify()`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

GENESIS_HASH = "0" * 64


def _entry_hash(index: int, timestamp: str, event: dict[str, Any], prev_hash: str) -> str:
    payload = json.dumps(
        {"index": index, "timestamp": timestamp, "event": event, "prev_hash": prev_hash},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class AuditLog:
    entries: list[dict[str, Any]] = field(default_factory=list)

    def append(self, timestamp: str, event: dict[str, Any]) -> dict[str, Any]:
        index = len(self.entries)
        prev_hash = self.entries[-1]["hash"] if self.entries else GENESIS_HASH
        entry = {
            "index": index,
            "timestamp": timestamp,
            "event": event,
            "prev_hash": prev_hash,
            "hash": _entry_hash(index, timestamp, event, prev_hash),
        }
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """Walk the chain recomputing hashes. Returns (valid, first_bad_index)."""
        expected_prev = GENESIS_HASH
        for entry in self.entries:
            if entry["prev_hash"] != expected_prev:
                return False, entry["index"]
            recomputed = _entry_hash(entry["index"], entry["timestamp"], entry["event"], entry["prev_hash"])
            if recomputed != entry["hash"]:
                return False, entry["index"]
            expected_prev = entry["hash"]
        return True, None
