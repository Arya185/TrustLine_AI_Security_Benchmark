# Phase 5 — Audit-chain integrity: threat model and design

## Reproducing the weakness (before any change)

`tests/test_audit_limitations.py::test_full_chain_recompute_tamper_evades_detection_known_limitation`
(written in Phase 3, left unchanged and unremoved — it remains correct
evidence against the *original*, still-present `AuditLog.verify()`
method) demonstrates: build a 3-entry chain, tamper entry 1's content,
then recompute entry 1's own hash and every downstream entry's
`prev_hash`/`hash` to stay internally consistent. `verify()` returns
`(True, None)` — fully valid. Re-run in this phase, unchanged, same
result. This is the vulnerability this phase addresses — not by changing
`verify()` (which still means exactly what it meant before: "is this
chain internally self-consistent"), but by adding a second, independent
check that a full internal recompute cannot defeat.

## Threat model: five attacker capability classes

| # | Capability | In scope for this phase's design? |
|---|---|---|
| 1 | Accidental corruption or deletion of a log entry (no adversarial intent, e.g. a disk error, a bad merge, a dropped write) | **Yes** — detected by the existing hash-chain linkage (`prev_hash` check), unchanged from before this phase |
| 2 | An attacker who can edit the local log and recompute *ordinary* (unkeyed) hashes | **Yes** — this is exactly the weakness reproduced above; detected by the new checkpoint cross-check (not by HMAC alone, see below) |
| 3 | An attacker who can modify the log **and** access the integrity key, if a keyed scheme is used | **Partially** — if a keyed (HMAC) scheme is in use and the attacker has the key, HMAC provides **no** additional protection over plain hashing; this phase is explicit about that rather than implying otherwise. The checkpoint mechanism still provides protection here **only if** the attacker cannot also rewrite the checkpoint store (see class 5) |
| 4 | An attacker who can also modify the verifier or application process itself | **No** — explicitly out of scope, same as Phase 4's handler-authorization threat model. An attacker who can edit `audit.py`, monkey-patch `verify_against_checkpoint`, or replace the `CheckpointStore` object has no boundary to defeat. No in-process Python mechanism can protect against this |
| 5 | An attacker who can rewrite local history but **cannot** alter a separately stored checkpoint | **Yes, this is the core design target** — a checkpoint recorded independently of the mutable log, checked against at verification time, is what actually defeats the full-recompute attack. This is the capability class the checkpoint mechanism is specifically built for |

**This phase does not claim a local hash chain is tamper-proof, with or
without HMAC.** It claims: *given a checkpoint recorded before a tamper
and held somewhere the tamperer's capability doesn't reach, that tamper
is detectable even after a full internal recompute.* The strength of that
claim is entirely a function of (a) how separate the checkpoint storage
actually is in a real deployment, and (b) how recently a checkpoint was
taken relative to the tamper — both discussed below as real, load-bearing
limitations, not footnotes.

## Design options considered

| Option | What it adds | What it still can't do |
|---|---|---|
| **Ordinary hash chain** (status quo, unchanged) | Detects class 1 and a careless class-2 edit (no recompute) | Nothing against a full-recompute attacker (classes 2, 3) |
| **HMAC-keyed chain** | If the key is genuinely held separately from whatever has write access to the log, defeats a class-2 attacker who can edit the log but not read the key | Provides **zero** additional protection against class 3 (attacker has both log and key) — this phase documents that explicitly rather than selling HMAC as a general fix. In this single-process Python benchmark, "separately held key" is a *configuration you could do in a real deployment* (e.g. key in a different process's env, not persisted alongside the log), not something this codebase enforces on its own |
| **Signed checkpoints** (asymmetric signature over a checkpoint) | Stronger than a plain checkpoint hash if the *verifier* only holds the public key — an attacker with full log+process access still can't forge a signature without the private key | Requires key-pair generation, storage, and lifecycle management (rotation, revocation) that this repo has no mechanism for yet, and pulls in a crypto-signing dependency for a benchmark that doesn't otherwise need one. Judged **not the smallest justified design** for what this phase needs to prove — noted as a future upgrade path if checkpoints themselves ever need to travel somewhere semi-trusted |
| **External/separately-controlled checkpoint storage** (a different process, a write-once store, a real external service) | The strongest real-world version of class 5 protection | Explicitly **out of scope for this phase** per the instruction not to add an external service dependency or network calls without approval. What's implemented instead is the *local* version of this idea: a `CheckpointStore` object that is architecturally separate from `AuditLog.entries` (a different object, not a field inside the same mutable list) — which models the separation of concerns and the verification logic correctly, but does **not** model a real OS- or network-level access boundary. In this process, anything with access to one has access to the other. This gap is documented as future work, not hidden |

## Chosen design

**HMAC-keyed entries (optional, off by default) + an architecturally
separate `CheckpointStore`, cross-checked by a new
`verify_against_checkpoint()` function.** `AuditLog.verify()` itself is
untouched — same signature, same behavior, same (documented) weakness,
so the Phase 3 regression test keeps meaning exactly what it always
meant.

Why this combination and not just one piece: HMAC alone doesn't defeat
class 3 (key-holding attacker); a checkpoint alone, taken once and never
updated, only protects history up to that point — anything after it is
exactly as vulnerable as before. Together: HMAC raises the bar for class
2 specifically (log-only access), and checkpointing is what actually
closes the "accepted a fully-recomputed lie" hole for class 5, with the
caveat below about checkpoint recency.

### Configuration, lifecycle, and failure behavior

- `AuditLog.key: bytes | None` — `None` by default (identical behavior to
  every prior phase; nothing changes for existing callers that don't set
  it). If set, must be `bytes`; a non-bytes key raises `TypeError`
  immediately rather than silently falling back to unkeyed hashing or
  producing a hash that looks valid but means nothing.
- **No real secret is hardcoded anywhere in this repo.** Tests that
  exercise the keyed path generate an ephemeral key with
  `secrets.token_bytes(32)` at test time; nothing resembling a production
  key lives in source control. A real deployment choosing to use this
  would need its own key-management story (where the key is generated,
  stored, rotated, and how the verifier obtains it without the same
  access the log-writer has) — not implemented or simulated here, because
  doing so honestly would require the external-storage pieces this phase
  explicitly defers.
- `CheckpointStore.record(index, hash)` — the caller decides when to
  checkpoint (e.g., after every append, after N appends, on a timer).
  This repo does not pick a policy for a real deployment; it only
  provides the mechanism and tests both a frequent-checkpoint and an
  infrequent-checkpoint scenario to make the tradeoff visible (see
  "Known limitation: checkpoint frequency" below).
- `verify_against_checkpoint(log, checkpoint_store, *, require_key=False, require_checkpoint=False)`
  fails safe on missing/malformed configuration: a required-but-absent
  key returns `reason_code="missing_integrity_key"`; a required-but-absent
  checkpoint returns `reason_code="checkpoint_missing"`; a malformed key
  (wrong type) is caught and reported as
  `reason_code="integrity_configuration_invalid"` rather than letting a
  raw exception escape. None of these failure paths return `valid=True`.

### Known limitation: checkpoint frequency

Checkpointing at index N protects everything **up to and including**
index N. A tamper-and-fully-recompute attack applied only to entries
**after** the last checkpoint, and not spanning back across it, is
**not** detected by this mechanism — it would need its own later
checkpoint to be caught. This is demonstrated directly in
`tests/test_audit_checkpoint_integrity.py::test_tamper_after_last_checkpoint_is_not_detected_known_limitation`,
alongside the contrasting case where the same tamper *does* span a
checkpoint and *is* caught. The practical implication for a real
deployment: how often you checkpoint is a direct, tunable tradeoff
against how large an undetectable tamper window you're leaving open —
this repo does not pick that tradeoff for you.

## What remains explicitly undefended, by this phase's own admission

- Class 4 (attacker controls the verifier/application process itself) —
  no in-process mechanism defends against this, here or anywhere else in
  this codebase.
- Class 3 fully (attacker has both the log and the HMAC key) — HMAC
  degrades to "as strong as an ordinary hash" in this case; only a
  checkpoint the attacker *also* can't reach still helps, and only up to
  its own recency limit above.
- The gap between the last checkpoint and "now," for whatever
  checkpointing policy a caller chooses.
- True separation of checkpoint storage from the log — `CheckpointStore`
  is a different Python object, which is correct *architecture* and
  *testable logic*, but is not a real OS/process/network boundary. A
  production system wanting the real version of class-5 protection needs
  genuinely separate storage (a different service, a write-once medium,
  or a real external anchor) — tracked here as future work, not claimed
  as already done.

**This is not production-grade tamper resistance, and nothing in this
repo should be read as claiming it is.** It is a locally-testable,
honestly-scoped improvement over a plain hash chain, verified against a
stated threat model, with its remaining gaps written down rather than
implied away.
