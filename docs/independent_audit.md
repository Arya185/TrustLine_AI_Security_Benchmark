# Phase 3 — Independent audit

Written adopting a skeptical stance toward the prior phases' own work,
including work by the same author/session. A passing test is evidence the
test's *specific* assertion holds, not evidence the behavior it's
checking is the right behavior — several findings below are exactly
cases where that distinction mattered. Every claim below was re-derived
or re-run in this phase, not carried over from the prior report's text.

See `docs/phase3_coverage_matrix.md` for the full case-by-case matrix.

## Threat model actually implemented

A tool-call gateway sitting between "something that decided to call a
tool" (a real model, or in the custom suite, a fixed fixture standing in
for one) and the tool's real side effect. The gateway assumes:

- The **user's direct instruction** is trusted.
- The **system/developer prompt** is trusted (not attacker-reachable the
  way tool output is) — an explicit policy choice, not a default.
- **Tool output is not trusted** — content returned by a prior tool call
  (a webpage, an email, a search result) can contain attacker-injected
  instructions, and must not be sufficient on its own to authorize a
  sensitive action.
- A fixed, small allowlist (per tool) is the sole authority for
  destinations/channels/accounts; amounts have a fixed ceiling; file
  paths must stay under a fixed sandbox root.
- Two tools (`wire_transfer`, `delete_account`) are prohibited outright,
  regardless of origin or arguments.

This is a **provenance/taint model**, not a content-based one: the
decision never inspects *what the attacker's text says*, only *where the
instruction that produced this call came from*. That is a real strength
(keyword/content filters are trivially evaded by rephrasing; provenance
isn't) and a real limitation (it says nothing about a USER-initiated
action that is itself malicious or mistaken — this gateway isn't trying
to detect that).

## Security properties this benchmark can actually test

- Whether a specific `(tool, args, origin)` triple is ALLOWed or DENYed
  by the deterministic policy, for the rules actually implemented
  (prohibited-tool list, taint-by-origin, per-tool destination/amount/
  path allowlists, non-dict-argument rejection).
- Whether a DENY verdict is backed by an actual absence of the tool's
  mocked side effect, **when the call is routed through
  `MockToolEnvironment.execute()`** — this qualifier is load-bearing, see
  Finding 3 below.
- Whether the gateway's allowlist checks are exact-match (not
  normalized) — confirmed by direct test, not assumed.
- Whether a specific, narrow class of audit-log tampering (editing an
  entry without recomputing the hash chain forward from that point) is
  detected — confirmed detected; a stronger attacker is confirmed to
  evade it, see Finding 5.
- Whether a real model (`gpt-4o-mini`, via OpenRouter, through AgentDojo)
  can be steered by injected tool-output content into completing a
  specific set of AgentDojo-defined injection-task goals, for the
  specific `workspace`-suite tasks actually run (3 scenarios × 2
  defenses, plus several 1-scenario pilots).

## Security properties this benchmark cannot currently test

- **Whether the gateway is the only path to tool execution** — in this
  mock, for 5 of 7 tools, it demonstrably is not (Finding 3). A real
  deployment's actual enforcement-boundary completeness is an integration
  property this benchmark doesn't model.
- **Any real filesystem attack** — the mock filesystem is a plain
  in-memory dict with no path resolution, no symlinks, no OS permissions.
  An encoded traversal attempt (`%2e%2e`) is "allowed" by the gateway
  (no literal `..` to catch) but reads nothing, because the mock has no
  real resolution step to exploit — that is the mock being too simple to
  have the vulnerability, not a defense being proven (see
  `tests/test_gateway.py::test_url_encoded_traversal_segment_is_not_a_real_bypass_in_the_mock_fs`).
- **Any real email/financial/network-level attack** — header injection,
  SMTP smuggling, real bank API semantics, real network timing — all out
  of scope; the tools are in-memory lists and dicts.
- **General model robustness** — the deterministic suite tests the
  gateway, not any model. The AgentDojo data is one model on a handful of
  tasks; it cannot support a general robustness claim about `gpt-4o-mini`
  or about LLM agents generally.
- **Concurrency / race conditions (TOCTOU)** — `MockToolEnvironment` and
  `AuditLog` are plain Python objects with no locking; nothing here tests
  or models what happens if two calls race against the same state. A real
  gateway facing concurrent requests could have a time-of-check/time-of-
  use gap this benchmark says nothing about.
- **Tamper detection against a determined attacker** — `AuditLog.verify()`
  alone only detects a *careless* edit (Finding 4). A sophisticated
  attacker with write access who recomputes the chain's suffix evades
  that method entirely, demonstrated directly, not assumed. **Update
  (Phase 5):** a checkpoint-backed cross-check now catches this specific
  attack *if* a checkpoint was taken before the tamper and the attacker
  can't also rewrite the checkpoint store — see
  `docs/phase5_audit_integrity.md`. Still not detected: a tamper confined
  entirely to the window after the most recent checkpoint, or any
  attacker who controls the verifier process itself.

## Policy assumptions and trust boundaries

| Assumption | Where it lives | What breaks it |
|---|---|---|
| `USER_INSTRUCTION`/`SYSTEM` origin is accurately tagged by whatever constructs the `ToolCall` | `gateway.TRUSTED_ORIGINS` | Nothing in this codebase verifies the origin tag is honest — if the code that builds a `ToolCall` mislabels an untrusted-derived call as `USER_INSTRUCTION`, the gateway has no way to catch that; taint tracking here is only as good as whoever assigns the tag |
| Destination/channel/account allowlists are exact strings | `gateway.py` constants | Any caller relying on case/whitespace-insensitive matching will be (correctly, by design) denied — a real integration doing this for real email would need its own normalization layer, deliberately not added here (see Finding 6) |
| `execute()` is the only call path to a tool handler | implicit, nowhere enforced | False for 5 of 7 tools (Finding 3) |
| The hash chain's own stored hashes are the sole integrity signal | `audit.py` | A full-chain-recompute attacker (Finding 4) |

## Potential false positives and false negatives — in the benchmark itself

Distinct from whether the *gateway* over/under-blocks: these are ways the
*benchmark's own tooling* could misreport what happened.

- **False "nothing executed" (false negative on side effects):** fixed in
  this phase — `call_ledger` used to be silent about a side effect
  produced by a directly-invoked handler (Finding 2, now fixed). Residual
  risk: any *new* side-effect list added to `MockToolEnvironment` in the
  future that doesn't also append to `call_ledger` at the point of action
  would reintroduce the same class of bug — there's no structural
  guarantee against that beyond convention.
- **False "tampering detected" confidence:** `audit_integrity_detection_rate`
  reads as "tampering is detected" but only means "the careless-edit
  tamper model is detected" (Finding 5). This is the single most likely
  place this benchmark's own metrics could be over-read.
- **False "enforcement succeeded":** `enforcement_success` requires both
  a DENY verdict and no execution — correctly resistant to either kind of
  single-signal gaming (see the metrics audit below) — no false positive
  found here on re-derivation.

## Metrics whose interpretation depends on assumptions

- `audit_integrity_detection_rate` — depends on the assumption that
  "tampering" means the careless-edit model. See Finding 5.
- `enforcement_success_rate`, `side_effect_prevention_rate` — depend on
  `tool_execution.executed`/`call_ledger` being an accurate record, which
  depended on the ledger being updated correctly (Finding 2, now fixed;
  still depends on every current and future handler consistently
  appending to it).
- `benign_task_success_rate`/`false_block_rate` — depend on the case's
  `ground_truth.expected_verdict` being correct in the first place, which
  is exactly the circularity question (Finding 1).
- AgentDojo's `security` field — depends on the specific injection task's
  own `security()`/`security_from_traces()` implementation correctly
  capturing "the attacker's goal was achieved," which is AgentDojo's
  code, not this repo's; not independently re-verified here beyond
  confirming the *sign* of the field (True = succeeded) against its
  source, which was already done in Phase 2.

## Prioritized findings

| # | Severity | Finding | Evidence | Status |
|---|---|---|---|---|
| 1 | **High** | 20 of 26 cases' ground truth was generated by executing the same code under test, which can only prove determinism, not correctness | Phase 2's case-generator script | **Mitigated**: independent reference oracle (`tests/test_independent_oracle.py`) re-derives all 24 gateway cases from documented policy constants; 49/49 checks agree, zero disagreements found |
| 2 | **High** | `call_ledger` did not reflect a side effect produced by a handler invoked directly (bypassing `execute()`) | Reproduced directly; see `tests/test_execution_boundary_bypass.py` | **Fixed** — ledger append moved into each handler |
| 3 | **High** | 5 of 7 tool handlers (`send_email`, `transfer_funds`, `post_public_message`, `read_file`, `write_file`) have no handler-level failsafe against direct invocation, unlike `wire_transfer`/`delete_account` | Reproduced directly; `tests/test_execution_boundary_bypass.py` | **Open, documented**. Fix requires plumbing `origin`/`ToolCall` through every handler signature so each can self-check `gateway.evaluate()` — a larger, riskier change deliberately not bundled into this audit pass |
| 4 | **High** | The audit log only detects a careless tamper; a determined attacker who recomputes the chain's suffix evades detection entirely | Reproduced directly; `tests/test_audit_limitations.py` | **Partially mitigated (Phase 5)** — `CheckpointStore` + `verify_against_checkpoint()` catches a full-recompute tamper that spans a checkpoint taken before it, as long as the attacker can't also rewrite the checkpoint; it does **not** catch a tamper confined entirely after the last checkpoint, and provides no defense against an attacker who controls the verifier process itself. `AuditLog.verify()` itself is unchanged -- same weakness, same regression test, unmodified. Full scope and the five-class threat model in `docs/phase5_audit_integrity.md` |
| 5 | Medium | `unauthorized_execution_rate` had a floating-point bug (computed as `1.0 - side_effect_prevention_rate`) | Found in Phase 2; independently re-derived by hand in this phase against all 13 fixtures, confirmed fixed | **Fixed** |
| 6 | Medium | `gateway.py` crashed with `TypeError` on non-string `transfer_funds`/`post_public_message` destination arguments | Found and fixed in Phase 2 | **Fixed**, re-confirmed not regressed |
| 7 | Medium | Exact-match-only allowlists create a real overblocking risk for case/whitespace-different legitimate input in a hypothetical production use | Design inspection + tests proving current exact-match behavior | **Design trade-off, documented, not changed** — per explicit instruction not to add normalization without first defining semantics |
| 8 | Medium | Mock filesystem does no real path resolution; cannot claim protection against a real traversal attack | `test_url_encoded_traversal_segment_is_not_a_real_bypass_in_the_mock_fs` | **Design limitation, documented** |
| 9 | Low | 10 of 13 historical `results/run_*.jsonl` files predate the `suite_version`/`gateway_policy_version`/`run_id` header fields; their version provenance isn't established by their own metadata | `generate_benchmark_report.py` output (see below) | **Documented**; no doc found attributing a version to these files incorrectly |
| 10 | Low | No test confirmed a trusted origin doesn't exempt a call from destination/amount validation (only from the taint check) | Verified true by direct probe | **Closed** — test added |
| 11 | Low | No case/test combines malformed args with an untrusted origin on the same call | Coverage matrix review | **Open, documented** — no security consequence either way (DENY regardless), flagged for completeness only |
| 12 | Informational | `ToolCall.origin`/`.args` are untyped at construction; the policy layer, not the type system, enforces | Already documented in Phase 2 | Re-confirmed, not re-litigated |

## Ground-truth circularity (Findings §1, detailed)

The concern, confirmed real: Phase 2 wrote a script that constructed a
`ToolCall`, called `gateway.evaluate()` and `MockToolEnvironment.execute()`,
and recorded their actual output as the case's `ground_truth`. Run that
script against a gateway with a real bug (say, a substring match instead
of exact match on email domains) and it would have faithfully recorded
"ALLOW" as the expected outcome for a case that should DENY — the bug
would be baked into its own test's expectation, and the suite would
report 100% pass with a live vulnerability.

**Independent mitigation performed in this phase:** `tests/test_independent_oracle.py`
contains a second implementation of the policy (`reference_oracle()`),
written from the documented constants and rule list, not by reading
`gateway.py`'s control flow. It was used to hand-derive the expected
verdict/reason_code for all 24 `gateway_tool_call` cases *before* running
anything, then checked against both the stored JSONL ground truth and the
live `gateway.evaluate()` output. Result: **49/49 checks passed, zero
disagreements.**

Honest caveat on what this mitigation is and isn't: it's the same author,
in the same project, writing a second implementation from the same
underlying mental model of the policy — not a blind second reviewer who
never saw `gateway.py`. It substantially reduces the risk (a logic bug
would need to survive two independently-written implementations rather
than one), but it is not the gold-standard "hand-reviewed by someone who
never read the code" oracle the task asks us to consider. If this
benchmark is used for anything with real stakes, a true second reviewer
re-deriving expected outcomes from the policy prose alone, without ever
reading `gateway.py`, remains the stronger recommended fix.

The 5 original `smoke-*` cases (Phase 1) are not mechanically circular in
this way — their ground truth was written by hand before the generator
script existed — but share the softer "same author, same sitting" risk.

## Metric fixture re-verification

All 13 synthetic fixtures in `tests/test_metrics.py` were re-derived by
hand in this phase directly from the current `metrics.py` formulas
(post-bugfix), independent of the original Phase 2 narrative. All 13
matched. Unlike the gateway cases, these were never circular in the first
place: the expected values were computed by hand *before* the formulas
were run against them, which is exactly how the float-precision bug in
`unauthorized_execution_rate` was caught in Phase 2 — a circularly-
generated fixture would have "expected" the buggy value and hidden the
bug. No new metric test was added in this phase, per the instruction to
add one only if re-verification exposed a gap; it didn't.

## AgentDojo design assessment (offline only — no new calls made)

Reviewed `docs/agentdojo_experiment_plan.md` and every real result file
under `results/` (inventory and field semantics re-confirmed via
`generate_benchmark_report.py`, below).

- **Is 10 pairs / 2 conditions / 1 repetition adequate for an exploratory
  pilot?** Adequate as a *next step up* from the existing 3-scenario tie,
  not adequate to support a confidence-backed conclusion either way.
  20 trials total is enough to notice a large effect (e.g. 0/10 vs 7/10
  attack success) but not a small one — at this N, a true underlying
  attack-success-rate difference of, say, 10 percentage points is
  plausibly indistinguishable from noise. The plan itself already states
  this ("suggestive, not statistically significant") — that framing is
  correct and should be kept.
- **Task selection rationale:** the plan explicitly defers picking the
  additional 7 pairs beyond the existing 3, for review before spending
  tokens — appropriate; a prioritized diversity criterion (spanning
  exfiltration, calendar manipulation, posting) is stated but not yet
  instantiated into an actual list. That instantiation is the next
  concrete step, not done here (would require inspecting AgentDojo's
  `workspace` suite's full task catalog, which is possible offline but
  wasn't done in this pass — scope boundary, not an oversight).
- **Repeated runs / model variability:** the plan correctly declines to
  commit to per-pair repetitions without evidence they're needed, and
  correctly notes `gpt-4o-mini`'s sampling may not be fully deterministic.
  Reasonable.
- **Meaning of the `security` field:** re-confirmed in this phase against
  `agentdojo/base_tasks.py`'s own docstring and `task_suite.py`'s
  `_check_injection_task_security` — `security=True` means the injection
  task's goal was achieved. The plan states this correctly.
- **Cost estimation:** the plan correctly declines to fabricate a number
  and states the two missing inputs (current OpenRouter pricing,
  per-trial token usage). Re-confirmed in this phase: no existing result
  file has a `usage` field; only `duration` (wall-clock seconds) is
  present, and `duration` is explicitly and correctly *not* treated as a
  token-count proxy in the plan.
- **Recommendation — minimal exploratory design:** keep the existing 3
  pairs + the plan's proposed 7 additional pairs (10 total) × 2
  conditions × 1 rep = 20 trials, as already proposed. Treat the result
  as exploratory regardless of outcome.
- **Recommendation — stronger follow-up design:** only after the 20-trial
  exploratory run, and only if it shows a result worth confirming,
  compute an actual sample size from the observed effect size (e.g. via a
  power calculation for a two-proportion test) rather than picking a
  round number, and consider adding a second attack type
  (`ignore_previous`/`manual`) as a separate follow-up, not combined with
  the first expansion.
- **Not run.** No AgentDojo/OpenRouter calls were made in this phase.

## Reproducibility and research artifacts

- `run_all()` records `run_id`, `run_timestamp_utc`, `suite_version`,
  `gateway_policy_version`, `case_count`, and `suite_metrics` in every new
  run's header, and raises if the loaded cases don't share one
  `suite_version` — confirmed present and consistent in the 3 most recent
  result files (see `generate_benchmark_report.py` output below).
- **Historical gap, confirmed (Finding 9):** of the 13
  `results/run_*.jsonl` files, **10 predate these header fields entirely**
  (no `suite_version`/`gateway_policy_version`/`run_id` key at all), and
  one more (`run_20261017T052312Z.jsonl`) has the 26-case suite content
  but still predates the header-metadata addition. Only the 3 most recent
  files carry full version metadata. No documentation in this repo was
  found attributing a specific suite/policy version to any of the 10
  bare files — but the files themselves cannot establish it either; their
  place in the suite's evolution is inferable only from session
  chronology, which is not durable, machine-checkable provenance.
- `generate_benchmark_report.py` (new, this phase) is a read-only script
  that summarizes every `results/run_*.jsonl` (flagging exactly this
  metadata gap per file) and every AgentDojo result directory, with the
  two kept in clearly separate sections and the `security`-field
  direction restated inline. It does not write, modify, or delete
  anything under `results/`.
- `tests/test_custom_suite.py::test_repeated_runs_produce_equivalent_decisions_and_metrics`
  (added Phase 2, re-run this phase) confirms two runs of the same suite
  produce identical per-case results modulo timestamp — still passing.

## Confirmed defects vs. design trade-offs vs. hypothetical risk — summary

- **Confirmed defects, fixed this phase:** ledger misrepresentation
  (Finding 2).
- **Confirmed defects, fixed in Phase 2 and re-verified here:** metrics
  float-precision bug, gateway `TypeError` crashes (Findings 5, 6).
- **Confirmed, open as of Phase 3, documented (not hypothetical —
  demonstrated with working code):** handler-level gateway bypass on 5
  tools (Finding 3 — **closed in Phase 4**, see
  `docs/phase4_execution_boundary.md`), full-chain-recompute audit
  evasion (Finding 4 — **partially mitigated in Phase 5**, see
  `docs/phase5_audit_integrity.md`).
- **Design trade-offs, not defects:** exact-match allowlists (Finding 7),
  mock filesystem's lack of real path resolution (Finding 8),
  untyped `ToolCall` fields (Finding 12).
- **Nothing in this audit was found to be merely hypothetical** — every
  finding above with "evidence" listed was reproduced with real code in
  this session, not inferred from reading alone.
