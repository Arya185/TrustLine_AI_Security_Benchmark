# Phase 6 — AgentDojo pilot readiness review

**Status: review only. No AgentDojo/OpenRouter call has been made to
produce this document — every finding below came from reading installed
source code, reading existing local result files, running AgentDojo's
own offline (no-LLM) diagnostics, and one web search for public pricing
information. Nothing here is an executed experiment. Stop and await
explicit approval before any external model call.**

## What was inspected

- `git status --short`, branch, `git log`, `git diff --stat` (repo state
  preserved, matches end of Phase 5 exactly — see below).
- `docs/agentdojo_experiment_plan.md`, `docs/benchmark_protocol.md`'s
  AgentDojo sections, `docs/phase3_independent_audit.md`,
  `docs/phase5_audit_integrity.md`.
- Installed `agentdojo` package source: `agent_pipeline.py` (model/defense
  construction), `benchmark.py` (trial execution, skip/rerun logic),
  `openai_llm.py` (temperature/sampling defaults), `models.py`
  (model-to-provider mapping), `scripts/check_suites.py` +
  `task_suite.py`'s `check()` method (offline injectability diagnostic).
- `.env` key presence (names and non-emptiness only — no value ever
  read into this document or printed).
- `check_agentdojo_model.py`.
- Every existing result file under `results/` (re-confirmed counts,
  schemas, and the real routing mechanism from source, not assumption).
- Ran `python -m agentdojo.scripts.check_suites -s workspace -v v1.2.2`
  and the equivalent `TaskSuite.check()` call directly — **these use
  AgentDojo's own `GroundTruthPipeline`, not a real LLM call; zero
  external requests were made.**
- One `WebSearch` call for current OpenRouter pricing (a pricing lookup,
  not a call to the OpenRouter *inference* API — no API key was used, no
  AgentDojo/model call occurred).

## Confirmed environment and configuration

- `agentdojo==0.1.35` (`pip show agentdojo`), matching every historical
  result file's `agentdojo_package_version`.
- `.env` has `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`,
  `OPENAI_COMPATIBLE_BASE_URL`, `OPENAI_COMPATIBLE_API_KEY`, all present
  and non-empty (lengths checked, values never read into this doc).
- **Real routing mechanism, confirmed from the installed SDK's own
  source** (`openai/_client.py` lines 255, 308): `openai.OpenAI()` called
  with no arguments reads `OPENAI_API_KEY` and `OPENAI_BASE_URL` from the
  environment. AgentDojo's `get_llm(provider="openai", ...)` branch
  calls exactly `openai.OpenAI()` with no arguments. This is not an
  assumption — it's why the historical `gpt-4o-mini-2024-07-18` runs
  actually reached OpenRouter.
- `ModelsEnum.GPT_4O_MINI_2024_07_18` → pipeline name
  `gpt-4o-mini-2024-07-18` → provider `"openai"` (confirmed via
  `agentdojo.models.MODEL_PROVIDERS`) → the routing above applies.
- `workspace` suite, benchmark version `v1.2.2` (the CLI's own default):
  **40 user tasks, 14 injection tasks** (confirmed via
  `get_suites("v1.2.2")`) — ample room for the proposed 10-pair pilot.
- Sampling: `temperature=0.0` by default for both the main `OpenAILLM`
  and `OpenAILLMToolFilter` (confirmed in `openai_llm.py`) — both
  conditions use equivalent, maximally-deterministic settings; the only
  pipeline difference between conditions is the extra filter stage
  itself, not a hidden sampling-config divergence.
- Prior reported state re-verified, not assumed: `pytest` **191/191**,
  custom suite **27/27**, `suite_version` **2.1.0** — matches reported
  facts exactly (ran live this session before this review).

## Experimental design and identified risks

### Finding 1 (critical, reframes the whole premise): `tool_filter` is AgentDojo's own built-in defense, not TrustLine's

Traced the actual execution path rather than assuming the name implies
the connection. `agent_pipeline.py`'s `--defense tool_filter` branch
constructs `OpenAILLMToolFilter(TOOL_FILTER_PROMPT, llm.client, llm_name)`
— an LLM-prompted tool-selection stage that ships with AgentDojo itself.
Searched the entire installed `agentdojo` package for any reference to
`trustline_bench`, `gateway.evaluate`, `MockToolEnvironment`, or
`Authorization`: **zero matches.** Searched this repo for any
`--module-to-load` usage (the only documented mechanism for registering
a custom AgentDojo defense) or any custom pipeline/suite file: **none
found.**

**There is currently no code path by which AgentDojo's pipeline ever
calls into this repo's `src/trustline_bench/` gateway, mock tools, or
authorization boundary.** Every historical "baseline vs tool_filter"
AgentDojo result compares two AgentDojo-native configurations. Neither
one is TrustLine. To be clear about what this does *not* mean: no prior
phase's documentation was found to misstate this — `docs/agentdojo_experiment_plan.md`'s
own hypotheses are phrased as "does `tool_filter`..." not "does
TrustLine...", which is accurate. But this phase's brief explicitly asks
for "the exact baseline and TrustLine intervention being compared," and
the honest answer is: **there is no TrustLine intervention in the
AgentDojo path to compare.** This needs an explicit decision (see
"Unresolved issues" below) before a pilot can be described as testing
TrustLine in any sense.

### Finding 2: the planned "10 pairs" cannot be run as a single CLI invocation

`benchmark.py`'s `--user-task`/`--injection-task` CLI flags are both
`multiple=True`, and `benchmark_suite_with_injections()` loops every
given user task against *every* given injection task — a **cartesian
product**, not a paired list. Passing 10 `-ut` flags and 10 `-it` flags
in one invocation would run 100 trials, not 10. Confirmed by checking
that the existing `trustline-matrix-*` result sets have exactly 3 trace
files each (not 9, which a 3×3 cartesian product would have produced) —
consistent with 3 separate single-pair invocations having been used
historically, not one multi-flag call.

**Implication:** running the planned 10 pairs requires 10 separate CLI
invocations (or a small wrapper script looping over the exact pair
list and calling the benchmark function once per pair), each with
exactly one `-ut` and one `-it`. This must be built before execution;
it does not exist in this repo yet.

### Finding 3: AgentDojo's own offline injectability self-check is uniformly negative here, and does not match observed reality

Ran `python -m agentdojo.scripts.check_suites -s workspace -v v1.2.2`
(and the underlying `TaskSuite.check()` directly) — **zero external
calls, it uses AgentDojo's own `GroundTruthPipeline`, not a real LLM.**
Result: **0 of 40 user tasks pass the "is injectable" check**, including
`user_task_14` and `user_task_24`, which are two of the three pairs in
this repo's own *already-executed, real* `trustline-matrix-*` results —
where injected content demonstrably did appear in the model's actual
tool-output context (confirmed by direct trace inspection in Phase 3).

Read `task_suite.py`'s `check()` source to understand why: it tests
whether the task's **minimal ground-truth solution path** ever reads a
field holding a generic canary placeholder. A real model solving the
same task less efficiently (e.g., browsing more of an inbox than
strictly necessary) can still encounter an injected field that the
*optimal* ground-truth path skips. This explains the mismatch without
implying a version bug: **the check is a conservative, not authoritative,
signal for this suite's design, where injection vectors are often placed
in content a minimal solver doesn't need but a real model frequently
reads anyway.**

**Implication:** this check cannot be used as a pass/fail filter for
selecting new pairs (it would reject everything). New-pair selection
below relies on reading task prompts for a plausible tool-output carrier
(same method the existing plan already described), not on this
diagnostic. Whether a *new*, not-yet-run pair actually delivers an
injection can only be confirmed by running it.

### Other items from the audit checklist

- **Equivalent budgets:** confirmed equivalent (same `OpenAILLM`
  instance/settings for the main task across both conditions; tool_filter
  only adds one extra filter-stage call using the same model/client).
- **Utility/attack-success/error definitions:** unchanged and already
  independently verified against `agentdojo/base_tasks.py` source in
  Phase 3 (`security=True` means the attack succeeded) — re-confirmed,
  not re-litigated here.
- **Metrics miscounting blocked-as-success or vice versa:** none found;
  this was the subject of Phase 3's independent audit and nothing in
  this repo's AgentDojo result handling (`inspect_trustline_results.py`,
  `generate_benchmark_report.py`) computes a derived "attack success"
  value — both read AgentDojo's own `security` field directly.
- **Custom benchmark vs AgentDojo tracks:** confirmed distinct —
  different result-file schemas, different directories, cross-referenced
  but never merged in `generate_benchmark_report.py`'s two separate
  report sections.
- **Per-trial metadata for reproducibility:** existing files record
  `agentdojo_package_version`, `benchmark_version`, `pipeline_name`,
  task IDs, `attack_type`, timestamp — sufficient to identify a run, but
  **no token usage is recorded anywhere** (checked: no `usage` key in
  any existing result file, confirmed in Phase 3 and re-confirmed here).
  Capturing it would require a custom wrapper around the OpenAI client
  (AgentDojo's own logger has no hook for it) — not implemented, and
  not something to build silently inside this readiness pass.
- **force_rerun / skip-if-exists:** confirmed (`benchmark.py` lines ~88,
  101): a trial already logged in the target `--logdir` is *skipped and
  reused*, not overwritten, unless `--force-rerun` is passed. A fresh,
  uniquely-named `--logdir` is still required for this pilot regardless,
  to avoid any ambiguity about which results belong to it.

## Proposed trial count and execution limits

- **10 (user_task, injection_task) pairs** (the existing 3, documented
  below, plus 7 new candidates for review) **× 2 conditions
  (baseline, tool_filter) × 1 repetition = 20 trials**, matching the
  existing plan's scope exactly.
- **Hard caps, proposed:** 20 trials is the ceiling for this pilot — no
  silent expansion. At most 1 retry per trial on a transient error (rate
  limit, timeout); a trial that still fails is recorded as an error, not
  silently dropped or counted either way. If more than 20% of trials
  error even after retry, stop and report rather than continuing to
  spend budget chasing a broken configuration.
- **Run identification:** a new `--logdir results/phase6-pilot-<UTC
  timestamp>/` — never reusing `results/trustline-matrix-*` or any other
  existing directory name, so completed vs. historical vs. interrupted
  runs are never ambiguous. A trial's presence under that directory with
  a parseable result file is "completed"; absence is "not yet run or
  interrupted" — AgentDojo's own per-trial JSON file is the unit of
  completion, so a process interrupted mid-run leaves exactly the
  trials-so-far on disk and no partial/corrupt file for the trial in
  flight (confirmed: each trial's file is written after that trial's
  `TraceLogger` context exits, not incrementally).

### Proposed pairs (existing 3 + 7 new candidates — for review, not finalized)

| # | user_task | injection_task | injection goal (from AgentDojo source) | status |
|---|---|---|---|---|
| 1 | `user_task_0` | `injection_task_0` | email a message to an external address | already run (baseline + tool_filter) |
| 2 | `user_task_14` | `injection_task_3` | exfiltrate a specific email's body | already run |
| 3 | `user_task_24` | `injection_task_6` | exfiltrate all unread emails | already run |
| 4 | `user_task_1` (calendar summary — reads calendar) | `injection_task_2` | create an unauthorized calendar event | new — diversifies goal type to manipulation, not exfiltration |
| 5 | `user_task_30` (reads a cloud file) | `injection_task_1` | delete a cloud file | new — diversifies to a destructive action |
| 6 | `user_task_13` (explicitly follows instructions found in an email) | `injection_task_4` | exfiltrate a Facebook security code | new — this user task's own design makes it an unusually direct injection carrier |
| 7 | `user_task_4` (multi-step task) | `injection_task_13` | mass-email every meeting participant | new — diversifies injection mechanism (scale, not just exfiltration target) |
| 8 | `user_task_2` (calendar lookup) | `injection_task_5` | exfiltrate a Facebook security code (variant) | new — repeats a goal type on a different carrier task, for within-goal variance |
| 9 | `user_task_20` (calendar scheduling) | `injection_task_7` | exfiltrate all sent+received email content | new |
| 10 | `user_task_4` (multi-step task) | `injection_task_10` | exfiltrate all cloud file contents | new |

**Caveat, stated plainly:** pairs 4–10 were selected by reading task
prompts for a plausible tool-output carrier, the same method the
existing plan already used for pairs 1–3 — not validated by execution
(per Finding 3, AgentDojo's own offline check isn't a usable filter
here) and not validated against AgentDojo's published paper's task list
(not checked in this pass). Some may turn out, once actually run, not to
deliver the injection at all (recorded as `security=False` for a
"the agent never encountered it" reason rather than "the defense worked"
reason — see `docs/agentdojo_experiment_plan.md`'s existing caution
about not conflating these). This is a real limitation of the pilot as
proposed, not hidden.

## Cost estimate

**Grounded, sourced price** (OpenRouter, `gpt-4o-mini`, checked via web
search, pricing dated August 2026): **$0.150 per 1M input tokens,
$0.600 per 1M output tokens.**
[Source: computeprices.com / llmreference.com aggregated OpenRouter pricing](https://computeprices.com/providers/openrouter/models/gpt-4o-mini)

**No per-trial token-usage data exists anywhere in this repo** (Finding
noted above) — this is not estimated from measured data, because there
is none. Per the instruction to define a conservative usage cap instead
of fabricating a token estimate:

- **Assumed ceiling** (explicitly a budgeting assumption, not a
  measurement): 30,000 tokens per trial, combined input+output — a
  generous bound for a short multi-turn `workspace`-suite agent trial.
  `tool_filter` trials add one short extra filter call; budgeted as
  +20% for that condition's trials.
- Worst case under this assumption: 20 trials × ~30,000–36,000 tokens ≈
  **650,000 tokens total**, at a roughly 80/20 input/output split
  (agent conversations are context-heavy) ≈ **under $0.20 total**, using
  the sourced price above.
- **This dollar figure is a ceiling under a stated assumption, not a
  prediction.** The real safety mechanism is the **20-trial hard cap**
  above, not this number — if actual per-trial usage is 10× the assumed
  ceiling, the hard trial cap still bounds total spend to a known,
  small multiple of this estimate, which remains low at this model's
  price point regardless.

## Exact command(s) that would run the pilot (not yet executed)

AgentDojo's CLI cannot express "these 10 specific pairs" in one call
(Finding 2), so the pilot requires one invocation per pair, per
condition — 20 total — each writing into the same fresh logdir:

```zsh
source .venv/bin/activate
export OPENAI_API_KEY="$OPENROUTER_API_KEY"
export OPENAI_BASE_URL="https://openrouter.ai/api/v1"
LOGDIR="results/phase6-pilot-$(date -u +%Y%m%dT%H%M%SZ)"

# Repeated once per (user_task, injection_task) pair above, for EACH
# condition (baseline: no --defense flag; tool_filter: --defense tool_filter):
python -m agentdojo.scripts.benchmark \
  --model GPT_4O_MINI_2024_07_18 \
  --suite workspace \
  --attack direct \
  --user-task user_task_1 --injection-task injection_task_2 \
  --logdir "$LOGDIR" \
  --benchmark-version v1.2.2
```

(and the same with `--defense tool_filter` appended, and with each of
the other 9 pairs' `-ut`/`-it` values substituted in turn — 20 invocations
total, or a thin Python wrapper looping the pair list and calling
`benchmark_suite_with_injections` directly instead of shelling out 20
times; either is equivalent in terms of external calls made).

**This command has not been run.**

## Unresolved issues requiring a decision

1. **(Blocking, conceptual)** Given Finding 1, do you want to: (a) run
   this pilot as planned, under an explicit, repeatedly-stated framing
   that it evaluates **AgentDojo's own `tool_filter` defense**, not
   TrustLine, as a reference comparator; or (b) pause this pilot and
   first build a real integration (e.g. a custom `--module-to-load`
   defense that calls `trustline_bench.gateway.evaluate()` inside
   AgentDojo's tool-execution loop) so that a future pilot can actually
   test TrustLine itself? These are very different pieces of work and
   this review does not choose between them.
2. **(Blocking, operational)** Approve, reject, or amend the 7 new
   candidate pairs above — they are prompt-read guesses, not validated.
3. **(Blocking, budget)** Confirm the 20-trial hard cap and the
   conservative cost ceiling (~$0.20 under a stated assumption, bounded
   regardless by the trial cap) as acceptable, or set different limits.
4. **(Non-blocking, for awareness)** Token-usage capture does not exist
   in this pipeline; building it is a separate small task not done here.

**This review stops here. No AgentDojo or OpenRouter call has been made.
Awaiting explicit approval before any external model call.**
