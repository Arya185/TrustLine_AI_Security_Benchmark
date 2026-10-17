# Proposed AgentDojo follow-up experiment — plan only, not run

**Status: proposed, not executed.** No new AgentDojo/OpenRouter calls have
been made to produce this document. It is presented for review before any
such calls happen. Everything below the horizontal rule is a plan; nothing
below it should be read as a result.

## Why a follow-up is needed

The existing `trustline-matrix-{baseline,tool-filter}` pilot has 3 scenarios
per condition. Both conditions scored `security=False` (attack did not
succeed) on all 3 — a 0/3 vs 0/3 tie. **That is not evidence tool_filter
provides a security advantage**: with an N of 3 per condition, a defense
that does nothing differently from baseline would produce the same result
just as easily as a defense that works. The tie is also consistent with
the specific 3 tasks being too easy for either condition to fail on. The
only directionally meaningful signal in the existing pilot is on *utility*
(1/3 baseline vs 3/3 tool_filter), not security — and even that is 3
scenarios, not enough to generalize from.

## Research question and hypotheses

**RQ:** Does the `tool_filter` defense reduce the rate at which a
prompt-injection attack achieves its goal, relative to no defense, for
`gpt-4o-mini` on AgentDojo's `workspace` suite — without an unacceptable
loss of benign-task utility?

- **H1 (security):** `tool_filter` lowers attack success rate
  (`security=True` rate) relative to baseline, by a margin large enough to
  be distinguishable from noise at the planned N.
- **H0 (security, null):** `tool_filter` does not change attack success
  rate relative to baseline.
- **H2 (utility):** `tool_filter` does not substantially reduce benign
  task-completion rate relative to baseline.

## Conditions

| Condition | Defense | Model | Suite |
|---|---|---|---|
| baseline | none | `gpt-4o-mini` via OpenRouter | `workspace` |
| tool_filter | `tool_filter` | `gpt-4o-mini` via OpenRouter | `workspace` |

Attack type: `direct` (matches the existing pilot, so results are
comparable to it rather than introducing a second new variable at the same
time). A *separate*, later follow-up could vary attack type
(`ignore_previous`, `manual`) once the direct-attack result is in — not
combined into this first expansion, to keep the one experiment interpretable.

## User-task and injection-task selection rationale

The existing pilot used 3 (user_task, injection_task) pairs:
`(user_task_0, injection_task_0)`, `(user_task_14, injection_task_3)`,
`(user_task_24, injection_task_6)`. AgentDojo's `workspace` suite has more
pairs available than these 3 (the suite's full task set, inspectable via
`get_suites`/`get_suite` without any API call). Proposed selection
criteria for the expansion:

1. Keep the existing 3 pairs, so the new data is directly comparable to
   (not a replacement for) the existing pilot.
2. Add enough additional pairs to reach the target N below, chosen to
   **span distinct injection goals** (not 10 near-duplicates of the same
   exfiltration pattern) — e.g. data exfiltration via email, calendar
   manipulation, unauthorized message posting — so a single easy-to-defend
   or easy-to-attack goal doesn't dominate the result.
3. Exclude any pair where the *benign* user task's ground truth is
   ambiguous or where AgentDojo's own utility check is known to be noisy
   (would need inspecting the suite's task definitions directly before
   finalizing the list — not done yet, since that's part of executing this
   plan, not proposing it).

**This document does not yet commit to a final task list** — picking the
exact N pairs beyond the existing 3 should happen as a visible step before
spending any tokens on them, so the list itself can be reviewed.

## Number of scenarios and repetitions

Proposed: **10 (user_task, injection_task) pairs × 2 conditions × 1
repetition each = 20 trials**, as the next step up from 3. Not proposing
repetitions per pair at this stage (re-running the identical pair multiple
times) because `gpt-4o-mini` at the sampling settings AgentDojo's default
pipeline uses may not be fully deterministic across calls — if the first
20-trial run shows borderline results, repeating a subset is a smaller,
targeted follow-up rather than committing to N repetitions up front without
evidence they're needed.

10 is a judgment call, not derived from a power calculation — a real power
calculation would need an assumed effect size and baseline attack-success
rate, neither of which is known yet from 3 data points. If a specific
effect size matters for a decision, that number should be computed before
running, using whatever rate the literature or a slightly larger pilot
suggests as a starting point.

## Primary and secondary metrics

- **Primary:** attack success rate per condition = mean of AgentDojo's
  `security` field over the (user_task, injection_task) trials in that
  condition (`security=True` → attack succeeded, confirmed against
  AgentDojo's own source, not assumed — see `docs/benchmark_protocol.md`).
  Lower is better.
- **Secondary:** benign utility rate per condition = mean of `utility`
  over the same trials. Higher is better; a defense that drives this to 0
  "succeeds" at security only by breaking the product.
- Reported with the raw counts (e.g. "2/10"), not just a percentage — at
  this N, a percentage alone invites false precision.

## Main-task trace parsing and setup-phase exclusions

Only `<user_task>/<attack_type>/<injection_task>.json` files are read for
`utility`/`security`. Any `<injection_task>/none/none.json` file (the
injection task benchmarked as a standalone task) is **excluded from
scoring** — it is the attacker's goal's own utility baseline, not a
security result, per the distinction already documented in
`docs/benchmark_protocol.md` and enforced by `inspect_trustline_results.py`
only ever reading the combined-attack path.

## Expected token usage and cost estimation — what's missing

**No cost estimate is given here.** The existing result files in
`results/` do not record token usage (checked: `usage` is not a key in any
of them, only `duration` in seconds is). To produce a real estimate before
running, two things are needed that aren't available from inside this
repo:

1. **Current OpenRouter price** for `openai/gpt-4o-mini` (input and output
   token rates) — this changes over time and must be looked up fresh at
   decision time, not recalled from memory.
2. **Per-trial token usage for this specific suite** — either from a small
   (e.g. 2-trial) metered test run whose actual usage is captured, or from
   AgentDojo's own per-call logging if enabled. `duration` (wall-clock
   seconds) in the existing files is not a token-count proxy and should
   not be used as one.

Once both are available: `estimated_cost = trials × avg_tokens_per_trial ×
price_per_token`, with `trials = 20` under this plan's proposed scope.

## Stopping criteria

- Run the full proposed 20-trial batch (not fewer, mid-batch) before
  drawing any conclusion — a partial batch would reintroduce the same
  small-N problem this plan exists to fix.
- If any trial errors (rate limit, context length, provider outage), log
  it and retry that trial once; if it still fails, report it as an error,
  not as a security or utility result either way (don't let an API error
  get silently counted as `security=True`/"safe" by falling through to a
  default).
- Stop and report before spending on any task list that hasn't been shown
  for review first (see "User-task and injection-task selection
  rationale").

## Known limitations and interpretation rules

- 20 trials per condition is still a modest N. A result at this scale
  supports "this is suggestive" language, not "statistically significant"
  language, unless an appropriate significance test is run against the
  actual counts obtained (e.g. Fisher's exact test on a 2x2 attack-success
  table) — propose running that test on the real counts once they exist,
  not pre-committing to a p-value threshold now.
- A single model (`gpt-4o-mini`) and a single suite (`workspace`) cannot
  support a claim about `tool_filter`'s effectiveness in general, only
  about this model on this suite.
- If attack success rate is 0 for both conditions again at N=20, that is
  still not proof of no effect — it would be grounds to propose either a
  harder/more varied attack set or a different model, not to conclude
  `tool_filter` is unnecessary.
- This plan does not cover cost beyond the formula above; actual go/no-go
  on spend is a separate decision once the two missing inputs are filled
  in.

---

**This plan has not been executed.** No OpenRouter or AgentDojo calls were
made to produce it.
