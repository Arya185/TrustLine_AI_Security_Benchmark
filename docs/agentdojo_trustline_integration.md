# AgentDojo ↔ TrustLine integration: design, implementation, and limits

**Status: a minimal adapter is implemented and tested in this phase
(`src/trustline_bench/agentdojo_adapter.py`,
`tests/test_agentdojo_adapter.py`) using the real installed AgentDojo
interfaces and real `FunctionCall`/`ChatAssistantMessage` objects — but
with no real model and no external API call anywhere in it.** It closes
part of the gap documented in `docs/readiness_review.md` Finding 1, not
all of it. The remaining, unclosed part is explained precisely below,
not glossed over.

## The current AgentDojo execution flow (traced from installed source, not assumed)

```
model turn (LLM) -> ChatAssistantMessage with tool_calls: list[FunctionCall]
        |
        v
ToolsExecutionLoop.query()  (agent_pipeline/tool_execution.py)
        |
        +--> for each pipeline element in order (e.g. OpenAILLMToolFilter, llm, ToolsExecutor):
        |         element.query(query, runtime, env, messages, extra_args)
        |
        v
ToolsExecutor.query()  <-- iterates messages[-1]["tool_calls"]
        |
        +--> for each tool_call:
        |       runtime.run_function(env, tool_call.function, tool_call.args)
        |              |
        |              v
        |       FunctionsRuntime.run_function()  (functions_runtime.py:246)
        |              |
        |              v
        |       the actual registered Python tool function executes
        |              against AgentDojo's own task environment (env)
        v
ChatToolResultMessage appended to messages, loop continues
```

**The exact point a real side effect happens** is inside
`FunctionsRuntime.run_function()`, called from `ToolsExecutor.query()`
(`tool_execution.py` line 103: `runtime.run_function(env, tool_call.function, tool_call.args)`).
Confirmed by reading this file directly, not inferred from a class name.

**`--defense tool_filter` inserts `OpenAILLMToolFilter` into the pipeline
*before* the main LLM element**, not anywhere near `ToolsExecutor`. It
restricts which tool *definitions* are shown to the model before it
decides what to call — an entirely different mechanism from checking a
specific proposed call against a policy at execution time. Confirmed in
`docs/readiness_review.md` Finding 1 and re-confirmed here: this ships
with AgentDojo, shares no code with TrustLine.

## The current TrustLine execution flow (for comparison)

```
ToolCall(tool, args, origin) -> gateway.evaluate(call) -> ALLOW/DENY
                                        |
                                   MockToolEnvironment.execute()
                                   mints Authorization, handler self-checks it,
                                   side effect happens only if authorized
```

Full detail in README.md sections F–H. The key structural facts that
matter for integration: TrustLine's policy decision is a pure function
of `(tool_name, args, origin)`; its *enforcement* additionally requires
every handler to verify a bound `Authorization` token before acting.

## The missing integration boundary, precisely

AgentDojo's `ToolsExecutor` calls `runtime.run_function()` directly, with
no policy check of any kind in between, and with AgentDojo's own task
tools (defined inside the `agentdojo` package, e.g. workspace's
`send_email`, `delete_file`) — **not** TrustLine's `MockToolEnvironment`
handlers. There are two distinct gaps, not one:

1. **No policy check runs before `run_function()`** — this is the gap a
   pipeline-element adapter (inserted the same way `OpenAILLMToolFilter`
   is) can close, and this phase does close it, for the subset of tools
   where a mapping exists (see below).
2. **AgentDojo's tools are not TrustLine's tools** — different functions,
   different argument schemas, different mock environments
   (`agentdojo`'s workspace `Environment` vs. TrustLine's
   `MockToolEnvironment`). Confirmed concretely: AgentDojo workspace's
   real `send_email` schema (read via
   `ws.tools` → `fn.parameters.model_json_schema()`) requires
   `recipients: list[str]` (a **list**), `subject: str`, `body: str`,
   plus optional `attachments`/`cc`/`bcc`. TrustLine's `send_email`
   expects a single `recipient: str`. These are not the same function
   with a different name — they are different schemas that happen to
   share a name and a general concept. **No TrustLine equivalent exists
   at all** for AgentDojo workspace tools like `delete_email` or
   `delete_file`.

## The adapter implemented this phase

`src/trustline_bench/agentdojo_adapter.py`:

- `translate_agentdojo_call(function_name, kwargs) -> AdapterTranslation`
  — a pure function mapping a **subset** of AgentDojo workspace tool
  calls onto a TrustLine `ToolCall`, where a sensible mapping exists:
  - `send_email` → TrustLine `send_email`. `recipients` (a list) is
    mapped by checking **every** recipient against TrustLine's
    `ALLOWED_EMAIL_DOMAINS` allowlist, denying if any one fails — the
    conservative choice, not "check only the first recipient."
  - Any other AgentDojo tool name (including `delete_email`,
    `delete_file`, and anything else in the suite) → explicitly
    `mapped=False`. **This is not silently allowed and not silently
    denied** — the adapter reports "TrustLine has no policy opinion on
    this tool" as its own distinct, visible outcome, and the caller
    (see below) treats unmapped tools as pass-through, documented as a
    real scope limit, not hidden as if TrustLine covered them.
- `TrustLineEnforcementElement` — a `BasePipelineElement` subclass (the
  same base class `OpenAILLMToolFilter` and `ToolsExecutor` use),
  designed to be inserted into the pipeline **immediately before**
  `ToolsExecutor`. For each `FunctionCall` in the last assistant
  message's `tool_calls`: translates it; if mapped and
  `gateway.evaluate()` returns `DENY`, **removes that call from
  `tool_calls` and appends a synthetic `ChatToolResultMessage` with
  `error` set** (the same pattern AgentDojo's own `ToolsExecutor` uses
  for an invalid-tool call, at `tool_execution.py` lines 86–96) — so
  the model sees a denial in its next turn, exactly like a real error,
  rather than the call silently vanishing. If unmapped or `ALLOW`, the
  call passes through unchanged to `ToolsExecutor`, which then runs it
  as it always would.

**Origin, stated as plainly as possible — this is the central, honest
limitation of this adapter:** TrustLine's gateway decision depends on
`origin` (`ToolCallOrigin.USER_INSTRUCTION` / `SYSTEM` /
`UNTRUSTED_TOOL_OUTPUT`) — this is what the taint check (TrustLine's
primary prompt-injection defense) is built on. **AgentDojo's message
history carries no first-class signal for this.** `ToolsExecutor` sees
only `(function_name, args)`; nothing in the installed AgentDojo
interfaces marks whether the model's decision to call a given tool was
influenced by a prior tool result containing injected content.

This adapter defaults every translated call's origin to
`ToolCallOrigin.USER_INSTRUCTION` — meaning **the taint check, the part
of TrustLine's policy this whole benchmark exists to test, is never
exercised through this integration path.** A call could be checked
against destination/amount/path/prohibited-tool rules (origin-independent
checks), but never against the untrusted-origin rule, because this
adapter has no honest way to know the real origin. Building a real
provenance signal would require tracking, across the whole message
history, which tool results an upcoming tool call's arguments or
triggering context trace back to — a non-trivial, heuristic,
architecturally invasive addition to AgentDojo's own message-passing
design, not something achievable as "the smallest justified adapter,"
and not attempted here. **Any claim that this integration tests
TrustLine's prompt-injection defense specifically would be false** —
flagged here explicitly so it is never made by accident.

**Bypass boundary, also stated plainly:** this adapter works by being
first in the pipeline list, ahead of `ToolsExecutor`. It does **not**
wrap `FunctionsRuntime.run_function()` itself. Anything that calls
`run_function()` directly — bypassing the pipeline ordering entirely —
has no TrustLine check in its way, the same class of gap Phase 3/4 found
and closed for TrustLine's *own* handlers, now re-appearing at the
AgentDojo integration boundary and **not closed here**. A stronger
integration would wrap or monkey-patch `run_function` itself; this was
judged too invasive a change to AgentDojo's own internals for this
phase's scope, and is listed as future work below.

## How allowed and denied actions are handled, and side effects recorded

- **Allowed** (origin-independent checks pass, or tool unmapped): the
  `FunctionCall` passes through unmodified; `ToolsExecutor` runs it
  exactly as it would without this adapter present; AgentDojo's own
  side-effect environment (e.g. workspace's simulated inbox) is what
  changes, not TrustLine's `MockToolEnvironment` — these remain two
  separate mock worlds, never merged.
- **Denied**: the `FunctionCall` is removed from `tool_calls` before
  `ToolsExecutor` ever sees it; a `ChatToolResultMessage` with a
  TrustLine-specific `error` string is appended in its place.
  `runtime.run_function()` is never called for that specific call —
  verified directly in `tests/test_agentdojo_adapter.py` by chaining
  `TrustLineEnforcementElement` with the real `ToolsExecutor` against a
  function with an observable side effect, and asserting that side
  effect never happened for a denied call, and did happen for an
  allowed one.

## Measuring attack success and legitimate-task utility, and fairness of comparison

This adapter does not change how AgentDojo itself measures `utility`/
`security` (those are still computed by AgentDojo's own
`_check_task_result` against its own ground truth, untouched). What it
can change is *whether a given tool call in a trace ever reaches
AgentDojo's environment at all*. For a fair baseline-vs-adapter
comparison (if one is ever run, which requires real model calls and is
explicitly **not done in this phase**):
- Both conditions must use the identical model, suite, task pairs, and
  sampling settings — the adapter is inserted or not; nothing else
  changes, the same discipline already established in
  `docs/agentdojo_experiment_plan.md`.
- The result would answer "does blocking certain tool calls by
  destination/amount/path/prohibited-tool rules change the outcome" —
  **not** "does TrustLine's prompt-injection defense change the
  outcome," per the origin limitation above. Any write-up of such a
  result must say so explicitly, every time, not just once in a caveat
  section.

## Compatibility constraints (installed AgentDojo 0.1.35)

- `BasePipelineElement.query()`'s signature
  (`query, runtime, env, messages, extra_args`) is what this adapter
  implements; a different AgentDojo version could change it.
- `ToolsExecutor`'s specific line-103 call site and its invalid-tool
  error-message pattern (which this adapter's denial message mirrors)
  are version-specific implementation details of 0.1.35, read directly
  from source — not part of AgentDojo's documented public API, so a
  future AgentDojo upgrade could silently break this adapter's
  assumptions without that being a "deprecation."

## What is and is not tested, this phase

**Tested, deterministically, with real AgentDojo types
(`FunctionCall`, `ChatAssistantMessage`, `FunctionsRuntime`), no model,
no network call:**
- A denied tool call is removed before `ToolsExecutor` runs it, and
  produces no side effect — verified against an observable side-effect
  flag, not just a verdict.
- An allowed tool call passes through unchanged and the underlying
  function genuinely executes.
- An unmapped tool (e.g. `delete_file`) passes through unchecked — this
  is the documented scope limit, verified as actual behavior, not
  merely claimed.
- Multi-recipient `send_email` is denied if *any* recipient fails the
  domain allowlist, not just the first.

**Not tested, and not claimable from anything in this repository:**
- Anything about TrustLine's taint/origin-based prompt-injection defense
  in the AgentDojo path (origin is never real here, per above).
- Any real-model outcome — this entire adapter has been exercised only
  with synthetic `FunctionCall` objects standing in for what a real
  model would produce, exactly as the custom suite's fixtures stand in
  for model turns elsewhere in this benchmark.
- Resistance to a caller that bypasses the pipeline ordering and calls
  `run_function()` directly.

## A real incompatibility found while writing the tests: reserved-TLD domains

While writing `tests/test_agentdojo_adapter.py`, a genuine, previously-
undiscovered incompatibility surfaced: **AgentDojo's real `send_email` tool
validates recipients through a real pydantic `Email` model backed by the
`email_validator` library, which rejects RFC 6761 special-use/reserved
TLDs (including `.test`) outright, before TrustLine is ever consulted.**
Confirmed directly:

```
>>> rt.run_function(env, "send_email", {"recipients": ["x@trustline-corp.test"], ...})
ValidationError: ... value is not a valid email address: The part after
the @-sign is a special-use or reserved name that cannot be used with
email.
```

TrustLine's only configured allowlisted email domain
(`ALLOWED_EMAIL_DOMAINS = {"trustline-corp.test"}`, in
`src/trustline_bench/gateway.py`) uses exactly this reserved `.test` TLD —
a deliberate choice elsewhere in this benchmark to avoid using a domain
that looks like a real address. The consequence: **no `send_email` call
to TrustLine's actual configured allowed domain could ever succeed
through AgentDojo's real tool, regardless of what TrustLine's policy
decides.** A real-model pilot that routed a `send_email` call for
`...@trustline-corp.test` through this adapter would see it denied by
AgentDojo's own tool on a `ValidationError`, not by TrustLine, even on a
turn TrustLine's policy would have allowed.

This was not fixed by changing `ALLOWED_EMAIL_DOMAINS` — that is
TrustLine's real policy configuration, not a test fixture, and changing
it to make a test pass would be changing ground truth to fit the test,
which this project's constraints forbid. Instead, the tests that need to
demonstrate "TrustLine allows this AND it genuinely executes"
(`test_allowed_call_executes_normally_against_the_real_environment`,
`test_mixed_allowed_and_denied_calls_in_one_turn`) monkeypatch
`gateway.ALLOWED_EMAIL_DOMAINS` to a validator-safe domain
(`trustline-corp.com`) for that one test's duration only, documented
inline in the test file. **Anyone planning a real pilot against
AgentDojo's workspace suite must either add a real, validator-safe
domain to `ALLOWED_EMAIL_DOMAINS` first, or accept that the allowed path
can never be exercised for email as currently configured.** This is a
configuration decision for whoever runs that pilot, not something this
phase changed.

## Known limitations and validation requirements for any future AgentDojo+TrustLine pilot

1. The origin/taint gap above is the single most important limitation —
   closing it requires new design work, not just more testing.
2. Only `send_email` has a real mapping; every other AgentDojo workspace
   tool is unmapped and passes through unchecked. Extending coverage
   means writing and validating a new mapping per tool, by hand, the
   same way `send_email`'s was (reading the real schema first, not
   guessing).
3. `run_function()` itself is not wrapped; a determined bypass of
   pipeline ordering defeats this adapter the same way a direct handler
   call used to defeat TrustLine's own boundary before Phase 4.
4. Running this adapter against a real model (to produce an actual
   AgentDojo-with-TrustLine result) requires real API calls, is not
   approved or performed in this phase, and would need its own
   readiness review the same way the plain `tool_filter` pilot did in
   `docs/readiness_review.md`.
5. TrustLine's only configured allowed email domain
   (`trustline-corp.test`) is rejected by AgentDojo's real email
   validator as a reserved TLD (see above) — a real pilot needs a
   validator-safe entry in `ALLOWED_EMAIL_DOMAINS` or the allowed path
   can never fire for `send_email`.
