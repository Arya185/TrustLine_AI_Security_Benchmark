# Phase 4 — Execution boundary: call graph, bypass, and the fix

## Call graph (before this phase)

```
MockToolEnvironment (dataclass, all attributes public)
  |
  +-- execute(call: ToolCall)            <- PUBLIC, intended entry point
  |     |
  |     +-- gateway.evaluate(call)       <- policy decision
  |     +-- self._registry()             <- maps tool name -> bound handler method
  |     +-- handler(call.args)           <- calls the handler with ONLY args
  |
  +-- _list_calendar_events(args)        <- "private" by naming convention only
  +-- _read_file(args)                   <-   (leading underscore, nothing more --
  +-- _write_file(args)                  <-    Python does not enforce this)
  +-- _send_email(args)
  +-- _transfer_funds(args)
  +-- _post_public_message(args)
  +-- _wire_transfer(args)               <- had ProhibitedToolInvoked failsafe
  +-- _delete_account(args)              <- had ProhibitedToolInvoked failsafe
```

Every handler was a regular bound method on a dataclass instance with no
attribute-level protection. `getattr(env, "_send_email")` returns the
same callable `execute()` uses internally; nothing distinguishes "called
via the sanctioned path" from "called directly."

## Which handlers enforced policy internally (before the fix)

| Handler | Internal policy check? | What stopped it |
|---|---|---|
| `_wire_transfer` | Yes | Unconditionally raises `ProhibitedToolInvoked` — absolute, no gateway check needed because the answer is always no |
| `_delete_account` | Yes | Same |
| `_send_email` | **No** | Nothing — produced its side effect unconditionally |
| `_transfer_funds` | **No** | Nothing |
| `_post_public_message` | **No** | Nothing |
| `_read_file` | **No** | Nothing |
| `_write_file` | **No** | Nothing |

Five of seven relied **entirely** on `execute()` to have been the caller.
That is a convention, not an enforced boundary.

## Reproduced bypass (before the fix)

```python
env = MockToolEnvironment()
env._send_email({"recipient": "attacker@evil.test", "subject": "x", "body": "secret"})
# -> 'queued'; env.sent_emails now has the entry; env.call_ledger now has
#    'send_email' (ledger fixed in Phase 3) -- but gateway.evaluate() was
#    NEVER called. No destination check, no origin check, nothing.
```

Reproduced live for all five handlers (`_send_email`, `_transfer_funds`,
`_post_public_message`, `_read_file`, `_write_file`): each one performs
its full mocked side effect given arbitrary arguments and no policy
context at all. `_wire_transfer`/`_delete_account` were confirmed to
still refuse unconditionally, by design.

Exceptions and malformed input were not a *separate* bypass path here --
a handler called directly with malformed args (e.g. `_send_email(None)`)
would raise a plain `AttributeError` (`None.get` doesn't exist) rather
than producing a side effect, so that specific failure mode happens to
fail safe by accident, not by design. That's still worth noting: "fails
safe by accident" is not the same guarantee as "fails safe by design,"
and the fix below removes the distinction by making every handler check
authorization before touching its arguments at all.

## Trust boundary (before the fix)

The only real boundary was **social convention**: "call `execute()`, not
a handler directly." Nothing in the type system, the object's API shape,
or any runtime check enforced that. Any code in the same process --
another part of this codebase, a future contributor's wiring mistake, a
test that reached for a handler instead of `execute()` for convenience --
could produce an unchecked side effect.

## The fix: bound, environment-issued authorization tokens

### Design

```
execute(call)
  |
  +-- decision = gateway.evaluate(call)
  |
  +-- if decision.verdict == ALLOW:
  |     token = secrets.token_hex(16)              <- unguessable, fresh per call
  |     self._issued_tokens.add(token)              <- environment remembers it issued this
  |     authorization = Authorization(
  |         tool=call.tool,
  |         args_fingerprint=fingerprint(call.args), <- binds token to THESE exact args
  |         token=token,
  |     )
  |     handler(authorization, call.args)
  |
  +-- else: return without ever constructing an Authorization or calling the handler

each handler(authorization, args):
  |
  +-- self._authorize(authorization, "<this tool's own name>", args)  <- FIRST line, always
  |     |
  |     +-- isinstance(authorization, Authorization)?        else raise UnauthorizedExecution
  |     +-- authorization.token in self._issued_tokens?       else raise UnauthorizedExecution
  |     +-- authorization.tool == this handler's tool name?   else raise UnauthorizedExecution
  |     +-- authorization.args_fingerprint == fingerprint(args)? else raise UnauthorizedExecution
  |     +-- self._issued_tokens.discard(token)                <- one-time use
  |
  +-- (only now) perform the mocked side effect
  +-- call_ledger.append(tool_name)
```

One authoritative check (`_authorize()`), called identically by all seven
handlers — not seven slightly different policy rules. `wire_transfer`/
`delete_account` call it too, then **still** unconditionally raise
`ProhibitedToolInvoked` afterward regardless of what `_authorize()`
decided — two independent reasons they can never run, not one.

### Why a token, not a boolean

`authorized=True` is a plain value any caller can pass by typing four
characters; it carries no information about *which* call it was supposed
to authorize. The `Authorization` object instead:

- is only ever constructed inside `execute()`, immediately after a real
  `gateway.evaluate()` ALLOW — not something a handler's caller is
  expected to build themselves in normal use,
- carries an unguessable token (`secrets.token_hex(16)`, 128 bits) that
  the environment itself tracks as "issued" — a handler checks the token
  against `self._issued_tokens`, not just against the shape of the
  object it was handed,
- is bound to the **exact** tool name and an **exact** fingerprint of the
  arguments it was issued for, checked against the arguments the handler
  was *actually* called with — not the arguments recorded in the
  authorization object itself. This specifically closes "take a valid
  authorization from one call and reuse it for a different tool or
  different arguments": the fingerprint comparison uses the live `args`
  parameter, so a mismatched reuse attempt is caught regardless of what
  the stale authorization object claims about itself,
- is single-use: a successful check removes the token from
  `self._issued_tokens`, so the same authorization cannot authorize a
  second action even for the identical call.

### What this design protects against, and what it does not

**Protects against:** an accidental or careless direct call to a handler
— any code in this process that calls `env._send_email(args)` the way it
used to, without going through `execute()`, now gets a loud
`UnauthorizedExecution` instead of a silent side effect. This closes the
exact bypass reproduced above.

**Does not protect against:** an attacker (or buggy code) with the
ability to execute arbitrary Python in the same process. Nothing stops
that attacker from:

- directly constructing a fake `Authorization(tool=..., args_fingerprint=...,
  token=...)` object,
- reaching into `env._issued_tokens` and adding their own fabricated
  token to it before calling a handler with a matching fake
  `Authorization`,
- monkey-patching `gateway.evaluate`, `MockToolEnvironment._authorize`,
  or any other part of this code at runtime,
- replacing the `MockToolEnvironment` class or instance outright.

Python offers no in-process sandbox, and this design does not pretend
to be one. It raises the bar from "call a method with a dict" (one line,
no special knowledge) to "fabricate internally-consistent authorization
state by hand" (requires knowing the exact shape of `Authorization`, the
fingerprint function, and `_issued_tokens`'s existence) — a real increase
in the effort and specificity required for a bypass, not a cryptographic
guarantee. If this benchmark ever needs to defend against a genuinely
adversarial co-resident process, that requires an out-of-process
boundary (a real RPC/IPC gateway, a separate privilege-separated process,
or a real authentication scheme) — out of scope for a same-process mock.

## Audit-chain limitation: explicitly deferred

The audit log's vulnerability to a full-chain-recompute attacker
(`docs/phase3_independent_audit.md`, Finding 4) is **not addressed in
this phase**. It is a separate, architectural issue (hash chains without
an external anchor cannot detect a sufficiently thorough tamperer) and
mixing its fix into this phase's handler-authorization work would blur
what each change is actually for. Tracked as an open issue for a future
phase.
