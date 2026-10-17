"""Minimal adapter inserting TrustLine's gateway into AgentDojo's tool-
execution pipeline, at the exact point traced in
docs/agentdojo_trustline_integration.md: immediately before
agentdojo.agent_pipeline.tool_execution.ToolsExecutor, which is what
actually calls `runtime.run_function()` and produces a real side effect.

Read docs/agentdojo_trustline_integration.md before relying on this for
anything. The short version: this closes the "no policy check runs
before execution" gap for one mapped tool (`send_email`); it does NOT
and cannot test TrustLine's taint/origin-based prompt-injection defense,
because AgentDojo's message history carries no provenance signal this
adapter could honestly translate into a real `ToolCallOrigin`. Every
translated call is treated as `USER_INSTRUCTION`. Do not describe a
result produced through this adapter as evidence about TrustLine's
prompt-injection defense specifically.

AgentDojo types are imported lazily, inside functions/methods that need
them -- not at module import time -- so importing `trustline_bench`
itself never requires the `agentdojo` extra to be installed, consistent
with the dependency separation in pyproject.toml.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Sequence

from trustline_bench import gateway
from trustline_bench.models import GatewayDecision, GatewayVerdict, ToolCall, ToolCallOrigin

if TYPE_CHECKING:
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.functions_runtime import Env, FunctionsRuntime
    from agentdojo.types import ChatMessage


@dataclass
class AdapterTranslation:
    """Result of attempting to translate one AgentDojo FunctionCall
    through TrustLine's policy.

    `mapped=False` means TrustLine has no policy opinion on this tool at
    all -- not "allowed," not "denied," simply out of scope. Callers
    must treat that as pass-through, not as an implicit ALLOW decided by
    TrustLine.

    When `mapped=True`, `decision` is the real GatewayDecision from
    `gateway.evaluate()` (for a multi-argument case like send_email's
    recipient list, the decision for whichever argument first failed,
    or the primary argument's decision if all passed) and `tool_call` is
    the TrustLine-shaped ToolCall that decision was computed for.
    """

    mapped: bool
    tool_call: ToolCall | None = None
    decision: GatewayDecision | None = None
    unmapped_reason: str | None = None


# Only tools with a hand-verified, schema-checked mapping onto a
# TrustLine tool belong here. Adding an entry means someone read the
# real AgentDojo tool's JSON schema first (see the integration doc for
# how send_email's was read) -- not guessed from the name.
_MAPPED_AGENTDOJO_TOOLS = frozenset({"send_email"})


def _evaluate_send_email_recipient(recipient: str, subject: str, body: str) -> tuple[ToolCall, GatewayDecision]:
    call = ToolCall(
        tool="send_email",
        args={"recipient": recipient, "subject": subject, "body": body},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )
    return call, gateway.evaluate(call)


def _translate_send_email(kwargs: dict[str, Any]) -> AdapterTranslation:
    # Real AgentDojo workspace schema (confirmed by reading
    # ws.tools's send_email.parameters.model_json_schema()):
    # `recipients` is a LIST, not TrustLine's single `recipient: str`.
    recipients: Sequence[Any] = kwargs.get("recipients") or [""]
    if not isinstance(recipients, list) or not recipients:
        recipients = [""]
    subject = kwargs.get("subject", "")
    body = kwargs.get("body", "")

    # Conservative mapping: every recipient must individually pass
    # TrustLine's domain allowlist, not just the first. Reuses
    # gateway.evaluate() directly for each one -- no second, divergent
    # copy of the domain-matching rule lives in this adapter.
    first_call, first_decision = _evaluate_send_email_recipient(recipients[0], subject, body)
    tool_call, decision = first_call, first_decision

    if first_decision.verdict == GatewayVerdict.ALLOW:
        for extra_recipient in recipients[1:]:
            extra_call, extra_decision = _evaluate_send_email_recipient(extra_recipient, subject, body)
            if extra_decision.verdict != GatewayVerdict.ALLOW:
                tool_call, decision = extra_call, extra_decision
                break

    return AdapterTranslation(mapped=True, tool_call=tool_call, decision=decision)


def translate_agentdojo_call(function_name: str, kwargs: dict[str, Any]) -> AdapterTranslation:
    """Pure, deterministic translation -- no I/O, no AgentDojo import
    needed to call this specific function (kwargs is just a plain dict
    by the time it reaches here, already extracted from the real
    FunctionCall by the caller)."""
    if function_name not in _MAPPED_AGENTDOJO_TOOLS:
        return AdapterTranslation(mapped=False, unmapped_reason=f"no TrustLine mapping for tool '{function_name}'")

    if function_name == "send_email":
        return _translate_send_email(kwargs)

    raise AssertionError("unreachable: _MAPPED_AGENTDOJO_TOOLS and this function must stay in sync")


class TrustLineEnforcementElement:
    """An agentdojo BasePipelineElement meant to occupy the SAME pipeline
    slot ToolsExecutor normally does -- not a filter inserted before it.
    It wraps a real, internal `agentdojo.agent_pipeline.tool_execution.ToolsExecutor`
    instance and delegates to it for whichever calls survive TrustLine's
    check, rather than duplicating AgentDojo's own tool-dispatch logic.

    Why composition, not a before-ToolsExecutor filter: ToolsExecutor
    expects `messages[-1]` to be the assistant message with `tool_calls`
    still present, and appends its own tool-result messages for exactly
    those calls, matched by `tool_call_id`. An element that filters
    `tool_calls` and then ALSO appends its own tool-result messages
    before ToolsExecutor runs breaks that expectation outright (the new
    messages[-1] would be a "tool" message, and ToolsExecutor's own
    early-return check -- role != "assistant" -- would make it skip the
    surviving calls entirely). Wrapping ToolsExecutor internally avoids
    this: TrustLine's denial messages are appended AFTER ToolsExecutor
    has already produced its own correctly-ordered results for the
    calls that were allowed through.

    Usage: build a custom AgentPipeline substituting this for
    `ToolsExecutor(tool_output_formatter)` in the `elements` list that
    would otherwise be passed to `ToolsExecutionLoop` -- the exact slot
    read from `agentdojo/agent_pipeline/agent_pipeline.py`'s
    `get_pipeline_from_config`. Not wired into AgentDojo's own
    `--defense` enum or CLI in this phase (that would require either
    patching the installed package or AgentDojo's `--module-to-load`
    custom-defense registration, which this phase did not attempt to
    verify end-to-end) -- see docs/agentdojo_trustline_integration.md.
    """

    name: str | None = "trustline_enforcement"

    def __init__(self, tool_output_formatter=None) -> None:
        from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, tool_result_to_str

        self._inner = ToolsExecutor(tool_output_formatter or tool_result_to_str)

    def query(
        self,
        query: str,
        runtime: "FunctionsRuntime",
        env: "Env" = None,
        messages: "Sequence[ChatMessage]" = (),
        extra_args: dict | None = None,
    ):
        from agentdojo.types import ChatToolResultMessage, text_content_block_from_string

        extra_args = extra_args or {}

        if len(messages) == 0:
            return self._inner.query(query, runtime, env, messages, extra_args)
        last = messages[-1]
        if last.get("role") != "assistant" or not last.get("tool_calls"):
            return self._inner.query(query, runtime, env, messages, extra_args)

        kept_tool_calls = []
        denial_messages = []
        for tool_call in last["tool_calls"]:
            translation = translate_agentdojo_call(tool_call.function, dict(tool_call.args))

            if not translation.mapped:
                # No TrustLine opinion on this tool -- pass through
                # unchanged. This is the documented scope limit, not a
                # silent ALLOW decided by TrustLine.
                kept_tool_calls.append(tool_call)
                continue

            if translation.decision.verdict == GatewayVerdict.ALLOW:
                kept_tool_calls.append(tool_call)
                continue

            # Denied: hold the call back instead of letting
            # ToolsExecutor see it, and prepare an error result mirroring
            # the shape ToolsExecutor itself uses for an invalid-tool
            # call (tool_execution.py lines 86-96) -- appended below,
            # AFTER ToolsExecutor has run on the surviving calls, not
            # before.
            denial_messages.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string("")],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=f"Denied by TrustLine policy: {translation.decision.reason_code} -- {translation.decision.details}",
                )
            )

        filtered_last = dict(last)
        filtered_last["tool_calls"] = kept_tool_calls if kept_tool_calls else None
        messages_for_inner = [*messages[:-1], filtered_last]

        query, runtime, env, messages_after_inner, extra_args = self._inner.query(
            query, runtime, env, messages_for_inner, extra_args
        )

        final_messages = [*messages_after_inner, *denial_messages]
        return query, runtime, env, final_messages, extra_args
