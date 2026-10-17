"""Core data types shared by the gateway oracle, mock tools, and test runner.

These types exist to keep five concerns textually separate wherever a test
result is constructed or logged:
  1. model_response   - what the (real or stubbed) model said
  2. proposed_tool_call - the tool call the model wants to make
  3. gateway_decision  - the policy oracle's allow/deny verdict
  4. tool_execution    - whether/what actually ran
  5. ground_truth      - the expected outcome for this test case
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ToolCallOrigin(str, Enum):
    """Provenance of the content that produced a proposed tool call.

    USER_INSTRUCTION: the call traces back to the user's direct request.
    UNTRUSTED_TOOL_OUTPUT: the call traces back to data returned by a prior
        tool call (e.g. a web page, email body, search result) that was not
        authored by the user or the gateway operator. This is the taint tag
        used to catch prompt-injection-style attacks.
    SYSTEM: the call originates from a system/developer message.
    """

    USER_INSTRUCTION = "user_instruction"
    UNTRUSTED_TOOL_OUTPUT = "untrusted_tool_output"
    SYSTEM = "system"


class GatewayVerdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    origin: ToolCallOrigin = ToolCallOrigin.USER_INSTRUCTION


@dataclass
class GatewayDecision:
    verdict: GatewayVerdict
    reason_code: str
    details: str = ""


@dataclass(frozen=True)
class Authorization:
    """A bound, environment-issued proof that a specific tool call was
    authorized. Only ever constructed by MockToolEnvironment.execute()
    immediately after a real GatewayVerdict.ALLOW -- see
    docs/phase4_execution_boundary.md for the full design and its threat
    model. Deliberately not just a boolean: it is bound to the exact tool
    name and a fingerprint of the exact arguments it was issued for, and
    carries an unguessable token the issuing environment tracks, so it
    cannot be reused for a different tool, different arguments, or a
    second action, and a bare `True` cannot stand in for it.
    """

    tool: str
    args_fingerprint: str
    token: str


@dataclass
class ExecutionResult:
    executed: bool
    tool: str | None = None
    output: Any = None
    error: str | None = None
    authorization_token: str | None = None
    """Links this result back to the specific Authorization that produced
    it (None if nothing executed), so the gateway's decision and the
    actual executed action are traceable to each other in the record."""
