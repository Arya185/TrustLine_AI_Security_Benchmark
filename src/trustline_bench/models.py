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


@dataclass
class ExecutionResult:
    executed: bool
    tool: str | None = None
    output: Any = None
    error: str | None = None
