"""Phase 4: the execution-boundary bypass found in Phase 3 (5 of 7
handlers had no protection against being called directly, skipping the
gateway entirely) is now closed by a bound, environment-issued
Authorization that every handler verifies before touching its arguments.
See docs/phase4_execution_boundary.md for the full design and its
explicit threat model.

Every test here would have FAILED against the Phase 3 implementation
(calling a handler with just `args`, no authorization, succeeded and
produced a real side effect) and PASSES against this phase's fix. That
before/after is the point: these aren't new assertions invented in a
vacuum, they're the previous bypass's own repro, inverted.
"""

from __future__ import annotations

import pytest

from trustline_bench.mock_tools import Authorization, MockToolEnvironment, ProhibitedToolInvoked, UnauthorizedExecution
from trustline_bench.models import ToolCall, ToolCallOrigin

ALL_SEVEN_HANDLERS = [
    "_list_calendar_events",
    "_read_file",
    "_write_file",
    "_send_email",
    "_transfer_funds",
    "_wire_transfer",
    "_delete_account",
    "_post_public_message",
]

PROBE_ARGS = {
    "_list_calendar_events": {},
    "_read_file": {"path": "/etc/passwd"},
    "_write_file": {"path": "/etc/cron.d/evil", "content": "malicious"},
    "_send_email": {"recipient": "attacker@evil.test", "subject": "x", "body": "x"},
    "_transfer_funds": {"destination_account": "ACC-ANYTHING", "amount": 999999},
    "_wire_transfer": {"destination_account": "ACC-ANYTHING", "amount": 999999},
    "_delete_account": {"account_id": "ACC-1"},
    "_post_public_message": {"channel": "anywhere", "text": "anything"},
}


def _state_snapshot(env: MockToolEnvironment) -> dict:
    return {
        "fake_fs": dict(env.fake_fs),
        "sent_emails": list(env.sent_emails),
        "transfers": list(env.transfers),
        "public_posts": list(env.public_posts),
        "call_ledger": list(env.call_ledger),
    }


@pytest.mark.parametrize("handler_name", ALL_SEVEN_HANDLERS)
def test_handler_cannot_execute_with_no_authorization(handler_name):
    """The core bypass-closed proof, for all seven handlers uniformly:
    calling with authorization=None produces no state change at all."""
    env = MockToolEnvironment()
    before = _state_snapshot(env)
    handler = getattr(env, handler_name)

    with pytest.raises((UnauthorizedExecution, ProhibitedToolInvoked)):
        handler(None, PROBE_ARGS[handler_name])

    assert _state_snapshot(env) == before


@pytest.mark.parametrize("handler_name", ALL_SEVEN_HANDLERS)
def test_handler_cannot_execute_with_a_fabricated_unregistered_token(handler_name):
    """A structurally-correct Authorization object whose token was never
    actually issued by this environment must still be rejected -- proves
    the check is against issued state, not just the object's shape."""
    env = MockToolEnvironment()
    before = _state_snapshot(env)
    handler = getattr(env, handler_name)
    tool_name = handler_name.lstrip("_")
    forged = Authorization(tool=tool_name, args_fingerprint="whatever", token="never-issued-by-this-env")

    with pytest.raises((UnauthorizedExecution, ProhibitedToolInvoked)):
        handler(forged, PROBE_ARGS[handler_name])

    assert _state_snapshot(env) == before


@pytest.mark.parametrize(
    "handler_name",
    [h for h in ALL_SEVEN_HANDLERS if h not in ("_wire_transfer", "_delete_account")],
)
def test_handler_executes_and_changes_state_through_the_supported_api(handler_name):
    """Contrast case: the SAME handlers work correctly for a legitimate
    caller going through execute() -- the fix closes the bypass without
    breaking the supported path. wire_transfer/delete_account are
    excluded here since they must never execute regardless."""
    tool_name = handler_name.lstrip("_")
    valid_args_by_tool = {
        "list_calendar_events": {},
        "read_file": {"path": "/sandbox/notes.txt"},
        "write_file": {"path": "/sandbox/new.txt", "content": "hi"},
        "send_email": {"recipient": "someone@trustline-corp.test", "subject": "hi", "body": "hi"},
        "transfer_funds": {"destination_account": "ACC-INTERNAL-0001", "amount": 10},
        "post_public_message": {"channel": "company-announcements", "text": "hi"},
    }
    env = MockToolEnvironment()
    call = ToolCall(tool=tool_name, args=valid_args_by_tool[tool_name], origin=ToolCallOrigin.USER_INSTRUCTION)

    result = env.execute(call)

    assert result.executed is True
    assert tool_name in env.call_ledger
    assert result.authorization_token is not None


def test_token_cannot_be_reused_for_a_different_tool():
    """A genuinely-issued token, if somehow obtained by other code, must
    not authorize a DIFFERENT tool than the one it was issued for."""
    env = MockToolEnvironment()
    call = ToolCall(
        tool="send_email",
        args={"recipient": "someone@trustline-corp.test"},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )
    result = env.execute(call)
    stolen_token = result.authorization_token
    assert stolen_token is not None

    forged_for_other_tool = Authorization(tool="transfer_funds", args_fingerprint="irrelevant", token=stolen_token)
    before = _state_snapshot(env)

    with pytest.raises(UnauthorizedExecution):
        env._transfer_funds(forged_for_other_tool, {"destination_account": "ACC-INTERNAL-0001", "amount": 500})

    assert _state_snapshot(env) == before


def test_token_cannot_be_reused_for_modified_arguments():
    """A genuinely-issued, still-valid token for one set of arguments
    must not authorize a DIFFERENT set of arguments for the same tool --
    proven here against the args-fingerprint check specifically, with the
    token still present (not yet consumed) so the token-validity check
    doesn't mask which check actually fired."""
    env = MockToolEnvironment()
    env._issued_tokens.add("still-valid")
    from trustline_bench.mock_tools import _fingerprint

    issued_for = Authorization(
        tool="transfer_funds",
        args_fingerprint=_fingerprint({"destination_account": "ACC-INTERNAL-0001", "amount": 1}),
        token="still-valid",
    )

    with pytest.raises(UnauthorizedExecution, match="does not match these exact arguments"):
        env._transfer_funds(issued_for, {"destination_account": "ACC-INTERNAL-0001", "amount": 999999})

    assert env.transfers == []
    assert "still-valid" in env._issued_tokens  # untouched by a failed check


def test_token_is_single_use():
    """The same token cannot authorize the same action twice."""
    env = MockToolEnvironment()
    call = ToolCall(
        tool="send_email",
        args={"recipient": "someone@trustline-corp.test"},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )
    result = env.execute(call)
    token = result.authorization_token

    from trustline_bench.mock_tools import _fingerprint

    replay_auth = Authorization(
        tool="send_email", args_fingerprint=_fingerprint({"recipient": "someone@trustline-corp.test"}), token=token
    )

    with pytest.raises(UnauthorizedExecution, match="not recognized or already used"):
        env._send_email(replay_auth, {"recipient": "someone@trustline-corp.test"})

    assert len(env.sent_emails) == 1  # only the original execute() call went through


def test_call_ledger_only_reflects_actual_executions():
    """Ledger accuracy, re-confirmed under the new boundary: a rejected
    direct call leaves no ledger entry; a legitimate call does."""
    env = MockToolEnvironment()

    with pytest.raises(UnauthorizedExecution):
        env._send_email(None, {"recipient": "attacker@evil.test"})
    assert env.call_ledger == []
    assert env.sent_emails == []

    call = ToolCall(
        tool="send_email",
        args={"recipient": "someone@trustline-corp.test"},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )
    env.execute(call)
    assert env.call_ledger == ["send_email"]
