"""Runs cases/custom_cases.jsonl through the real runner (not a shortcut
re-implementation) and checks the recorded results, including the rule that
a DENY only counts as successful enforcement if the tool did not execute.

Assertions here are structural (schema, category coverage, no duplicates,
enforcement semantics, repeatability) rather than pinned to an exact set of
case IDs -- the suite is expected to keep growing, and hardcoding IDs would
make this file need an edit every time a case is added, which defeats the
point of a generic check.
"""

from __future__ import annotations

import copy
from pathlib import Path

from trustline_bench.mock_tools import MockToolEnvironment
from trustline_bench.runner import load_cases, run_case

CASES_PATH = Path(__file__).resolve().parents[1] / "cases" / "custom_cases.jsonl"

EXPECTED_CATEGORIES = {
    "benign_permitted",
    "explicitly_prohibited_action",
    "prompt_injection_in_untrusted_output",
    "destination_argument_violation",
    "unauthorized_email_destination",
    "unauthorized_transfer_destination",
    "invalid_financial_amount",
    "file_path_violation",
    "public_message_destination_violation",
    "unknown_tool",
    "malformed_arguments",
    "tool_call_origin_policy",
    "audit_log_integrity",
}


def _run_all(cases):
    return [run_case(case, MockToolEnvironment()) for case in cases]


def test_suite_has_minimum_scale_and_category_diversity():
    cases = load_cases(CASES_PATH)
    assert 20 <= len(cases) <= 40, f"expected roughly 20-30 cases, got {len(cases)}"

    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids found"

    categories = {c["category"] for c in cases}
    assert EXPECTED_CATEGORIES <= categories, f"missing categories: {EXPECTED_CATEGORIES - categories}"

    # Both positive (ALLOW) and negative (DENY) cases must be present --
    # a suite that only tests denials can't detect overblocking.
    gateway_cases = [c for c in cases if c["type"] == "gateway_tool_call"]
    verdicts = {c["ground_truth"]["expected_verdict"] for c in gateway_cases}
    assert verdicts == {"ALLOW", "DENY"}


def test_no_true_duplicate_cases():
    """Catches cases that differ only by ID -- same tool, same args, same
    origin, same type -- which would pad the count without adding
    coverage."""
    cases = load_cases(CASES_PATH)
    seen = {}
    for c in cases:
        if c["type"] == "gateway_tool_call":
            key = (
                c["proposed_tool_call"]["tool"],
                tuple(sorted((c["proposed_tool_call"].get("args") or {}).items(), key=str)),
                c["proposed_tool_call"]["origin"],
            )
        else:
            chain_length = c.get("chain_length", 3)
            key = (
                c["type"],
                chain_length,
                c.get("tamper_index", 1),
                c.get("checkpoint_index", chain_length - 1),
            )
        assert key not in seen, f"{c['id']} duplicates {seen[key]} (same {c['type']} scenario)"
        seen[key] = c["id"]


def test_suite_version_is_consistent_across_all_cases():
    cases = load_cases(CASES_PATH)
    versions = {c["suite_version"] for c in cases}
    assert len(versions) == 1, f"mixed suite_version values: {versions}"


def test_case_schema_is_well_formed():
    cases = load_cases(CASES_PATH)
    for c in cases:
        assert c["type"] in ("gateway_tool_call", "audit_integrity", "audit_checkpoint_integrity"), c["id"]
        assert "ground_truth" in c, c["id"]
        if c["type"] == "gateway_tool_call":
            for key in ("model_response", "proposed_tool_call"):
                assert key in c, f"{c['id']} missing {key}"
            for key in ("expected_verdict", "expected_reason_code", "expected_executed"):
                assert key in c["ground_truth"], f"{c['id']} ground_truth missing {key}"
            assert c["ground_truth"]["expected_verdict"] in ("ALLOW", "DENY"), c["id"]
        elif c["type"] == "audit_integrity":
            for key in ("expected_valid_before_tamper", "expected_valid_after_tamper"):
                assert key in c["ground_truth"], f"{c['id']} ground_truth missing {key}"
            tamper_index = c.get("tamper_index", 1)
            chain_length = c.get("chain_length", 3)
            assert 0 <= tamper_index < chain_length, f"{c['id']} tamper_index out of range"
        else:  # audit_checkpoint_integrity
            for key in ("expected_valid_before_tamper", "expected_valid_after_tamper_checkpoint_backed"):
                assert key in c["ground_truth"], f"{c['id']} ground_truth missing {key}"
            chain_length = c.get("chain_length", 3)
            tamper_index = c.get("tamper_index", 1)
            checkpoint_index = c.get("checkpoint_index", chain_length - 1)
            assert 0 <= tamper_index < chain_length, f"{c['id']} tamper_index out of range"
            assert 0 <= checkpoint_index < chain_length, f"{c['id']} checkpoint_index out of range"


def test_each_case_passes_against_its_own_ground_truth():
    cases = load_cases(CASES_PATH)
    # Fresh environment per case: matches run_all()'s isolation, so one
    # case's side effects can't leak into the next case's observed state.
    results = _run_all(cases)

    for result in results:
        assert result["errors"] == [], f"{result['test_id']} raised errors: {result['errors']}"
        assert result["pass"] is True, f"{result['test_id']} failed checks: {result['checks']}"


def test_enforcement_semantics_hold_for_every_case():
    """Generalizes the old hardcoded per-ID checks: for EVERY case in the
    suite (not a fixed list of five), the enforcement/execution semantics
    must hold. A DENY-expected case must show enforcement_success True and
    executed False; an ALLOW-expected case must show enforcement_success
    None and executed True (an ALLOW that never executes would be an
    undetected overblock, not a benign success); an audit case has no
    enforcement concept at all."""
    cases = load_cases(CASES_PATH)
    results = _run_all(cases)

    for result in results:
        if result["type"] in ("audit_integrity", "audit_checkpoint_integrity"):
            assert result["enforcement_success"] is None, result["test_id"]
            continue

        expected_verdict = result["ground_truth"]["expected_verdict"]
        executed = result["stages"]["tool_execution"]["executed"]

        if expected_verdict == "DENY":
            assert result["enforcement_success"] is True, result["test_id"]
            assert executed is False, result["test_id"]
        else:
            assert result["enforcement_success"] is None, result["test_id"]
            assert executed is True, result["test_id"]


def test_repeated_runs_produce_equivalent_decisions_and_metrics():
    """Same deterministic fixtures, same policy -> same decisions and
    metric values on a second run, modulo intentionally variable metadata:
    timestamp_utc, and (since Phase 4) authorization_token, which is a
    fresh unguessable value per execution by design (secrets.token_hex)
    -- it is supposed to differ between runs; what must stay equal is
    whether a token is present at all (i.e. whether execution happened),
    not its specific value."""
    cases = load_cases(CASES_PATH)
    run1 = _run_all(cases)
    run2 = _run_all(copy.deepcopy(cases))

    def strip_variable_fields(result):
        result = copy.deepcopy(result)
        result.pop("timestamp_utc", None)
        tool_execution = result["stages"].get("tool_execution")
        if tool_execution is not None:
            token = tool_execution.pop("authorization_token", None)
            # Presence/absence must still be deterministic, even though the
            # exact value isn't: a token exists iff execution happened.
            assert (token is not None) == tool_execution["executed"], result["test_id"]
        return result

    stripped1 = [strip_variable_fields(r) for r in run1]
    stripped2 = [strip_variable_fields(r) for r in run2]
    assert stripped1 == stripped2
