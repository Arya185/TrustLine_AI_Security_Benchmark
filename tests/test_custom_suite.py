"""Runs cases/custom_cases.jsonl through the real runner (not a shortcut
re-implementation) and checks the recorded results, including the rule that
a DENY only counts as successful enforcement if the tool did not execute.
"""

from __future__ import annotations

from pathlib import Path

from trustline_bench.runner import load_cases, run_case
from trustline_bench.mock_tools import MockToolEnvironment

CASES_PATH = Path(__file__).resolve().parents[1] / "cases" / "custom_cases.jsonl"

EXPECTED_CASE_IDS = {
    "smoke-001",
    "smoke-002",
    "smoke-003",
    "smoke-004",
    "smoke-005",
}

EXPECTED_DENY_ENFORCEMENT = {"smoke-002", "smoke-003", "smoke-004"}


def test_all_five_smoke_categories_are_present():
    cases = load_cases(CASES_PATH)
    assert {c["id"] for c in cases} == EXPECTED_CASE_IDS
    categories = {c["category"] for c in cases}
    assert categories == {
        "benign_permitted",
        "explicitly_prohibited_action",
        "prompt_injection_in_untrusted_output",
        "destination_argument_violation",
        "audit_log_integrity",
    }


def test_each_case_passes_against_its_own_ground_truth():
    cases = load_cases(CASES_PATH)
    env = MockToolEnvironment()
    results = [run_case(case, env) for case in cases]

    for result in results:
        assert result["errors"] == [], f"{result['test_id']} raised errors: {result['errors']}"
        assert result["pass"] is True, f"{result['test_id']} failed checks: {result['checks']}"


def test_deny_cases_only_count_as_enforced_if_nothing_executed():
    cases = load_cases(CASES_PATH)
    env = MockToolEnvironment()
    results = {r["test_id"]: r for r in (run_case(c, env) for c in cases)}

    for test_id in EXPECTED_DENY_ENFORCEMENT:
        assert results[test_id]["enforcement_success"] is True, test_id

    # The benign case has no enforcement concept (it's an ALLOW case).
    assert results["smoke-001"]["enforcement_success"] is None
    # Audit integrity has no enforcement concept either.
    assert results["smoke-005"]["enforcement_success"] is None
