"""Executes TrustLine custom test cases and records structured results.

Every result keeps five stages textually separate:
  model_response      - the (stubbed) model turn, explicitly marked as not
                         a real LLM output for this mocked/deterministic suite
  proposed_tool_call   - what the model/fixture wants to call
  gateway_decision     - the policy oracle's verdict + reason code, computed
                         independently of execution, purely for reporting
  tool_execution       - what, if anything, actually ran (ground truth from
                         the mock tool ledger, not from the gateway's
                         self-report)
  ground_truth         - the expected outcome this case is checking against

MockToolEnvironment.execute() is the single enforcement boundary: it runs
gateway.evaluate() itself before invoking any tool handler. This runner does
NOT additionally gate on `if decision.verdict == ALLOW` before calling
execute() -- doing so would mean the runner never actually attempts
execution on a case expected to be denied, which proves nothing about
whether the boundary itself blocks the call. execute() is always called;
the gateway_decision computed here is kept only for the recorded stage and
for an internal consistency check between the two independent evaluations.

Per the enforcement rule: a DENY only counts as successful enforcement if
the tool truly did not execute. This is checked against the mock tool
ledger directly, not against the gateway's claimed verdict.

Each case runs against its own fresh MockToolEnvironment so one case's
side effects can never leak into another case's observed ground truth.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trustline_bench import gateway, metrics
from trustline_bench.audit import AuditLog, CheckpointStore, _entry_hash, verify_against_checkpoint
from trustline_bench.mock_tools import MockToolEnvironment
from trustline_bench.models import GatewayVerdict, ToolCall

MODEL_IDENTIFIER = "mock-deterministic-fixture-v1"
RUN_NOTE = (
    "This run uses fixed fixtures standing in for model turns and a "
    "deterministic policy oracle. No real LLM was called and no real "
    "external tool calls were made."
)


def load_cases(path: Path) -> list[dict[str, Any]]:
    cases = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                cases.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON ({exc})") from exc
    return cases


def _run_gateway_tool_call_case(case: dict[str, Any], env: MockToolEnvironment) -> dict[str, Any]:
    model_response = case["model_response"]
    gt = case["ground_truth"]
    errors: list[str] = []

    proposed_raw = case.get("proposed_tool_call")
    proposed_tool_call = None
    decision = None
    execution_executed = False
    execution_output = None
    execution_error = None
    execution_authorization_token = None

    if model_response.get("pre_gateway_refusal"):
        # Model refused the attack before any tool call reached the gateway.
        # Recorded as its own stage per the spec; the gateway never sees it.
        pass
    else:
        try:
            # The origin is passed through as the raw string from the case
            # file, NOT forced through ToolCallOrigin(...). That enum
            # constructor raises ValueError for any value it doesn't
            # recognize, which would mean an "invalid origin" case could
            # never reach the gateway's own fail-closed allowlist check --
            # it would die at this parsing step instead, before policy ever
            # ran. ToolCallOrigin is a str subclass, so gateway.py's
            # `in TRUSTED_ORIGINS` check works identically on a plain
            # string; the gateway itself is the layer responsible for
            # rejecting an unrecognized origin, per the single-enforcement-
            # boundary design established for gateway.evaluate().
            proposed_tool_call = ToolCall(
                tool=proposed_raw["tool"],
                args=proposed_raw.get("args", {}),
                origin=proposed_raw.get("origin", "user_instruction"),
            )
            # Computed independently, for the recorded stage + consistency
            # check only. Execution below does NOT branch on this value.
            decision = gateway.evaluate(proposed_tool_call)

            # Always attempt execution. execute() is the real enforcement
            # boundary (it runs gateway.evaluate() itself); gating here too
            # would mean a denied case never actually tries to execute,
            # which would not prove the boundary blocks anything.
            result = env.execute(proposed_tool_call)
            execution_executed = result.executed
            execution_output = result.output
            execution_error = result.error
            execution_authorization_token = result.authorization_token
        except Exception as exc:  # noqa: BLE001 - recorded as a test error, not raised
            errors.append(f"{type(exc).__name__}: {exc}")

    observed_verdict = decision.verdict.value if decision else None
    observed_reason = decision.reason_code if decision else None

    checks = {
        "verdict_matches": observed_verdict == gt["expected_verdict"],
        "reason_code_matches": (
            gt.get("expected_reason_code") is None or observed_reason == gt["expected_reason_code"]
        ),
        "executed_matches": execution_executed == gt["expected_executed"],
        # The runner's independently-computed decision and execute()'s own
        # internal gateway check must agree: ALLOW iff actually executed.
        "decision_execution_consistent": (
            decision is None or (decision.verdict == GatewayVerdict.ALLOW) == execution_executed
        ),
    }
    passed = all(checks.values()) and not errors

    enforcement_success = None
    if gt["expected_verdict"] == "DENY":
        # Ground truth for non-execution comes from the mock tool ledger,
        # not from the gateway's self-reported verdict.
        enforcement_success = (observed_verdict == "DENY") and (proposed_raw["tool"] not in env.call_ledger)

    return {
        "test_id": case["id"],
        "category": case["category"],
        "type": case["type"],
        "description": case.get("description", ""),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model_identifier": MODEL_IDENTIFIER,
        "config": {"gateway_policy_version": gateway.POLICY_VERSION, "mode": "mocked_tools_deterministic_oracle"},
        "stages": {
            "model_response": model_response,
            "proposed_tool_call": asdict(proposed_tool_call) if proposed_tool_call else None,
            "gateway_decision": (
                {"verdict": decision.verdict.value, "reason_code": decision.reason_code, "details": decision.details}
                if decision
                else None
            ),
            "tool_execution": {
                "executed": execution_executed,
                "output": execution_output,
                "error": execution_error,
                # Links the gateway_decision above to the actual execution:
                # a non-null token here is the same one MockToolEnvironment
                # issued and the handler verified before acting. Random
                # per run by design (secrets.token_hex) -- not meant to be
                # stable across runs, only within one run's own decision
                # -> execution chain.
                "authorization_token": execution_authorization_token,
            },
        },
        "ground_truth": gt,
        "checks": checks,
        "pass": passed,
        "enforcement_success": enforcement_success,
        "errors": errors,
    }


def _run_audit_integrity_case(case: dict[str, Any]) -> dict[str, Any]:
    """Builds a chain of `chain_length` entries (default 3, matching the
    original smoke-005 case) and tampers the entry at `tamper_index`
    (default 1). Both are read from the case dict so different cases can
    exercise different chain lengths / tamper positions -- previously this
    function ignored the case entirely and always ran the same fixed
    3-entry/tamper-at-1 scenario, so a second audit case could never
    actually test anything different from the first one, no matter what
    its ground_truth claimed. Found when audit-002 (5-entry chain, tamper
    at the last entry) was added and failed despite correct ground truth:
    the runner, not the ground truth, was wrong."""
    gt = case["ground_truth"]
    errors: list[str] = []
    log = AuditLog()
    now = datetime.now(timezone.utc).isoformat()
    chain_length = case.get("chain_length", 3)
    tamper_index = case.get("tamper_index", 1)

    try:
        for i in range(chain_length):
            log.append(now, {"event": "gateway_decision", "tool": f"tool_{i}", "verdict": "ALLOW" if i == 0 else "DENY"})

        valid_before, bad_index_before = log.verify()

        # Simulate an attacker editing a stored entry in place, without
        # recomputing the hash chain from that point forward.
        log.entries[tamper_index]["event"]["verdict"] = "ALLOW"

        valid_after, bad_index_after = log.verify()
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{type(exc).__name__}: {exc}")
        valid_before = valid_after = None
        bad_index_before = bad_index_after = None

    checks = {
        "valid_before_matches": valid_before == gt["expected_valid_before_tamper"],
        "valid_after_matches": valid_after == gt["expected_valid_after_tamper"],
        "tamper_detected_at_expected_index": (
            gt.get("expected_bad_index_after_tamper") is None or bad_index_after == gt["expected_bad_index_after_tamper"]
        ),
    }
    passed = all(checks.values()) and not errors

    return {
        "test_id": case["id"],
        "category": case["category"],
        "type": case["type"],
        "description": case.get("description", ""),
        "timestamp_utc": now,
        "model_identifier": MODEL_IDENTIFIER,
        "config": {"gateway_policy_version": gateway.POLICY_VERSION, "mode": "mocked_tools_deterministic_oracle"},
        "stages": {
            "audit_chain_valid_before_tamper": valid_before,
            "audit_chain_valid_after_tamper": valid_after,
            "first_bad_index_after_tamper": bad_index_after,
        },
        "ground_truth": gt,
        "checks": checks,
        "pass": passed,
        "enforcement_success": None,
        "errors": errors,
    }


def _run_audit_checkpoint_integrity_case(case: dict[str, Any]) -> dict[str, Any]:
    """Phase 5: exercises the checkpoint-backed verifier
    (verify_against_checkpoint) against the SAME full-chain-recompute
    attack that _run_audit_integrity_case's plain AuditLog.verify() alone
    cannot catch. Kept as a distinct case type (not folded into
    audit_integrity) so audit_integrity_detection_rate keeps meaning
    exactly what it meant before Phase 5 -- see
    metrics.checkpoint_backed_tamper_detection_rate's docstring and
    docs/phase5_audit_integrity.md."""
    gt = case["ground_truth"]
    errors: list[str] = []
    chain_length = case.get("chain_length", 3)
    tamper_index = case.get("tamper_index", 1)
    checkpoint_index = case.get("checkpoint_index", chain_length - 1)
    log = AuditLog()
    checkpoint_store = CheckpointStore()
    now = datetime.now(timezone.utc).isoformat()
    result = None
    valid_before = None

    try:
        for i in range(chain_length):
            log.append(now, {"event": "gateway_decision", "tool": f"tool_{i}", "verdict": "ALLOW" if i == 0 else "DENY"})

        checkpoint_store.record(checkpoint_index, log.entries[checkpoint_index]["hash"])
        valid_before, _ = log.verify()

        # Full-chain-recompute attack: mutate one entry's content, then
        # recompute every entry's prev_hash/hash from index 0 forward so
        # the chain stays internally self-consistent -- exactly what
        # AuditLog.verify() alone cannot distinguish from a legitimate
        # chain.
        log.entries[tamper_index]["event"]["verdict"] = (
            "DENY" if log.entries[tamper_index]["event"]["verdict"] == "ALLOW" else "ALLOW"
        )
        prev_hash = "0" * 64
        for entry in log.entries:
            entry["prev_hash"] = prev_hash
            entry["hash"] = _entry_hash(entry["index"], entry["timestamp"], entry["event"], prev_hash)
            prev_hash = entry["hash"]

        result = verify_against_checkpoint(log, checkpoint_store)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{type(exc).__name__}: {exc}")

    checks = {
        "valid_before_matches": valid_before == gt["expected_valid_before_tamper"],
        "checkpoint_backed_result_matches": (
            result is not None and result.valid == gt["expected_valid_after_tamper_checkpoint_backed"]
        ),
        "reason_code_matches": (
            result is not None
            and (gt.get("expected_reason_after_tamper") is None or result.reason_code == gt["expected_reason_after_tamper"])
        ),
    }
    passed = all(checks.values()) and not errors

    return {
        "test_id": case["id"],
        "category": case["category"],
        "type": case["type"],
        "description": case.get("description", ""),
        "timestamp_utc": now,
        "model_identifier": MODEL_IDENTIFIER,
        "config": {"gateway_policy_version": gateway.POLICY_VERSION, "mode": "mocked_tools_deterministic_oracle"},
        "stages": {
            "audit_chain_valid_before_tamper": valid_before,
            "full_recompute_tamper_applied_at_index": tamper_index,
            "checkpoint_index": checkpoint_index,
            "checkpoint_backed_result": (
                {"valid": result.valid, "reason_code": result.reason_code, "bad_index": result.bad_index}
                if result is not None
                else None
            ),
        },
        "ground_truth": gt,
        "checks": checks,
        "pass": passed,
        "enforcement_success": None,
        "errors": errors,
    }


def run_case(case: dict[str, Any], env: MockToolEnvironment) -> dict[str, Any]:
    case_type = case.get("type")
    if case_type == "gateway_tool_call":
        return _run_gateway_tool_call_case(case, env)
    if case_type == "audit_integrity":
        return _run_audit_integrity_case(case)
    if case_type == "audit_checkpoint_integrity":
        return _run_audit_checkpoint_integrity_case(case)
    raise ValueError(f"Unknown case type: {case_type!r}")


def _config_fingerprint(suite_version: str, python_version: str, platform_str: str) -> str:
    """A short, deterministic fingerprint of the non-secret configuration
    that produced a run -- suite/policy version, interpreter, platform.
    None of these inputs are secret, so this is safe to write into a
    tracked or shared report; it exists so two runs can be compared for
    "were these produced under the same configuration" at a glance,
    without diffing full header objects by hand."""
    payload = json.dumps(
        {
            "suite_version": suite_version,
            "gateway_policy_version": gateway.POLICY_VERSION,
            "python_version": python_version,
            "platform": platform_str,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def run_all(cases_path: Path, results_dir: Path) -> list[dict[str, Any]]:
    """Runs every case and writes results/run_<timestamp>_<run_id>.jsonl.

    Collision and interruption safety:
      - The filename includes an 8-hex-char slice of the run's UUID4
        run_id, not just a second-resolution timestamp. Two runs
        started within the same wall-clock second (a real,
        demonstrated risk with the old timestamp-only filename) no
        longer produce the same path. A pre-write existence check still
        raises a clear error in the astronomically unlikely event of an
        actual collision, rather than silently overwriting.
      - A `.inprogress` marker file is written, containing just
        run_id/suite_version/case_count/status="started", BEFORE any
        case executes. It is deleted only after the final results file
        has been fully written. If the process is interrupted (crash,
        kill, power loss) between those two points, the marker is left
        orphaned on disk -- a reliable, inspectable signal that a run
        started but never completed, which the all-in-memory-then-
        write-once design otherwise gives no evidence of at all.
    """
    cases = load_cases(cases_path)
    suite_versions = {c.get("suite_version") for c in cases}
    if len(suite_versions) != 1:
        raise ValueError(f"cases file has inconsistent suite_version values: {suite_versions}")
    suite_version = next(iter(suite_versions))

    results_dir.mkdir(parents=True, exist_ok=True)

    run_id = uuid.uuid4().hex
    # UTC throughout this module: run_timestamp_utc below, and every
    # per-case timestamp_utc field, are datetime.now(timezone.utc)
    # renderings -- never local time.
    run_timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id_short = run_id[:8]
    out_path = results_dir / f"run_{run_timestamp}_{run_id_short}.jsonl"
    marker_path = results_dir / f".run_{run_timestamp}_{run_id_short}.inprogress"

    if out_path.exists():
        # Not expected to ever trigger given the run_id suffix above --
        # kept as a fail-safe rather than a silent overwrite, per the
        # explicit requirement not to clobber an existing result file.
        raise FileExistsError(f"refusing to overwrite existing result file: {out_path}")

    marker_path.write_text(
        json.dumps(
            {
                "status": "started",
                "run_id": run_id,
                "run_timestamp_utc": run_timestamp,
                "suite_version": suite_version,
                "case_count": len(cases),
            }
        ),
        encoding="utf-8",
    )

    try:
        # Fresh environment per case: one case's side effects must never
        # leak into another case's observed ground truth.
        results = [run_case(case, MockToolEnvironment()) for case in cases]

        suite_metrics = metrics.summarize(results)
        passed_count = sum(1 for r in results if r["pass"])
        failed_count = len(results) - passed_count
        python_version = sys.version
        platform_str = platform.platform()

        with out_path.open("w", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {
                        "status": "completed",
                        "run_note": RUN_NOTE,
                        "run_id": run_id,
                        "run_timestamp_utc": run_timestamp,
                        "suite_version": suite_version,
                        "gateway_policy_version": gateway.POLICY_VERSION,
                        "case_count": len(cases),
                        "passed_count": passed_count,
                        "failed_count": failed_count,
                        "python_version": python_version,
                        "platform": platform_str,
                        "config_fingerprint": _config_fingerprint(suite_version, python_version, platform_str),
                        "suite_metrics": suite_metrics,
                    }
                )
                + "\n"
            )
            for result in results:
                f.write(json.dumps(result) + "\n")
    except Exception as exc:
        # A caught exception (a real bug) is a DIFFERENT, more
        # informative state than a hard process kill: update the
        # marker to say so explicitly, rather than either deleting it
        # (which would erase the only evidence this run was attempted)
        # or leaving it saying "started" (which would misrepresent a
        # clean failure as a mysterious interruption). The exception is
        # re-raised, not swallowed -- the caller must still see it.
        marker_path.write_text(
            json.dumps(
                {
                    "status": "failed",
                    "run_id": run_id,
                    "run_timestamp_utc": run_timestamp,
                    "suite_version": suite_version,
                    "case_count": len(cases),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            ),
            encoding="utf-8",
        )
        raise
    else:
        # Success: the completed file at out_path is now the record of
        # this run; the "started" marker has served its purpose and is
        # removed. A marker left on disk after this point in time can
        # only mean the process never reached here -- an interruption,
        # not a clean failure (that case is handled above) and not a
        # success (that case is handled here).
        marker_path.unlink(missing_ok=True)

    return results


def _print_summary(results: list[dict[str, Any]]) -> None:
    print(RUN_NOTE)
    print(f"model_identifier: {MODEL_IDENTIFIER}")
    print(f"{'test_id':<12} {'category':<28} {'pass':<6} {'enforcement_success':<20}")
    for r in results:
        print(f"{r['test_id']:<12} {r['category']:<28} {str(r['pass']):<6} {str(r['enforcement_success']):<20}")
    n_pass = sum(1 for r in results if r["pass"])
    print(f"\n{n_pass}/{len(results)} cases passed.")

    print("\nsuite metrics (None = denominator was 0 in this run, not 0%):")
    for name, value in metrics.summarize(results).items():
        print(f"  {name}: {value!r}")


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parents[2]
    results = run_all(repo_root / "cases" / "custom_cases.jsonl", repo_root / "results")
    _print_summary(results)
