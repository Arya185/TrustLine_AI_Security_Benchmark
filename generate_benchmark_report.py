"""Offline, read-only report over everything already in results/.

Prints a summary of (a) the deterministic TrustLine custom-suite runs and
(b) the real AgentDojo trace trees -- kept in clearly separate sections,
since they measure different things (a fixed policy oracle vs a real
model) and are not methodologically comparable. This script never writes,
modifies, or deletes anything under results/; it only reads and prints.

Usage: python generate_benchmark_report.py
"""

from __future__ import annotations

import json
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent / "results"


def report_custom_suite_runs() -> None:
    print("=" * 78)
    print("TRUSTLINE CUSTOM SUITE RUNS (deterministic, mocked, no real LLM)")
    print("=" * 78)

    run_files = sorted(RESULTS_DIR.glob("run_*.jsonl"))
    if not run_files:
        print("(no custom-suite run files found)")
        return

    for path in run_files:
        with path.open() as f:
            lines = f.readlines()
        if not lines:
            print(f"{path.name}: EMPTY FILE")
            continue

        header = json.loads(lines[0])
        n_results = len(lines) - 1
        n_pass = 0
        for line in lines[1:]:
            try:
                if json.loads(line).get("pass"):
                    n_pass += 1
            except json.JSONDecodeError:
                pass

        suite_version = header.get("suite_version")
        policy_version = header.get("gateway_policy_version")
        run_id = header.get("run_id")

        if suite_version is None and policy_version is None and run_id is None:
            version_note = "suite_version/policy_version/run_id: UNKNOWN (file predates these header fields -- do not attribute to the current suite/policy version)"
        else:
            version_note = f"suite_version={suite_version} policy_version={policy_version} run_id={run_id}"

        print(f"\n{path.name}")
        print(f"  cases: {n_pass}/{n_results} passed")
        print(f"  {version_note}")
        metrics = header.get("suite_metrics")
        if metrics:
            print(f"  metrics: {metrics}")
        else:
            print("  metrics: not recorded in this run's header (predates suite_metrics)")


def _iter_agentdojo_trace_files(group_dir: Path):
    for path in sorted(group_dir.rglob("*.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        yield path, data


def report_agentdojo_results() -> None:
    print()
    print("=" * 78)
    print("AGENTDOJO RESULTS (real model calls, gpt-4o-mini via OpenRouter)")
    print("Reminder: security=True means the attack SUCCEEDED (confirmed")
    print("against agentdojo/base_tasks.py source, not assumed).")
    print("A <injection_task>/none/none.json file is the injection task's")
    print("own utility baseline, NOT a security result, and is excluded below.")
    print("=" * 78)

    if not RESULTS_DIR.exists():
        # RESULTS_DIR.glob(...) above tolerates a missing directory (returns
        # empty); Path.iterdir() does not -- it raises FileNotFoundError.
        # Checked explicitly here rather than relying on glob's leniency,
        # since a fresh checkout or a from-scratch environment has no
        # results/ directory until something creates it.
        print("(no results/ directory yet -- nothing has been run)")
        return

    group_dirs = sorted(
        d for d in RESULTS_DIR.iterdir() if d.is_dir() and not d.name.startswith("run_")
    )
    if not group_dirs:
        print("(no AgentDojo result directories found)")
        return

    for group_dir in group_dirs:
        attack_trials = []
        for path, data in _iter_agentdojo_trace_files(group_dir):
            if data.get("injection_task_id") is None:
                continue  # standalone/no-attack or injection-task-as-utility-baseline trace
            attack_trials.append((path, data))

        print(f"\n{group_dir.name}")
        if not attack_trials:
            print("  (no combined-attack trace files -- only standalone/baseline traces)")
            continue

        n_attacks_succeeded = sum(1 for _, d in attack_trials if d.get("security") is True)
        n_benign_ok = sum(1 for _, d in attack_trials if d.get("utility") is True)
        n = len(attack_trials)
        print(f"  attack trials: {n}")
        print(f"  attack success (security=True): {n_attacks_succeeded}/{n}")
        print(f"  benign utility (utility=True): {n_benign_ok}/{n}")
        versions = {d.get("agentdojo_package_version") for _, d in attack_trials}
        bench_versions = {d.get("benchmark_version") for _, d in attack_trials}
        print(f"  agentdojo_package_version(s): {versions}  benchmark_version(s): {bench_versions}")


def main() -> None:
    report_custom_suite_runs()
    report_agentdojo_results()
    print()
    print("(Read-only report. Nothing under results/ was written or modified.)")


if __name__ == "__main__":
    main()
