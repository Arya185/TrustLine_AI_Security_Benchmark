"""Tests for generate_benchmark_report.py's handling of a missing or
partially-populated results/ directory. This is a root-level script
(not part of the trustline_bench package), loaded here via
importlib so it can be tested without a subprocess and with its
RESULTS_DIR safely redirected to a tmp_path -- the real results/
directory is never touched by these tests.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "generate_benchmark_report.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("generate_benchmark_report_under_test", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_missing_results_directory_does_not_crash(tmp_path, capsys):
    """Regression test for a real bug: report_agentdojo_results() called
    RESULTS_DIR.iterdir(), which raises FileNotFoundError on a directory
    that doesn't exist (e.g. a fresh checkout before anything has been
    run) -- unlike the custom-suite section's RESULTS_DIR.glob(), which
    tolerates a missing directory gracefully. Verified by direct
    comparison of Path.iterdir() vs Path.glob() behavior on a
    nonexistent path before this fix was written."""
    module = _load_module()
    module.RESULTS_DIR = tmp_path / "does_not_exist"

    module.main()  # must not raise

    output = capsys.readouterr().out
    assert "no results/ directory yet" in output
    assert "no custom-suite run files found" in output


def test_empty_but_existing_results_directory_does_not_crash(tmp_path, capsys):
    module = _load_module()
    module.RESULTS_DIR = tmp_path  # exists, but empty

    module.main()

    output = capsys.readouterr().out
    assert "no custom-suite run files found" in output
    assert "no AgentDojo result directories found" in output


def test_report_never_writes_to_results_dir(tmp_path):
    """The script's own docstring promises it is read-only; this checks
    that promise directly rather than trusting the comment."""
    module = _load_module()
    (tmp_path / "run_20990101T000000Z_deadbeef.jsonl").write_text(
        '{"run_id": "x", "suite_metrics": {}}\n{"pass": true}\n'
    )
    module.RESULTS_DIR = tmp_path

    before = {p.name: p.read_text() for p in tmp_path.iterdir()}
    module.main()
    after = {p.name: p.read_text() for p in tmp_path.iterdir()}

    assert before == after
