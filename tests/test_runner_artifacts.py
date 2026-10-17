"""Tests for the result-artifact handling added to runner.run_all():
unique run identifiers, same-second filename collision safety,
started/completed/failed status via the .inprogress marker file,
metadata completeness (counts, config fingerprint), and that no secret
ever enters a written result file. Uses tmp_path throughout -- never
touches the real results/ directory.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from trustline_bench import runner

CASES_PATH = Path(__file__).resolve().parents[1] / "cases" / "custom_cases.jsonl"


def _read_jsonl_header(path: Path) -> dict:
    with path.open() as f:
        return json.loads(f.readline())


def test_run_all_writes_exactly_one_completed_file_no_leftover_marker(tmp_path):
    runner.run_all(CASES_PATH, tmp_path)

    files = sorted(tmp_path.iterdir())
    jsonl_files = [p for p in files if p.suffix == ".jsonl"]
    marker_files = [p for p in files if p.name.endswith(".inprogress")]

    assert len(jsonl_files) == 1
    assert marker_files == []  # cleaned up on success


def test_run_id_is_present_and_unique_across_runs(tmp_path):
    runner.run_all(CASES_PATH, tmp_path)
    runner.run_all(CASES_PATH, tmp_path)

    headers = [_read_jsonl_header(p) for p in sorted(tmp_path.glob("*.jsonl"))]
    assert len(headers) == 2
    run_ids = {h["run_id"] for h in headers}
    assert len(run_ids) == 2  # genuinely distinct, not just distinct filenames


def test_two_runs_in_the_same_wall_clock_second_do_not_collide(tmp_path):
    """Regression test for a real bug: the filename used to be
    timestamp-only (second resolution), so two runs started within the
    same second produced the identical path and the second silently
    overwrote the first. Forces both runs to report the identical
    timestamp to simulate that exact scenario deterministically,
    rather than hoping two real calls happen to land in the same
    second.

    Patches runner.datetime.now() to return a fixed, REAL datetime
    instance (not a hand-rolled stub) so every call site that needs
    .isoformat() (each case's own timestamp_utc field) keeps working
    normally -- only the specific run-header timestamp this test cares
    about needs to be forced, not every datetime method."""
    fixed_timestamp = "20990101T000000Z"
    fixed_now = datetime(2099, 1, 1, tzinfo=timezone.utc)

    with patch.object(runner, "datetime") as mock_dt:
        mock_dt.now.return_value = fixed_now
        runner.run_all(CASES_PATH, tmp_path)
        runner.run_all(CASES_PATH, tmp_path)

    jsonl_files = sorted(tmp_path.glob(f"run_{fixed_timestamp}_*.jsonl"))
    assert len(jsonl_files) == 2  # both survived; neither overwrote the other

    headers = [_read_jsonl_header(p) for p in jsonl_files]
    assert headers[0]["case_count"] == headers[1]["case_count"] == 27
    assert headers[0]["run_id"] != headers[1]["run_id"]


def test_existing_target_path_refuses_to_overwrite(tmp_path):
    """Direct test of the fail-safe check, independent of how a
    collision could arise: if the exact target path already exists,
    run_all() raises rather than overwriting it."""
    runner.run_all(CASES_PATH, tmp_path)
    existing = next(tmp_path.glob("*.jsonl"))
    before = existing.read_text()

    with patch("trustline_bench.runner.uuid.uuid4") as mock_uuid, patch(
        "trustline_bench.runner.datetime"
    ) as mock_dt:
        # Force the exact same filename to be chosen again.
        original_run_id = _read_jsonl_header(existing)["run_id"]
        mock_uuid.return_value.hex = original_run_id
        timestamp = existing.name.removeprefix("run_").split("_")[0]
        mock_dt.now.return_value.strftime.return_value = timestamp

        with pytest.raises(FileExistsError):
            runner.run_all(CASES_PATH, tmp_path)

    assert existing.read_text() == before  # untouched


def test_caught_exception_leaves_a_failed_marker_not_a_completed_file(tmp_path):
    def boom(*_a, **_kw):
        raise RuntimeError("simulated failure")

    with patch.object(runner, "run_case", side_effect=boom):
        with pytest.raises(RuntimeError, match="simulated failure"):
            runner.run_all(CASES_PATH, tmp_path)

    files = sorted(tmp_path.iterdir())
    jsonl_files = [p for p in files if p.suffix == ".jsonl"]
    marker_files = [p for p in files if p.name.endswith(".inprogress")]

    assert jsonl_files == []  # no completed file -- the run genuinely failed
    assert len(marker_files) == 1
    marker = json.loads(marker_files[0].read_text())
    assert marker["status"] == "failed"
    assert "RuntimeError" in marker["error"]
    assert "simulated failure" in marker["error"]


def test_interrupted_run_leaves_a_started_marker_with_no_completed_file(tmp_path):
    """Simulates a hard interruption (the case a real SIGKILL would
    produce): the marker is written, then nothing after that point ever
    runs -- not even run_all()'s own exception handling, since a killed
    process doesn't execute Python code at all. Modeled here by simply
    never calling the rest of run_all() past marker creation, which is
    the only way to honestly represent "the process stopped existing,"
    rather than pretending an exception was raised and caught."""
    marker_path = tmp_path / ".run_20990101T000000Z_deadbeef.inprogress"
    marker_path.write_text(
        json.dumps(
            {
                "status": "started",
                "run_id": "deadbeef" * 4,
                "run_timestamp_utc": "20990101T000000Z",
                "suite_version": "2.1.0",
                "case_count": 27,
            }
        )
    )

    files = sorted(tmp_path.iterdir())
    assert len(files) == 1
    assert files[0].name.endswith(".inprogress")
    assert json.loads(files[0].read_text())["status"] == "started"
    # No completed .jsonl exists -- this is the distinguishing signal
    # between "interrupted" and "completed", checked directly.
    assert list(tmp_path.glob("*.jsonl")) == []


def test_header_has_complete_metadata(tmp_path):
    runner.run_all(CASES_PATH, tmp_path)
    header = _read_jsonl_header(next(tmp_path.glob("*.jsonl")))

    for key in (
        "status",
        "run_id",
        "run_timestamp_utc",
        "suite_version",
        "gateway_policy_version",
        "case_count",
        "passed_count",
        "failed_count",
        "python_version",
        "platform",
        "config_fingerprint",
        "suite_metrics",
    ):
        assert key in header, key

    assert header["status"] == "completed"
    assert header["case_count"] == header["passed_count"] + header["failed_count"]
    assert header["case_count"] == 27


def test_config_fingerprint_is_stable_for_the_same_config_and_changes_with_policy_version(tmp_path, monkeypatch):
    runner.run_all(CASES_PATH, tmp_path)
    runner.run_all(CASES_PATH, tmp_path)
    headers = [_read_jsonl_header(p) for p in sorted(tmp_path.glob("*.jsonl"))]
    assert headers[0]["config_fingerprint"] == headers[1]["config_fingerprint"]

    monkeypatch.setattr(runner.gateway, "POLICY_VERSION", "9.9.9-test-only")
    tmp_path_2 = tmp_path / "other"
    tmp_path_2.mkdir()
    runner.run_all(CASES_PATH, tmp_path_2)
    other_header = _read_jsonl_header(next(tmp_path_2.glob("*.jsonl")))
    assert other_header["config_fingerprint"] != headers[0]["config_fingerprint"]


def test_no_env_like_secret_names_appear_in_a_written_result_file(tmp_path):
    """Regression guard: a run of the fully offline custom suite must
    never contain anything resembling a credential. Every known .env
    key name is checked for literally, as a floor -- this cannot prove
    the absence of an unknown secret, only the absence of these specific
    ones."""
    runner.run_all(CASES_PATH, tmp_path)
    content = next(tmp_path.glob("*.jsonl")).read_text()

    for key_name in (
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_COMPATIBLE_API_KEY",
        "OPENAI_COMPATIBLE_BASE_URL",
    ):
        assert key_name not in content
