"""Behavioral coverage for the user-visible memory benchmark command."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from shisad.cli import main as cli_main


def test_memory_benchmark_cli_surfaces_stage_instrumentation(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(
        cli_main.cli,
        [
            "memory",
            "benchmark",
            "--storage-dir",
            str(tmp_path / "bench-memory"),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["allowed"] is True
    assert [stage["name"] for stage in payload["stages"]] == [
        "indexing",
        "retrieval",
        "reading",
        "oracle",
    ]
    assert payload["metrics"]["retrieval_quality"]["recall_at_k"] == 1.0
    assert payload["questions"][0]["user_visible_answer"]


def test_memory_benchmark_cli_threshold_failure_is_actionable(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(
        cli_main.cli,
        [
            "memory",
            "benchmark",
            "--storage-dir",
            str(tmp_path / "bench-memory"),
            "--fail-under-accuracy",
            "1.01",
        ],
    )

    assert result.exit_code != 0
    assert "FAIL memory benchmark synthetic-memory-smoke" in result.output
    assert "accuracy_below_threshold" in result.output


def test_memory_benchmark_cli_reports_invalid_operator_inputs(tmp_path: Path) -> None:
    runner = CliRunner()

    limit_result = runner.invoke(
        cli_main.cli,
        ["memory", "benchmark", "--limit", "0"],
    )
    assert limit_result.exit_code != 0
    assert "Invalid value for '--limit'" in limit_result.output
    assert "Traceback" not in limit_result.output

    capacity_result = runner.invoke(
        cli_main.cli,
        ["memory", "benchmark", "--capacity-tokens", "0"],
    )
    assert capacity_result.exit_code != 0
    assert "Invalid value for '--capacity-tokens'" in capacity_result.output
    assert "Traceback" not in capacity_result.output

    storage_dir = tmp_path / "bench-memory"
    storage_dir.mkdir()
    (storage_dir / "memory.sqlite3").write_text("previous-run", encoding="utf-8")
    storage_result = runner.invoke(
        cli_main.cli,
        ["memory", "benchmark", "--storage-dir", str(storage_dir)],
    )
    assert storage_result.exit_code != 0
    assert "Error:" in storage_result.output
    assert "storage directory must be empty" in storage_result.output
    assert "Traceback" not in storage_result.output

    storage_parent_file = tmp_path / "not-a-directory"
    storage_parent_file.write_text("not a directory", encoding="utf-8")
    storage_path_result = runner.invoke(
        cli_main.cli,
        ["memory", "benchmark", "--storage-dir", str(storage_parent_file / "child")],
    )
    assert storage_path_result.exit_code != 0
    assert "Error:" in storage_path_result.output
    assert "Not a directory" in storage_path_result.output
    assert "Traceback" not in storage_path_result.output

    threshold_result = runner.invoke(
        cli_main.cli,
        ["memory", "benchmark", "--fail-under-accuracy", "nan"],
    )
    assert threshold_result.exit_code != 0
    assert "threshold must be finite" in threshold_result.output
    assert "Traceback" not in threshold_result.output
