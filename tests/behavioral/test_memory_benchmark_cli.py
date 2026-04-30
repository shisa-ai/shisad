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
