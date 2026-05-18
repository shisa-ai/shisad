"""Behavioral coverage for the public memory SUT command."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from shisad.cli import main as cli_main
from shisad.memory.evaluation_sut import CONTRACT_VERSION


def test_memory_sut_cli_jsonl_smoke(tmp_path: Path) -> None:
    runner = CliRunner()
    messages = [
        {
            "op": "hello",
            "contract_version": CONTRACT_VERSION,
            "run": {"run_id": "run-001", "case_id": "case-001", "seed": 7},
            "owner": {"user_id": "alice", "workspace_id": "workspace-a"},
            "paths": {
                "state_dir": str(tmp_path / "state"),
                "config_dir": str(tmp_path / "config"),
                "artifact_dir": str(tmp_path / "artifacts"),
            },
            "capabilities_requested": [
                "reset",
                "time_control",
                "consolidation",
                "query_as_of",
                "structured_memory_write",
                "answer_generation",
            ],
            "config_overrides": {"embedding_mode": "deterministic"},
        },
        {"op": "reset", "run_id": "run-001/case-001"},
        {
            "op": "ingest",
            "event_id": "event-1",
            "source_type": "user",
            "content": "Alice keeps the Paris launch checklist in the blue notebook.",
            "timestamp": "2026-03-01T09:00:00Z",
        },
        {
            "op": "query",
            "query_id": "query-1",
            "query": "Where is the Paris launch checklist?",
            "top_k": 2,
            "timestamp": "2026-03-02T09:00:00Z",
        },
        {"op": "shutdown"},
    ]

    result = runner.invoke(
        cli_main.cli,
        ["memory", "sut"],
        input="".join(json.dumps(message) + "\n" for message in messages),
    )

    assert result.exit_code == 0, result.output
    responses = [json.loads(line) for line in result.output.splitlines()]
    assert responses[0]["op"] == "hello_ack"
    assert responses[0]["ok"] is True
    assert responses[0]["identity"]["id"] == "shisad"
    assert responses[0]["capabilities_unsupported"] == ["answer_generation"]
    assert responses[2]["op"] == "ack"
    assert responses[3]["op"] == "query_result"
    assert responses[3]["query_id"] == "query-1"
    assert responses[3]["answer"] == ""
    assert responses[3]["evidence"][0]["source_id"] == responses[2]["source_id"]
    assert responses[4] == {"op": "shutdown_ack", "ok": True}
