"""Behavioral coverage for the public memory SUT command."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from shisad.cli import main as cli_main
from shisad.memory.evaluation_sut import EvaluationSutSession


def test_memory_sut_cli_jsonl_smoke(tmp_path: Path) -> None:
    runner = CliRunner()
    messages = [
        {
            "op": "hello",
            "contract_version": "b2",
            "run": {"run_id": "run-001", "seed": 7},
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
        {
            "op": "memory_write",
            "event_id": "structured-1",
            "entry_type": "fact",
            "key": "parking_permit",
            "value": "Alice's old parking permit note is stale.",
            "source_id": "structured-decay",
            "timestamp": "2026-03-01T09:00:00Z",
        },
        {"op": "consolidate", "timestamp": "2026-06-15T09:00:00Z"},
        {
            "op": "query",
            "query_id": "query-structured",
            "query": "parking permit",
            "top_k": 2,
            "timestamp": "2026-06-16T09:00:00Z",
        },
        {
            "op": "memory_write",
            "event_id": "structured-jasmine",
            "entry_type": "preference",
            "key": "favorite_drink",
            "predicate": "likes(jasmine)",
            "value": "Alice likes jasmine tea.",
            "source_id": "structured-jasmine",
            "timestamp": "2026-03-02T09:00:00Z",
        },
        {
            "op": "memory_write",
            "event_id": "structured-oolong",
            "entry_type": "preference",
            "key": "favorite_drink",
            "predicate": "likes(oolong)",
            "value": "Alice likes oolong tea.",
            "source_id": "structured-oolong",
            "timestamp": "2026-03-03T09:00:00Z",
        },
        {"op": "consolidate", "timestamp": "2026-03-04T09:00:00Z"},
        {
            "op": "query",
            "query_id": "query-conflict",
            "query": "jasmine oolong",
            "top_k": 5,
            "timestamp": "2026-03-05T09:00:00Z",
        },
        {
            "op": "query",
            "query_id": "query-conflict-historical",
            "query": "jasmine oolong",
            "top_k": 5,
            "timestamp": "2026-03-03T12:00:00Z",
        },
        {"op": "metadata"},
        {"op": "tick", "timestamp": "2026-03-06T09:00:00Z"},
        {
            "op": "answer",
            "query_id": "answer-unsupported",
            "query": "jasmine oolong",
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
    assert responses[0]["contract_version"] == "b2"
    assert responses[0]["identity"]["id"] == "shisad"
    assert responses[0]["capabilities_supported"] == [
        "reset",
        "time_control",
        "consolidation",
        "query_as_of",
        "structured_memory_write",
    ]
    assert responses[0]["capabilities_unsupported"] == ["answer_generation"]
    assert responses[0]["envelope_metadata"]["embedding_model"]
    assert responses[0]["config_overrides_accepted"] == {
        "embedding_mode": "deterministic"
    }
    assert responses[0]["config_overrides_rejected"] == {}
    assert responses[1]["op"] == "reset_ack"
    assert responses[1]["run_id"] == "run-001/case-001"
    assert responses[2]["op"] == "ack"
    assert str(responses[2]["source_id"]).startswith("melt:event:")
    assert str(responses[2]["chunk_id"])
    assert responses[2]["created_at"] == "2026-03-01T09:00:00Z"
    assert responses[3]["op"] == "query_result"
    assert responses[3]["query_id"] == "query-1"
    assert responses[3]["answer"] == ""
    assert responses[3]["evidence"][0]["source_id"] == responses[2]["source_id"]
    assert responses[4]["op"] == "memory_write_ack"
    assert responses[5]["op"] == "consolidate_ack"
    query_results = {
        response["query_id"]: response
        for response in responses
        if response.get("op") == "query_result"
    }
    structured_query = query_results["query-structured"]
    structured = [
        item
        for item in structured_query["evidence"]
        if item.get("surface") == "structured_memory"
    ]
    assert structured_query["op"] == "query_result"
    assert structured[0]["source_id"] == "structured-decay"
    assert structured[0]["metadata"]["decay_score"] < 0.35
    conflict_query = query_results["query-conflict"]
    conflict_structured = [
        item
        for item in conflict_query["evidence"]
        if item.get("surface") == "structured_memory"
    ]
    conflict_sources = {
        item["source_id"]: set(item["metadata"].get("conflict_source_ids", []))
        for item in conflict_structured
    }
    assert conflict_sources["structured-jasmine"] == {"structured-oolong"}
    assert conflict_sources["structured-oolong"] == {"structured-jasmine"}
    historical_conflict_query = query_results["query-conflict-historical"]
    historical_conflict_structured = [
        item
        for item in historical_conflict_query["evidence"]
        if item.get("surface") == "structured_memory"
    ]
    assert {item["source_id"] for item in historical_conflict_structured} == {
        "structured-jasmine",
        "structured-oolong",
    }
    assert all(
        "conflict_source_ids" not in item["metadata"]
        and "conflict_entry_ids" not in item["metadata"]
        for item in historical_conflict_structured
    )
    metadata = next(response for response in responses if response.get("op") == "metadata")
    assert metadata["ok"] is True
    assert metadata["contract_version"] == "b2"
    assert metadata["id"] == "shisad"
    assert (
        metadata["envelope_metadata"]["embedding_model"]
        == responses[0]["envelope_metadata"]["embedding_model"]
    )
    assert metadata["capabilities"] == [
        "reset",
        "time_control",
        "consolidation",
        "query_as_of",
        "structured_memory_write",
    ]
    assert metadata["capabilities_unsupported"] == ["answer_generation"]
    tick_ack = next(response for response in responses if response.get("op") == "tick_ack")
    assert tick_ack["ok"] is True
    answer = next(response for response in responses if response.get("op") == "answer_result")
    assert answer["ok"] is False
    assert answer["error"]["code"] == "unsupported_capability"
    assert responses[-1] == {"op": "shutdown_ack", "ok": True}


def test_memory_sut_structured_relationship_metadata_as_of(tmp_path: Path) -> None:
    session = EvaluationSutSession()
    try:
        assert session.handle(
            {
                "op": "hello",
                "contract_version": "b2",
                "run": {"run_id": "run-001", "seed": 7},
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
                ],
                "config_overrides": {"embedding_mode": "deterministic"},
            }
        )["ok"] is True
        old = session.handle(
            {
                "op": "memory_write",
                "entry_type": "fact",
                "key": "favorite_drink",
                "value": "Alice's favorite drink is jasmine tea.",
                "source_id": "structured-old",
                "timestamp": "2026-03-01T09:00:00Z",
            }
        )
        session.handle(
            {
                "op": "memory_write",
                "entry_type": "fact",
                "key": "favorite_drink",
                "value": "Alice's favorite drink is oolong tea.",
                "source_id": "structured-new",
                "supersedes": old["entry_id"],
                "timestamp": "2026-03-03T09:00:00Z",
            }
        )
        historical = session.handle(
            {
                "op": "query",
                "query_id": "historical",
                "query": "favorite drink",
                "top_k": 3,
                "timestamp": "2026-03-02T09:00:00Z",
            }
        )
        current = session.handle(
            {
                "op": "query",
                "query_id": "current",
                "query": "favorite drink",
                "top_k": 3,
                "timestamp": "2026-03-04T09:00:00Z",
            }
        )
    finally:
        session.close()

    assert [item["source_id"] for item in historical["evidence"]] == ["structured-old"]
    assert "superseded_by_source_id" not in historical["evidence"][0]["metadata"]
    assert [item["source_id"] for item in current["evidence"]] == ["structured-new"]
    assert current["evidence"][0]["metadata"]["supersedes_source_id"] == "structured-old"
