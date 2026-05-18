from __future__ import annotations

import inspect
import json
from io import StringIO
from pathlib import Path

from shisad.daemon import services as daemon_services
from shisad.memory.evaluation_sut import CONTRACT_VERSION, run_sut_jsonl
from shisad.memory.runtime_wiring import build_memory_runtime_components


def _run_messages(messages: list[dict[str, object]]) -> list[dict[str, object]]:
    stdin = StringIO("".join(json.dumps(message) + "\n" for message in messages))
    stdout = StringIO()
    exit_code = run_sut_jsonl(stdin=stdin, stdout=stdout)
    assert exit_code == 0
    return [json.loads(line) for line in stdout.getvalue().splitlines()]


def _hello(tmp_path: Path, **updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "op": "hello",
        "contract_version": CONTRACT_VERSION,
        "run": {"run_id": "run-001", "case_id": "case-001", "seed": 42},
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
    }
    payload.update(updates)
    return payload


def test_hello_rejects_unknown_contract_version(tmp_path: Path) -> None:
    responses = _run_messages(
        [
            _hello(tmp_path, contract_version="unknown"),
            {"op": "shutdown"},
        ]
    )

    assert responses[0]["op"] == "hello_ack"
    assert responses[0]["ok"] is False
    assert responses[0]["error"]["code"] == "unsupported_contract_version"


def test_hello_rejects_partial_owner_scope(tmp_path: Path) -> None:
    responses = _run_messages(
        [
            _hello(tmp_path, owner={"user_id": "alice"}),
            {"op": "shutdown"},
        ]
    )

    assert responses[0]["op"] == "hello_ack"
    assert responses[0]["ok"] is False
    assert responses[0]["error"]["code"] == "owner_scope_requires_user_and_workspace"


def test_malformed_json_returns_structured_error() -> None:
    stdin = StringIO("{not json}\n")
    stdout = StringIO()

    exit_code = run_sut_jsonl(stdin=stdin, stdout=stdout)

    assert exit_code == 0
    response = json.loads(stdout.getvalue())
    assert response["op"] == "error"
    assert response["ok"] is False
    assert response["error"]["code"] == "malformed_input"


def test_ingest_query_reset_and_time_scope(tmp_path: Path) -> None:
    marker = tmp_path / "outside-marker.txt"
    marker.write_text("keep", encoding="utf-8")

    responses = _run_messages(
        [
            _hello(tmp_path),
            {"op": "reset", "run_id": "run-001/case-001"},
            {
                "op": "ingest",
                "event_id": "event-1",
                "source_type": "user",
                "content": "Alice prefers jasmine tea for late coding sessions.",
                "timestamp": "2026-01-01T12:00:00Z",
            },
            {
                "op": "query",
                "query_id": "query-1",
                "query": "jasmine tea",
                "top_k": 3,
                "timestamp": "2026-01-02T12:00:00Z",
            },
            {"op": "reset", "run_id": "run-001/case-001/reset"},
            {
                "op": "query",
                "query_id": "query-2",
                "query": "jasmine tea",
                "top_k": 3,
                "timestamp": "2026-01-02T12:00:00Z",
            },
            {"op": "shutdown"},
        ]
    )

    ack = responses[2]
    query = responses[3]
    reset_query = responses[5]
    assert marker.read_text(encoding="utf-8") == "keep"
    assert responses[0]["capabilities_unsupported"] == ["answer_generation"]
    assert ack["op"] == "ack"
    assert ack["event_id"] == "event-1"
    assert str(ack["source_id"]).startswith("melt:event:")
    assert query["op"] == "query_result"
    assert query["owner"] == {"user_id": "alice", "workspace_id": "workspace-a"}
    assert query["evidence"][0]["source_id"] == ack["source_id"]
    assert query["evidence"][0]["created_at"] == "2026-01-01T12:00:00Z"
    assert reset_query["evidence"] == []


def test_owner_workspace_scope_prevents_recall_leakage(tmp_path: Path) -> None:
    bob_hello = _hello(
        tmp_path,
        owner={"user_id": "bob", "workspace_id": "workspace-b"},
    )

    responses = _run_messages(
        [
            _hello(tmp_path),
            {
                "op": "ingest",
                "event_id": "event-1",
                "source_type": "user",
                "content": "Alice keeps the Zurich notes in the green folder.",
                "timestamp": "2026-01-01T12:00:00Z",
            },
            {
                "op": "query",
                "query_id": "alice-query",
                "query": "Zurich notes",
                "top_k": 3,
                "timestamp": "2026-01-02T12:00:00Z",
            },
            bob_hello,
            {
                "op": "query",
                "query_id": "bob-query",
                "query": "Zurich notes",
                "top_k": 3,
                "timestamp": "2026-01-02T12:00:00Z",
            },
            {"op": "shutdown"},
        ]
    )

    assert responses[2]["evidence"][0]["source_id"] == responses[1]["source_id"]
    assert responses[4]["evidence"] == []


def test_memory_write_uses_synthetic_created_at_for_structured_evidence(tmp_path: Path) -> None:
    responses = _run_messages(
        [
            _hello(tmp_path),
            {"op": "reset", "run_id": "run-001/case-001"},
            {
                "op": "memory_write",
                "entry_type": "fact",
                "key": "favorite_drink",
                "value": "Alice prefers jasmine tea.",
                "source_id": "structured-1",
                "timestamp": "2026-02-03T04:05:06Z",
            },
            {
                "op": "query",
                "query_id": "query-1",
                "query": "favorite drink",
                "top_k": 3,
                "timestamp": "2026-02-04T00:00:00Z",
            },
            {"op": "shutdown"},
        ]
    )

    write_ack = responses[2]
    query = responses[3]
    assert write_ack["op"] == "memory_write_ack"
    assert write_ack["source_id"] == "structured-1"
    assert write_ack["created_at"] == "2026-02-03T04:05:06Z"
    structured = [
        item for item in query["evidence"] if item.get("surface") == "structured_memory"
    ]
    assert structured
    assert structured[0]["source_id"] == "structured-1"
    assert structured[0]["created_at"] == "2026-02-03T04:05:06Z"


def test_answer_generation_is_capability_gated(tmp_path: Path) -> None:
    responses = _run_messages(
        [
            _hello(tmp_path),
            {"op": "answer", "query_id": "query-1", "query": "What does Alice like?"},
            {"op": "shutdown"},
        ]
    )

    assert responses[1]["op"] == "answer_result"
    assert responses[1]["ok"] is False
    assert responses[1]["error"]["code"] == "unsupported_capability"


def test_runtime_component_wiring_uses_daemon_memory_paths(tmp_path: Path) -> None:
    components = build_memory_runtime_components(tmp_path)

    assert components.storage_root == tmp_path / "memory_entries"
    assert components.legacy_storage_dir == tmp_path / "memory"
    assert components.ingestion.embedding_fingerprint.model_id == "shisad-deterministic-sha256"
    assert components.memory_manager is not None


def test_daemon_and_sut_share_memory_runtime_builder() -> None:
    build_source = inspect.getsource(daemon_services.DaemonServices.build)

    assert "build_memory_runtime_components(" in build_source
