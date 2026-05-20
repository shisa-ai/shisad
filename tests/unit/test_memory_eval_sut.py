from __future__ import annotations

import inspect
import json
from io import StringIO
from pathlib import Path

import pytest

import shisad.memory.evaluation_sut as evaluation_sut
from shisad.daemon import services as daemon_services
from shisad.memory.evaluation_sut import EvaluationSutSession, run_sut_jsonl
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
        "contract_version": "b2",
        "run": {"run_id": "run-001", "seed": 42},
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


def test_provider_override_metadata_redacts_base_url_secrets(tmp_path: Path) -> None:
    secret_url = (
        "https://user:pass@embedding.example/v1"
        "?api_key=base-secret#access_token=fragment-secret"
    )

    responses = _run_messages(
        [
            _hello(
                tmp_path,
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": secret_url,
                    "embedding_api_key": "provider-secret",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {"op": "shutdown"},
        ]
    )

    ack = responses[0]
    rendered = json.dumps(ack, sort_keys=True)
    assert ack["ok"] is True
    assert ack["config_overrides_accepted"]["embedding_base_url"] == (
        "https://embedding.example/v1"
    )
    assert ack["envelope_metadata"]["embedding_base_url"] == (
        "https://embedding.example/v1"
    )
    assert "base-secret" not in rendered
    assert "fragment-secret" not in rendered
    assert "user:pass" not in rendered
    assert "provider-secret" not in rendered


def test_provider_override_metadata_redacts_malformed_base_url_secrets(tmp_path: Path) -> None:
    secret_url = "user:pass@embedding.example/v1?api_key=base-secret#access_token=fragment-secret"

    responses = _run_messages(
        [
            _hello(
                tmp_path,
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": secret_url,
                    "embedding_api_key": "provider-secret",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {"op": "shutdown"},
        ]
    )

    ack = responses[0]
    rendered = json.dumps(ack, sort_keys=True)
    assert ack["ok"] is True
    assert ack["config_overrides_accepted"]["embedding_base_url"] == "<redacted>"
    assert ack["envelope_metadata"]["embedding_base_url"] == "<redacted>"
    assert "base-secret" not in rendered
    assert "fragment-secret" not in rendered
    assert "user:pass" not in rendered
    assert "provider-secret" not in rendered


def test_provider_override_metadata_redacts_encoded_secret_parameter_names(
    tmp_path: Path,
) -> None:
    secret_url = "embedding.example/v1?api%5Fkey=base-secret#access%5Ftoken=fragment-secret"

    responses = _run_messages(
        [
            _hello(
                tmp_path,
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": secret_url,
                    "embedding_api_key": "provider-secret",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {"op": "shutdown"},
        ]
    )

    ack = responses[0]
    rendered = json.dumps(ack, sort_keys=True)
    assert ack["ok"] is True
    assert ack["config_overrides_accepted"]["embedding_base_url"] == "<redacted>"
    assert ack["envelope_metadata"]["embedding_base_url"] == "<redacted>"
    assert "base-secret" not in rendered
    assert "fragment-secret" not in rendered
    assert "provider-secret" not in rendered


def test_provider_override_metadata_redacts_path_style_secret_parameter(
    tmp_path: Path,
) -> None:
    secret_url = "https://embedding.example/v1&api_key=base-secret"

    responses = _run_messages(
        [
            _hello(
                tmp_path,
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": secret_url,
                    "embedding_api_key": "provider-secret",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {"op": "shutdown"},
        ]
    )

    ack = responses[0]
    rendered = json.dumps(ack, sort_keys=True)
    assert ack["ok"] is True
    assert ack["config_overrides_accepted"]["embedding_base_url"] == "<redacted>"
    assert ack["envelope_metadata"]["embedding_base_url"] == "<redacted>"
    assert "base-secret" not in rendered
    assert "provider-secret" not in rendered


def test_provider_override_metadata_redacts_semicolon_secret_parameter(
    tmp_path: Path,
) -> None:
    secret_url = "https://embedding.example/v1;api_key=base-secret"

    responses = _run_messages(
        [
            _hello(
                tmp_path,
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": secret_url,
                    "embedding_api_key": "provider-secret",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {"op": "shutdown"},
        ]
    )

    ack = responses[0]
    rendered = json.dumps(ack, sort_keys=True)
    assert ack["ok"] is True
    assert ack["config_overrides_accepted"]["embedding_base_url"] == "<redacted>"
    assert ack["envelope_metadata"]["embedding_base_url"] == "<redacted>"
    assert "base-secret" not in rendered
    assert "provider-secret" not in rendered


def test_provider_embedding_fingerprint_uses_public_base_url_identity(tmp_path: Path) -> None:
    first_secret_url = (
        "https://user:pass@embedding.example/v1"
        "?api_key=first-secret#access_token=first-fragment"
    )
    second_secret_url = (
        "https://other:creds@embedding.example/v1"
        "?api_key=second-secret#access_token=second-fragment"
    )

    first = _run_messages(
        [
            _hello(
                tmp_path / "first",
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": first_secret_url,
                    "embedding_api_key": "provider-secret-1",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {"op": "shutdown"},
        ]
    )[0]
    second = _run_messages(
        [
            _hello(
                tmp_path / "second",
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": second_secret_url,
                    "embedding_api_key": "provider-secret-2",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {"op": "shutdown"},
        ]
    )[0]

    first_rendered = json.dumps(first, sort_keys=True)
    second_rendered = json.dumps(second, sort_keys=True)
    assert first["envelope_metadata"]["embedding_base_url"] == "https://embedding.example/v1"
    assert second["envelope_metadata"]["embedding_base_url"] == "https://embedding.example/v1"
    assert (
        first["envelope_metadata"]["embedding_fingerprint"]
        == second["envelope_metadata"]["embedding_fingerprint"]
    )
    assert "first-secret" not in first_rendered
    assert "first-fragment" not in first_rendered
    assert "user:pass" not in first_rendered
    assert "provider-secret-1" not in first_rendered
    assert "second-secret" not in second_rendered
    assert "second-fragment" not in second_rendered
    assert "other:creds" not in second_rendered
    assert "provider-secret-2" not in second_rendered


def test_provider_operation_error_redacts_provider_url_secrets(tmp_path: Path) -> None:
    secret_url = "https://user:pass@127.0.0.1/v1?api_key=base-secret#access_token=fragment-secret"

    responses = _run_messages(
        [
            _hello(
                tmp_path,
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": secret_url,
                    "embedding_api_key": "provider-secret",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {
                "op": "ingest",
                "event_id": "event-1",
                "source_type": "user",
                "content": "Alice keeps the Zurich notes in the blue folder.",
                "timestamp": "2026-01-01T12:00:00Z",
            },
            {"op": "shutdown"},
        ]
    )

    error = responses[1]
    rendered = json.dumps(error, sort_keys=True)
    assert error["ok"] is False
    assert error["error"]["code"] == "operation_failed"
    assert "base-secret" not in rendered
    assert "fragment-secret" not in rendered
    assert "user:pass" not in rendered
    assert "provider-secret" not in rendered


def test_provider_runtime_error_redacts_encoded_secret_parameter_names(
    tmp_path: Path, monkeypatch
) -> None:
    class FailingEmbeddingsAdapter:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def embed(self, _input_texts: list[str]) -> list[list[float]]:
            raise RuntimeError(
                "provider failed with encoded-base-secret and encoded-fragment-secret"
            )

        def close(self, *, wait: bool = False) -> None:
            del wait

    monkeypatch.setattr(evaluation_sut, "SyncEmbeddingsAdapter", FailingEmbeddingsAdapter)

    responses = _run_messages(
        [
            _hello(
                tmp_path,
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": (
                        "embedding.example/v1"
                        "?api%5Fkey=encoded-base-secret"
                        "#access%5Ftoken=encoded-fragment-secret"
                    ),
                    "embedding_api_key": "provider-secret",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {
                "op": "ingest",
                "event_id": "event-1",
                "source_type": "user",
                "content": "Alice keeps the Zurich notes in the blue folder.",
                "timestamp": "2026-01-01T12:00:00Z",
            },
            {"op": "shutdown"},
        ]
    )

    rendered = json.dumps(responses[1], sort_keys=True)
    assert responses[1]["ok"] is False
    assert "provider failed" in responses[1]["error"]["message"]
    assert "encoded-base-secret" not in rendered
    assert "encoded-fragment-secret" not in rendered
    assert "provider-secret" not in rendered


def test_provider_runtime_error_redacts_path_style_secret_parameter(
    tmp_path: Path, monkeypatch
) -> None:
    class FailingEmbeddingsAdapter:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def embed(self, _input_texts: list[str]) -> list[list[float]]:
            raise RuntimeError("provider failed with path-secret")

        def close(self, *, wait: bool = False) -> None:
            del wait

    monkeypatch.setattr(evaluation_sut, "SyncEmbeddingsAdapter", FailingEmbeddingsAdapter)

    responses = _run_messages(
        [
            _hello(
                tmp_path,
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": (
                        "https://embedding.example/v1&api_key=path-secret?mode=debug"
                    ),
                    "embedding_api_key": "provider-secret",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {
                "op": "ingest",
                "event_id": "event-1",
                "source_type": "user",
                "content": "Alice keeps the Zurich notes in the blue folder.",
                "timestamp": "2026-01-01T12:00:00Z",
            },
            {"op": "shutdown"},
        ]
    )

    rendered = json.dumps(responses[1], sort_keys=True)
    assert responses[1]["ok"] is False
    assert "provider failed" in responses[1]["error"]["message"]
    assert "path-secret" not in rendered
    assert "provider-secret" not in rendered


def test_provider_runtime_error_redacts_semicolon_secret_parameter(
    tmp_path: Path, monkeypatch
) -> None:
    class FailingEmbeddingsAdapter:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def embed(self, _input_texts: list[str]) -> list[list[float]]:
            raise RuntimeError("provider failed with semi-secret")

        def close(self, *, wait: bool = False) -> None:
            del wait

    monkeypatch.setattr(evaluation_sut, "SyncEmbeddingsAdapter", FailingEmbeddingsAdapter)

    responses = _run_messages(
        [
            _hello(
                tmp_path,
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": "https://embedding.example/v1;api_key=semi-secret",
                    "embedding_api_key": "provider-secret",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {
                "op": "ingest",
                "event_id": "event-1",
                "source_type": "user",
                "content": "Alice keeps the Zurich notes in the blue folder.",
                "timestamp": "2026-01-01T12:00:00Z",
            },
            {"op": "shutdown"},
        ]
    )

    rendered = json.dumps(responses[1], sort_keys=True)
    assert responses[1]["ok"] is False
    assert "provider failed" in responses[1]["error"]["message"]
    assert "semi-secret" not in rendered
    assert "provider-secret" not in rendered


def test_provider_runtime_error_redacts_fragment_path_secret_parameter(
    tmp_path: Path, monkeypatch
) -> None:
    class FailingEmbeddingsAdapter:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def embed(self, _input_texts: list[str]) -> list[list[float]]:
            raise RuntimeError(
                "provider failed with frag-path-secret and frag-semi-secret"
            )

        def close(self, *, wait: bool = False) -> None:
            del wait

    monkeypatch.setattr(evaluation_sut, "SyncEmbeddingsAdapter", FailingEmbeddingsAdapter)

    responses = _run_messages(
        [
            _hello(
                tmp_path,
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": (
                        "https://embedding.example/v1"
                        "#/oauth&api_key=frag-path-secret"
                        ";secondary_secret=frag-semi-secret?mode=debug"
                    ),
                    "embedding_api_key": "provider-secret",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {
                "op": "ingest",
                "event_id": "event-1",
                "source_type": "user",
                "content": "Alice keeps the Zurich notes in the blue folder.",
                "timestamp": "2026-01-01T12:00:00Z",
            },
            {"op": "shutdown"},
        ]
    )

    rendered = json.dumps(responses[1], sort_keys=True)
    assert responses[1]["ok"] is False
    assert "provider failed" in responses[1]["error"]["message"]
    assert "frag-path-secret" not in rendered
    assert "frag-semi-secret" not in rendered
    assert "provider-secret" not in rendered


def test_provider_runtime_error_does_not_fallback_to_deterministic(
    tmp_path: Path, monkeypatch
) -> None:
    class FailingEmbeddingsAdapter:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def embed(self, _input_texts: list[str]) -> list[list[float]]:
            raise RuntimeError(
                "provider failed with provider-secret and base-secret and ab%2Bcd "
                "and fragment+secret and user:pass at "
                "https://user:pass@embedding.example/v1?api_key=runtime-secret"
            )

        def close(self, *, wait: bool = False) -> None:
            del wait

    monkeypatch.setattr(evaluation_sut, "SyncEmbeddingsAdapter", FailingEmbeddingsAdapter)

    responses = _run_messages(
        [
            _hello(
                tmp_path,
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": (
                        "https://user:pass@embedding.example/v1"
                        "?api_key=base-secret&secondary_secret=ab%2Bcd"
                        "#access_token=fragment+secret"
                    ),
                    "embedding_api_key": "provider-secret",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {
                "op": "ingest",
                "event_id": "event-1",
                "source_type": "user",
                "content": "Alice keeps the Zurich notes in the blue folder.",
                "timestamp": "2026-01-01T12:00:00Z",
            },
            {"op": "shutdown"},
        ]
    )

    error = responses[1]
    rendered = json.dumps(error, sort_keys=True)
    assert responses[0]["envelope_metadata"]["embedding_mode"] == "provider"
    assert error["ok"] is False
    assert error["error"]["code"] == "operation_failed"
    assert "provider failed" in error["error"]["message"]
    assert "runtime-secret" not in rendered
    assert "base-secret" not in rendered
    assert "ab%2Bcd" not in rendered
    assert "ab+cd" not in rendered
    assert "fragment+secret" not in rendered
    assert "fragment secret" not in rendered
    assert "user:pass" not in rendered
    assert "provider-secret" not in rendered


def test_provider_runtime_error_redacts_malformed_base_url_secret_literals(
    tmp_path: Path, monkeypatch
) -> None:
    class FailingEmbeddingsAdapter:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def embed(self, _input_texts: list[str]) -> list[list[float]]:
            raise RuntimeError(
                "provider failed with bad%2Bsecret and bad+secret "
                "and bad+fragment and bad fragment"
            )

        def close(self, *, wait: bool = False) -> None:
            del wait

    monkeypatch.setattr(evaluation_sut, "SyncEmbeddingsAdapter", FailingEmbeddingsAdapter)

    responses = _run_messages(
        [
            _hello(
                tmp_path,
                config_overrides={
                    "embedding_mode": "provider",
                    "embedding_base_url": (
                        "https://[bad?secondary_secret=bad%2Bsecret"
                        "#access_token=bad+fragment"
                    ),
                    "embedding_api_key": "provider-secret",
                    "embedding_model_id": "text-embedding-test",
                },
            ),
            {
                "op": "ingest",
                "event_id": "event-1",
                "source_type": "user",
                "content": "Alice keeps the Zurich notes in the blue folder.",
                "timestamp": "2026-01-01T12:00:00Z",
            },
            {"op": "shutdown"},
        ]
    )

    rendered = json.dumps(responses[1], sort_keys=True)
    assert responses[1]["ok"] is False
    assert "provider failed" in responses[1]["error"]["message"]
    assert "bad%2Bsecret" not in rendered
    assert "bad+secret" not in rendered
    assert "bad+fragment" not in rendered
    assert "bad fragment" not in rendered
    assert "provider-secret" not in rendered


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

    hello = responses[0]
    reset_ack = responses[1]
    ack = responses[2]
    query = responses[3]
    reset_query = responses[5]
    assert marker.read_text(encoding="utf-8") == "keep"
    assert hello["contract_version"] == "b2"
    assert hello["capabilities_supported"] == [
        "reset",
        "time_control",
        "consolidation",
        "query_as_of",
        "structured_memory_write",
    ]
    assert hello["capabilities_unsupported"] == ["answer_generation"]
    assert hello["envelope_metadata"]["embedding_model"]
    assert hello["config_overrides_accepted"] == {"embedding_mode": "deterministic"}
    assert hello["config_overrides_rejected"] == {}
    assert reset_ack["op"] == "reset_ack"
    assert reset_ack["run_id"] == "run-001/case-001"
    assert ack["op"] == "ack"
    assert ack["event_id"] == "event-1"
    assert str(ack["source_id"]).startswith("melt:event:")
    assert str(ack["chunk_id"])
    assert ack["created_at"] == "2026-01-01T12:00:00Z"
    assert query["op"] == "query_result"
    assert query["query_id"] == "query-1"
    assert query["owner"] == {"user_id": "alice", "workspace_id": "workspace-a"}
    assert query["evidence"][0]["source_id"] == ack["source_id"]
    assert query["evidence"][0]["created_at"] == "2026-01-01T12:00:00Z"
    assert reset_query["query_id"] == "query-2"
    assert reset_query["evidence"] == []


def test_hello_capability_partition_preserves_requested_order_and_subset(
    tmp_path: Path,
) -> None:
    responses = _run_messages(
        [
            _hello(
                tmp_path,
                capabilities_requested=[
                    "query_as_of",
                    "reset",
                    "answer_generation",
                    "time_control",
                ],
            ),
            {"op": "shutdown"},
        ]
    )

    hello = responses[0]
    assert hello["op"] == "hello_ack"
    assert hello["capabilities_supported"] == [
        "query_as_of",
        "reset",
        "time_control",
    ]
    assert hello["capabilities_unsupported"] == ["answer_generation"]


def test_metadata_reports_fixed_capability_partition(tmp_path: Path) -> None:
    responses = _run_messages(
        [
            _hello(tmp_path),
            {"op": "metadata"},
            {"op": "shutdown"},
        ]
    )

    metadata = responses[1]
    assert metadata["op"] == "metadata"
    assert metadata["envelope_metadata"]["embedding_model"]
    assert metadata["capabilities"] == [
        "reset",
        "time_control",
        "consolidation",
        "query_as_of",
        "structured_memory_write",
    ]
    assert metadata["capabilities_unsupported"] == ["answer_generation"]


def test_hello_rejects_unknown_capabilities_requested(tmp_path: Path) -> None:
    responses = _run_messages(
        [
            _hello(tmp_path, capabilities_requested=["reset", "bogus_capability"]),
            {"op": "shutdown"},
        ]
    )

    response = responses[0]
    assert response["op"] == "hello_ack"
    assert response["ok"] is False
    assert response["error"]["code"] == "unknown_capability"
    assert "bogus_capability" in response["error"]["message"]


@pytest.mark.parametrize(
    "capabilities_requested",
    [
        ["reset", ""],
        ["reset", "   "],
        ["reset", "reset"],
    ],
)
def test_hello_rejects_malformed_capabilities_requested(
    tmp_path: Path,
    capabilities_requested: list[str],
) -> None:
    responses = _run_messages(
        [
            _hello(tmp_path, capabilities_requested=capabilities_requested),
            {"op": "shutdown"},
        ]
    )

    response = responses[0]
    assert response["op"] == "hello_ack"
    assert response["ok"] is False
    assert response["error"]["code"] == "invalid_field"
    assert "capabilities_requested" in response["error"]["message"]


def test_hello_rejects_non_empty_unmarked_state_root(tmp_path: Path) -> None:
    unsafe_state = tmp_path / "shared"
    unsafe_state.mkdir()
    (unsafe_state / "unrelated.txt").write_text("do not delete", encoding="utf-8")

    responses = _run_messages(
        [
            _hello(
                tmp_path,
                paths={
                    "state_dir": str(unsafe_state),
                    "config_dir": str(tmp_path / "config"),
                    "artifact_dir": str(tmp_path / "artifacts"),
                },
            ),
            {"op": "shutdown"},
        ]
    )

    assert responses[0]["op"] == "hello_ack"
    assert responses[0]["ok"] is False
    assert responses[0]["error"]["code"] == "unsafe_path"
    assert (unsafe_state / "unrelated.txt").read_text(encoding="utf-8") == "do not delete"


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
                "event_id": "event-unrelated",
                "entry_type": "fact",
                "key": "project_code",
                "value": "The project code is ember.",
                "source_id": "structured-unrelated",
                "timestamp": "2026-02-01T00:00:00Z",
            },
            {
                "op": "memory_write",
                "event_id": "event-1",
                "entry_type": "fact",
                "key": "favorite_drink",
                "value": "Alice prefers jasmine tea.",
                "source_id": "structured-1",
                "timestamp": "2026-02-03T04:05:06Z",
            },
            {
                "op": "memory_write",
                "event_id": "event-future",
                "entry_type": "fact",
                "key": "favorite_drink",
                "value": "Alice switches to oolong.",
                "source_id": "structured-future",
                "timestamp": "2026-02-10T00:00:00Z",
            },
            {
                "op": "query",
                "query_id": "query-1",
                "query": "favorite drink",
                "top_k": 3,
                "timestamp": "2026-02-04T00:00:00Z",
            },
            {
                "op": "query",
                "query_id": "query-before-write",
                "query": "favorite drink",
                "top_k": 3,
                "timestamp": "2026-02-02T00:00:00Z",
            },
            {"op": "shutdown"},
        ]
    )

    write_ack = responses[3]
    query = responses[5]
    before_write_query = responses[6]
    assert write_ack["op"] == "memory_write_ack"
    assert write_ack["source_id"] == "structured-1"
    assert write_ack["created_at"] == "2026-02-03T04:05:06Z"
    structured = [
        item for item in query["evidence"] if item.get("surface") == "structured_memory"
    ]
    assert structured
    assert structured[0]["source_id"] == "structured-1"
    assert structured[0]["created_at"] == "2026-02-03T04:05:06Z"
    assert {item["source_id"] for item in structured} == {"structured-1"}
    assert before_write_query["evidence"] == []


def test_structured_query_exposes_decay_metadata_after_consolidation(tmp_path: Path) -> None:
    responses = _run_messages(
        [
            _hello(tmp_path),
            {"op": "reset", "run_id": "run-001/case-001"},
            {
                "op": "memory_write",
                "entry_type": "fact",
                "key": "parking_permit",
                "value": "The old parking permit note is stale.",
                "source_id": "structured-decay",
                "timestamp": "2026-01-01T00:00:00Z",
            },
            {"op": "consolidate", "timestamp": "2026-05-01T00:00:00Z"},
            {
                "op": "query",
                "query_id": "query-decay",
                "query": "parking permit",
                "top_k": 3,
                "timestamp": "2026-05-02T00:00:00Z",
            },
            {"op": "shutdown"},
        ]
    )

    query = responses[4]
    structured = [
        item for item in query["evidence"] if item.get("surface") == "structured_memory"
    ]
    assert structured[0]["source_id"] == "structured-decay"
    assert structured[0]["metadata"]["decay_score"] < 0.35


def test_structured_query_as_of_keeps_entry_before_successor_exists(tmp_path: Path) -> None:
    session = EvaluationSutSession()
    try:
        assert session.handle(_hello(tmp_path))["ok"] is True
        old = session.handle(
            {
                "op": "memory_write",
                "entry_type": "fact",
                "key": "favorite_drink",
                "value": "Alice prefers jasmine tea.",
                "source_id": "structured-old",
                "timestamp": "2026-02-03T00:00:00Z",
            }
        )
        new = session.handle(
            {
                "op": "memory_write",
                "entry_type": "fact",
                "key": "favorite_drink",
                "value": "Alice prefers oolong.",
                "source_id": "structured-new",
                "supersedes": old["entry_id"],
                "timestamp": "2026-02-10T00:00:00Z",
            }
        )

        historical = session.handle(
            {
                "op": "query",
                "query_id": "historical",
                "query": "favorite drink",
                "top_k": 3,
                "timestamp": "2026-02-05T00:00:00Z",
            }
        )
        current = session.handle(
            {
                "op": "query",
                "query_id": "current",
                "query": "favorite drink",
                "top_k": 3,
                "timestamp": "2026-02-11T00:00:00Z",
            }
        )
    finally:
        session.close()

    assert new["source_id"] == "structured-new"
    assert [item["source_id"] for item in historical["evidence"]] == ["structured-old"]
    assert "superseded_by" not in historical["evidence"][0]["metadata"]
    assert "superseded_by_source_id" not in historical["evidence"][0]["metadata"]
    assert [item["source_id"] for item in current["evidence"]] == ["structured-new"]
    assert current["evidence"][0]["metadata"]["supersedes"] == old["entry_id"]
    assert current["evidence"][0]["metadata"]["supersedes_source_id"] == "structured-old"


def test_structured_query_as_of_hides_future_conflict_links(tmp_path: Path) -> None:
    session = EvaluationSutSession()
    try:
        assert session.handle(_hello(tmp_path))["ok"] is True
        session.handle(
            {
                "op": "memory_write",
                "entry_type": "preference",
                "key": "favorite_drink",
                "predicate": "likes(jasmine)",
                "value": "Morgan likes jasmine tea.",
                "source_id": "structured-jasmine",
                "timestamp": "2026-02-03T00:00:00Z",
            }
        )
        session.handle(
            {
                "op": "memory_write",
                "entry_type": "preference",
                "key": "favorite_drink",
                "predicate": "likes(oolong)",
                "value": "Morgan likes oolong tea.",
                "source_id": "structured-oolong",
                "timestamp": "2026-02-04T00:00:00Z",
            }
        )
        consolidated = session.handle(
            {"op": "consolidate", "timestamp": "2026-02-10T00:00:00Z"}
        )
        historical = session.handle(
            {
                "op": "query",
                "query_id": "historical",
                "query": "jasmine oolong",
                "top_k": 5,
                "timestamp": "2026-02-05T00:00:00Z",
            }
        )
        current = session.handle(
            {
                "op": "query",
                "query_id": "current",
                "query": "jasmine oolong",
                "top_k": 5,
                "timestamp": "2026-02-11T00:00:00Z",
            }
        )
    finally:
        session.close()

    assert consolidated["contradicted_entry_ids"]
    historical_structured = [
        item for item in historical["evidence"] if item.get("surface") == "structured_memory"
    ]
    assert {item["source_id"] for item in historical_structured} == {
        "structured-jasmine",
        "structured-oolong",
    }
    assert all(
        "conflict_entry_ids" not in item["metadata"]
        and "conflict_source_ids" not in item["metadata"]
        for item in historical_structured
    )
    current_structured = [
        item for item in current["evidence"] if item.get("surface") == "structured_memory"
    ]
    current_conflicts = {
        item["source_id"]: set(item["metadata"].get("conflict_source_ids", []))
        for item in current_structured
    }
    assert current_conflicts["structured-jasmine"] == {"structured-oolong"}
    assert current_conflicts["structured-oolong"] == {"structured-jasmine"}


def test_structured_conflict_links_survive_reopen(tmp_path: Path) -> None:
    session = EvaluationSutSession()
    try:
        assert session.handle(_hello(tmp_path))["ok"] is True
        session.handle(
            {
                "op": "memory_write",
                "entry_type": "preference",
                "key": "favorite_drink",
                "predicate": "likes(jasmine)",
                "value": "Morgan likes jasmine tea.",
                "source_id": "structured-jasmine",
                "timestamp": "2026-02-03T00:00:00Z",
            }
        )
        session.handle(
            {
                "op": "memory_write",
                "entry_type": "preference",
                "key": "favorite_drink",
                "predicate": "likes(oolong)",
                "value": "Morgan likes oolong tea.",
                "source_id": "structured-oolong",
                "timestamp": "2026-02-04T00:00:00Z",
            }
        )
        assert session.handle(
            {"op": "consolidate", "timestamp": "2026-02-10T00:00:00Z"}
        )["contradicted_entry_ids"]
    finally:
        session.close()

    reopened = EvaluationSutSession()
    try:
        assert reopened.handle(_hello(tmp_path))["ok"] is True
        current = reopened.handle(
            {
                "op": "query",
                "query_id": "current",
                "query": "jasmine oolong",
                "top_k": 5,
                "timestamp": "2026-02-11T00:00:00Z",
            }
        )
    finally:
        reopened.close()

    current_structured = [
        item for item in current["evidence"] if item.get("surface") == "structured_memory"
    ]
    current_conflicts = {
        item["source_id"]: set(item["metadata"].get("conflict_source_ids", []))
        for item in current_structured
    }
    assert current_conflicts["structured-jasmine"] == {"structured-oolong"}
    assert current_conflicts["structured-oolong"] == {"structured-jasmine"}


def test_structured_query_as_of_searches_beyond_newer_entries(tmp_path: Path) -> None:
    session = EvaluationSutSession()
    try:
        assert session.handle(_hello(tmp_path))["ok"] is True
        session.handle(
            {
                "op": "memory_write",
                "entry_type": "fact",
                "key": "favorite_drink",
                "value": "Alice prefers jasmine tea.",
                "source_id": "structured-old",
                "timestamp": "2026-02-01T00:00:00Z",
            }
        )
        for index in range(120):
            session.handle(
                {
                    "op": "memory_write",
                    "entry_type": "fact",
                    "key": f"future_note_{index}",
                    "value": f"Future filler note {index}.",
                    "source_id": f"future-{index}",
                    "timestamp": f"2026-03-01T00:{index % 60:02d}:00Z",
                }
            )
        historical = session.handle(
            {
                "op": "query",
                "query_id": "historical",
                "query": "favorite drink",
                "top_k": 3,
                "timestamp": "2026-02-05T00:00:00Z",
            }
        )
    finally:
        session.close()

    assert [item["source_id"] for item in historical["evidence"]] == ["structured-old"]


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
