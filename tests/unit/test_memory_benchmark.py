"""M6 memory benchmark adapter and metrics coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import shisad.memory.benchmark as benchmark_module
from shisad.memory.benchmark import (
    MemoryBenchmarkDataset,
    MemoryBenchmarkDocument,
    MemoryBenchmarkQuestion,
    builtin_memory_benchmark_dataset,
    evaluate_memory_benchmark,
    load_memory_benchmark_dataset,
    main,
)


def test_m6_memory_benchmark_reports_stage_metrics_and_oracle_diagnostics(
    tmp_path: Path,
) -> None:
    dataset = builtin_memory_benchmark_dataset()

    report = evaluate_memory_benchmark(
        dataset,
        storage_dir=tmp_path / "memory",
        limit=4,
        oracle_diagnostics=True,
        capacity_tokens=(128,),
    )

    assert report["benchmark"]["id"] == "synthetic-memory-smoke"
    assert report["allowed"] is True
    assert [stage["name"] for stage in report["stages"]] == [
        "indexing",
        "retrieval",
        "reading",
        "oracle",
    ]
    assert report["metrics"]["accuracy"] == 1.0
    assert report["metrics"]["retrieval_quality"]["recall_at_k"] == 1.0
    assert report["metrics"]["retrieval_quality"]["mrr"] > 0.0
    assert report["metrics"]["harm_rate"] == 0.0
    assert report["metrics"]["token_cost"]["estimated_total_tokens"] > 0
    assert report["metrics"]["capacity_cliffs"][0]["target_tokens"] == 128
    assert report["metrics"]["capacity_cliffs"][0]["retrieved"] is True
    first_question = report["questions"][0]
    assert first_question["oracle"]["retrieval_failed"] is False
    assert first_question["oracle"]["reading_failed"] is False
    assert first_question["retrieval"]["expected_source_ids"]
    assert first_question["retrieval"]["retrieved_source_ids"]


def test_m6_memory_benchmark_threshold_failure_is_user_visible(tmp_path: Path) -> None:
    report = evaluate_memory_benchmark(
        builtin_memory_benchmark_dataset(),
        storage_dir=tmp_path / "memory",
        limit=3,
        fail_under_accuracy=1.01,
    )

    assert report["allowed"] is False
    assert "accuracy_below_threshold" in report["failures"]


def test_m6_memory_benchmark_rejects_non_finite_threshold(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="fail_under_accuracy threshold must be finite"):
        evaluate_memory_benchmark(
            builtin_memory_benchmark_dataset(),
            storage_dir=tmp_path / "memory",
            limit=4,
            fail_under_accuracy=float("nan"),
        )


def test_m6_memory_benchmark_stage_durations_are_attributed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dataset = MemoryBenchmarkDataset(
        benchmark_id="stage-timing",
        benchmark_version="fixture-v1",
        documents=(
            MemoryBenchmarkDocument(
                id="owner",
                content="Aiko owns the v0.7 release.",
            ),
        ),
        questions=(
            MemoryBenchmarkQuestion(
                id="q1",
                query="Who owns the v0.7 release?",
                expected_source_ids=("owner",),
                answer_terms=("Aiko",),
            ),
        ),
    )
    elapsed_values = iter([7.0, 11.0, 2.0, 1.5, 99.0])
    monkeypatch.setattr(
        benchmark_module,
        "_elapsed_ms",
        lambda _start: next(elapsed_values),
    )

    report = evaluate_memory_benchmark(
        dataset,
        storage_dir=tmp_path / "memory",
        limit=1,
        fail_over_p95_latency_ms=14.0,
    )

    stages = {stage["name"]: stage for stage in report["stages"]}
    assert stages["indexing"]["duration_ms"] == 7.0
    assert stages["retrieval"]["duration_ms"] == 11.0
    assert stages["reading"]["duration_ms"] == 2.0
    assert stages["oracle"]["duration_ms"] == 1.5
    assert report["metrics"]["latency_ms"]["p50"] == 14.5
    assert report["metrics"]["latency_ms"]["p95"] == 14.5
    assert report["metrics"]["latency_ms"]["retrieval_total"] == 11.0
    assert report["elapsed_ms"] == 99.0
    assert report["allowed"] is False
    assert "p95_latency_above_threshold" in report["failures"]


def test_m6_memory_benchmark_capacity_probe_failure_is_gating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        benchmark_module,
        "_run_capacity_probe",
        lambda *, token_count, limit: {
            "target_tokens": token_count,
            "retrieved": False,
            "latency_ms": 12.0,
        },
    )

    report = evaluate_memory_benchmark(
        builtin_memory_benchmark_dataset(),
        storage_dir=tmp_path / "memory",
        limit=4,
        capacity_tokens=(10_000,),
    )

    assert report["allowed"] is False
    assert "capacity_probe_failed:10000" in report["failures"]


def test_m6_memory_benchmark_loads_json_dataset(tmp_path: Path) -> None:
    fixture = tmp_path / "dataset.json"
    fixture.write_text(
        json.dumps(
            {
                "benchmark_id": "locomo",
                "benchmark_version": "fixture-v1",
                "documents": [
                    {
                        "id": "dialogue-1",
                        "content": "Mina moved the release meeting to Tuesday.",
                        "collection": "user_curated",
                    }
                ],
                "questions": [
                    {
                        "id": "q1",
                        "query": "When is the release meeting?",
                        "expected_source_ids": ["dialogue-1"],
                        "answer_terms": ["Tuesday"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    dataset = load_memory_benchmark_dataset(fixture)
    report = evaluate_memory_benchmark(dataset, storage_dir=tmp_path / "memory", limit=1)

    assert dataset.benchmark_id == "locomo"
    assert dataset.benchmark_version == "fixture-v1"
    assert report["metrics"]["accuracy"] == 1.0


def test_m6_memory_benchmark_defaults_omitted_provenance_fields(tmp_path: Path) -> None:
    fixture = tmp_path / "dataset.json"
    fixture.write_text(
        json.dumps(
            {
                "benchmark_id": "minimal",
                "benchmark_version": "fixture-v1",
                "documents": [
                    {
                        "id": "doc-1",
                        "content": "Mina moved the release meeting to Tuesday.",
                    }
                ],
                "questions": [
                    {
                        "id": "q1",
                        "query": "When is the release meeting?",
                        "expected_source_ids": ["doc-1"],
                        "answer_terms": ["Tuesday"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    dataset = load_memory_benchmark_dataset(fixture)

    assert dataset.documents[0].collection == "project_docs"
    assert dataset.documents[0].source_type == "external"


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ({"benchmark_id": ""}, "non-empty benchmark_id"),
        ({"benchmark_version": ""}, "non-empty benchmark_version"),
        ({"benchmark_id": None}, "requires string field: benchmark_id"),
        ({"benchmark_version": None}, "requires string field: benchmark_version"),
        (
            {
                "documents": [
                    {
                        "id": None,
                        "content": "Mina moved the release meeting to Tuesday.",
                        "collection": "user_curated",
                    }
                ]
            },
            "requires string field: id",
        ),
        (
            {
                "documents": [
                    {
                        "id": "dialogue-1",
                        "content": None,
                        "collection": "user_curated",
                    }
                ]
            },
            "requires string field: content",
        ),
        (
            {
                "documents": [
                    {
                        "id": "dialogue-1",
                        "content": "Mina moved the release meeting to Tuesday.",
                        "collection": None,
                    }
                ]
            },
            "requires string field: collection",
        ),
        (
            {
                "documents": [
                    {
                        "id": "dialogue-1",
                        "content": "Mina moved the release meeting to Tuesday.",
                        "collection": "",
                    }
                ]
            },
            "unsupported memory benchmark collection",
        ),
        (
            {
                "documents": [
                    {
                        "id": "dialogue-1",
                        "content": "Mina moved the release meeting to Tuesday.",
                        "collection": "unknown",
                    }
                ]
            },
            "unsupported memory benchmark collection",
        ),
        (
            {
                "documents": [
                    {
                        "id": "dialogue-1",
                        "content": "Mina moved the release meeting to Tuesday.",
                        "collection": "user_curated",
                        "source_type": None,
                    }
                ]
            },
            "requires string field: source_type",
        ),
        (
            {
                "documents": [
                    {
                        "id": "dialogue-1",
                        "content": "Mina moved the release meeting to Tuesday.",
                        "collection": "user_curated",
                        "source_type": "",
                    }
                ]
            },
            "unsupported memory benchmark source_type",
        ),
        (
            {
                "documents": [
                    {
                        "id": "dialogue-1",
                        "content": "Mina moved the release meeting to Tuesday.",
                        "collection": "user_curated",
                        "source_type": "unknown",
                    }
                ]
            },
            "unsupported memory benchmark source_type",
        ),
        (
            {
                "documents": [
                    {
                        "id": "dialogue-1",
                        "content": "Mina moved the release meeting to Tuesday.",
                        "collection": "user_curated",
                        "source_type": "project_docs",
                    }
                ]
            },
            "unsupported memory benchmark source_type",
        ),
        (
            {
                "documents": [
                    {
                        "id": "dialogue-1",
                        "content": "Mina moved the release meeting to Tuesday.",
                        "collection": "tool_outputs",
                        "source_type": "tool_outputs",
                    }
                ]
            },
            "unsupported memory benchmark source_type",
        ),
        (
            {
                "questions": [
                    {
                        "id": "q1",
                        "query": None,
                        "expected_source_ids": ["dialogue-1"],
                        "answer_terms": ["Tuesday"],
                    }
                ]
            },
            "requires string field: query",
        ),
        (
            {
                "questions": [
                    {
                        "id": None,
                        "query": "When is the release meeting?",
                        "expected_source_ids": ["dialogue-1"],
                        "answer_terms": ["Tuesday"],
                    }
                ]
            },
            "requires string field: id",
        ),
        (
            {
                "questions": [
                    {
                        "id": "q1",
                        "query": "When is the release meeting?",
                        "expected_source_ids": [None],
                        "answer_terms": ["Tuesday"],
                    }
                ]
            },
            "expected_source_ids\\[\\] values must be strings",
        ),
        (
            {
                "questions": [
                    {
                        "id": "q1",
                        "query": "When is the release meeting?",
                        "expected_source_ids": ["dialogue-1"],
                        "answer_terms": [None],
                    }
                ]
            },
            "answer_terms\\[\\] values must be strings",
        ),
        ({"questions": []}, "at least one question"),
        (
            {
                "questions": [
                    {
                        "id": "q1",
                        "query": "When is the release meeting?",
                        "expected_source_ids": ["dialogue-1", "dialogue-1"],
                        "answer_terms": ["Tuesday"],
                    }
                ]
            },
            "duplicate expected_source_ids",
        ),
        (
            {
                "questions": [
                    {
                        "id": "q1",
                        "query": "When is the release meeting?",
                        "expected_source_ids": ["missing"],
                        "answer_terms": ["Tuesday"],
                    }
                ]
            },
            "unknown source ids",
        ),
        (
            {
                "questions": [
                    {
                        "id": "q1",
                        "query": "When is the release meeting?",
                        "expected_source_ids": ["dialogue-1"],
                        "answer_terms": [],
                    }
                ]
            },
            "requires answer_terms",
        ),
    ],
)
def test_m6_memory_benchmark_rejects_malformed_json_dataset(
    tmp_path: Path,
    mutation: dict[str, object],
    expected_error: str,
) -> None:
    payload = {
        "benchmark_id": "locomo",
        "benchmark_version": "fixture-v1",
        "documents": [
            {
                "id": "dialogue-1",
                "content": "Mina moved the release meeting to Tuesday.",
                "collection": "user_curated",
            }
        ],
        "questions": [
            {
                "id": "q1",
                "query": "When is the release meeting?",
                "expected_source_ids": ["dialogue-1"],
                "answer_terms": ["Tuesday"],
            }
        ],
    }
    payload.update(mutation)
    fixture = tmp_path / "dataset.json"
    fixture.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=expected_error):
        load_memory_benchmark_dataset(fixture)


def test_m6_memory_benchmark_requires_clean_storage_dir(tmp_path: Path) -> None:
    storage_dir = tmp_path / "memory"
    storage_dir.mkdir()
    (storage_dir / "memory.sqlite3").write_text("previous-run", encoding="utf-8")

    with pytest.raises(ValueError, match="must be empty"):
        evaluate_memory_benchmark(
            builtin_memory_benchmark_dataset(),
            storage_dir=storage_dir,
            limit=4,
        )


def test_m6_memory_benchmark_script_reports_invalid_args(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--output", str(tmp_path / "out.json"), "--limit", "0"])

    assert exc_info.value.code == 2
    assert "must be positive" in capsys.readouterr().err

    with pytest.raises(SystemExit) as threshold_exc:
        main(
            [
                "--output",
                str(tmp_path / "out.json"),
                "--fail-under-accuracy",
                "nan",
            ]
        )
    assert threshold_exc.value.code == 2
    stderr = capsys.readouterr().err
    assert "threshold must be finite" in stderr
    assert "Traceback" not in stderr


def test_m6_memory_benchmark_script_reports_invalid_fixture(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "--output",
                str(tmp_path / "out.json"),
                "--fixture",
                str(tmp_path / "missing.json"),
            ]
        )

    assert exc_info.value.code == 2
    stderr = capsys.readouterr().err
    assert "fixture path does not exist" in stderr
    assert "Traceback" not in stderr


def test_m6_memory_benchmark_script_reports_invalid_storage(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    storage_dir = tmp_path / "memory"
    storage_dir.mkdir()
    (storage_dir / "memory.sqlite3").write_text("previous-run", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "--output",
                str(tmp_path / "out.json"),
                "--storage-dir",
                str(storage_dir),
            ]
        )

    assert exc_info.value.code == 2
    stderr = capsys.readouterr().err
    assert "storage directory must be empty" in stderr
    assert "Traceback" not in stderr

    storage_file = tmp_path / "memory-file"
    storage_file.write_text("not a directory", encoding="utf-8")
    with pytest.raises(SystemExit) as file_exc:
        main(
            [
                "--output",
                str(tmp_path / "file-out.json"),
                "--storage-dir",
                str(storage_file),
            ]
        )
    assert file_exc.value.code == 2
    file_stderr = capsys.readouterr().err
    assert "File exists" in file_stderr
    assert "Traceback" not in file_stderr


def test_m6_memory_benchmark_script_reports_invalid_output_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_parent = tmp_path / "not-a-directory"
    output_parent.write_text("not a directory", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main(["--output", str(output_parent / "out.json")])

    assert exc_info.value.code == 2
    stderr = capsys.readouterr().err
    assert "File exists" in stderr
    assert "Traceback" not in stderr
