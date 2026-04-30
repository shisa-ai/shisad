"""M6 memory benchmark adapter and metrics coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shisad.memory.benchmark import (
    builtin_memory_benchmark_dataset,
    evaluate_memory_benchmark,
    load_memory_benchmark_dataset,
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
