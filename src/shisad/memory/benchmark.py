"""Deterministic memory benchmark adapters and metrics."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from shisad.memory.ingestion import IngestionPipeline

BenchmarkCollection = Literal["user_curated", "project_docs", "external_web", "tool_outputs"]


@dataclass(frozen=True, slots=True)
class MemoryBenchmarkDocument:
    id: str
    content: str
    collection: BenchmarkCollection = "project_docs"
    source_type: Literal["user", "external", "tool"] = "external"


@dataclass(frozen=True, slots=True)
class MemoryBenchmarkQuestion:
    id: str
    query: str
    expected_source_ids: tuple[str, ...]
    answer_terms: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class MemoryBenchmarkDataset:
    benchmark_id: str
    benchmark_version: str
    documents: tuple[MemoryBenchmarkDocument, ...]
    questions: tuple[MemoryBenchmarkQuestion, ...]


def builtin_memory_benchmark_dataset() -> MemoryBenchmarkDataset:
    """Return the CI-friendly built-in M6 memory benchmark fixture."""

    return MemoryBenchmarkDataset(
        benchmark_id="synthetic-memory-smoke",
        benchmark_version="2026-04-30",
        documents=(
            MemoryBenchmarkDocument(
                id="release-owner",
                content="The v0.7 release owner is Aiko and the release channel is shisad.",
                collection="user_curated",
                source_type="user",
            ),
            MemoryBenchmarkDocument(
                id="migration-runbook",
                content=(
                    "The memory migration runbook says to create a snapshot before "
                    "running finalize."
                ),
                collection="project_docs",
                source_type="external",
            ),
            MemoryBenchmarkDocument(
                id="incident-retention",
                content=(
                    "Incident notes must retain evidence references for ninety days after closure."
                ),
                collection="project_docs",
                source_type="external",
            ),
            MemoryBenchmarkDocument(
                id="tool-output-summary",
                content=(
                    "Previous tool output confirmed the staging host is staging.internal.example."
                ),
                collection="tool_outputs",
                source_type="tool",
            ),
        ),
        questions=(
            MemoryBenchmarkQuestion(
                id="q-release-owner",
                query="Who owns the v0.7 release?",
                expected_source_ids=("release-owner",),
                answer_terms=("Aiko",),
            ),
            MemoryBenchmarkQuestion(
                id="q-migration-snapshot",
                query="What should happen before memory migration finalize?",
                expected_source_ids=("migration-runbook",),
                answer_terms=("snapshot",),
            ),
            MemoryBenchmarkQuestion(
                id="q-evidence-retention",
                query="How long should incident evidence references be retained?",
                expected_source_ids=("incident-retention",),
                answer_terms=("ninety", "days"),
            ),
            MemoryBenchmarkQuestion(
                id="q-staging-host",
                query="What staging host did the previous tool output confirm?",
                expected_source_ids=("tool-output-summary",),
                answer_terms=("staging.internal.example",),
            ),
        ),
    )


def load_memory_benchmark_dataset(path: Path) -> MemoryBenchmarkDataset:
    """Load the JSON adapter format used for SOTA benchmark fixtures."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"memory benchmark fixture must be a JSON object: {path}")
    documents_payload = payload.get("documents")
    questions_payload = payload.get("questions")
    if not isinstance(documents_payload, list) or not isinstance(questions_payload, list):
        raise ValueError("memory benchmark fixture requires documents[] and questions[]")

    documents: list[MemoryBenchmarkDocument] = []
    for item in documents_payload:
        if not isinstance(item, dict):
            raise ValueError("document entries must be objects")
        documents.append(
            MemoryBenchmarkDocument(
                id=str(item["id"]),
                content=str(item["content"]),
                collection=_collection_value(item.get("collection", "project_docs")),
                source_type=_source_type_value(item.get("source_type", item.get("collection"))),
            )
        )

    questions: list[MemoryBenchmarkQuestion] = []
    for item in questions_payload:
        if not isinstance(item, dict):
            raise ValueError("question entries must be objects")
        expected = item.get("expected_source_ids")
        terms = item.get("answer_terms")
        if not isinstance(expected, list) or not isinstance(terms, list):
            raise ValueError("question entries require expected_source_ids[] and answer_terms[]")
        questions.append(
            MemoryBenchmarkQuestion(
                id=str(item["id"]),
                query=str(item["query"]),
                expected_source_ids=tuple(str(value) for value in expected),
                answer_terms=tuple(str(value) for value in terms),
            )
        )

    return MemoryBenchmarkDataset(
        benchmark_id=str(payload.get("benchmark_id") or path.stem),
        benchmark_version=str(payload.get("benchmark_version") or "external-json-v1"),
        documents=tuple(documents),
        questions=tuple(questions),
    )


def evaluate_memory_benchmark(
    dataset: MemoryBenchmarkDataset,
    *,
    storage_dir: Path | None = None,
    limit: int = 5,
    oracle_diagnostics: bool = True,
    capacity_tokens: tuple[int, ...] = (),
    fail_under_accuracy: float | None = None,
    fail_under_recall: float | None = None,
    fail_over_harm_rate: float | None = None,
    fail_over_p95_latency_ms: float | None = None,
) -> dict[str, Any]:
    """Run a deterministic memory benchmark and return a JSON-ready report."""

    if limit <= 0:
        raise ValueError("limit must be positive")
    started = time.perf_counter()
    with _pipeline_storage(storage_dir) as resolved_storage:
        pipeline = IngestionPipeline(resolved_storage)
        corpus_payload = _dataset_payload(dataset)
        corpus_hash = hashlib.sha256(
            json.dumps(corpus_payload, sort_keys=True, ensure_ascii=True).encode("utf-8")
        ).hexdigest()

        index_start = time.perf_counter()
        _index_documents(pipeline, dataset.documents)
        indexing_ms = _elapsed_ms(index_start)

        question_reports: list[dict[str, Any]] = []
        retrieval_latencies: list[float] = []
        reading_latencies: list[float] = []
        oracle_latencies: list[float] = []
        recall_values: list[float] = []
        mrr_values: list[float] = []
        coverage_values: list[float] = []
        accuracy_values: list[float] = []
        harmful_questions = 0
        for question in dataset.questions:
            per_question_start = time.perf_counter()
            pack = pipeline.compile_recall(
                question.query,
                limit=limit,
                user_id="benchmark-user",
                workspace_id="benchmark-workspace",
            )
            retrieval_ms = _elapsed_ms(per_question_start)
            retrieval_latencies.append(retrieval_ms)
            retrieved = list(pack.results)
            retrieved_source_ids = [item.source_id for item in retrieved]
            expected = list(question.expected_source_ids)
            expected_set = set(expected)
            found = [source_id for source_id in expected if source_id in retrieved_source_ids]
            recall_at_k = len(found) / float(len(expected_set) or 1)
            rank = next(
                (
                    index + 1
                    for index, source_id in enumerate(retrieved_source_ids)
                    if source_id in expected_set
                ),
                0,
            )
            reciprocal_rank = (1.0 / float(rank)) if rank else 0.0
            evidence_coverage = recall_at_k
            recall_values.append(recall_at_k)
            mrr_values.append(reciprocal_rank)
            coverage_values.append(evidence_coverage)

            read_start = time.perf_counter()
            retrieved_text = "\n".join(item.content_sanitized for item in retrieved)
            answer_match = _contains_terms(retrieved_text, question.answer_terms)
            user_visible_answer = _answer_preview(retrieved_text)
            reading_ms = _elapsed_ms(read_start)
            reading_latencies.append(reading_ms)
            accuracy_values.append(1.0 if answer_match else 0.0)

            harmful_retrievals = sum(1 for item in retrieved if item.risk_score > 0.0)
            if harmful_retrievals:
                harmful_questions += 1

            oracle_payload: dict[str, Any] = {}
            if oracle_diagnostics:
                oracle_start = time.perf_counter()
                oracle_payload = _oracle_payload(
                    question=question,
                    documents=dataset.documents,
                    answer_match=answer_match,
                    evidence_coverage=evidence_coverage,
                )
                oracle_latencies.append(_elapsed_ms(oracle_start))
            question_reports.append(
                {
                    "id": question.id,
                    "query": question.query,
                    "retrieval": {
                        "expected_source_ids": expected,
                        "retrieved_source_ids": retrieved_source_ids,
                        "recall_at_k": round(recall_at_k, 6),
                        "mrr": round(reciprocal_rank, 6),
                        "evidence_coverage": round(evidence_coverage, 6),
                        "latency_ms": round(retrieval_ms, 3),
                        "harmful_retrievals": harmful_retrievals,
                    },
                    "reading": {
                        "answer_terms": list(question.answer_terms),
                        "answer_match": answer_match,
                        "latency_ms": round(reading_ms, 3),
                    },
                    "oracle": oracle_payload,
                    "user_visible_answer": user_visible_answer,
                }
            )

        retrieval_total_ms = sum(retrieval_latencies)
        all_latencies = retrieval_latencies + reading_latencies
        accuracy = _mean(accuracy_values)
        recall = _mean(recall_values)
        harm_rate = harmful_questions / float(len(dataset.questions) or 1)
        p95_latency = _percentile(all_latencies, 95)
        capacity_reports = [
            _run_capacity_probe(token_count=token_count, limit=limit)
            for token_count in capacity_tokens
        ]

    metrics = {
        "accuracy": round(accuracy, 6),
        "retrieval_quality": {
            "recall_at_k": round(recall, 6),
            "mrr": round(_mean(mrr_values), 6),
            "evidence_coverage": round(_mean(coverage_values), 6),
        },
        "latency_ms": {
            "p50": round(_percentile(all_latencies, 50), 3),
            "p95": round(p95_latency, 3),
            "retrieval_total": round(retrieval_total_ms, 3),
        },
        "token_cost": _token_cost(dataset=dataset, questions=question_reports),
        "harm_rate": round(harm_rate, 6),
        "capacity_cliffs": capacity_reports,
    }
    failures = _threshold_failures(
        metrics=metrics,
        fail_under_accuracy=fail_under_accuracy,
        fail_under_recall=fail_under_recall,
        fail_over_harm_rate=fail_over_harm_rate,
        fail_over_p95_latency_ms=fail_over_p95_latency_ms,
    )
    failures.extend(_capacity_failures(capacity_reports))
    return {
        "benchmark": {
            "id": dataset.benchmark_id,
            "version": dataset.benchmark_version,
            "corpus_hash": corpus_hash,
        },
        "generated_at": _iso_timestamp(),
        "stages": [
            {
                "name": "indexing",
                "duration_ms": round(indexing_ms, 3),
                "input_records": len(dataset.documents),
                "output_records": len(dataset.documents),
            },
            {
                "name": "retrieval",
                "duration_ms": round(retrieval_total_ms, 3),
                "input_records": len(dataset.questions),
                "output_records": sum(
                    len(item["retrieval"]["retrieved_source_ids"]) for item in question_reports
                ),
            },
            {
                "name": "reading",
                "duration_ms": round(sum(reading_latencies), 3),
                "input_records": len(question_reports),
                "output_records": len(question_reports),
            },
            {
                "name": "oracle",
                "duration_ms": round(sum(oracle_latencies), 3),
                "input_records": len(question_reports),
                "output_records": len(question_reports) if oracle_diagnostics else 0,
            },
        ],
        "metrics": metrics,
        "questions": question_reports,
        "failures": failures,
        "allowed": not failures,
        "elapsed_ms": round(_elapsed_ms(started), 3),
    }


def _collection_value(value: object) -> BenchmarkCollection:
    allowed = {"user_curated", "project_docs", "external_web", "tool_outputs"}
    normalized = str(value or "project_docs")
    if normalized not in allowed:
        raise ValueError(f"unsupported memory benchmark collection: {normalized}")
    return normalized  # type: ignore[return-value]


def _source_type_value(value: object) -> Literal["user", "external", "tool"]:
    if value in {"user", "external", "tool"}:
        return str(value)  # type: ignore[return-value]
    return {
        "user_curated": "user",
        "project_docs": "external",
        "external_web": "external",
        "tool_outputs": "tool",
    }.get(str(value), "external")  # type: ignore[return-value]


def _dataset_payload(dataset: MemoryBenchmarkDataset) -> dict[str, Any]:
    return {
        "benchmark_id": dataset.benchmark_id,
        "benchmark_version": dataset.benchmark_version,
        "documents": [
            {
                "id": item.id,
                "content": item.content,
                "collection": item.collection,
                "source_type": item.source_type,
            }
            for item in dataset.documents
        ],
        "questions": [
            {
                "id": item.id,
                "query": item.query,
                "expected_source_ids": list(item.expected_source_ids),
                "answer_terms": list(item.answer_terms),
            }
            for item in dataset.questions
        ],
    }


def _index_documents(
    pipeline: IngestionPipeline,
    documents: tuple[MemoryBenchmarkDocument, ...],
) -> None:
    for document in documents:
        owner_args: dict[str, Any] = {}
        if document.collection == "user_curated" or document.collection == "tool_outputs":
            owner_args = {
                "user_id": "benchmark-user",
                "workspace_id": "benchmark-workspace",
            }
        pipeline.ingest(
            source_id=document.id,
            source_type=document.source_type,
            collection=document.collection,
            content=document.content,
            **owner_args,
        )


def _oracle_payload(
    *,
    question: MemoryBenchmarkQuestion,
    documents: tuple[MemoryBenchmarkDocument, ...],
    answer_match: bool,
    evidence_coverage: float,
) -> dict[str, Any]:
    by_id = {document.id: document.content for document in documents}
    oracle_text = "\n".join(
        by_id[source_id] for source_id in question.expected_source_ids if source_id in by_id
    )
    oracle_match = _contains_terms(oracle_text, question.answer_terms)
    retrieval_failed = oracle_match and evidence_coverage < 1.0
    reading_failed = oracle_match and evidence_coverage >= 1.0 and not answer_match
    return {
        "oracle_answer_match": oracle_match,
        "retrieval_failed": retrieval_failed,
        "reading_failed": reading_failed,
    }


def _contains_terms(text: str, terms: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return all(term.lower() in lowered for term in terms)


def _answer_preview(text: str) -> str:
    collapsed = " ".join(text.split())
    if not collapsed:
        return "No benchmark evidence was retrieved."
    if len(collapsed) > 240:
        return collapsed[:237] + "..."
    return collapsed


def _token_cost(
    *,
    dataset: MemoryBenchmarkDataset,
    questions: list[dict[str, Any]],
) -> dict[str, int]:
    prompt_chars = sum(len(document.content) for document in dataset.documents)
    prompt_chars += sum(len(question.query) for question in dataset.questions)
    completion_chars = sum(
        len(str(question.get("user_visible_answer", ""))) for question in questions
    )
    input_tokens = _estimate_tokens(prompt_chars)
    output_tokens = _estimate_tokens(completion_chars)
    return {
        "estimated_input_tokens": input_tokens,
        "estimated_output_tokens": output_tokens,
        "estimated_total_tokens": input_tokens + output_tokens,
    }


def _run_capacity_probe(*, token_count: int, limit: int) -> dict[str, Any]:
    if token_count <= 0:
        raise ValueError("capacity token counts must be positive")
    with tempfile.TemporaryDirectory(prefix="shisad-memory-benchmark-capacity-") as temp_dir:
        pipeline = IngestionPipeline(Path(temp_dir))
        content = " ".join(["capacity"] * token_count) + " sentinel-anchor"
        start = time.perf_counter()
        pipeline.ingest(
            source_id=f"capacity-{token_count}",
            source_type="external",
            collection="project_docs",
            content=content,
        )
        pack = pipeline.compile_recall("sentinel-anchor", limit=limit)
        latency_ms = _elapsed_ms(start)
        retrieved = any(item.source_id == f"capacity-{token_count}" for item in pack.results)
    return {
        "target_tokens": token_count,
        "retrieved": retrieved,
        "latency_ms": round(latency_ms, 3),
    }


def _threshold_failures(
    *,
    metrics: dict[str, Any],
    fail_under_accuracy: float | None,
    fail_under_recall: float | None,
    fail_over_harm_rate: float | None,
    fail_over_p95_latency_ms: float | None,
) -> list[str]:
    failures: list[str] = []
    if fail_under_accuracy is not None and metrics["accuracy"] < fail_under_accuracy:
        failures.append("accuracy_below_threshold")
    recall_at_k = metrics["retrieval_quality"]["recall_at_k"]
    if fail_under_recall is not None and recall_at_k < fail_under_recall:
        failures.append("recall_below_threshold")
    if fail_over_harm_rate is not None and metrics["harm_rate"] > fail_over_harm_rate:
        failures.append("harm_rate_above_threshold")
    p95_latency = metrics["latency_ms"]["p95"]
    if fail_over_p95_latency_ms is not None and p95_latency > fail_over_p95_latency_ms:
        failures.append("p95_latency_above_threshold")
    return failures


def _capacity_failures(capacity_reports: list[dict[str, Any]]) -> list[str]:
    return [
        f"capacity_probe_failed:{report['target_tokens']}"
        for report in capacity_reports
        if not bool(report.get("retrieved"))
    ]


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / float(len(values))


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    rank = (len(ordered) - 1) * (percentile / 100.0)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return ordered[int(rank)]
    return ordered[lower] + ((ordered[upper] - ordered[lower]) * (rank - lower))


def _estimate_tokens(chars: int) -> int:
    return max(1, math.ceil(chars / 4.0))


def _elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0


def _iso_timestamp() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


class _pipeline_storage:
    def __init__(self, storage_dir: Path | None) -> None:
        self._provided = storage_dir
        self._tempdir: tempfile.TemporaryDirectory[str] | None = None

    def __enter__(self) -> Path:
        if self._provided is not None:
            self._provided.mkdir(parents=True, exist_ok=True)
            if any(self._provided.iterdir()):
                raise ValueError(
                    "memory benchmark storage directory must be empty for a reproducible run"
                )
            return self._provided
        self._tempdir = tempfile.TemporaryDirectory(prefix="shisad-memory-benchmark-")
        return Path(self._tempdir.name)

    def __exit__(self, *_exc: object) -> None:
        if self._tempdir is not None:
            self._tempdir.cleanup()


def run_memory_benchmark_cli(
    *,
    fixture: Path | None = None,
    storage_dir: Path | None = None,
    limit: int = 5,
    capacity_tokens: tuple[int, ...] = (),
    fail_under_accuracy: float | None = None,
    fail_under_recall: float | None = None,
    fail_over_harm_rate: float | None = None,
    fail_over_p95_latency_ms: float | None = None,
) -> dict[str, Any]:
    dataset = (
        load_memory_benchmark_dataset(fixture) if fixture else builtin_memory_benchmark_dataset()
    )
    return evaluate_memory_benchmark(
        dataset,
        storage_dir=storage_dir,
        limit=limit,
        capacity_tokens=capacity_tokens,
        fail_under_accuracy=fail_under_accuracy,
        fail_under_recall=fail_under_recall,
        fail_over_harm_rate=fail_over_harm_rate,
        fail_over_p95_latency_ms=fail_over_p95_latency_ms,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run deterministic M6 memory benchmarks.")
    parser.add_argument("--fixture", type=Path, help="External JSON benchmark fixture.")
    parser.add_argument("--storage-dir", type=Path, help="Memory benchmark storage directory.")
    parser.add_argument("--limit", type=int, default=5, help="Retrieval limit per question.")
    parser.add_argument(
        "--capacity-tokens",
        type=int,
        action="append",
        default=[],
        help="Run a capacity probe at the given approximate token count.",
    )
    parser.add_argument("--fail-under-accuracy", type=float)
    parser.add_argument("--fail-under-recall", type=float)
    parser.add_argument("--fail-over-harm-rate", type=float)
    parser.add_argument("--fail-over-p95-latency-ms", type=float)
    parser.add_argument("--output", type=Path, required=True, help="Output JSON report path.")
    args = parser.parse_args(argv)
    report = run_memory_benchmark_cli(
        fixture=args.fixture,
        storage_dir=args.storage_dir,
        limit=args.limit,
        capacity_tokens=tuple(args.capacity_tokens),
        fail_under_accuracy=args.fail_under_accuracy,
        fail_under_recall=args.fail_under_recall,
        fail_over_harm_rate=args.fail_over_harm_rate,
        fail_over_p95_latency_ms=args.fail_over_p95_latency_ms,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["allowed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
