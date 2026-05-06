"""Recall/MemoryPack surface helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shisad.memory.ingestion import RetrievalResult

_RECALL_TERM_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{1,80}")
_RECALL_TERM_STOPWORDS = {
    "about",
    "and",
    "are",
    "for",
    "from",
    "has",
    "have",
    "includes",
    "into",
    "not",
    "only",
    "the",
    "this",
    "that",
    "what",
    "when",
    "where",
    "who",
    "with",
}


@dataclass(slots=True)
class SufficiencyReport:
    """Deterministic recall sufficiency summary for planner/user surfaces."""

    sufficient: bool
    reason: str
    result_count: int
    min_results: int
    coverage: float
    query_terms: list[str]
    covered_terms: list[str]
    missing_terms: list[str]
    verification_gap_result_ids: list[str]
    low_confidence_result_ids: list[str]
    expanded: bool = False
    expanded_queries: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sufficient": self.sufficient,
            "reason": self.reason,
            "result_count": self.result_count,
            "min_results": self.min_results,
            "coverage": self.coverage,
            "query_terms": list(self.query_terms),
            "covered_terms": list(self.covered_terms),
            "missing_terms": list(self.missing_terms),
            "verification_gap_result_ids": list(self.verification_gap_result_ids),
            "low_confidence_result_ids": list(self.low_confidence_result_ids),
            "expanded": self.expanded,
            "expanded_queries": list(self.expanded_queries or []),
        }


@dataclass(slots=True)
class RecallPack:
    """Internal Recall surface result used by M2 rewiring."""

    query: str
    results: list[RetrievalResult]
    count: int
    citation_ids: list[str]
    max_tokens: int | None = None
    as_of: datetime | None = None
    include_archived: bool = False
    sufficiency: SufficiencyReport | None = None

    def legacy_payload(self) -> dict[str, Any]:
        """Return the current public `memory.retrieve` response shape."""
        payload: dict[str, Any] = {
            "results": [item.model_dump(mode="json") for item in self.results],
            "count": self.count,
        }
        if self.max_tokens is not None:
            payload["max_tokens"] = self.max_tokens
        if self.as_of is not None:
            payload["as_of"] = self.as_of.isoformat()
        payload["include_archived"] = self.include_archived
        if self.sufficiency is not None:
            payload["sufficiency"] = self.sufficiency.to_dict()
        return payload


def build_recall_pack(
    *,
    query: str,
    results: list[RetrievalResult],
    max_tokens: int | None = None,
    as_of: datetime | None = None,
    include_archived: bool = False,
    sufficiency: SufficiencyReport | None = None,
) -> RecallPack:
    """Wrap scored retrieval results in the emerging Recall surface shape."""

    return RecallPack(
        query=query,
        results=results,
        count=len(results),
        citation_ids=[item.chunk_id for item in results],
        max_tokens=max_tokens,
        as_of=as_of,
        include_archived=include_archived,
        sufficiency=sufficiency,
    )


def verify_recall_sufficiency(
    pack: RecallPack,
    *,
    task: str | None = None,
    min_results: int = 1,
    min_coverage: float = 0.8,
    expanded: bool = False,
    expanded_queries: list[str] | None = None,
) -> SufficiencyReport:
    """Check whether recalled snippets cover the query/task terms.

    This is deliberately deterministic and lexical. It is a floor for
    observable retrieval health, not an oracle that decides whether the user
    is allowed to continue.
    """

    if not 0.0 <= min_coverage <= 1.0:
        raise ValueError("min_sufficiency_coverage must be between 0.0 and 1.0")
    query_terms = extract_recall_terms(" ".join(part for part in (pack.query, task or "") if part))
    if not query_terms:
        return SufficiencyReport(
            sufficient=pack.count >= max(1, min_results),
            reason="no_query_terms",
            result_count=pack.count,
            min_results=max(1, min_results),
            coverage=1.0 if pack.count else 0.0,
            query_terms=[],
            covered_terms=[],
            missing_terms=[],
            verification_gap_result_ids=[
                item.chunk_id for item in pack.results if item.verification_gap
            ],
            low_confidence_result_ids=[
                item.chunk_id for item in pack.results if item.confidence < 0.4
            ],
            expanded=expanded,
            expanded_queries=list(expanded_queries or []),
        )

    result_terms: set[str] = set()
    for item in pack.results:
        result_terms.update(extract_recall_terms(item.content_sanitized))
    covered = sorted(term for term in query_terms if term in result_terms)
    missing = sorted(term for term in query_terms if term not in result_terms)
    coverage = len(covered) / max(1, len(query_terms))
    needed_results = max(1, min_results)
    sufficient = pack.count >= needed_results and coverage >= min_coverage
    if pack.count < needed_results:
        reason = "not_enough_results"
    elif coverage < min_coverage:
        reason = "low_coverage"
    elif missing:
        reason = "sufficient_partial_coverage"
    else:
        reason = "sufficient"
    return SufficiencyReport(
        sufficient=sufficient,
        reason=reason,
        result_count=pack.count,
        min_results=needed_results,
        coverage=round(coverage, 4),
        query_terms=query_terms,
        covered_terms=covered,
        missing_terms=missing,
        verification_gap_result_ids=[
            item.chunk_id for item in pack.results if item.verification_gap
        ],
        low_confidence_result_ids=[item.chunk_id for item in pack.results if item.confidence < 0.4],
        expanded=expanded,
        expanded_queries=list(expanded_queries or []),
    )


def extract_recall_terms(text: str) -> list[str]:
    """Extract normalized recall terms for sufficiency and conflict checks."""

    seen: set[str] = set()
    terms: list[str] = []
    for match in _RECALL_TERM_RE.finditer(text.lower()):
        term = match.group(0).strip("_.-")
        if len(term) < 3 and not any(character.isdigit() for character in term):
            continue
        if not term or term in _RECALL_TERM_STOPWORDS or term in seen:
            continue
        seen.add(term)
        terms.append(term)
    return terms
