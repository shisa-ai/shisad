"""Cross-thread leak detection helpers for outbound payloads."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)


def _tokens(text: str) -> list[str]:
    return [match.group(0).lower() for match in TOKEN_RE.finditer(text)]


def _ngrams(tokens: list[str], n: int) -> set[str]:
    if len(tokens) < n:
        return set()
    return {" ".join(tokens[index : index + n]) for index in range(len(tokens) - n + 1)}


def _simhash(tokens: Iterable[str]) -> int:
    vector = [0] * 64
    for token in tokens:
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        value = int.from_bytes(digest[:8], "big")
        for bit in range(64):
            if value & (1 << bit):
                vector[bit] += 1
            else:
                vector[bit] -= 1
    output = 0
    for bit, weight in enumerate(vector):
        if weight >= 0:
            output |= 1 << bit
    return output


def _hamming_distance(left: int, right: int) -> int:
    return (left ^ right).bit_count()


@dataclass(slots=True)
class LeakCheckResult:
    detected: bool
    overlap_score: float
    matched_source_ids: list[str] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    requires_confirmation: bool = False
    detector_version: str = "m6-leakcheck-v1"


class CrossThreadLeakDetector:
    """Detect outbound overlap with out-of-scope source evidence."""

    def __init__(
        self,
        *,
        exact_ngram_size: int = 5,
        warning_threshold: float = 0.2,
        confirmation_threshold: float = 0.35,
    ) -> None:
        self._exact_ngram_size = max(2, exact_ngram_size)
        self._warning_threshold = max(0.05, min(warning_threshold, 0.9))
        self._confirmation_threshold = max(
            self._warning_threshold,
            min(confirmation_threshold, 0.95),
        )

    def evaluate(
        self,
        *,
        outbound_text: str,
        source_text_by_id: dict[str, str],
        allowed_source_ids: set[str] | None = None,
        explicit_cross_thread_intent: bool = False,
    ) -> LeakCheckResult:
        allowed = allowed_source_ids or set()
        outbound_tokens = _tokens(outbound_text)
        if not outbound_tokens:
            return LeakCheckResult(detected=False, overlap_score=0.0)

        outbound_ngrams = _ngrams(outbound_tokens, self._exact_ngram_size)
        outbound_hash = _simhash(outbound_tokens)
        highest = 0.0
        matched: list[str] = []
        reason_codes: list[str] = []

        for source_id, source_text in source_text_by_id.items():
            if source_id in allowed:
                continue
            source_tokens = _tokens(source_text)
            if not source_tokens:
                continue
            source_ngrams = _ngrams(source_tokens, self._exact_ngram_size)
            exact_overlap = 0.0
            if outbound_ngrams and source_ngrams:
                intersection = len(outbound_ngrams & source_ngrams)
                union = len(outbound_ngrams | source_ngrams)
                if union > 0:
                    exact_overlap = intersection / union

            source_hash = _simhash(source_tokens)
            approx_similarity = 1.0 - (_hamming_distance(outbound_hash, source_hash) / 64.0)
            score = max(exact_overlap, approx_similarity * 0.5)
            if score >= self._warning_threshold:
                matched.append(source_id)
                highest = max(highest, score)
                reason_codes.append("leakcheck:cross_thread_overlap")
                if exact_overlap >= self._warning_threshold:
                    reason_codes.append("leakcheck:exact_overlap")
                else:
                    reason_codes.append("leakcheck:approx_overlap")

        if not matched:
            return LeakCheckResult(detected=False, overlap_score=0.0)

        requires_confirmation = (
            highest >= self._confirmation_threshold and not explicit_cross_thread_intent
        )
        if requires_confirmation:
            reason_codes.append("leakcheck:high_overlap_requires_confirmation")
        return LeakCheckResult(
            detected=True,
            overlap_score=round(highest, 4),
            matched_source_ids=sorted(set(matched)),
            reason_codes=sorted(set(reason_codes)),
            requires_confirmation=requires_confirmation,
        )
