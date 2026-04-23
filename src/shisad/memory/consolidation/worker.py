"""Sandboxed consolidation worker over the memory substrate."""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime

from shisad.memory.consolidation.config import ConsolidationConfig
from shisad.memory.manager import MemoryManager
from shisad.memory.schema import MemoryEntry, MemorySource

_PREDICATE_RE = re.compile(r"^(?P<name>[a-z][a-z0-9_]*)\((?P<object>[^()]+)\)$")
_TOKEN_RE = re.compile(r"[a-z][a-z0-9_-]{1,80}", re.IGNORECASE)
_PREFERENCE_RE = re.compile(
    r"\b(?:i\s+)?(?:like|love|prefer|favorite|favourite)\s+(?P<object>[a-z][a-z0-9_-]{2,80})\b",
    re.IGNORECASE,
)
_FAVORITE_OBJECT_RE = re.compile(
    r"\b(?P<object>[a-z][a-z0-9_-]{2,80})\s+is\s+my\s+favou?rite\b",
    re.IGNORECASE,
)
_NEGATION_RE = re.compile(r"\b(?:no longer|not|don't|do not|avoid|hate|dislike)\b", re.IGNORECASE)


@dataclass(frozen=True)
class ConsolidationCapabilityScope:
    """Explicit worker capability scope."""

    network: bool = False
    tool_recursion: bool = False
    self_invocation: bool = False
    write_scope: str = "memory_substrate"


@dataclass
class StrongInvalidationProposal:
    target_entry_id: str
    signal_entry_id: str
    pattern: str
    message: str


@dataclass
class ConsolidationRunResult:
    updated_entry_ids: list[str] = field(default_factory=list)
    corroborating_entry_ids: list[str] = field(default_factory=list)
    contradicted_entry_ids: list[str] = field(default_factory=list)
    strong_invalidations: list[StrongInvalidationProposal] = field(default_factory=list)
    identity_candidates: list[MemoryEntry] = field(default_factory=list)


def _entry_text(entry: MemoryEntry) -> str:
    return f"{entry.key}\n{entry.predicate or ''}\n{entry.value}"


def _tokens(entry: MemoryEntry) -> set[str]:
    return {token.lower() for token in _TOKEN_RE.findall(_entry_text(entry))}


def _predicate_parts(entry: MemoryEntry) -> tuple[str, str] | None:
    if not entry.predicate:
        return None
    match = _PREDICATE_RE.match(entry.predicate.strip())
    if match is None:
        return None
    return match.group("name").lower(), match.group("object").strip().lower()


def _source_weight(entry: MemoryEntry) -> float:
    if entry.trust_band == "elevated":
        return 1.0
    if entry.trust_band == "observed":
        return 0.7
    return 0.45


def _confidence_score(entry: MemoryEntry) -> float:
    return max(0.0, min(0.99, entry.confidence))


class ConsolidationWorker:
    """Deterministic local consolidation worker.

    The worker is deliberately narrow: it mutates only the memory substrate via
    `MemoryManager`, has no network capability, and never invokes tools.
    """

    capability_scope = ConsolidationCapabilityScope()

    def __init__(
        self,
        manager: MemoryManager,
        *,
        config: ConsolidationConfig | None = None,
    ) -> None:
        self._manager = manager
        self._config = config or ConsolidationConfig()

    def run_once(self, *, now: datetime | None = None) -> ConsolidationRunResult:
        result = ConsolidationRunResult()
        decay = self.recompute_decay_scores(now=now)
        confidence = self.apply_confidence_updates()
        result.updated_entry_ids.extend(decay.updated_entry_ids)
        result.updated_entry_ids.extend(confidence.updated_entry_ids)
        result.corroborating_entry_ids.extend(confidence.corroborating_entry_ids)
        result.contradicted_entry_ids.extend(confidence.contradicted_entry_ids)
        result.strong_invalidations.extend(self.propose_strong_invalidations())
        result.identity_candidates.extend(self.accumulate_identity_candidates())
        return result

    def recompute_decay_scores(self, *, now: datetime | None = None) -> ConsolidationRunResult:
        current = now or datetime.now(UTC)
        result = ConsolidationRunResult()
        entries = self._manager.list_entries(
            limit=max(1, len(self._manager._entries)),
            include_quarantined=True,
        )
        for entry in entries:
            score = self._decay_score(entry, now=current)
            if abs(score - entry.decay_score) < 0.001:
                continue
            if self._manager.update_decay_score(entry.id, score):
                result.updated_entry_ids.append(entry.id)
        return result

    def apply_confidence_updates(self) -> ConsolidationRunResult:
        result = ConsolidationRunResult()
        entries = self._manager.list_entries(
            limit=max(1, len(self._manager._entries)),
            include_quarantined=True,
        )
        preferences = [entry for entry in entries if entry.entry_type == "preference"]
        for preference in preferences:
            parts = _predicate_parts(preference)
            if parts is None:
                continue
            _name, wanted = parts
            support_ids: list[str] = []
            for candidate in entries:
                if candidate.id == preference.id:
                    continue
                text = _entry_text(candidate).lower()
                if wanted not in text or _NEGATION_RE.search(text):
                    continue
                if candidate.entry_type == "preference" and _predicate_parts(candidate) != parts:
                    continue
                support_ids.append(candidate.id)
            if support_ids:
                previous = preference.confidence
                delta = self._config.delta_corroborate / math.sqrt(len(support_ids))
                target = min(0.99, preference.confidence + delta)
                if self._manager.update_confidence(
                    preference.id,
                    target,
                    event_type="corroborated",
                    reference_entry_ids=support_ids,
                    metadata={"delta": target - previous},
                ):
                    result.updated_entry_ids.append(preference.id)
                    result.corroborating_entry_ids.extend(support_ids)

        preferences = self._manager.list_entries(
            entry_type="preference",
            limit=max(1, len(self._manager._entries)),
        )
        for left_index, left in enumerate(preferences):
            left_parts = _predicate_parts(left)
            if left_parts is None:
                continue
            for right in preferences[left_index + 1 :]:
                right_parts = _predicate_parts(right)
                if right_parts is None:
                    continue
                if left.key != right.key and left_parts[0] != right_parts[0]:
                    continue
                if left_parts[1] == right_parts[1]:
                    continue
                older, newer = (
                    (left, right) if left.created_at <= right.created_at else (right, left)
                )
                drop = (
                    self._config.delta_contradict
                    * _confidence_score(newer)
                    * _source_weight(newer)
                )
                if self._manager.update_confidence(
                    older.id,
                    max(0.0, older.confidence - drop),
                    event_type="contradicted",
                    reference_entry_ids=[newer.id],
                    metadata={"delta": -drop, "predicate": left_parts[0]},
                ):
                    result.updated_entry_ids.append(older.id)
                self._manager.mark_conflict(
                    older.id,
                    newer.id,
                    metadata={"predicate": left_parts[0]},
                )
                self._manager.mark_conflict(
                    newer.id,
                    older.id,
                    metadata={"predicate": left_parts[0]},
                )
                result.contradicted_entry_ids.extend([older.id, newer.id])
        return result

    def propose_strong_invalidations(self) -> list[StrongInvalidationProposal]:
        entries = self._manager.list_entries(
            limit=max(1, len(self._manager._entries)),
            include_quarantined=True,
        )
        targets = [
            entry
            for entry in entries
            if entry.entry_type in {"persona_fact", "preference", "relationship", "fact"}
        ]
        signals = [entry for entry in entries if entry.entry_type in {"episode", "note", "fact"}]
        proposals: list[StrongInvalidationProposal] = []
        for signal in signals:
            signal_text = _entry_text(signal).lower()
            pattern = self._matching_invalidation_pattern(signal_text)
            if pattern is None:
                continue
            signal_tokens = _tokens(signal)
            for target in targets:
                if target.id == signal.id:
                    continue
                overlap = signal_tokens & _tokens(target)
                if not overlap:
                    continue
                proposal = StrongInvalidationProposal(
                    target_entry_id=target.id,
                    signal_entry_id=signal.id,
                    pattern=pattern,
                    message=(
                        f"I noticed a possible update for `{target.key}` based on "
                        f"`{signal.key}`. Confirm before changing it?"
                    ),
                )
                if self._manager.record_consolidation_event(
                    target.id,
                    "strong_invalidation_proposed",
                    metadata={
                        "signal_entry_id": signal.id,
                        "pattern": pattern,
                        "overlap": sorted(overlap),
                        "surface_limit": self._config.surface_limit,
                    },
                ):
                    proposals.append(proposal)
        return proposals

    def accumulate_identity_candidates(self) -> list[MemoryEntry]:
        observations: dict[str, list[MemoryEntry]] = defaultdict(list)
        entries = self._manager.list_entries(
            limit=max(1, len(self._manager._entries)),
            include_quarantined=True,
        )
        for entry in entries:
            if entry.channel_trust != "owner_observed":
                continue
            preference = self._extract_preference_object(_entry_text(entry))
            if preference is None:
                continue
            observations[preference].append(entry)

        created: list[MemoryEntry] = []
        existing_predicates = {
            entry.predicate
            for entry in self._manager.list_entries(
                limit=max(1, len(self._manager._entries)),
                include_pending_review=True,
            )
            if entry.entry_type == "preference"
        }
        for preference, evidence in observations.items():
            threshold = self._config.identity_candidate_threshold
            if len({entry.source_id for entry in evidence}) < threshold:
                continue
            predicate = f"prefers({preference})"
            if predicate in existing_predicates:
                continue
            confidence = min(0.90, 0.30 * len(evidence))
            decision = self._manager.write_with_provenance(
                entry_type="preference",
                key=f"preference:{preference}",
                value=f"Observed preference: {preference}",
                predicate=predicate,
                source=MemorySource(
                    origin="inferred",
                    source_id=f"consolidation:candidate:{preference}",
                    extraction_method="identity_candidate_accumulation",
                ),
                source_origin="consolidation_derived",
                channel_trust="consolidation",
                confirmation_status="pending_review",
                source_id=f"consolidation:candidate:{preference}",
                scope="user",
                confidence=confidence,
                confirmation_satisfied=True,
                ingress_handle_id=f"consolidation:{preference}",
            )
            if decision.entry is None:
                continue
            evidence_ids = [entry.id for entry in evidence]
            self._manager.record_consolidation_event(
                decision.entry.id,
                "candidate_proposed",
                ingress_handle_id=decision.entry.ingress_handle_id,
                metadata={
                    "evidence_entry_ids": evidence_ids,
                    "threshold": threshold,
                    "candidate_ttl_activity_days": self._config.candidate_ttl_activity_days,
                },
            )
            created.append(decision.entry)
        return created

    def _decay_score(self, entry: MemoryEntry, *, now: datetime) -> float:
        created = entry.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        age_days = max(0.0, (now - created).total_seconds() / 86400)
        age_factor = 1.0 / (1.0 + (age_days / 90.0))
        activity_anchor = entry.last_cited_at or entry.last_verified_at or entry.created_at
        if activity_anchor.tzinfo is None:
            activity_anchor = activity_anchor.replace(tzinfo=UTC)
        activity_days = max(0.0, (now - activity_anchor).total_seconds() / 86400)
        activity_factor = 1.0 / (1.0 + (activity_days / 60.0))
        citation_factor = min(
            1.0,
            0.55 + (math.log1p(entry.citation_count) / math.log1p(10)) * 0.45,
        )
        verification_factor = 1.0 if entry.last_verified_at is not None else 0.85
        source_factor = _source_weight(entry)
        score = age_factor * activity_factor * citation_factor * verification_factor * source_factor
        return round(
            max(0.0, min(1.0, score)),
            4,
        )

    def _matching_invalidation_pattern(self, text: str) -> str | None:
        for pattern in self._config.strong_invalidation_patterns:
            if pattern.strip() and pattern.lower() in text:
                return pattern
        return None

    @staticmethod
    def _extract_preference_object(text: str) -> str | None:
        match = _FAVORITE_OBJECT_RE.search(text)
        if match is None:
            match = _PREFERENCE_RE.search(text)
        if match is None:
            return None
        return match.group("object").strip().lower()
