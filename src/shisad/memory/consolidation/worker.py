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
_EXTRACTION_RE = re.compile(
    r"\b(?P<label>Decision|Todo|Fact|Note):\s*(?P<body>.*?)(?=\s+\b(?:Decision|Todo|Fact|Note):|$)",
    re.IGNORECASE,
)
_DIETARY_PREFERENCES = {
    "ramen",
    "sushi",
    "coffee",
    "tea",
    "pizza",
    "vegetarian",
    "vegan",
    "gluten",
    "dairy",
    "peanut",
    "peanuts",
    "shellfish",
}
_MEDICAL_PREFERENCES = {
    "insulin",
    "medication",
    "medicine",
    "allergy",
    "allergies",
    "asthma",
    "diabetes",
}
_STRONG_INVALIDATION_EVENT_LOOKBACK = 10_000


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


@dataclass(frozen=True)
class ExtractionCandidate:
    entry_type: str
    key: str
    value: str
    phase: str


@dataclass
class ConsolidationRunResult:
    updated_entry_ids: list[str] = field(default_factory=list)
    corroborating_entry_ids: list[str] = field(default_factory=list)
    contradicted_entry_ids: list[str] = field(default_factory=list)
    strong_invalidations: list[StrongInvalidationProposal] = field(default_factory=list)
    identity_candidates: list[MemoryEntry] = field(default_factory=list)
    merged_entry_ids: list[str] = field(default_factory=list)
    archive_candidate_ids: list[str] = field(default_factory=list)
    quarantined_entry_ids: list[str] = field(default_factory=list)


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


def _dedup_value(value: object) -> str:
    return str(value).strip().casefold()


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
        scope_filter: set[str] | frozenset[str] | None = None,
    ) -> None:
        self._manager = manager
        self._config = config or ConsolidationConfig()
        self._scope_filter = frozenset(scope_filter) if scope_filter is not None else None

    def _list_entries(
        self,
        *,
        entry_type: str | None = None,
        include_quarantined: bool = False,
        include_pending_review: bool = False,
    ) -> list[MemoryEntry]:
        entries = self._manager.list_entries(
            entry_type=entry_type,
            limit=max(1, len(self._manager._entries)),
            include_quarantined=include_quarantined,
            include_pending_review=include_pending_review,
        )
        if self._scope_filter is None:
            return entries
        return [entry for entry in entries if entry.scope in self._scope_filter]

    def run_once(self, *, now: datetime | None = None) -> ConsolidationRunResult:
        result = ConsolidationRunResult()
        decay = self.recompute_decay_scores(now=now)
        confidence = self.apply_confidence_updates()
        dedup = self.deduplicate_entries()
        retention = self.enforce_retention(now=now)
        result.updated_entry_ids.extend(decay.updated_entry_ids)
        result.updated_entry_ids.extend(confidence.updated_entry_ids)
        result.corroborating_entry_ids.extend(confidence.corroborating_entry_ids)
        result.contradicted_entry_ids.extend(confidence.contradicted_entry_ids)
        result.merged_entry_ids.extend(dedup.merged_entry_ids)
        result.archive_candidate_ids.extend(retention.archive_candidate_ids)
        result.quarantined_entry_ids.extend(retention.quarantined_entry_ids)
        result.strong_invalidations.extend(self.propose_strong_invalidations())
        result.identity_candidates.extend(self.accumulate_identity_candidates())
        return result

    def recompute_decay_scores(self, *, now: datetime | None = None) -> ConsolidationRunResult:
        current = now or datetime.now(UTC)
        result = ConsolidationRunResult()
        entries = self._list_entries(include_quarantined=True)
        for entry in entries:
            score = self._decay_score(entry, now=current)
            if abs(score - entry.decay_score) < 0.001:
                continue
            if self._manager.update_decay_score(entry.id, score):
                result.updated_entry_ids.append(entry.id)
        return result

    def apply_confidence_updates(self) -> ConsolidationRunResult:
        result = ConsolidationRunResult()
        entries = self._list_entries(include_quarantined=True)
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
                support_ids = [
                    support_id
                    for support_id in support_ids
                    if not self._corroboration_already_recorded(preference.id, support_id)
                ]
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

        preferences = self._list_entries(entry_type="preference")
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
                if self._contradiction_already_recorded(
                    older,
                    newer,
                    predicate=left_parts[0],
                ):
                    continue
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

    def deduplicate_entries(self) -> ConsolidationRunResult:
        result = ConsolidationRunResult()
        entries = self._list_entries()
        groups: dict[tuple[str, str, str], list[MemoryEntry]] = defaultdict(list)
        for entry in entries:
            if (
                entry.source_origin != "consolidation_derived"
                or entry.channel_trust != "consolidation"
                or entry.confirmation_status != "auto_accepted"
                or entry.superseded_by is not None
            ):
                continue
            groups[(entry.entry_type, entry.key, _dedup_value(entry.value))].append(entry)

        for group in groups.values():
            if len(group) < 2:
                continue
            keeper = max(group, key=lambda item: (item.confidence, item.created_at, item.id))
            for duplicate in group:
                if duplicate.id == keeper.id:
                    continue
                if self._manager.mark_merged(
                    duplicate.id,
                    keeper.id,
                    metadata={
                        "reason": "deduplicate_entries",
                        "entry_type": duplicate.entry_type,
                        "key": duplicate.key,
                    },
                ):
                    result.merged_entry_ids.append(duplicate.id)
        return result

    def enforce_retention(self, *, now: datetime | None = None) -> ConsolidationRunResult:
        current = now or datetime.now(UTC)
        result = ConsolidationRunResult()
        entries = self._list_entries(include_quarantined=True, include_pending_review=True)
        for entry in entries:
            if entry.superseded_by is not None:
                continue
            if entry.decay_score >= self._config.archive_threshold:
                continue
            self._manager.record_consolidation_event(
                entry.id,
                "archive_review_candidate",
                metadata={
                    "decay_score": entry.decay_score,
                    "archive_threshold": self._config.archive_threshold,
                },
            )
            result.archive_candidate_ids.append(entry.id)
            created = entry.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=UTC)
            age_days = max(0.0, (current - created).total_seconds() / 86400)
            if (
                entry.last_verified_at is None
                and entry.trust_band != "elevated"
                and age_days >= self._config.max_unused_days
                and self._manager.quarantine(entry.id, reason="consolidation_retention")
            ):
                result.quarantined_entry_ids.append(entry.id)
        return result

    def reverify_entry(self, entry_id: str) -> bool:
        return self._manager.verify(
            entry_id,
            confidence_delta=self._config.delta_reverify,
            confidence_cap=0.95,
        )

    def propose_strong_invalidations(self) -> list[StrongInvalidationProposal]:
        entries = self._list_entries(include_quarantined=True)
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
                if target.scope != signal.scope:
                    continue
                if self._strong_invalidation_event_exists(
                    target_entry_id=target.id,
                    signal_entry_id=signal.id,
                    event_types={
                        "strong_invalidation_confirmed",
                        "strong_invalidation_rejected",
                        "strong_invalidation_expired",
                        "strong_invalidation_proposed",
                    },
                ):
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
                        "message": proposal.message,
                        "surface_limit": self._config.surface_limit,
                    },
                ):
                    proposals.append(proposal)
        return proposals

    def confirm_strong_invalidation(
        self,
        *,
        target_entry_id: str,
        signal_entry_id: str,
        new_value: str,
        ingress_handle_id: str,
    ) -> MemoryEntry | None:
        target = self._manager.get_entry(
            target_entry_id,
            include_quarantined=True,
            include_pending_review=True,
        )
        signal = self._manager.get_entry(
            signal_entry_id,
            include_quarantined=True,
            include_pending_review=True,
        )
        if target is None or signal is None:
            return None
        decision = self._manager.write_with_provenance(
            entry_type=target.entry_type,
            key=target.key,
            value=new_value,
            predicate=target.predicate,
            strength=target.strength,
            source=MemorySource(
                origin="user",
                source_id=f"strong-invalidation:{signal.id}",
                extraction_method="strong_invalidation.confirm",
            ),
            source_origin="user_confirmed",
            channel_trust="command",
            confirmation_status="user_confirmed",
            source_id=f"strong-invalidation:{signal.id}",
            scope=target.scope,
            confidence=max(target.confidence, 0.90),
            confirmation_satisfied=True,
            ingress_handle_id=ingress_handle_id,
            supersedes=target.id,
        )
        if decision.entry is None:
            return None
        self._manager.record_consolidation_event(
            decision.entry.id,
            "strong_invalidation_confirmed",
            ingress_handle_id=ingress_handle_id,
            metadata={
                "target_entry_id": target.id,
                "signal_entry_id": signal.id,
                "old_value": target.value,
                "new_value": new_value,
            },
        )
        return decision.entry

    def reject_strong_invalidation(
        self,
        *,
        target_entry_id: str,
        signal_entry_id: str,
        ingress_handle_id: str | None = None,
    ) -> bool:
        return self._record_strong_invalidation_resolution(
            target_entry_id=target_entry_id,
            signal_entry_id=signal_entry_id,
            event_type="strong_invalidation_rejected",
            ingress_handle_id=ingress_handle_id,
        )

    def expire_strong_invalidation(
        self,
        *,
        target_entry_id: str,
        signal_entry_id: str,
        ingress_handle_id: str | None = None,
    ) -> bool:
        return self._record_strong_invalidation_resolution(
            target_entry_id=target_entry_id,
            signal_entry_id=signal_entry_id,
            event_type="strong_invalidation_expired",
            ingress_handle_id=ingress_handle_id,
        )

    def two_phase_extract(self, text: str) -> list[ExtractionCandidate]:
        candidates: list[ExtractionCandidate] = []
        for match in _EXTRACTION_RE.finditer(text):
            label = match.group("label").casefold()
            body = match.group("body").strip().rstrip(".")
            if not body:
                continue
            entry_type = "todo" if label == "todo" else label
            key = f"{entry_type}:{self._key_fragment(body)}"
            candidates.append(
                ExtractionCandidate(
                    entry_type=entry_type,
                    key=key,
                    value=body,
                    phase="cheap",
                )
            )
        return candidates

    def accumulate_identity_candidates(self) -> list[MemoryEntry]:
        observations: dict[str, list[MemoryEntry]] = defaultdict(list)
        entries = self._list_entries(include_quarantined=True)
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
            for entry in self._list_entries(include_pending_review=True)
            if entry.entry_type == "preference"
        }
        for preference, evidence in observations.items():
            threshold = self._identity_candidate_threshold(preference)
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
                    "threshold_category": self._identity_candidate_threshold_category(
                        preference
                    ),
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

    def _contradiction_already_recorded(
        self,
        older: MemoryEntry,
        newer: MemoryEntry,
        *,
        predicate: str,
    ) -> bool:
        if newer.id in older.conflict_entry_ids and older.id in newer.conflict_entry_ids:
            return True
        for event in self._manager.list_events(
            entry_id=older.id,
            event_type="contradicted",
            limit=_STRONG_INVALIDATION_EVENT_LOOKBACK,
        ):
            metadata = event.metadata_json
            if str(metadata.get("predicate", "")) != predicate:
                continue
            if str(metadata.get("conflicting_entry_id", "")) == newer.id:
                return True
            references = metadata.get("reference_entry_ids", [])
            if isinstance(references, list) and newer.id in {str(item) for item in references}:
                return True
        return False

    def _corroboration_already_recorded(self, entry_id: str, support_id: str) -> bool:
        for event in self._manager.list_events(
            entry_id=entry_id,
            event_type="corroborated",
            limit=_STRONG_INVALIDATION_EVENT_LOOKBACK,
        ):
            references = event.metadata_json.get("reference_entry_ids", [])
            if isinstance(references, list) and support_id in {str(item) for item in references}:
                return True
        return False

    def _strong_invalidation_event_exists(
        self,
        *,
        target_entry_id: str,
        signal_entry_id: str,
        event_types: set[str],
    ) -> bool:
        for event_type in event_types:
            for event in self._manager.list_events(
                entry_id=target_entry_id,
                event_type=event_type,
                limit=_STRONG_INVALIDATION_EVENT_LOOKBACK,
            ):
                if str(event.metadata_json.get("signal_entry_id", "")).strip() == signal_entry_id:
                    return True
        return False

    def _identity_candidate_threshold(self, preference: str) -> int:
        category = self._identity_candidate_threshold_category(preference)
        if category is None:
            return self._config.identity_candidate_threshold
        return max(
            1,
            int(
                self._config.per_pattern_candidate_thresholds.get(
                    category,
                    self._config.identity_candidate_threshold,
                )
            ),
        )

    @staticmethod
    def _identity_candidate_threshold_category(preference: str) -> str | None:
        normalized = preference.strip().lower()
        if normalized in _DIETARY_PREFERENCES:
            return "dietary"
        if normalized in _MEDICAL_PREFERENCES:
            return "medical"
        return None

    def _record_strong_invalidation_resolution(
        self,
        *,
        target_entry_id: str,
        signal_entry_id: str,
        event_type: str,
        ingress_handle_id: str | None,
    ) -> bool:
        target = self._manager.get_entry(
            target_entry_id,
            include_quarantined=True,
            include_pending_review=True,
        )
        signal = self._manager.get_entry(
            signal_entry_id,
            include_quarantined=True,
            include_pending_review=True,
        )
        if target is None or signal is None:
            return False
        return self._manager.record_consolidation_event(
            target.id,
            event_type,
            ingress_handle_id=ingress_handle_id,
            metadata={"signal_entry_id": signal.id},
        )

    @staticmethod
    def _key_fragment(text: str) -> str:
        tokens = [token.lower() for token in _TOKEN_RE.findall(text)]
        return "-".join(tokens[:6]) or "candidate"

    @staticmethod
    def _extract_preference_object(text: str) -> str | None:
        match = _FAVORITE_OBJECT_RE.search(text)
        if match is None:
            match = _PREFERENCE_RE.search(text)
        if match is None:
            return None
        return match.group("object").strip().lower()
