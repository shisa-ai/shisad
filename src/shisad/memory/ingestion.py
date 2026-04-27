"""Retrieval ingestion and trust-aware hybrid ranking."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import shutil
import sqlite3
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pydantic import BaseModel, Field, ValidationError, model_validator

from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, TaintLabel, ToolName
from shisad.memory.backend import RetrievalBackendRow, SQLiteRetrievalBackend
from shisad.memory.events import MemoryEvent, MemoryEventStore
from shisad.memory.schema import MemoryScope
from shisad.memory.surfaces import RecallPack, build_recall_pack
from shisad.memory.trust import (
    ChannelTrust,
    ConfirmationStatus,
    SourceOrigin,
    TrustBand,
    default_confidence_for_triple,
    derive_trust_band,
)
from shisad.security.firewall import ContentFirewall, SanitizationMode

RetrievalCollection = Literal["user_curated", "project_docs", "external_web", "tool_outputs"]

_TRUST_PRIOR: dict[RetrievalCollection, float] = {
    "user_curated": 1.0,
    "project_docs": 0.8,
    "tool_outputs": 0.6,
    "external_web": 0.35,
}

_SIDE_EFFECT_CAPABILITIES = {
    Capability.EMAIL_SEND,
    Capability.FILE_WRITE,
    Capability.HTTP_REQUEST,
    Capability.MESSAGE_SEND,
}

_RECALL_COLLECTION_PRIORITY: tuple[RetrievalCollection, ...] = (
    "user_curated",
    "project_docs",
    "tool_outputs",
    "external_web",
)
_RECALL_CONFIDENCE_PRIOR: dict[RetrievalCollection, float] = {
    "user_curated": 0.95,
    "project_docs": 0.8,
    "tool_outputs": 0.65,
    "external_web": 0.55,
}
_RECALL_IMPORTANCE_PRIOR: dict[RetrievalCollection, float] = {
    "user_curated": 1.2,
    "project_docs": 1.0,
    "tool_outputs": 0.95,
    "external_web": 0.85,
}
_RECALL_STALE_AFTER_DAYS = 14.0
_RECALL_ARCHIVE_AFTER_DAYS = 45.0
_RECALL_MIN_DECAY_SCORE = 0.2
_RECALL_DEFAULT_PROVENANCE_BY_COLLECTION: dict[
    RetrievalCollection,
    tuple[SourceOrigin, ChannelTrust, ConfirmationStatus],
] = {
    "user_curated": ("user_direct", "command", "user_asserted"),
    "project_docs": ("tool_output", "tool_passed", "auto_accepted"),
    "tool_outputs": ("tool_output", "tool_passed", "auto_accepted"),
    "external_web": ("external_web", "web_passed", "auto_accepted"),
}


def _default_recall_provenance(
    *,
    collection: RetrievalCollection,
    source_type: Literal["user", "external", "tool"],
) -> tuple[SourceOrigin, ChannelTrust, ConfirmationStatus]:
    if collection in _RECALL_DEFAULT_PROVENANCE_BY_COLLECTION:
        return _RECALL_DEFAULT_PROVENANCE_BY_COLLECTION[collection]
    if source_type == "user":
        return ("user_direct", "command", "user_asserted")
    if source_type == "tool":
        return ("tool_output", "tool_passed", "auto_accepted")
    return ("external_web", "web_passed", "auto_accepted")


def _trust_caveat_for(
    *,
    source_origin: SourceOrigin,
    channel_trust: ChannelTrust,
    confirmation_status: ConfirmationStatus,
    trust_band: TrustBand,
) -> str | None:
    if trust_band == "elevated":
        return None
    if channel_trust == "owner_observed":
        return "owner-observed content is not user-confirmed"
    if source_origin == "external_web":
        return "web content is untrusted recall data"
    if source_origin == "tool_output":
        return "tool-derived content is not user-authored"
    if confirmation_status == "pending_review":
        return "pending-review content is not surfaced as trusted recall"
    return "non-elevated provenance; treat as untrusted recall data"


class Fact(BaseModel):
    """Extracted fact from sanitized content."""

    text: str
    confidence: float = 0.5


class RetrievalResult(BaseModel):
    """Structured retrieval result for planner consumption."""

    chunk_id: str
    source_id: str
    source_type: Literal["user", "external", "tool"]
    collection: RetrievalCollection
    created_at: datetime
    content_sanitized: str
    extracted_facts: list[Fact] = Field(default_factory=list)
    risk_score: float
    original_hash: str
    source_origin: SourceOrigin = "user_direct"
    channel_trust: ChannelTrust = "command"
    confirmation_status: ConfirmationStatus = "user_asserted"
    scope: MemoryScope = "user"
    # (user, workspace) ownership mirror of the MemoryEntry fields; surfaced
    # so call sites filtering recall results can see the owner without a
    # second backend round-trip. Optional for legacy rows (see
    # planning/PLAN-lockdown-no-deadend.md §4.4).
    user_id: str | None = None
    workspace_id: str | None = None
    taint_labels: list[TaintLabel] = Field(default_factory=list)
    trust_band: TrustBand = "elevated"
    trust_caveat: str | None = None
    quarantined: bool = False
    citation_count: int = 0
    last_cited_at: datetime | None = None
    lexical_score: float = 0.0
    semantic_score: float = 0.0
    blended_score: float = 0.0
    confidence: float = 0.5
    importance_weight: float = 1.0
    decay_score: float = 1.0
    effective_score: float = 0.0
    corroborated: bool = False
    archived: bool = False
    stale: bool = False
    verification_gap: bool = False
    revision_churn: bool = False
    conflict: bool = False

    @model_validator(mode="before")
    @classmethod
    def _backfill_recall_provenance(cls, payload: Any) -> Any:
        if not isinstance(payload, dict):
            return payload
        collection = payload.get("collection")
        source_type = payload.get("source_type")
        if collection not in _TRUST_PRIOR or source_type not in {"user", "external", "tool"}:
            return payload
        source_origin, channel_trust, confirmation_status = _default_recall_provenance(
            collection=collection,
            source_type=source_type,
        )
        if payload.get("source_origin") is None:
            payload["source_origin"] = source_origin
        if payload.get("channel_trust") is None:
            payload["channel_trust"] = channel_trust
        if payload.get("confirmation_status") is None:
            payload["confirmation_status"] = confirmation_status
        if payload.get("scope") is None:
            payload["scope"] = "user"
        return payload

    @model_validator(mode="after")
    def _derive_trust_metadata(self) -> RetrievalResult:
        band = derive_trust_band(
            self.source_origin,
            self.channel_trust,
            self.confirmation_status,
        )
        self.trust_band = band
        self.trust_caveat = _trust_caveat_for(
            source_origin=self.source_origin,
            channel_trust=self.channel_trust,
            confirmation_status=self.confirmation_status,
            trust_band=band,
        )
        return self


class SyncEmbeddingsProvider(Protocol):
    """Embeddings provider abstraction."""

    def embed(self, input_texts: list[str]) -> list[list[float]]: ...


class EmbeddingFingerprint(BaseModel):
    """Captures embedding pipeline identity for reindex checks."""

    model_id: str
    base_url: str
    chunk_size: int = 1024

    def stable_hash(self) -> str:
        payload = f"{self.model_id}|{self.base_url}|{self.chunk_size}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class IngestionPipeline:
    """Ingests content through firewall and stores retrieval records."""

    def __init__(
        self,
        storage_dir: Path,
        *,
        firewall: ContentFirewall | None = None,
        embedding_fingerprint: EmbeddingFingerprint | None = None,
        embeddings_provider: SyncEmbeddingsProvider | None = None,
        encryption_key: str | None = None,
        legacy_storage_dir: Path | None = None,
        quarantine_threshold: float = 0.75,
        audit_hook: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        self._storage_dir = storage_dir
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._legacy_storage_dir = legacy_storage_dir
        self._db_path = self._storage_dir / "memory.sqlite3"
        self._backend = SQLiteRetrievalBackend(self._db_path)
        self._event_store = MemoryEventStore(
            self._db_path,
            legacy_jsonl_path=self._storage_dir / "memory_events.jsonl",
        )
        self._firewall = firewall or ContentFirewall()
        self._embedding_fingerprint = embedding_fingerprint or EmbeddingFingerprint(
            model_id="text-embedding-3-small",
            base_url="https://api.openai.com/v1",
            chunk_size=1024,
        )
        self._embeddings_provider = embeddings_provider
        self._explicit_encryption_key = encryption_key
        self._quarantine_threshold = quarantine_threshold
        self._audit_hook = audit_hook
        self._ensure_schema()
        self._master_secret = self._resolve_master_secret(encryption_key)
        self._key_material_by_id: dict[str, bytes] = {}
        self._key_metadata_by_id: dict[str, dict[str, str]] = {}
        self._active_key_id = ""
        self._load_or_create_keys()
        self._import_legacy_records()
        self._backend.backfill_search_index(embed_text=self._embed_text)

    @property
    def embedding_fingerprint(self) -> EmbeddingFingerprint:
        return self._embedding_fingerprint

    @property
    def active_key_id(self) -> str:
        return self._active_key_id

    def reindex_required(self, new_fingerprint: EmbeddingFingerprint) -> bool:
        """Whether index should be rebuilt due to embedding config change."""
        return new_fingerprint.stable_hash() != self._embedding_fingerprint.stable_hash()

    def ingest(
        self,
        *,
        source_id: str,
        source_type: Literal["user", "external", "tool"],
        content: str,
        collection: RetrievalCollection | None = None,
        source_origin: SourceOrigin | None = None,
        channel_trust: ChannelTrust | None = None,
        confirmation_status: ConfirmationStatus | None = None,
        scope: MemoryScope = "user",
        user_id: str | None = None,
        workspace_id: str | None = None,
    ) -> RetrievalResult:
        """Process content through firewall and store retrieval record.

        `user_id` and `workspace_id` tag the record with the owning
        operator/workspace so later recall can scope by session identity.
        See `planning/PLAN-lockdown-no-deadend.md §4.4` for the rework
        rationale. Call sites that write memory from a session context
        should pass `session.user_id` and `session.workspace_id`; sites
        that have no session (e.g., legacy maintenance imports) may pass
        None, in which case the row is written with NULL owner and
        excluded from default recall.
        """
        chunk_id = uuid.uuid4().hex
        resolved_collection = collection or self._default_collection(source_type)
        source_default_collection = self._default_collection(source_type)
        source_default_origin, source_default_channel, source_default_confirmation = (
            _default_recall_provenance(
                collection=source_default_collection,
                source_type=source_type,
            )
        )
        default_origin, default_channel, default_confirmation = _default_recall_provenance(
            collection=resolved_collection,
            source_type=source_type,
        )
        resolved_origin = source_origin or source_default_origin
        resolved_channel = channel_trust or source_default_channel
        resolved_confirmation = confirmation_status or source_default_confirmation
        if (
            source_type == "user"
            and resolved_collection != source_default_collection
            and (
                source_origin is None
                or (
                    resolved_origin,
                    resolved_channel,
                    resolved_confirmation,
                )
                == (
                    source_default_origin,
                    source_default_channel,
                    source_default_confirmation,
                )
            )
        ):
            resolved_origin = default_origin
            resolved_channel = default_channel
            resolved_confirmation = default_confirmation
        trusted_input = (
            derive_trust_band(
                resolved_origin,
                resolved_channel,
                resolved_confirmation,
            )
            == "elevated"
        )
        inspection = self._firewall.inspect(
            content,
            mode=SanitizationMode.EXTRACT_FACTS,
            trusted_input=trusted_input,
        )
        quarantined = inspection.risk_score >= self._quarantine_threshold

        result = RetrievalResult(
            chunk_id=chunk_id,
            source_id=source_id,
            source_type=source_type,
            collection=resolved_collection,
            created_at=datetime.now(UTC),
            content_sanitized=inspection.sanitized_text,
            extracted_facts=[
                Fact(text=fact, confidence=0.6) for fact in inspection.extracted_facts
            ],
            risk_score=inspection.risk_score,
            original_hash=inspection.original_hash,
            source_origin=resolved_origin,
            channel_trust=resolved_channel,
            confirmation_status=resolved_confirmation,
            scope=scope,
            user_id=user_id,
            workspace_id=workspace_id,
            taint_labels=list(inspection.taint_labels),
            quarantined=quarantined,
        )

        embedding = self._embed_text(result.content_sanitized)
        encrypted_original = self._encrypt_payload(content.encode("utf-8"), chunk_id=chunk_id)
        self._backend.upsert_record(
            row=self._backend_row_for_result(result, embedding=embedding),
            original_payload=encrypted_original,
        )
        return result

    def compile_recall(
        self,
        query: str,
        *,
        limit: int = 5,
        capabilities: set[Capability] | None = None,
        allowed_collections: set[RetrievalCollection] | None = None,
        include_quarantined: bool = False,
        require_corroboration: bool = False,
        max_tokens: int | None = None,
        as_of: datetime | None = None,
        include_archived: bool = False,
        class_budgets: dict[RetrievalCollection, int] | None = None,
        scope_filter: set[str] | None = None,
        user_id: str | None = None,
        workspace_id: str | None = None,
        include_unowned: bool = False,
    ) -> RecallPack:
        """Compile the current Recall surface over retrieval storage.

        `user_id` / `workspace_id` scope recall to the session owner for
        the **personal** collection (`user_curated`) only — that is the
        collection where LUS-9 Phase C observed cross-user leakage (see
        `planning/PLAN-lockdown-no-deadend.md §4.4`). Public collections
        (`project_docs`, `external_web`, `tool_outputs`) are collection-
        level content, not personal-to-a-user data, and continue to flow
        across sessions under their existing trust labels.

        When the scoping filter applies (owner set *and* collection is
        personal), rows whose `record.user_id` / `record.workspace_id` do
        not match are excluded, and personal-collection rows with NULL
        owner (pre-migration legacy data) are excluded by default unless
        `include_unowned=True` — reserved for maintenance/diagnostic call
        sites only. When the caller leaves both `user_id` and
        `workspace_id` as None the filter is a no-op, which preserves
        pre-rework behavior for any call site that has not yet been
        migrated to the scoped API.
        """
        if self._backend.count_records() == 0:
            return build_recall_pack(
                query=query,
                results=[],
                max_tokens=max_tokens,
                as_of=as_of,
                include_archived=include_archived,
            )

        collections = (
            set(allowed_collections) if allowed_collections is not None else set(_TRUST_PRIOR)
        )
        if capabilities is not None and capabilities & _SIDE_EFFECT_CAPABILITIES:
            collections.discard("external_web")
        if not collections:
            return build_recall_pack(
                query=query,
                results=[],
                max_tokens=max_tokens,
                as_of=as_of,
                include_archived=include_archived,
            )
        normalized_scopes = set(scope_filter) if scope_filter is not None else None
        if normalized_scopes is not None and not normalized_scopes:
            return build_recall_pack(
                query=query,
                results=[],
                max_tokens=max_tokens,
                as_of=as_of,
                include_archived=include_archived,
            )

        terms = [term for term in query.lower().split() if term]
        query_vector = self._embed_text(query)
        rows = self._backend.list_records(
            collections=set(collections),
            include_quarantined=include_quarantined,
        )
        if not rows:
            return build_recall_pack(
                query=query,
                results=[],
                max_tokens=max_tokens,
                as_of=as_of,
                include_archived=include_archived,
            )
        lexical_matches = self._backend.lexical_match_ids(
            query,
            collections=set(collections),
            include_quarantined=include_quarantined,
        )
        reference_time = as_of.astimezone(UTC) if as_of is not None else datetime.now(UTC)
        scope_by_owner = user_id is not None or workspace_id is not None
        visible_rows: list[tuple[Any, RetrievalResult]] = []
        for row in rows:
            record = self._record_from_backend_row(row)
            if record is None:
                continue
            if record.confirmation_status == "pending_review":
                continue
            if normalized_scopes is not None and record.scope not in normalized_scopes:
                continue
            if as_of is not None and record.created_at > reference_time:
                continue
            # v0.7.1 C2: scope to (user, workspace) when the caller provided
            # either. The filter applies to *personal* collections only —
            # user-curated notes and prior-session personal memory — where
            # cross-user leakage is the bug LUS-9 Phase C exposed. Public
            # collections (project_docs, external_web, tool_outputs) flow
            # across sessions because they are collection-level content,
            # not personal-to-a-user data. Legacy (pre-migration) rows in
            # the personal collection are excluded unless include_unowned
            # is set explicitly.
            if scope_by_owner and record.collection == "user_curated":
                row_unowned = record.user_id is None and record.workspace_id is None
                if row_unowned and not include_unowned:
                    continue
                if not row_unowned:
                    if user_id is not None and record.user_id != user_id:
                        continue
                    if workspace_id is not None and record.workspace_id != workspace_id:
                        continue
            visible_rows.append((row, record))

        revision_counts: dict[str, int] = {}
        for _row, record in visible_rows:
            revision_counts[record.source_id] = revision_counts.get(record.source_id, 0) + 1

        active_scored: list[tuple[float, RetrievalResult]] = []
        archived_scored: list[tuple[float, RetrievalResult]] = []

        for row, record in visible_rows:
            lexical = 0.0
            if row.chunk_id in lexical_matches:
                text = row.content_sanitized.lower()
                lexical = float(sum(text.count(term) for term in terms))
            semantic = self._cosine_similarity(query_vector, row.embedding)
            lexical_score = self._normalized_lexical_score(lexical, term_count=len(terms))
            blended = (
                (0.55 * semantic)
                + (0.35 * lexical_score)
                + (0.10 * _TRUST_PRIOR[record.collection])
            )
            age_days = max(
                0.0,
                (reference_time - record.created_at).total_seconds() / 86_400.0,
            )
            decay_score = self._decay_score_for_age(age_days)
            confidence = (
                default_confidence_for_triple(
                    record.source_origin,
                    record.channel_trust,
                    record.confirmation_status,
                )
                or _RECALL_CONFIDENCE_PRIOR[record.collection]
            )
            importance_weight = _RECALL_IMPORTANCE_PRIOR[record.collection]
            archived = age_days >= _RECALL_ARCHIVE_AFTER_DAYS
            scored_record = record.model_copy(
                update={
                    "lexical_score": lexical_score,
                    "semantic_score": semantic,
                    "blended_score": blended,
                    "confidence": confidence,
                    "importance_weight": importance_weight,
                    "decay_score": decay_score,
                    "effective_score": blended * decay_score * confidence * importance_weight,
                    "archived": archived,
                    "stale": age_days >= _RECALL_STALE_AFTER_DAYS,
                    "verification_gap": record.trust_band != "elevated",
                    "revision_churn": revision_counts.get(record.source_id, 0) > 1,
                    "conflict": False,
                }
            )
            if archived:
                archived_scored.append((scored_record.effective_score, scored_record))
            else:
                active_scored.append((scored_record.effective_score, scored_record))

        scored = active_scored
        used_archived = include_archived
        if include_archived:
            scored = active_scored + archived_scored
        elif not active_scored and archived_scored:
            scored = archived_scored
            used_archived = True
        top = self._select_recall_results(
            scored,
            limit=limit,
            class_budgets=class_budgets,
        )
        if require_corroboration:
            source_ids = {record.source_id for record in top}
            tiers = {record.collection for record in top}
            corroborated = len(source_ids) >= 2 and len(tiers) >= 2
            top = [
                record.model_copy(
                    update={
                        "corroborated": corroborated,
                        "verification_gap": record.verification_gap and not corroborated,
                    }
                )
                for record in top
            ]
        top = self._mark_conflicting_results(top, terms=terms)
        if max_tokens is not None:
            top = self._trim_recall_to_token_budget(top, max_tokens=max_tokens)
        return build_recall_pack(
            query=query,
            results=top,
            max_tokens=max_tokens,
            as_of=as_of,
            include_archived=used_archived or any(record.archived for record in top),
        )

    @staticmethod
    def _normalized_lexical_score(raw_hits: float, *, term_count: int) -> float:
        if raw_hits <= 0.0:
            return 0.0
        ceiling = max(1.0, float(max(1, term_count) * 2))
        return min(raw_hits, ceiling) / ceiling

    @staticmethod
    def _decay_score_for_age(age_days: float) -> float:
        age_ratio = min(max(age_days, 0.0) / _RECALL_ARCHIVE_AFTER_DAYS, 1.0)
        return max(_RECALL_MIN_DECAY_SCORE, 1.0 - (0.8 * age_ratio))

    @classmethod
    def _resolve_class_budgets(
        cls,
        *,
        limit: int,
        scored: list[tuple[float, RetrievalResult]],
        class_budgets: dict[RetrievalCollection, int] | None,
    ) -> dict[RetrievalCollection, int]:
        if limit <= 0:
            return {}
        present_collections = {
            record.collection
            for _, record in scored
            if record.collection in _RECALL_COLLECTION_PRIORITY
        }
        if class_budgets is not None:
            return {
                collection: max(0, int(class_budgets.get(collection, 0)))
                for collection in _RECALL_COLLECTION_PRIORITY
                if collection in present_collections
            }
        budgets: dict[RetrievalCollection, int] = {}
        remaining = limit
        for collection in _RECALL_COLLECTION_PRIORITY:
            if collection not in present_collections or remaining <= 0:
                continue
            budgets[collection] = 1
            remaining -= 1
        return budgets

    @classmethod
    def _select_recall_results(
        cls,
        scored: list[tuple[float, RetrievalResult]],
        *,
        limit: int,
        class_budgets: dict[RetrievalCollection, int] | None,
    ) -> list[RetrievalResult]:
        if limit <= 0 or not scored:
            return []
        by_collection: dict[RetrievalCollection, list[tuple[float, RetrievalResult]]] = {
            collection: [] for collection in _RECALL_COLLECTION_PRIORITY
        }
        for score, record in scored:
            by_collection[record.collection].append((score, record))
        for rows in by_collection.values():
            rows.sort(key=lambda item: item[0], reverse=True)
        budgets = cls._resolve_class_budgets(
            limit=limit,
            scored=scored,
            class_budgets=class_budgets,
        )
        selected: list[tuple[float, RetrievalResult]] = []
        selected_ids: set[str] = set()
        for collection in _RECALL_COLLECTION_PRIORITY:
            budget = budgets.get(collection, 0)
            if budget <= 0:
                continue
            taken = 0
            for score, record in by_collection[collection]:
                if taken >= budget or len(selected) >= limit:
                    break
                if record.chunk_id in selected_ids:
                    continue
                selected.append((score, record))
                selected_ids.add(record.chunk_id)
                taken += 1
        leftovers = sorted(scored, key=lambda item: item[0], reverse=True)
        for score, record in leftovers:
            if len(selected) >= limit:
                break
            if record.chunk_id in selected_ids:
                continue
            selected.append((score, record))
            selected_ids.add(record.chunk_id)
        selected.sort(key=lambda item: item[0], reverse=True)
        return [record for _, record in selected[:limit]]

    @staticmethod
    def _trim_recall_to_token_budget(
        results: list[RetrievalResult],
        *,
        max_tokens: int,
    ) -> list[RetrievalResult]:
        if max_tokens <= 0 or not results:
            return results[:1]
        kept: list[RetrievalResult] = []
        used_tokens = 0
        for record in results:
            token_estimate = max(1, len(record.content_sanitized.split()))
            if kept and used_tokens + token_estimate > max_tokens:
                break
            kept.append(record)
            used_tokens += token_estimate
        return kept or results[:1]

    @staticmethod
    def _mark_conflicting_results(
        results: list[RetrievalResult],
        *,
        terms: list[str],
    ) -> list[RetrievalResult]:
        if len(results) < 2 or not terms:
            return results
        query_terms = {term for term in terms if len(term) > 2}
        if not query_terms:
            return results
        negation_markers = (" not ", " never ", " no longer ", " cannot ", " can't ", " isn't ")
        updated = list(results)
        conflict_indexes: set[int] = set()
        token_sets = [
            {token for token in record.content_sanitized.lower().replace(".", " ").split() if token}
            for record in results
        ]
        negated = [
            any(marker in f" {record.content_sanitized.lower()} " for marker in negation_markers)
            for record in results
        ]
        for left in range(len(results)):
            for right in range(left + 1, len(results)):
                overlap = (token_sets[left] & token_sets[right]) & query_terms
                if len(overlap) >= 2 and negated[left] != negated[right]:
                    conflict_indexes.add(left)
                    conflict_indexes.add(right)
        if not conflict_indexes:
            return results
        for index in conflict_indexes:
            updated[index] = updated[index].model_copy(update={"conflict": True})
        return updated

    def retrieve(
        self,
        query: str,
        *,
        limit: int = 5,
        capabilities: set[Capability] | None = None,
        allowed_collections: set[RetrievalCollection] | None = None,
        include_quarantined: bool = False,
        require_corroboration: bool = False,
    ) -> list[RetrievalResult]:
        """Backwards-compatible alias for the emerging Recall surface."""

        return self.compile_recall(
            query,
            limit=limit,
            capabilities=capabilities,
            allowed_collections=allowed_collections,
            include_quarantined=include_quarantined,
            require_corroboration=require_corroboration,
        ).results

    def record_citations(
        self,
        chunk_ids: list[str],
        *,
        cited_at: datetime | None = None,
    ) -> int:
        """Persist citation usage for surfaced retrieval results."""
        try:
            return self._backend.record_citations(
                chunk_ids,
                cited_at=(cited_at or datetime.now(UTC)).isoformat(),
            )
        except sqlite3.OperationalError as exc:
            self._audit(
                "memory.citation_record_failed",
                {
                    "reason": str(exc),
                    "chunk_count": len([chunk_id for chunk_id in chunk_ids if chunk_id]),
                },
            )
            return 0

    def read_original(
        self,
        chunk_id: str,
        *,
        audit_context: dict[str, Any] | None = None,
    ) -> str | None:
        """Return decrypted original content for explicit user inspection."""
        caller_context = dict(audit_context or {})
        payload = self._backend.read_original_payload(chunk_id)
        if payload is None:
            self._audit(
                "memory.evidence_read",
                {
                    "chunk_id": chunk_id,
                    "found": False,
                    "caller_context": caller_context,
                },
            )
            return None
        try:
            decrypted = self._decrypt_payload(payload, chunk_id=chunk_id)
        except (InvalidTag, OSError, ValueError, TypeError, KeyError):
            self._audit(
                "memory.original_read_failed",
                {"chunk_id": chunk_id, "reason": "decrypt_failed"},
            )
            self._audit(
                "memory.evidence_read",
                {
                    "chunk_id": chunk_id,
                    "found": False,
                    "caller_context": caller_context,
                },
            )
            return None
        self._event_store.append(
            MemoryEvent(
                entry_id=f"chunk:{chunk_id}",
                event_type="evidence_read",
                actor=str(caller_context.get("method", "memory.read_original")),
                metadata_json={
                    "chunk_id": chunk_id,
                    "caller_context": caller_context,
                },
            )
        )
        self._audit(
            "memory.evidence_read",
            {
                "chunk_id": chunk_id,
                "found": True,
                "caller_context": caller_context,
            },
        )
        return decrypted.decode("utf-8", errors="replace")

    def rotate_data_key(self, *, reencrypt_existing: bool = True) -> str:
        """Rotate active data key; optionally re-encrypt existing original payloads."""
        new_key_id = self._add_data_key()
        self._active_key_id = new_key_id
        self._persist_key_manifest()
        if reencrypt_existing:
            for chunk_id, payload in self._backend.iter_original_payloads():
                plaintext = self._decrypt_payload(payload, chunk_id=chunk_id)
                self._backend.replace_original_payload(
                    chunk_id=chunk_id,
                    original_payload=self._encrypt_payload(plaintext, chunk_id=chunk_id),
                )
        self._audit(
            "memory.key_rotated",
            {"active_key_id": self._active_key_id, "reencrypt_existing": reencrypt_existing},
        )
        return self._active_key_id

    def quarantine_source(self, source_id: str, *, reason: str = "") -> int:
        """Quarantine all chunks from a suspicious source."""
        count = self._backend.quarantine_source(source_id)
        _ = reason
        return count

    def persisted_artifact_count(self) -> int:
        """Return the number of persisted retrieval records."""
        return self._backend.count_records()

    def artifacts_empty(self) -> bool:
        """Whether retrieval storage is empty apart from key metadata."""
        return self.persisted_artifact_count() == 0

    def search_index_count(self) -> int:
        """Return the number of persisted vector-index rows."""
        return self._backend.count_vectors()

    def list_records(
        self,
        *,
        limit: int = 100,
        allowed_collections: set[RetrievalCollection] | None = None,
        include_quarantined: bool = False,
    ) -> list[RetrievalResult]:
        """Return persisted retrieval records without ranking."""
        rows = self._backend.list_records(
            collections=set(allowed_collections) if allowed_collections is not None else None,
            include_quarantined=include_quarantined,
        )
        records = [
            record for row in rows if (record := self._record_from_backend_row(row)) is not None
        ]
        records.sort(key=lambda item: item.created_at, reverse=True)
        return records[:limit]

    def reset_storage(self) -> None:
        """Clear retrieval rows while preserving the shared SQLite substrate."""
        self._key_material_by_id.clear()
        self._key_metadata_by_id.clear()
        self._active_key_id = ""
        self._backend.clear_records()
        with self._connect_db() as conn:
            conn.execute("DELETE FROM retrieval_keys")
            conn.execute("DELETE FROM retrieval_metadata WHERE key != 'master_salt_b64'")
        for root in self._legacy_storage_roots():
            shutil.rmtree(root / "sanitized", ignore_errors=True)
            shutil.rmtree(root / "original_encrypted", ignore_errors=True)
            (root / "keys.json").unlink(missing_ok=True)
            (root / "key.bin").unlink(missing_ok=True)
            (root / "master_salt.bin").unlink(missing_ok=True)
        self._load_or_create_keys()

    def collections_for_capabilities(
        self,
        capabilities: set[Capability],
    ) -> set[RetrievalCollection]:
        collections: set[RetrievalCollection] = set(_TRUST_PRIOR)
        if capabilities & _SIDE_EFFECT_CAPABILITIES:
            collections.discard("external_web")
        return collections

    def _resolve_master_secret(self, encryption_key: str | None) -> bytes:
        salt = self._load_master_salt()
        return self._resolve_storage_secret(
            storage_dir=self._storage_dir,
            secret_override=encryption_key,
            salt=salt,
        )

    def _resolve_storage_secret(
        self,
        *,
        storage_dir: Path,
        secret_override: str | None,
        salt: bytes,
    ) -> bytes:
        if secret_override:
            return self._derive_password_secret(secret_override.encode("utf-8"), salt=salt)
        env_secret = os.getenv("SHISAD_MEMORY_MASTER_KEY", "").strip()
        if env_secret:
            return self._derive_password_secret(env_secret.encode("utf-8"), salt=salt)
        machine_id = ""
        for candidate in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
            if candidate.exists():
                machine_id = candidate.read_text(encoding="utf-8").strip()
                break
        basis = f"{os.getuid()}|{machine_id}|{storage_dir.resolve()}"
        return self._derive_password_secret(basis.encode("utf-8"), salt=salt)

    def _derive_password_secret(self, secret: bytes, *, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=300_000,
        )
        return kdf.derive(secret)

    def _load_master_salt(self) -> bytes:
        stored = self._metadata_get("master_salt_b64")
        if stored is not None:
            salt = self._unb64(stored)
            if len(salt) != 16:
                raise ValueError("Invalid master salt length")
            return salt
        for root in self._legacy_storage_roots():
            salt_path = root / "master_salt.bin"
            if not salt_path.exists():
                continue
            salt = salt_path.read_bytes()
            if len(salt) != 16:
                raise ValueError("Invalid master salt length")
            self._metadata_set("master_salt_b64", self._b64(salt))
            return salt
        salt = os.urandom(16)
        self._metadata_set("master_salt_b64", self._b64(salt))
        return salt

    def _derive_kek(self, salt: bytes, *, master_secret: bytes | None = None) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200_000,
        )
        return kdf.derive(self._master_secret if master_secret is None else master_secret)

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.b64encode(data).decode("utf-8")

    @staticmethod
    def _unb64(data: str) -> bytes:
        return base64.b64decode(data.encode("utf-8"))

    def _wrap_data_key(self, key_material: bytes) -> tuple[str, str, str]:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        kek = self._derive_kek(salt)
        wrapped = AESGCM(kek).encrypt(nonce, key_material, associated_data=None)
        return self._b64(salt), self._b64(nonce), self._b64(wrapped)

    def _unwrap_data_key(
        self,
        *,
        salt_b64: str,
        nonce_b64: str,
        wrapped_key_b64: str,
        master_secret: bytes | None = None,
    ) -> bytes:
        salt = self._unb64(salt_b64)
        nonce = self._unb64(nonce_b64)
        wrapped = self._unb64(wrapped_key_b64)
        kek = self._derive_kek(salt, master_secret=master_secret)
        return AESGCM(kek).decrypt(nonce, wrapped, associated_data=None)

    def _load_or_create_keys(self) -> None:
        self._key_material_by_id.clear()
        self._key_metadata_by_id.clear()
        with self._connect_db() as conn:
            rows = conn.execute(
                """
                SELECT key_id, created_at, salt_b64, nonce_b64, wrapped_key_b64
                FROM retrieval_keys
                ORDER BY created_at ASC, key_id ASC
                """
            ).fetchall()
            active = self._metadata_get("active_key_id", conn=conn)
        if rows:
            for entry in rows:
                key_id = str(entry["key_id"])
                key_material = self._unwrap_data_key(
                    salt_b64=str(entry["salt_b64"]),
                    nonce_b64=str(entry["nonce_b64"]),
                    wrapped_key_b64=str(entry["wrapped_key_b64"]),
                )
                self._key_material_by_id[key_id] = key_material
                self._key_metadata_by_id[key_id] = {
                    "key_id": key_id,
                    "created_at": str(entry["created_at"]),
                    "salt_b64": str(entry["salt_b64"]),
                    "nonce_b64": str(entry["nonce_b64"]),
                    "wrapped_key_b64": str(entry["wrapped_key_b64"]),
                }
            self._active_key_id = active or next(iter(self._key_material_by_id))
            return

        if self._import_legacy_keys():
            return

        # First-run key bootstrap.
        self._active_key_id = self._add_data_key()
        self._persist_key_manifest()

    def _import_legacy_keys(self) -> bool:
        for root in self._legacy_storage_roots():
            manifest_path = root / "keys.json"
            if manifest_path.exists():
                raw = json.loads(manifest_path.read_text(encoding="utf-8"))
                keys = raw.get("keys", [])
                active = str(raw.get("active_key_id", "")).strip()
                if not isinstance(keys, list) or not keys:
                    raise ValueError("Invalid key manifest: keys missing")
                salt_path = root / "master_salt.bin"
                if not salt_path.exists():
                    raise ValueError("Legacy key manifest missing master salt")
                salt = salt_path.read_bytes()
                if len(salt) != 16:
                    raise ValueError("Invalid master salt length")
                legacy_secret = self._resolve_storage_secret(
                    storage_dir=root,
                    secret_override=self._explicit_encryption_key,
                    salt=salt,
                )
                for entry in keys:
                    key_material = self._unwrap_data_key(
                        salt_b64=str(entry["salt_b64"]),
                        nonce_b64=str(entry["nonce_b64"]),
                        wrapped_key_b64=str(entry["wrapped_key_b64"]),
                        master_secret=legacy_secret,
                    )
                    self._register_data_key(
                        key_material,
                        key_id=str(entry["key_id"]),
                        created_at=str(entry.get("created_at", "")),
                    )
                self._active_key_id = active or next(iter(self._key_material_by_id))
                self._persist_key_manifest()
                return True
            legacy_key_file = root / "key.bin"
            if not legacy_key_file.exists():
                continue
            legacy = legacy_key_file.read_bytes()
            if len(legacy) != 32:
                raise ValueError("Invalid legacy key length")
            self._active_key_id = self._register_data_key(legacy)
            self._persist_key_manifest()
            return True
        return False

    def _register_data_key(
        self,
        key_material: bytes,
        *,
        key_id: str | None = None,
        created_at: str | None = None,
    ) -> str:
        key_id = key_id or uuid.uuid4().hex
        salt_b64, nonce_b64, wrapped_key_b64 = self._wrap_data_key(key_material)
        self._key_material_by_id[key_id] = key_material
        self._key_metadata_by_id[key_id] = {
            "key_id": key_id,
            "created_at": created_at or datetime.now(UTC).isoformat(),
            "salt_b64": salt_b64,
            "nonce_b64": nonce_b64,
            "wrapped_key_b64": wrapped_key_b64,
        }
        return key_id

    def _add_data_key(self) -> str:
        return self._register_data_key(os.urandom(32))

    def _persist_key_manifest(self) -> None:
        with self._connect_db() as conn:
            conn.execute("DELETE FROM retrieval_keys")
            conn.executemany(
                """
                INSERT INTO retrieval_keys (
                    key_id,
                    created_at,
                    salt_b64,
                    nonce_b64,
                    wrapped_key_b64
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        metadata["key_id"],
                        metadata["created_at"],
                        metadata["salt_b64"],
                        metadata["nonce_b64"],
                        metadata["wrapped_key_b64"],
                    )
                    for metadata in (
                        self._key_metadata_by_id[key_id]
                        for key_id in sorted(self._key_metadata_by_id)
                    )
                ],
            )
            self._metadata_set("active_key_id", self._active_key_id, conn=conn)

    def _import_legacy_records(self) -> None:
        with self._connect_db() as conn:
            existing_chunk_ids = {
                str(row["chunk_id"])
                for row in conn.execute("SELECT chunk_id FROM retrieval_records").fetchall()
            }
            for root in self._legacy_storage_roots():
                sanitized_dir = root / "sanitized"
                original_dir = root / "original_encrypted"
                if not sanitized_dir.is_dir():
                    continue
                for path in sorted(sanitized_dir.glob("*.json")):
                    if path.stem in existing_chunk_ids:
                        continue
                    try:
                        record = RetrievalResult.model_validate_json(
                            path.read_text(encoding="utf-8")
                        )
                        encrypted_original = (original_dir / f"{record.chunk_id}.bin").read_bytes()
                    except (OSError, UnicodeError, ValidationError):
                        continue
                    self._backend.upsert_record(
                        row=self._backend_row_for_result(
                            record,
                            embedding=self._embed_text(record.content_sanitized),
                        ),
                        original_payload=encrypted_original,
                    )
                    existing_chunk_ids.add(record.chunk_id)

    def _connect_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        with self._connect_db() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS retrieval_keys (
                    key_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    salt_b64 TEXT NOT NULL,
                    nonce_b64 TEXT NOT NULL,
                    wrapped_key_b64 TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS retrieval_metadata (
                    key TEXT PRIMARY KEY,
                    value_text TEXT NOT NULL
                )
                """
            )

    def _metadata_get(
        self,
        key: str,
        *,
        conn: sqlite3.Connection | None = None,
    ) -> str | None:
        if conn is None:
            with self._connect_db() as inner:
                return self._metadata_get(key, conn=inner)
        row = conn.execute(
            "SELECT value_text FROM retrieval_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        return str(row["value_text"])

    def _metadata_set(
        self,
        key: str,
        value: str,
        *,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        if conn is None:
            with self._connect_db() as inner:
                self._metadata_set(key, value, conn=inner)
                return
        conn.execute(
            """
            INSERT INTO retrieval_metadata (key, value_text)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value_text = excluded.value_text
            """,
            (key, value),
        )

    def _legacy_storage_roots(self) -> tuple[Path, ...]:
        roots = [self._storage_dir]
        if (
            self._legacy_storage_dir is not None
            and self._legacy_storage_dir.resolve() != self._storage_dir.resolve()
        ):
            roots.append(self._legacy_storage_dir)
        return tuple(roots)

    @staticmethod
    def _backend_row_for_result(
        record: RetrievalResult,
        *,
        embedding: list[float],
    ) -> RetrievalBackendRow:
        payload = record.model_dump(mode="json")
        return RetrievalBackendRow(
            chunk_id=str(payload["chunk_id"]),
            source_id=str(payload["source_id"]),
            source_type=str(payload["source_type"]),
            collection=str(payload["collection"]),
            created_at=str(payload["created_at"]),
            content_sanitized=str(payload["content_sanitized"]),
            extracted_facts_json=json.dumps(payload["extracted_facts"], sort_keys=True),
            risk_score=float(payload["risk_score"]),
            original_hash=str(payload["original_hash"]),
            source_origin=str(payload["source_origin"]),
            channel_trust=str(payload["channel_trust"]),
            confirmation_status=str(payload["confirmation_status"]),
            scope=str(payload["scope"]),
            user_id=(
                str(payload["user_id"]) if payload.get("user_id") is not None else None
            ),
            workspace_id=(
                str(payload["workspace_id"])
                if payload.get("workspace_id") is not None
                else None
            ),
            taint_labels_json=json.dumps(payload["taint_labels"], sort_keys=True),
            quarantined=bool(payload["quarantined"]),
            citation_count=int(payload.get("citation_count", 0)),
            last_cited_at=(
                str(payload["last_cited_at"]) if payload.get("last_cited_at") is not None else None
            ),
            embedding=embedding,
        )

    @staticmethod
    def _record_from_backend_row(row: RetrievalBackendRow) -> RetrievalResult | None:
        try:
            return RetrievalResult.model_validate(
                {
                    "chunk_id": row.chunk_id,
                    "source_id": row.source_id,
                    "source_type": row.source_type,
                    "collection": row.collection,
                    "created_at": row.created_at,
                    "content_sanitized": row.content_sanitized,
                    "extracted_facts": json.loads(row.extracted_facts_json),
                    "risk_score": row.risk_score,
                    "original_hash": row.original_hash,
                    "source_origin": row.source_origin,
                    "channel_trust": row.channel_trust,
                    "confirmation_status": row.confirmation_status,
                    "scope": row.scope,
                    "user_id": row.user_id,
                    "workspace_id": row.workspace_id,
                    "taint_labels": json.loads(row.taint_labels_json),
                    "quarantined": row.quarantined,
                    "citation_count": row.citation_count,
                    "last_cited_at": row.last_cited_at,
                }
            )
        except (TypeError, ValueError, ValidationError, json.JSONDecodeError):
            return None

    def _encrypt_payload(self, payload: bytes, *, chunk_id: str | None = None) -> bytes:
        key = self._key_material_by_id[self._active_key_id]
        nonce = os.urandom(12)
        aad = self._aad(self._active_key_id, chunk_id)
        ciphertext = AESGCM(key).encrypt(nonce, payload, associated_data=aad)
        envelope = {
            "v": 3,
            "kid": self._active_key_id,
            "chunk_id": chunk_id or "",
            "nonce_b64": self._b64(nonce),
            "ciphertext_b64": self._b64(ciphertext),
        }
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    def _decrypt_payload(self, payload: bytes, *, chunk_id: str | None = None) -> bytes:
        envelope: Any | None = None
        try:
            envelope = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            envelope = None

        if isinstance(envelope, dict) and envelope.get("v") in {2, 3}:
            key_id = str(envelope["kid"])
            key = self._key_material_by_id[key_id]
            bound_chunk = str(envelope.get("chunk_id", "")).strip() or None
            if chunk_id and bound_chunk and chunk_id != bound_chunk:
                raise ValueError("chunk_id binding mismatch")
            nonce = self._unb64(str(envelope["nonce_b64"]))
            ciphertext = self._unb64(str(envelope["ciphertext_b64"]))
            if envelope.get("v") == 2 and "chunk_id" not in envelope:
                return AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)
            aad = self._aad(key_id, bound_chunk)
            return AESGCM(key).decrypt(nonce, ciphertext, associated_data=aad)

        # Legacy payload format fallback: nonce + ciphertext.
        if len(payload) < 13:
            raise ValueError("ciphertext too short")
        key = self._key_material_by_id[self._active_key_id]
        nonce = payload[:12]
        ciphertext = payload[12:]
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)

    @staticmethod
    def _aad(key_id: str, chunk_id: str | None) -> bytes:
        return f"shisad:v2|kid={key_id}|chunk={chunk_id or ''}".encode()

    def _audit(self, action: str, payload: dict[str, Any]) -> None:
        if self._audit_hook is not None:
            self._audit_hook(action, payload)

    @staticmethod
    def _default_collection(
        source_type: Literal["user", "external", "tool"],
    ) -> RetrievalCollection:
        mapping: dict[str, RetrievalCollection] = {
            "user": "user_curated",
            "external": "external_web",
            "tool": "tool_outputs",
        }
        return mapping[source_type]

    def _embed_text(self, text: str) -> list[float]:
        # Provider-backed semantic vectors with deterministic local fallback.
        if self._embeddings_provider is not None:
            try:
                vectors = self._embeddings_provider.embed([text])
                if vectors and vectors[0]:
                    values = [float(v) for v in vectors[0]]
                    norm = math.sqrt(sum(v * v for v in values)) or 1.0
                    return [v / norm for v in values]
            except (OSError, RuntimeError, TypeError, ValueError):
                # Fail closed to deterministic local fallback.
                pass

        if not text:
            return [0.0] * 12
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        values = [digest[i] / 255.0 for i in range(12)]
        norm = math.sqrt(sum(v * v for v in values)) or 1.0
        return [v / norm for v in values]

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        if not a or not b or len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b, strict=True))
        return max(0.0, min(dot, 1.0))


class RetrieveRagTool:
    """PEP-gated retrieval tool facade."""

    name = ToolName("retrieve_rag")

    def __init__(self, ingestion: IngestionPipeline) -> None:
        self._ingestion = ingestion

    @staticmethod
    def tool_definition() -> ToolDefinition:
        return ToolDefinition(
            name=ToolName("retrieve_rag"),
            description="Retrieve sanitized evidence from indexed content",
            parameters=[
                ToolParameter(name="query", type="string", required=True),
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.MEMORY_READ],
            require_confirmation=False,
        )

    def execute(
        self,
        *,
        query: str,
        limit: int = 5,
        capabilities: set[Capability] | None = None,
    ) -> list[RetrievalResult]:
        pack = self._ingestion.compile_recall(
            query,
            limit=limit,
            capabilities=capabilities,
        )
        results = pack.results
        self._ingestion.record_citations([item.chunk_id for item in results])
        return results
