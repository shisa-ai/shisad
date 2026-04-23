"""Long-term memory manager with write gating and TTL handling."""

from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

from pydantic import ValidationError

from shisad.core.types import TaintLabel
from shisad.memory.events import MemoryEvent, MemoryEventStore
from shisad.memory.remap import (
    ACTIVE_AGENDA_ENTRY_TYPES,
    PROCEDURAL_ENTRY_TYPES,
    resolve_legacy_source_origin,
)
from shisad.memory.schema import MemoryEntry, MemorySource, MemoryWriteDecision, WorkflowState
from shisad.memory.surfaces import (
    ActiveAttentionPack,
    IdentityPack,
    ProceduralArtifact,
    ProceduralArtifactSummary,
    ProceduralInvocation,
    build_active_attention_pack,
    build_identity_pack,
    build_procedural_artifact,
    build_procedural_summary,
)
from shisad.memory.trust import (
    ChannelTrust,
    ConfirmationStatus,
    SourceOrigin,
    backfill_legacy_triple,
    clamp_confidence,
    derive_trust_band,
    is_invocation_eligible_triple,
)
from shisad.security.firewall.pii import PIIDetector

_TRUST_BAND_ORDER: dict[str, int] = {"untrusted": 0, "observed": 1, "elevated": 2}


class MemoryManager:
    """Memory manager enforcing attribution + anti-poisoning gates."""

    _INSTRUCTION_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(
            r"\balways\b.{0,24}\b(do|send|forward|share|post|upload|run|execute|call|cc|bcc)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bnever\b.{0,24}\b(ask|confirm|verify|warn|block|refuse|check)\b",
            re.IGNORECASE,
        ),
        re.compile(r"\bignore\b.{0,40}\b(policy|instruction|rule)s?\b", re.IGNORECASE),
        re.compile(r"\bwhen you see\b.{0,80}\bdo\b", re.IGNORECASE),
        re.compile(
            r"\b(if|whenever)\b.{0,40}\b(then|,)\b.{0,40}\b(send|run|execute|call|share)\b",
            re.IGNORECASE,
        ),
    ]
    _PREFERENCE_PREDICATE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^[a-z][a-z0-9_]*\([^()\n]{1,200}\)$"
    )
    _DISALLOWED_PREFERENCE_PREFIXES: ClassVar[tuple[str, ...]] = (
        "always",
        "never",
        "ignore",
        "prioritize",
    )
    _LOW_SIGNAL_PHRASES: ClassVar[set[str]] = {
        "got it",
        "great",
        "later",
        "maybe",
        "no",
        "noted",
        "ok",
        "okay",
        "sure",
        "thanks",
        "thank you",
        "yes",
    }
    _LOW_SIGNAL_TOKENS: ClassVar[set[str]] = {
        "fine",
        "got",
        "great",
        "it",
        "later",
        "maybe",
        "no",
        "noted",
        "ok",
        "okay",
        "sure",
        "thanks",
        "them",
        "thing",
        "things",
        "this",
        "those",
        "yes",
    }
    _GENERIC_KEY_SEGMENTS: ClassVar[set[str]] = {
        "conversation",
        "entry",
        "fact",
        "item",
        "memory",
        "note",
        "profile",
        "project",
        "record",
        "remembered",
        "summary",
        "user",
        "value",
    }
    _USER_AUTHORED_ORIGINS: ClassVar[set[str]] = {
        "user_direct",
        "user_confirmed",
        "user_corrected",
    }
    _IDENTITY_ENTRY_TYPES: ClassVar[set[str]] = {
        "persona_fact",
        "preference",
        "soft_constraint",
    }

    def __init__(
        self,
        storage_dir: Path,
        *,
        default_ttl_days: int = 30,
        audit_hook: Callable[[str, dict[str, Any]], None] | None = None,
        pii_detector: PIIDetector | None = None,
    ) -> None:
        self._storage_dir = storage_dir
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._storage_dir / "memory.sqlite3"
        self._entries: dict[str, MemoryEntry] = {}
        self._ensure_entry_schema()
        self._event_store = MemoryEventStore(
            self._db_path,
            legacy_jsonl_path=self._storage_dir / "memory_events.jsonl",
        )
        self._default_ttl_days = default_ttl_days
        self._audit_hook = audit_hook
        self._pii_detector = pii_detector or PIIDetector()
        self._import_legacy_entry_files_if_needed()
        self._load_existing_entries()

    def write(
        self,
        *,
        entry_type: str,
        key: str,
        value: Any,
        predicate: str | None = None,
        strength: str = "moderate",
        source: MemorySource,
        confidence: float = 0.5,
        user_confirmed: bool = False,
        workflow_state: WorkflowState | None = None,
        invocation_eligible: bool = False,
        supersedes: str | None = None,
    ) -> MemoryWriteDecision:
        source_origin = resolve_legacy_source_origin(
            source.origin,
            source_id=source.source_id,
            extraction_method=source.extraction_method,
        )
        source_origin, channel_trust, confirmation_status = backfill_legacy_triple(
            source_origin=source_origin
        )
        return self.write_with_provenance(
            entry_type=entry_type,
            key=key,
            value=value,
            predicate=predicate,
            strength=strength,
            source=source,
            source_origin=source_origin,
            channel_trust=channel_trust,
            confirmation_status=confirmation_status,
            source_id=source.source_id,
            scope="user",
            confidence=confidence,
            confirmation_satisfied=user_confirmed,
            workflow_state=workflow_state,
            invocation_eligible=invocation_eligible,
            supersedes=supersedes,
        )

    def write_with_provenance(
        self,
        *,
        entry_type: str,
        key: str,
        value: Any,
        predicate: str | None = None,
        strength: str = "moderate",
        source: MemorySource,
        source_origin: SourceOrigin,
        channel_trust: ChannelTrust,
        confirmation_status: ConfirmationStatus,
        source_id: str,
        scope: str,
        confidence: float = 0.5,
        confirmation_satisfied: bool = False,
        taint_labels: list[TaintLabel] | None = None,
        ingress_handle_id: str | None = None,
        content_digest: str | None = None,
        workflow_state: WorkflowState | None = None,
        invocation_eligible: bool = False,
        supersedes: str | None = None,
    ) -> MemoryWriteDecision:
        text_value = str(value)
        pending_review = confirmation_status == "pending_review"
        if self._looks_instruction_like(text_value):
            return MemoryWriteDecision(
                kind="reject",
                reason="instruction_like_content_blocked",
            )

        if source.origin == "external" and not confirmation_satisfied and not pending_review:
            return MemoryWriteDecision(
                kind="require_confirmation",
                reason="external_origin_requires_confirmation",
            )

        suspicious = self._looks_suspicious(text_value)
        if suspicious and not confirmation_satisfied and not pending_review:
            return MemoryWriteDecision(
                kind="require_confirmation",
                reason="suspicious_memory_write_requires_confirmation",
            )

        if source_origin not in self._USER_AUTHORED_ORIGINS and self._fails_minimum_signal(
            key=key,
            value=value,
        ):
            return MemoryWriteDecision(
                kind="reject",
                reason="insufficient_memory_signal",
            )

        stored_value = value
        pii_findings: list[str] = []
        if isinstance(value, str):
            redacted, findings = self._pii_detector.redact(value)
            if findings:
                pii_findings = sorted({finding.kind for finding in findings})
                stored_value = redacted

        expires_at = None
        if source.origin != "user":
            expires_at = datetime.now(UTC) + timedelta(days=self._default_ttl_days)

        resolved_taints = list(taint_labels or [])
        if source.origin != "user" and TaintLabel.UNTRUSTED not in resolved_taints:
            resolved_taints.append(TaintLabel.UNTRUSTED)

        confidence = clamp_confidence(
            confidence,
            source_origin,
            channel_trust,
            confirmation_status,
            fallback=confidence,
        )
        normalized_predicate = predicate.strip() if isinstance(predicate, str) else None
        if entry_type in {"preference", "soft_constraint"}:
            if not normalized_predicate:
                return MemoryWriteDecision(kind="reject", reason="preference_predicate_required")
            if not self._PREFERENCE_PREDICATE_PATTERN.match(normalized_predicate):
                return MemoryWriteDecision(kind="reject", reason="preference_predicate_invalid")
            predicate_name = normalized_predicate.split("(", 1)[0].lower()
            if predicate_name.startswith(self._DISALLOWED_PREFERENCE_PREFIXES):
                return MemoryWriteDecision(kind="reject", reason="preference_predicate_invalid")
            if (
                source_origin not in self._USER_AUTHORED_ORIGINS
                and confirmation_status != "pending_review"
            ):
                return MemoryWriteDecision(
                    kind="require_confirmation",
                    reason="preference_requires_user_provenance",
                )
        elif normalized_predicate is not None:
            return MemoryWriteDecision(
                kind="reject",
                reason="predicate_requires_preference_entry_type",
            )
        if entry_type not in ACTIVE_AGENDA_ENTRY_TYPES and workflow_state is not None:
            return MemoryWriteDecision(
                kind="reject",
                reason="workflow_state_requires_active_agenda_entry_type",
            )
        if entry_type not in PROCEDURAL_ENTRY_TYPES and invocation_eligible:
            return MemoryWriteDecision(
                kind="reject",
                reason="invocation_eligible_requires_procedural_entry_type",
            )
        if invocation_eligible and not is_invocation_eligible_triple(
            source_origin,
            channel_trust,
            confirmation_status,
        ):
            return MemoryWriteDecision(
                kind="reject",
                reason="invocation_eligible_requires_install_triple",
            )
        resolved_trust_band = derive_trust_band(
            source_origin,
            channel_trust,
            confirmation_status,
        )
        prior_entry: MemoryEntry | None = None
        prior_trust_band: str | None = None
        if supersedes is not None:
            prior_entry = self._entries.get(supersedes)
            if prior_entry is None or self._is_deleted(prior_entry):
                return MemoryWriteDecision(kind="reject", reason="supersedes_target_not_found")
            if prior_entry.superseded_by is not None:
                return MemoryWriteDecision(
                    kind="reject",
                    reason="supersedes_target_already_has_successor",
                )
            if prior_entry.entry_type != entry_type or prior_entry.key != key:
                return MemoryWriteDecision(kind="reject", reason="supersedes_target_mismatch")
            prior_trust_band = derive_trust_band(
                prior_entry.source_origin,
                prior_entry.channel_trust,
                prior_entry.confirmation_status,
            )
            if _TRUST_BAND_ORDER[resolved_trust_band] > _TRUST_BAND_ORDER[prior_trust_band]:
                if confirmation_status not in {"user_confirmed", "user_corrected"}:
                    return MemoryWriteDecision(
                        kind="reject",
                        reason="trust_upgrade_requires_user_confirmation",
                    )
                if not ingress_handle_id:
                    return MemoryWriteDecision(
                        kind="reject",
                        reason="trust_upgrade_requires_ingress_handle",
                    )
        resolved_workflow_state = workflow_state or (
            "active" if entry_type in ACTIVE_AGENDA_ENTRY_TYPES else None
        )
        entry = MemoryEntry(
            version=(prior_entry.version + 1) if prior_entry is not None else 1,
            supersedes=supersedes,
            entry_type=entry_type,
            key=key,
            value=stored_value,
            predicate=normalized_predicate,
            strength=strength,
            source=source,
            source_origin=source_origin,
            channel_trust=channel_trust,
            confirmation_status=confirmation_status,
            source_id=source_id,
            confidence=confidence,
            expires_at=expires_at,
            taint_labels=resolved_taints,
            scope=scope,
            ingress_handle_id=ingress_handle_id,
            content_digest=content_digest,
            workflow_state=resolved_workflow_state,
            invocation_eligible=invocation_eligible,
        )
        self._entries[entry.id] = entry
        self._persist_entry(entry)
        if prior_entry is not None:
            prior_entry.superseded_by = entry.id
            self._persist_entry(prior_entry)
            self._record_event(
                entry=prior_entry,
                event_type="superseded",
                ingress_handle_id=entry.ingress_handle_id,
                metadata={
                    "superseded_by": entry.id,
                    "replacement_version": entry.version,
                },
            )
            self._audit(
                "memory.supersede",
                {
                    "entry_id": prior_entry.id,
                    "superseded_by": entry.id,
                    "replacement_version": entry.version,
                },
            )
        self._record_event(
            entry=entry,
            event_type="created",
            ingress_handle_id=ingress_handle_id,
            metadata={
                "status": entry.status,
                "workflow_state": entry.workflow_state,
                "source_origin": entry.source_origin,
                "invocation_eligible": entry.invocation_eligible,
                "supersedes": entry.supersedes,
            },
        )
        if prior_entry is not None and prior_trust_band != resolved_trust_band:
            self._record_event(
                entry=entry,
                event_type="trust_tier_changed",
                ingress_handle_id=ingress_handle_id,
                metadata={
                    "from": prior_trust_band,
                    "to": resolved_trust_band,
                    "supersedes": prior_entry.id,
                },
            )
            self._audit(
                "memory.trust_tier_changed",
                {
                    "entry_id": entry.id,
                    "supersedes": prior_entry.id,
                    "from": prior_trust_band,
                    "to": resolved_trust_band,
                    "ingress_handle_id": ingress_handle_id,
                },
            )
        if entry.entry_type in ACTIVE_AGENDA_ENTRY_TYPES:
            self._record_event(
                entry=entry,
                event_type="workflow_state_changed",
                ingress_handle_id=ingress_handle_id,
                metadata={
                    "from": None,
                    "to": entry.workflow_state,
                    "status": entry.status,
                    "reason": "init_default" if workflow_state is None else "init_explicit",
                },
            )
            self._audit(
                "memory.workflow_state_changed",
                {
                    "entry_id": entry.id,
                    "from": None,
                    "to": entry.workflow_state,
                    "status": entry.status,
                },
            )
        self._audit(
            "memory.write",
            {
                "entry_id": entry.id,
                "key": key,
                "source_origin": source_origin,
                "ingress_handle_id": ingress_handle_id,
                "pii_findings": pii_findings,
            },
        )
        return MemoryWriteDecision(kind="allow", entry=entry)

    def list_entries(
        self,
        *,
        entry_type: str | None = None,
        include_deleted: bool = False,
        include_quarantined: bool = False,
        include_pending_review: bool = False,
        limit: int = 100,
    ) -> list[MemoryEntry]:
        self.purge_expired()
        selected_type = (entry_type or "").strip().lower()
        rows = []
        for entry in self._entries.values():
            if selected_type and str(entry.entry_type).lower() != selected_type:
                continue
            if self._is_deleted(entry) and not include_deleted:
                continue
            if self._is_quarantined(entry) and not include_quarantined:
                continue
            if self._is_pending_review(entry) and not include_pending_review:
                continue
            rows.append(self._refresh_ttl(entry))
        rows.sort(key=lambda item: item.created_at, reverse=True)
        return rows[:limit]

    def get_entry(
        self,
        entry_id: str,
        *,
        include_deleted: bool = False,
        include_quarantined: bool = False,
        include_pending_review: bool = False,
    ) -> MemoryEntry | None:
        self.purge_expired()
        entry = self._entries.get(entry_id)
        if entry is None:
            return None
        if self._is_deleted(entry) and not include_deleted:
            return None
        if self._is_quarantined(entry) and not include_quarantined:
            return None
        if self._is_pending_review(entry) and not include_pending_review:
            return None
        return self._refresh_ttl(entry)

    def list_events(
        self,
        *,
        entry_id: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[MemoryEvent]:
        return self._event_store.list(entry_id=entry_id, event_type=event_type, limit=limit)

    def list_review_queue(self, *, limit: int = 100) -> list[MemoryEntry]:
        self.purge_expired()
        rows = [
            self._refresh_ttl(entry)
            for entry in self._entries.values()
            if (
                not self._is_deleted(entry)
                and self._is_pending_review(entry)
                and entry.superseded_by is None
            )
        ]
        rows.sort(key=lambda item: item.created_at, reverse=True)
        selected = rows[:limit]
        self._audit(
            "memory.review_queue_list",
            {
                "limit": limit,
                "count": len(selected),
                "entry_ids": [entry.id for entry in selected],
            },
        )
        return selected

    def compile_identity(self, *, max_tokens: int = 750) -> IdentityPack:
        entries = self.list_entries(limit=max(1, len(self._entries)))
        return build_identity_pack(entries=entries, max_tokens=max_tokens)

    def compile_active_attention(
        self,
        *,
        max_tokens: int = 750,
        scope_filter: set[str] | None = None,
        allowed_channel_trusts: set[str] | None = None,
        channel_binding: str | None = None,
    ) -> ActiveAttentionPack:
        entries = self.list_entries(limit=max(1, len(self._entries)))
        return build_active_attention_pack(
            entries=entries,
            max_tokens=max_tokens,
            scope_filter=scope_filter,
            allowed_channel_trusts=allowed_channel_trusts,
            channel_binding=channel_binding,
        )

    def list_invocable_skills(
        self,
        *,
        query: str | None = None,
        limit: int = 100,
    ) -> list[ProceduralArtifactSummary]:
        self.purge_expired()
        normalized_query = (query or "").strip().lower()
        ranked: list[tuple[datetime, ProceduralArtifactSummary]] = []
        for entry in self._entries.values():
            if (
                entry.entry_type not in PROCEDURAL_ENTRY_TYPES
                or self._is_deleted(entry)
                or self._is_quarantined(entry)
                or self._is_pending_review(entry)
                or entry.superseded_by is not None
                or not entry.invocation_eligible
            ):
                continue
            refreshed = self._refresh_ttl(entry)
            summary = build_procedural_summary(refreshed)
            haystack = f"{summary.name}\n{summary.description}".lower()
            if normalized_query and normalized_query not in haystack:
                continue
            ranked.append((refreshed.last_cited_at or refreshed.created_at, summary))
        ranked.sort(key=lambda item: item[0], reverse=True)
        return [summary for _timestamp, summary in ranked[:limit]]

    def describe_skill(self, skill_id: str) -> ProceduralArtifact | None:
        entry, _reason = self._resolve_procedural_entry(skill_id)
        if entry is None:
            return None
        return build_procedural_artifact(entry)

    def invoke_skill(
        self,
        skill_id: str,
        *,
        audit_context: dict[str, Any] | None = None,
    ) -> ProceduralInvocation:
        caller_context = dict(audit_context or {})
        entry, reason = self._resolve_procedural_entry(skill_id)
        if entry is None:
            self._audit(
                "memory.skill_invoked",
                {
                    "skill_id": skill_id,
                    "entry_id": "",
                    "entry_type": "",
                    "found": False,
                    "invoked": False,
                    "reason": reason,
                    "trust_band": "",
                    "caller_context": caller_context,
                },
            )
            return ProceduralInvocation(
                skill_id=skill_id,
                found=False,
                invoked=False,
                reason=reason,
            )
        if not entry.invocation_eligible:
            self._audit(
                "memory.skill_invoked",
                {
                    "skill_id": skill_id,
                    "entry_id": entry.id,
                    "entry_type": str(entry.entry_type),
                    "found": True,
                    "invoked": False,
                    "reason": "skill_not_invocation_eligible",
                    "trust_band": str(entry.trust_band),
                    "caller_context": caller_context,
                },
            )
            return ProceduralInvocation(
                skill_id=skill_id,
                found=True,
                invoked=False,
                reason="skill_not_invocation_eligible",
            )

        timestamp = datetime.now(UTC)
        self.record_citations([entry.id], cited_at=timestamp)
        refreshed = self.get_entry(entry.id)
        if refreshed is None:
            refreshed = entry
        self._record_event(
            entry=refreshed,
            event_type="skill_invoked",
            ingress_handle_id=refreshed.ingress_handle_id,
            metadata={
                "skill_id": refreshed.id,
                "invoked_at": timestamp.isoformat(),
                "caller_context": caller_context,
                "entry_type": str(refreshed.entry_type),
            },
        )
        self._audit(
            "memory.skill_invoked",
            {
                "skill_id": skill_id,
                "entry_id": refreshed.id,
                "entry_type": str(refreshed.entry_type),
                "found": True,
                "invoked": True,
                "reason": "",
                "trust_band": str(refreshed.trust_band),
                "caller_context": caller_context,
            },
        )
        return ProceduralInvocation(
            skill_id=skill_id,
            found=True,
            invoked=True,
            artifact=build_procedural_artifact(refreshed),
        )

    def record_citations(
        self,
        entry_ids: list[str],
        *,
        cited_at: datetime | None = None,
    ) -> int:
        timestamp = cited_at or datetime.now(UTC)
        unique_entry_ids = [entry_id for entry_id in dict.fromkeys(entry_ids) if entry_id]
        changed = 0
        for entry_id in unique_entry_ids:
            entry = self._entries.get(entry_id)
            if entry is None or self._is_deleted(entry):
                continue
            entry.citation_count += 1
            entry.last_cited_at = timestamp
            self._persist_entry(entry)
            self._record_event(
                entry=entry,
                event_type="cited",
                ingress_handle_id=entry.ingress_handle_id,
                metadata={"cited_at": timestamp.isoformat()},
            )
            changed += 1
        if changed:
            self._audit(
                "memory.citations_recorded",
                {
                    "entry_ids": unique_entry_ids,
                    "count": changed,
                    "cited_at": timestamp.isoformat(),
                },
            )
        return changed

    def promote_identity_candidate(
        self,
        *,
        candidate_id: str,
        source: MemorySource,
        source_origin: SourceOrigin,
        channel_trust: ChannelTrust,
        confirmation_status: ConfirmationStatus,
        source_id: str,
        scope: str,
        ingress_handle_id: str,
        content_digest: str | None,
        taint_labels: list[TaintLabel] | None = None,
        value: Any | None = None,
    ) -> MemoryWriteDecision:
        candidate, reason = self._resolve_identity_candidate(candidate_id)
        if candidate is None:
            return MemoryWriteDecision(kind="reject", reason=reason)
        if confirmation_status not in {"user_confirmed", "user_corrected"}:
            return MemoryWriteDecision(
                kind="reject",
                reason="candidate_promotion_requires_user_confirmation",
            )

        promoted_value = candidate.value if value is None else value
        confidence_floor = 0.90 if confirmation_status == "user_confirmed" else 0.85
        decision = self.write_with_provenance(
            entry_type=candidate.entry_type,
            key=candidate.key,
            value=promoted_value,
            predicate=candidate.predicate,
            strength=candidate.strength,
            source=source,
            source_origin=source_origin,
            channel_trust=channel_trust,
            confirmation_status=confirmation_status,
            source_id=source_id,
            scope=scope,
            confidence=max(candidate.confidence, confidence_floor),
            confirmation_satisfied=True,
            taint_labels=list(taint_labels or []),
            ingress_handle_id=ingress_handle_id,
            content_digest=content_digest,
            supersedes=candidate.id,
        )
        if decision.kind != "allow" or decision.entry is None:
            return decision
        self._record_event(
            entry=decision.entry,
            event_type="candidate_promoted",
            ingress_handle_id=ingress_handle_id,
            metadata={
                "candidate_id": candidate.id,
                "confirmation_status": confirmation_status,
                "edited": promoted_value != candidate.value,
            },
        )
        self._audit(
            "memory.candidate_promoted",
            {
                "candidate_id": candidate.id,
                "entry_id": decision.entry.id,
                "confirmation_status": confirmation_status,
                "edited": promoted_value != candidate.value,
                "ingress_handle_id": ingress_handle_id,
            },
        )
        return decision

    def reject_identity_candidate(
        self,
        candidate_id: str,
        *,
        ingress_handle_id: str | None = None,
    ) -> tuple[bool, str]:
        candidate, reason = self._resolve_identity_candidate(candidate_id)
        if candidate is None:
            return False, reason
        candidate.deleted_at = datetime.now(UTC)
        candidate.status = "tombstoned"
        self._persist_entry(candidate)
        self._record_event(
            entry=candidate,
            event_type="tombstoned",
            ingress_handle_id=ingress_handle_id,
            metadata={
                "reason": "candidate_rejected",
                "workflow_state": candidate.workflow_state,
            },
        )
        backoff_key = candidate.predicate or candidate.key
        self._record_event(
            entry=candidate,
            event_type="candidate_rejected",
            ingress_handle_id=ingress_handle_id,
            metadata={"backoff_key": backoff_key},
        )
        self._audit(
            "memory.candidate_rejected",
            {
                "candidate_id": candidate.id,
                "backoff_key": backoff_key,
                "ingress_handle_id": ingress_handle_id,
            },
        )
        return True, "candidate_rejected"

    def note_identity_candidate_surface(
        self,
        candidate_id: str,
        *,
        surfaced_at: datetime | None = None,
    ) -> tuple[bool, int]:
        candidate, _reason = self._resolve_identity_candidate(candidate_id)
        if candidate is None:
            return False, 0
        timestamp = surfaced_at or datetime.now(UTC)
        surface_count = self._identity_candidate_surface_count(candidate.id) + 1
        self._record_event(
            entry=candidate,
            event_type="candidate_surfaced",
            ingress_handle_id=None,
            metadata={
                "surface_count": surface_count,
                "surfaced_at": timestamp.isoformat(),
            },
        )
        self._audit(
            "memory.candidate_surfaced",
            {
                "candidate_id": candidate.id,
                "surface_count": surface_count,
            },
        )
        return True, surface_count

    def expire_identity_candidate(
        self,
        candidate_id: str,
        *,
        ingress_handle_id: str | None = None,
    ) -> tuple[bool, str]:
        candidate, reason = self._resolve_identity_candidate(candidate_id)
        if candidate is None:
            return False, reason
        candidate.deleted_at = datetime.now(UTC)
        candidate.status = "tombstoned"
        self._persist_entry(candidate)
        surface_count = self._identity_candidate_surface_count(candidate.id)
        self._record_event(
            entry=candidate,
            event_type="tombstoned",
            ingress_handle_id=ingress_handle_id,
            metadata={
                "reason": "candidate_expired",
                "workflow_state": candidate.workflow_state,
            },
        )
        self._record_event(
            entry=candidate,
            event_type="candidate_expired",
            ingress_handle_id=ingress_handle_id,
            metadata={"surface_count": surface_count},
        )
        self._audit(
            "memory.candidate_expired",
            {
                "candidate_id": candidate.id,
                "surface_count": surface_count,
                "ingress_handle_id": ingress_handle_id,
            },
        )
        return True, "candidate_expired"

    def delete(self, entry_id: str) -> bool:
        entry = self._entries.get(entry_id)
        if entry is None:
            return False
        if self._is_deleted(entry):
            return True
        entry.deleted_at = datetime.now(UTC)
        entry.status = "tombstoned"
        self._persist_entry(entry)
        self._record_event(
            entry=entry,
            event_type="tombstoned",
            ingress_handle_id=entry.ingress_handle_id,
            metadata={"workflow_state": entry.workflow_state},
        )
        self._audit("memory.delete", {"entry_id": entry_id})
        return True

    def verify(self, entry_id: str) -> bool:
        entry = self._entries.get(entry_id)
        if entry is None:
            return False
        entry.user_verified = True
        entry.last_verified_at = datetime.now(UTC)
        self._persist_entry(entry)
        self._record_event(
            entry=entry,
            event_type="verified",
            ingress_handle_id=entry.ingress_handle_id,
            metadata={"last_verified_at": entry.last_verified_at.isoformat()},
        )
        self._audit("memory.verify", {"entry_id": entry_id})
        return True

    def export(self, *, fmt: str = "json") -> str:
        items = [entry.model_dump(mode="json") for entry in self.list_entries(include_deleted=True)]
        for item in items:
            item["value"] = self._redact_export_value(item.get("value"))
        if fmt == "json":
            return json.dumps(items, indent=2)
        if fmt == "csv":
            buffer = io.StringIO()
            writer = csv.DictWriter(
                buffer,
                fieldnames=[
                    "id",
                    "entry_type",
                    "key",
                    "value",
                    "origin",
                    "source_id",
                    "created_at",
                    "expires_at",
                    "user_verified",
                    "deleted_at",
                ],
            )
            writer.writeheader()
            for item in items:
                source = item.get("source", {})
                writer.writerow(
                    {
                        "id": item["id"],
                        "entry_type": item["entry_type"],
                        "key": item["key"],
                        "value": self._redact_export_value(item["value"]),
                        "origin": source.get("origin", ""),
                        "source_id": source.get("source_id", ""),
                        "created_at": item["created_at"],
                        "expires_at": item.get("expires_at"),
                        "user_verified": item["user_verified"],
                        "deleted_at": item.get("deleted_at"),
                    }
                )
            return buffer.getvalue()
        raise ValueError(f"Unsupported export format: {fmt}")

    def reset_storage(self) -> None:
        """Clear persisted memory rows without deleting the shared SQLite file."""
        self._entries.clear()
        with self._connect_db() as conn:
            conn.execute("DELETE FROM memory_entries")
        self._event_store.clear()
        for path in self._storage_dir.glob("*.json"):
            path.unlink(missing_ok=True)

    def quarantine(self, entry_id: str, *, reason: str) -> bool:
        entry = self._entries.get(entry_id)
        if entry is None:
            return False
        entry.quarantined = True
        entry.status = "quarantined"
        self._persist_entry(entry)
        self._record_event(
            entry=entry,
            event_type="quarantined",
            ingress_handle_id=entry.ingress_handle_id,
            metadata={"reason": reason, "workflow_state": entry.workflow_state},
        )
        self._audit("memory.quarantine", {"entry_id": entry_id, "reason": reason})
        return True

    def unquarantine(self, entry_id: str, *, reason: str) -> bool:
        entry = self._entries.get(entry_id)
        if entry is None or self._is_deleted(entry):
            return False
        if not self._is_quarantined(entry):
            return True
        if entry.superseded_by is not None or self._has_active_key_collision(entry):
            self._audit(
                "memory.unquarantine_blocked",
                {
                    "entry_id": entry_id,
                    "reason": reason,
                    "superseded_by": entry.superseded_by,
                },
            )
            return False
        entry.quarantined = False
        entry.status = "active"
        self._persist_entry(entry)
        self._record_event(
            entry=entry,
            event_type="unquarantined",
            ingress_handle_id=entry.ingress_handle_id,
            metadata={"reason": reason, "workflow_state": entry.workflow_state},
        )
        self._audit("memory.unquarantine", {"entry_id": entry_id, "reason": reason})
        return True

    def set_workflow_state(self, entry_id: str, workflow_state: WorkflowState) -> bool:
        entry = self._entries.get(entry_id)
        if entry is None or self._is_deleted(entry):
            return False
        if entry.entry_type not in ACTIVE_AGENDA_ENTRY_TYPES:
            raise ValueError("workflow_state only applies to active-agenda entry types")
        previous_state = entry.workflow_state
        if previous_state == workflow_state:
            return True
        entry.workflow_state = workflow_state
        self._persist_entry(entry)
        self._record_event(
            entry=entry,
            event_type="workflow_state_changed",
            ingress_handle_id=entry.ingress_handle_id,
            metadata={
                "from": previous_state,
                "to": workflow_state,
                "status": entry.status,
            },
        )
        self._audit(
            "memory.workflow_state_changed",
            {
                "entry_id": entry_id,
                "from": previous_state,
                "to": workflow_state,
                "status": entry.status,
            },
        )
        return True

    def purge_expired(self) -> None:
        now = datetime.now(UTC)
        for entry in self._entries.values():
            if self._is_deleted(entry):
                continue
            if entry.expires_at is not None and entry.expires_at < now:
                entry.deleted_at = now
                entry.status = "tombstoned"
                self._persist_entry(entry)
                self._record_event(
                    entry=entry,
                    event_type="tombstoned",
                    ingress_handle_id=entry.ingress_handle_id,
                    metadata={"reason": "expired", "workflow_state": entry.workflow_state},
                )
                self._audit("memory.expire", {"entry_id": entry.id})

    def _persist_entry(self, entry: MemoryEntry) -> None:
        with self._connect_db() as conn:
            self._upsert_entry(conn, entry)

    def _load_existing_entries(self) -> None:
        self._entries = {}
        with self._connect_db() as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    version,
                    supersedes,
                    superseded_by,
                    entry_type,
                    key,
                    value_json,
                    predicate,
                    strength,
                    source_json,
                    source_origin,
                    channel_trust,
                    confirmation_status,
                    source_id,
                    created_at,
                    valid_from,
                    valid_to,
                    last_verified_at,
                    expires_at,
                    confidence,
                    taint_labels_json,
                    citation_count,
                    last_cited_at,
                    decay_score,
                    importance_weight,
                    status,
                    workflow_state,
                    scope,
                    invocation_eligible,
                    ingress_handle_id,
                    content_digest,
                    user_verified,
                    deleted_at,
                    quarantined
                FROM memory_entries
                ORDER BY created_at ASC, id ASC
                """
            ).fetchall()
        for row in rows:
            try:
                entry = MemoryEntry.model_validate(
                    {
                        "id": str(row["id"]),
                        "version": int(row["version"]),
                        "supersedes": row["supersedes"],
                        "superseded_by": row["superseded_by"],
                        "entry_type": str(row["entry_type"]),
                        "key": str(row["key"]),
                        "value": json.loads(str(row["value_json"])),
                        "predicate": row["predicate"],
                        "strength": str(row["strength"]),
                        "source": json.loads(str(row["source_json"])),
                        "source_origin": str(row["source_origin"]),
                        "channel_trust": str(row["channel_trust"]),
                        "confirmation_status": str(row["confirmation_status"]),
                        "source_id": str(row["source_id"]),
                        "created_at": str(row["created_at"]),
                        "valid_from": row["valid_from"],
                        "valid_to": row["valid_to"],
                        "last_verified_at": row["last_verified_at"],
                        "expires_at": row["expires_at"],
                        "confidence": float(row["confidence"]),
                        "taint_labels": json.loads(str(row["taint_labels_json"])),
                        "citation_count": int(row["citation_count"]),
                        "last_cited_at": row["last_cited_at"],
                        "decay_score": float(row["decay_score"]),
                        "importance_weight": float(row["importance_weight"]),
                        "status": str(row["status"]),
                        "workflow_state": row["workflow_state"],
                        "scope": str(row["scope"]),
                        "invocation_eligible": bool(row["invocation_eligible"]),
                        "ingress_handle_id": row["ingress_handle_id"],
                        "content_digest": row["content_digest"],
                        "user_verified": bool(row["user_verified"]),
                        "deleted_at": row["deleted_at"],
                        "quarantined": bool(row["quarantined"]),
                    }
                )
            except (TypeError, ValueError, ValidationError, json.JSONDecodeError):
                continue
            self._entries[entry.id] = entry
        snapshots = self._event_store.latest_entry_snapshots()
        if not snapshots:
            return
        rebuilt_entries: list[MemoryEntry] = []
        for snapshot in snapshots:
            try:
                entry = MemoryEntry.model_validate(snapshot)
            except (TypeError, ValueError, ValidationError, json.JSONDecodeError):
                continue
            self._entries[entry.id] = entry
            rebuilt_entries.append(entry)
        if not rebuilt_entries:
            return
        with self._connect_db() as conn:
            for entry in rebuilt_entries:
                self._upsert_entry(conn, entry)

    def _connect_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_entry_schema(self) -> None:
        with self._connect_db() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_entries (
                    id TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    supersedes TEXT,
                    superseded_by TEXT,
                    entry_type TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    predicate TEXT,
                    strength TEXT NOT NULL DEFAULT 'moderate',
                    source_json TEXT NOT NULL,
                    source_origin TEXT NOT NULL,
                    channel_trust TEXT NOT NULL,
                    confirmation_status TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    valid_from TEXT,
                    valid_to TEXT,
                    last_verified_at TEXT,
                    expires_at TEXT,
                    confidence REAL NOT NULL,
                    taint_labels_json TEXT NOT NULL,
                    citation_count INTEGER NOT NULL,
                    last_cited_at TEXT,
                    decay_score REAL NOT NULL,
                    importance_weight REAL NOT NULL,
                    status TEXT NOT NULL,
                    workflow_state TEXT,
                    scope TEXT NOT NULL,
                    invocation_eligible INTEGER NOT NULL,
                    ingress_handle_id TEXT,
                    content_digest TEXT,
                    user_verified INTEGER NOT NULL,
                    deleted_at TEXT,
                    quarantined INTEGER NOT NULL
                )
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(memory_entries)")}
            if "predicate" not in columns:
                conn.execute("ALTER TABLE memory_entries ADD COLUMN predicate TEXT")
            if "strength" not in columns:
                conn.execute(
                    "ALTER TABLE memory_entries "
                    "ADD COLUMN strength TEXT NOT NULL DEFAULT 'moderate'"
                )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_memory_entries_type_created
                ON memory_entries (entry_type, created_at)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_memory_entries_status_created
                ON memory_entries (status, created_at)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_memory_entries_workflow_created
                ON memory_entries (workflow_state, created_at)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_memory_entries_trust
                ON memory_entries (source_origin, channel_trust, confirmation_status)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_memory_entries_scope_created
                ON memory_entries (scope, created_at)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_memory_entries_key_type
                ON memory_entries (entry_type, key)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_memory_entries_supersedes
                ON memory_entries (supersedes)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_memory_entries_superseded_by
                ON memory_entries (superseded_by)
                """
            )

    def _import_legacy_entry_files_if_needed(self) -> None:
        with self._connect_db() as conn:
            row = conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()
            existing = int(row[0]) if row is not None else 0
            if existing:
                return
            for path in sorted(self._storage_dir.glob("*.json")):
                try:
                    entry = MemoryEntry.model_validate_json(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, ValidationError):
                    continue
                self._upsert_entry(conn, entry)

    @staticmethod
    def _upsert_entry(conn: sqlite3.Connection, entry: MemoryEntry) -> None:
        payload = entry.model_dump(mode="json")
        conn.execute(
            """
            INSERT OR REPLACE INTO memory_entries (
                id,
                version,
                supersedes,
                superseded_by,
                entry_type,
                key,
                value_json,
                predicate,
                strength,
                source_json,
                source_origin,
                channel_trust,
                confirmation_status,
                source_id,
                created_at,
                valid_from,
                valid_to,
                last_verified_at,
                expires_at,
                confidence,
                taint_labels_json,
                citation_count,
                last_cited_at,
                decay_score,
                importance_weight,
                status,
                workflow_state,
                scope,
                invocation_eligible,
                ingress_handle_id,
                content_digest,
                user_verified,
                deleted_at,
                quarantined
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                payload["id"],
                payload["version"],
                payload["supersedes"],
                payload["superseded_by"],
                payload["entry_type"],
                payload["key"],
                json.dumps(payload["value"], sort_keys=True),
                payload["predicate"],
                payload["strength"],
                json.dumps(payload["source"], sort_keys=True),
                payload["source_origin"],
                payload["channel_trust"],
                payload["confirmation_status"],
                payload.get("source_id", ""),
                payload["created_at"],
                payload["valid_from"],
                payload["valid_to"],
                payload["last_verified_at"],
                payload["expires_at"],
                payload["confidence"],
                json.dumps(payload["taint_labels"], sort_keys=True),
                payload["citation_count"],
                payload["last_cited_at"],
                payload["decay_score"],
                payload["importance_weight"],
                payload["status"],
                payload["workflow_state"],
                payload["scope"],
                int(bool(payload["invocation_eligible"])),
                payload["ingress_handle_id"],
                payload["content_digest"],
                int(bool(payload["user_verified"])),
                payload["deleted_at"],
                int(bool(payload["quarantined"])),
            ),
        )

    def _record_event(
        self,
        *,
        entry: MemoryEntry,
        event_type: str,
        ingress_handle_id: str | None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        payload = dict(metadata or {})
        payload["entry_snapshot"] = entry.model_dump(mode="json")
        self._event_store.append(
            MemoryEvent(
                entry_id=entry.id,
                event_type=event_type,
                ingress_handle_id=ingress_handle_id,
                metadata_json=payload,
            )
        )

    def _refresh_ttl(self, entry: MemoryEntry) -> MemoryEntry:
        if entry.source.origin == "user":
            return entry
        if entry.expires_at is not None and not self._is_deleted(entry):
            entry.expires_at = datetime.now(UTC) + timedelta(days=self._default_ttl_days)
            self._persist_entry(entry)
        return entry

    def _resolve_identity_candidate(self, candidate_id: str) -> tuple[MemoryEntry | None, str]:
        candidate = self.get_entry(
            candidate_id,
            include_pending_review=True,
            include_quarantined=True,
        )
        if candidate is None:
            return None, "candidate_not_found"
        if self._is_deleted(candidate):
            return None, "candidate_not_found"
        if candidate.superseded_by is not None:
            return None, "candidate_already_resolved"
        if not self._is_pending_review(candidate):
            return None, "candidate_not_pending_review"
        if candidate.entry_type not in self._IDENTITY_ENTRY_TYPES:
            return None, "candidate_entry_type_invalid"
        return candidate, ""

    def _resolve_procedural_entry(self, skill_id: str) -> tuple[MemoryEntry | None, str]:
        entry = self.get_entry(skill_id)
        if entry is None:
            return None, "skill_not_found"
        if entry.entry_type not in PROCEDURAL_ENTRY_TYPES:
            return None, "skill_not_found"
        if entry.superseded_by is not None:
            return None, "skill_not_found"
        return entry, ""

    def _identity_candidate_surface_count(self, candidate_id: str) -> int:
        return len(
            self.list_events(
                entry_id=candidate_id,
                event_type="candidate_surfaced",
                limit=10,
            )
        )

    @staticmethod
    def _is_deleted(entry: MemoryEntry) -> bool:
        return entry.status in {"tombstoned", "hard_deleted"} or entry.deleted_at is not None

    @staticmethod
    def _is_quarantined(entry: MemoryEntry) -> bool:
        return entry.status == "quarantined" or entry.quarantined

    @staticmethod
    def _is_pending_review(entry: MemoryEntry) -> bool:
        return entry.confirmation_status == "pending_review"

    def _has_active_key_collision(self, entry: MemoryEntry) -> bool:
        for candidate in self.list_entries(
            entry_type=entry.entry_type,
            include_pending_review=True,
            limit=max(1, len(self._entries)),
        ):
            if (
                candidate.id == entry.id
                or candidate.superseded_by is not None
                or self._is_quarantined(candidate)
                or self._is_deleted(candidate)
            ):
                continue
            if candidate.key == entry.key:
                return True
        return False

    def _audit(self, action: str, payload: dict[str, Any]) -> None:
        if self._audit_hook is not None:
            self._audit_hook(action, payload)

    def _redact_export_value(self, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        redacted, _ = self._pii_detector.redact(value)
        return redacted

    @classmethod
    def _looks_instruction_like(cls, text: str) -> bool:
        lowered = text.lower()
        if "do not" in lowered and "instructions" in lowered:
            return True
        return any(pattern.search(text) for pattern in cls._INSTRUCTION_PATTERNS)

    @staticmethod
    def _looks_suspicious(text: str) -> bool:
        lowered = text.lower()
        suspicious_tokens = ("cc attacker", "exfiltrate", "bypass", "steal")
        return any(token in lowered for token in suspicious_tokens)

    @classmethod
    def _fails_minimum_signal(cls, *, key: str, value: Any) -> bool:
        if isinstance(value, (dict, list, tuple, set)):
            text = json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
        else:
            text = str(value)
        normalized = " ".join(text.split()).strip()
        if not normalized:
            return True
        lowered = normalized.lower().strip(" \t\r\n.,;:!?\"'")
        if not lowered:
            return True
        if lowered in cls._LOW_SIGNAL_PHRASES:
            return True

        tokens = [token.lower() for token in re.findall(r"[a-z0-9]+", lowered)]
        informative_tokens = [
            token
            for token in tokens
            if len(token) >= 3 and token not in cls._LOW_SIGNAL_TOKENS
        ]
        if len(informative_tokens) >= 2:
            return False
        if len(informative_tokens) == 1:
            token = informative_tokens[0]
            if len(token) >= 6:
                return False
            key_segments = [
                segment
                for segment in re.split(r"[._:-]+", key.lower())
                if segment and segment not in cls._GENERIC_KEY_SEGMENTS
            ]
            return not (len(token) >= 4 and bool(key_segments))
        return True
