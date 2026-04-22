"""Long-term memory manager with write gating and TTL handling."""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

from pydantic import ValidationError

from shisad.core.types import TaintLabel
from shisad.memory.remap import resolve_legacy_source_origin
from shisad.memory.schema import MemoryEntry, MemorySource, MemoryWriteDecision
from shisad.memory.trust import (
    ChannelTrust,
    ConfirmationStatus,
    SourceOrigin,
    backfill_legacy_triple,
    clamp_confidence,
)
from shisad.security.firewall.pii import PIIDetector


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
        self._entries: dict[str, MemoryEntry] = {}
        self._default_ttl_days = default_ttl_days
        self._audit_hook = audit_hook
        self._pii_detector = pii_detector or PIIDetector()
        self._load_existing_entries()

    def write(
        self,
        *,
        entry_type: str,
        key: str,
        value: Any,
        source: MemorySource,
        confidence: float = 0.5,
        user_confirmed: bool = False,
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
            source=source,
            source_origin=source_origin,
            channel_trust=channel_trust,
            confirmation_status=confirmation_status,
            source_id=source.source_id,
            scope="user",
            confidence=confidence,
            confirmation_satisfied=user_confirmed,
        )

    def write_with_provenance(
        self,
        *,
        entry_type: str,
        key: str,
        value: Any,
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
    ) -> MemoryWriteDecision:
        text_value = str(value)
        if self._looks_instruction_like(text_value):
            return MemoryWriteDecision(
                kind="reject",
                reason="instruction_like_content_blocked",
            )

        if source.origin == "external" and not confirmation_satisfied:
            return MemoryWriteDecision(
                kind="require_confirmation",
                reason="external_origin_requires_confirmation",
            )

        suspicious = self._looks_suspicious(text_value)
        if suspicious and not confirmation_satisfied:
            return MemoryWriteDecision(
                kind="require_confirmation",
                reason="suspicious_memory_write_requires_confirmation",
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
        entry = MemoryEntry(
            entry_type=entry_type,
            key=key,
            value=stored_value,
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
        )
        self._entries[entry.id] = entry
        self._persist_entry(entry)
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
            rows.append(self._refresh_ttl(entry))
        rows.sort(key=lambda item: item.created_at, reverse=True)
        return rows[:limit]

    def get_entry(self, entry_id: str) -> MemoryEntry | None:
        self.purge_expired()
        entry = self._entries.get(entry_id)
        if entry is None or self._is_deleted(entry):
            return None
        if self._is_quarantined(entry):
            return None
        return self._refresh_ttl(entry)

    def delete(self, entry_id: str) -> bool:
        entry = self._entries.get(entry_id)
        if entry is None:
            return False
        if self._is_deleted(entry):
            return True
        entry.deleted_at = datetime.now(UTC)
        entry.status = "tombstoned"
        self._persist_entry(entry)
        self._audit("memory.delete", {"entry_id": entry_id})
        return True

    def verify(self, entry_id: str) -> bool:
        entry = self._entries.get(entry_id)
        if entry is None:
            return False
        entry.user_verified = True
        entry.last_verified_at = datetime.now(UTC)
        self._persist_entry(entry)
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

    def quarantine(self, entry_id: str, *, reason: str) -> bool:
        entry = self._entries.get(entry_id)
        if entry is None:
            return False
        entry.quarantined = True
        entry.status = "quarantined"
        self._persist_entry(entry)
        self._audit("memory.quarantine", {"entry_id": entry_id, "reason": reason})
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
                self._audit("memory.expire", {"entry_id": entry.id})

    def _persist_entry(self, entry: MemoryEntry) -> None:
        path = self._storage_dir / f"{entry.id}.json"
        path.write_text(entry.model_dump_json(indent=2))

    def _load_existing_entries(self) -> None:
        for path in sorted(self._storage_dir.glob("*.json")):
            try:
                entry = MemoryEntry.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValidationError):
                continue
            self._entries[entry.id] = entry

    def _refresh_ttl(self, entry: MemoryEntry) -> MemoryEntry:
        if entry.source.origin == "user":
            return entry
        if entry.expires_at is not None and not self._is_deleted(entry):
            entry.expires_at = datetime.now(UTC) + timedelta(days=self._default_ttl_days)
            self._persist_entry(entry)
        return entry

    @staticmethod
    def _is_deleted(entry: MemoryEntry) -> bool:
        return entry.status in {"tombstoned", "hard_deleted"} or entry.deleted_at is not None

    @staticmethod
    def _is_quarantined(entry: MemoryEntry) -> bool:
        return entry.status == "quarantined" or entry.quarantined

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
