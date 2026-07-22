"""Session transcript storage.

Append-only JSONL transcript per session. Large content blobs are stored
separately and referenced by hash from transcript entries.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from shisad.core.storage_platform import sync_parent_directory
from shisad.core.types import SessionId, TaintLabel

logger = logging.getLogger(__name__)


def derive_legacy_transcript_entry_id(
    *,
    session_id: SessionId | str,
    line_number: int,
    payload: Mapping[str, Any],
) -> str:
    """Derive a stable entry id for legacy transcript rows missing entry_id."""
    serialized_metadata = json.dumps(
        payload.get("metadata", {}),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    digest = hashlib.sha256(
        (
            f"{session_id}:{line_number}:"
            f"{payload.get('role', '')}:"
            f"{payload.get('content_hash', '')}:"
            f"{payload.get('timestamp', '')}:"
            f"{serialized_metadata}"
        ).encode()
    ).hexdigest()
    return f"tx-{digest[:32]}"


class TranscriptEntry(BaseModel):
    """A single transcript entry for a session."""

    entry_id: str = Field(default_factory=lambda: f"tx-{uuid.uuid4().hex}")
    role: str
    content_hash: str
    taint_labels: list[TaintLabel] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    blob_ref: str | None = None
    content_preview: str = ""
    evidence_ref_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TranscriptStore:
    """Append-only transcript store with content-addressed blob references."""

    def __init__(self, root_dir: Path, *, blob_threshold_bytes: int = 4096) -> None:
        self._root_dir = root_dir
        self._blob_threshold_bytes = blob_threshold_bytes
        self._append_observers: list[Callable[[SessionId, TranscriptEntry, str], None]] = []
        self._transcript_dir = root_dir / "transcripts"
        self._blob_dir = root_dir / "blobs"
        self._transcript_dir.mkdir(parents=True, exist_ok=True)
        self._blob_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_dir_permissions(self._transcript_dir)
        self._ensure_dir_permissions(self._blob_dir)

    def append(
        self,
        session_id: SessionId,
        *,
        role: str,
        content: str,
        taint_labels: set[TaintLabel] | None = None,
        metadata: dict[str, Any] | None = None,
        evidence_ref_id: str | None = None,
        timestamp: datetime | None = None,
        durable: bool = False,
    ) -> TranscriptEntry:
        """Append a transcript entry for a session."""
        raw = content.encode("utf-8")
        content_hash = hashlib.sha256(raw).hexdigest()
        entry_timestamp = self._normalize_timestamp(timestamp)
        entry_metadata = dict(metadata or {})
        entry_metadata["timestamp_utc"] = entry_timestamp.isoformat()
        if evidence_ref_id:
            entry_metadata.setdefault("evidence_ref_id", evidence_ref_id)

        blob_ref: str | None = None
        preview = content
        if len(raw) > self._blob_threshold_bytes:
            blob_ref = content_hash
            preview = content[:200]
            blob_path = self._blob_dir / f"{content_hash}.txt"
            if not blob_path.exists():
                blob_path.write_text(content)
            self._ensure_file_permissions(blob_path)
            if durable:
                self._sync_file(blob_path)
                sync_parent_directory(self._blob_dir)

        entry = TranscriptEntry(
            role=role,
            content_hash=content_hash,
            taint_labels=sorted(taint_labels or set()),
            timestamp=entry_timestamp,
            blob_ref=blob_ref,
            content_preview=preview,
            evidence_ref_id=evidence_ref_id,
            metadata=entry_metadata,
        )

        transcript_path = self._transcript_dir / f"{session_id}.jsonl"
        transcript_existed = transcript_path.exists()
        with transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(entry.model_dump_json() + "\n")
            if durable:
                handle.flush()
                os.fsync(handle.fileno())
        self._ensure_file_permissions(transcript_path)
        if durable and not transcript_existed:
            sync_parent_directory(self._transcript_dir)
        for observer in list(self._append_observers):
            try:
                observer(session_id, entry, content)
            except Exception:
                logger.exception(
                    "Transcript append observer failed for session %s entry %s",
                    session_id,
                    entry.entry_id,
                )

        return entry

    def add_append_observer(
        self,
        observer: Callable[[SessionId, TranscriptEntry, str], None],
    ) -> None:
        """Register a best-effort observer for append-time derived indexes."""
        self._append_observers.append(observer)

    def list_entries(self, session_id: SessionId) -> list[TranscriptEntry]:
        """Return transcript entries for a session."""
        path = self._transcript_dir / f"{session_id}.jsonl"
        if not path.exists():
            return []

        entries: list[TranscriptEntry] = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            payload = json.loads(line)
            if not isinstance(payload, dict):
                continue
            entry_id = str(payload.get("entry_id", "")).strip()
            if not entry_id:
                payload["entry_id"] = self._derive_legacy_entry_id(
                    session_id=session_id,
                    line_number=line_number,
                    payload=payload,
                )
            entries.append(TranscriptEntry.model_validate(payload))
        return entries

    def list_session_ids(self) -> list[SessionId]:
        """Return session ids that have persisted transcript rows."""
        if not self._transcript_dir.exists():
            return []
        session_ids: list[SessionId] = []
        for path in sorted(self._transcript_dir.glob("*.jsonl")):
            session_id = path.stem.strip()
            if session_id:
                session_ids.append(SessionId(session_id))
        return session_ids

    def truncate(self, session_id: SessionId, *, keep_entries: int) -> int:
        """Keep only the first ``keep_entries`` transcript rows for a session."""
        path = self._transcript_dir / f"{session_id}.jsonl"
        if not path.exists():
            return 0

        entries = self.list_entries(session_id)
        normalized_keep = max(0, int(keep_entries))
        if normalized_keep >= len(entries):
            return 0

        kept = entries[:normalized_keep]
        removed = len(entries) - len(kept)
        with path.open("w", encoding="utf-8") as handle:
            for entry in kept:
                handle.write(entry.model_dump_json() + "\n")
        self._ensure_file_permissions(path)
        return removed

    def delete_session(self, session_id: SessionId) -> None:
        path = self._transcript_dir / f"{session_id}.jsonl"
        with contextlib.suppress(OSError):
            path.unlink()

    def read_blob(self, content_hash: str) -> str | None:
        """Read a large blob by its content hash."""
        path = self._blob_dir / f"{content_hash}.txt"
        with contextlib.suppress(OSError, UnicodeError):
            return path.read_text(encoding="utf-8")
        return None

    def entry_content(self, entry: TranscriptEntry) -> str | None:
        content = self.read_blob(entry.blob_ref) if entry.blob_ref else entry.content_preview
        digest = hashlib.sha256(content.encode()).hexdigest() if content is not None else ""
        return (
            content
            if entry.blob_ref in {None, entry.content_hash} and digest == entry.content_hash
            else None
        )

    @staticmethod
    def _ensure_dir_permissions(path: Path) -> None:
        with contextlib.suppress(OSError):
            os.chmod(path, 0o700)

    @staticmethod
    def _ensure_file_permissions(path: Path) -> None:
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)

    @staticmethod
    def _sync_file(path: Path) -> None:
        with path.open("rb") as handle:
            os.fsync(handle.fileno())

    @staticmethod
    def _normalize_timestamp(timestamp: datetime | None) -> datetime:
        if timestamp is None:
            return datetime.now(UTC)
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=UTC)
        return timestamp.astimezone(UTC)

    @staticmethod
    def _derive_legacy_entry_id(
        *,
        session_id: SessionId,
        line_number: int,
        payload: dict[str, Any],
    ) -> str:
        return derive_legacy_transcript_entry_id(
            session_id=session_id,
            line_number=line_number,
            payload=payload,
        )
