"""Session transcript storage.

Append-only JSONL transcript per session. Large content blobs are stored
separately and referenced by hash from transcript entries.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from shisad.core.types import SessionId, TaintLabel


class TranscriptEntry(BaseModel):
    """A single transcript entry for a session."""

    role: str
    content_hash: str
    taint_labels: list[TaintLabel] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    blob_ref: str | None = None
    content_preview: str = ""


class TranscriptStore:
    """Append-only transcript store with content-addressed blob references."""

    def __init__(self, root_dir: Path, *, blob_threshold_bytes: int = 4096) -> None:
        self._root_dir = root_dir
        self._blob_threshold_bytes = blob_threshold_bytes
        self._transcript_dir = root_dir / "transcripts"
        self._blob_dir = root_dir / "blobs"
        self._transcript_dir.mkdir(parents=True, exist_ok=True)
        self._blob_dir.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        session_id: SessionId,
        *,
        role: str,
        content: str,
        taint_labels: set[TaintLabel] | None = None,
    ) -> TranscriptEntry:
        """Append a transcript entry for a session."""
        raw = content.encode("utf-8")
        content_hash = hashlib.sha256(raw).hexdigest()

        blob_ref: str | None = None
        preview = content
        if len(raw) > self._blob_threshold_bytes:
            blob_ref = content_hash
            preview = content[:200]
            blob_path = self._blob_dir / f"{content_hash}.txt"
            if not blob_path.exists():
                blob_path.write_text(content)

        entry = TranscriptEntry(
            role=role,
            content_hash=content_hash,
            taint_labels=sorted(taint_labels or set()),
            blob_ref=blob_ref,
            content_preview=preview,
        )

        transcript_path = self._transcript_dir / f"{session_id}.jsonl"
        with transcript_path.open("a", encoding="utf-8") as handle:
            handle.write(entry.model_dump_json() + "\n")

        return entry

    def list_entries(self, session_id: SessionId) -> list[TranscriptEntry]:
        """Return transcript entries for a session."""
        path = self._transcript_dir / f"{session_id}.jsonl"
        if not path.exists():
            return []

        entries: list[TranscriptEntry] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entries.append(TranscriptEntry.model_validate_json(line))
        return entries

    def read_blob(self, content_hash: str) -> str | None:
        """Read a large blob by its content hash."""
        path = self._blob_dir / f"{content_hash}.txt"
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8")
