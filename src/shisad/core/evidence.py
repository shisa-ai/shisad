"""Evidence reference storage for large tainted content."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from shisad.core.types import SessionId, TaintLabel
from shisad.security.firewall import ContentFirewall, SanitizationMode

_EVIDENCE_REF_PREFIX = "ev-"
_EVIDENCE_SUMMARY_MAX_CHARS = 200
_SUMMARY_INJECTION_RISK_THRESHOLD = 0.25
_HTML_LIKE_RE = re.compile(r"<[a-zA-Z][^>]{0,200}>")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")
_COOKIE_HINTS = ("cookie", "consent", "privacy", "gdpr", "banner")
_SKIP_TAGS = {"nav", "header", "footer", "script", "style", "noscript"}
_SEMANTIC_TAGS = {"article", "main", "p"}
_DEFAULT_EVIDENCE_MAX_AGE_SECONDS = 3600
_DEFAULT_ORPHAN_RETENTION_SECONDS = 7 * 24 * 3600
_EVIDENCE_METADATA_FILENAME = "refs_index.json"

logger = logging.getLogger(__name__)


class EvidenceRef(BaseModel):
    """Opaque reference to tainted content stored out-of-band."""

    ref_id: str
    content_hash: str
    taint_labels: list[TaintLabel] = Field(default_factory=list)
    source: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    summary: str
    byte_size: int
    ttl_seconds: int | None = None


@dataclass(frozen=True)
class _MetadataLoadResult:
    refs: dict[str, dict[str, EvidenceRef]]
    loaded_ok: bool
    dirty: bool = False


class _HTMLSummaryParser(HTMLParser):
    """Small HTML-to-text extractor tuned for summary generation."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._semantic_depth = 0
        self._semantic_chunks: list[str] = []
        self._fallback_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized = tag.lower().strip()
        attrs_dict = {key.lower(): (value or "") for key, value in attrs}
        marker_values = " ".join(
            value.lower() for key, value in attrs_dict.items() if key in {"id", "class", "role"}
        )
        if self._skip_depth > 0 or normalized in _SKIP_TAGS or any(
            hint in marker_values for hint in _COOKIE_HINTS
        ):
            self._skip_depth += 1
            return
        if normalized in _SEMANTIC_TAGS:
            self._semantic_depth += 1

    def handle_endtag(self, tag: str) -> None:
        normalized = tag.lower().strip()
        if self._skip_depth > 0:
            self._skip_depth -= 1
            return
        if normalized in _SEMANTIC_TAGS and self._semantic_depth > 0:
            self._semantic_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        text = " ".join(data.split()).strip()
        if not text:
            return
        if self._semantic_depth > 0:
            self._semantic_chunks.append(text)
        else:
            self._fallback_chunks.append(text)

    def extracted_text(self) -> str:
        semantic = " ".join(self._semantic_chunks).strip()
        if semantic:
            return semantic
        return " ".join(self._fallback_chunks).strip()


def _compact_whitespace(text: str) -> str:
    return " ".join(text.split()).strip()


def _looks_like_html(content: str) -> bool:
    snippet = content[:4096]
    return bool(_HTML_LIKE_RE.search(snippet))


def _html_to_text(content: str) -> str:
    parser = _HTMLSummaryParser()
    try:
        parser.feed(content)
        parser.close()
    except Exception:
        return _compact_whitespace(content)
    extracted = parser.extracted_text()
    return _compact_whitespace(extracted) if extracted else _compact_whitespace(content)


def _extractive_summary_sentences(content: str) -> list[str]:
    source_text = (
        _html_to_text(content)
        if _looks_like_html(content)
        else _compact_whitespace(content)
    )
    if not source_text:
        return []
    return [segment.strip() for segment in _SENTENCE_SPLIT_RE.split(source_text) if segment.strip()]


def _generic_summary(*, source: str, byte_size: int) -> str:
    return f"Content from {source}, {byte_size} bytes"


def _summary_requires_fallback(risk_score: float, risk_factors: list[str]) -> bool:
    if risk_score >= _SUMMARY_INJECTION_RISK_THRESHOLD:
        return True
    return bool(risk_factors)


def _generate_safe_summary(
    content: str,
    *,
    source: str,
    byte_size: int,
    firewall: ContentFirewall,
) -> str:
    """Generate an extractive summary that does not preserve obvious injections."""

    sentences = _extractive_summary_sentences(content)
    if not sentences:
        return _generic_summary(source=source, byte_size=byte_size)

    selected: list[str] = []
    safe_summary = ""
    for sentence in sentences[:3]:
        candidate = _compact_whitespace(" ".join([*selected, sentence]))
        if len(candidate) > _EVIDENCE_SUMMARY_MAX_CHARS:
            if not selected:
                candidate = sentence[:_EVIDENCE_SUMMARY_MAX_CHARS].rstrip()
            else:
                break
        inspected = firewall.inspect(
            candidate,
            mode=SanitizationMode.REWRITE,
            trusted_input=False,
        )
        if _summary_requires_fallback(inspected.risk_score, inspected.risk_factors):
            break
        safe_summary = _compact_whitespace(inspected.sanitized_text)[:_EVIDENCE_SUMMARY_MAX_CHARS]
        selected.append(sentence)
        if len(candidate) >= _EVIDENCE_SUMMARY_MAX_CHARS:
            break
    return safe_summary or _generic_summary(source=source, byte_size=byte_size)


def format_evidence_stub(ref: EvidenceRef) -> str:
    """Render a single-line evidence stub for transcript/context use."""

    summary = (
        ref.summary
        .replace("\\", "\\\\")
        .replace("]", "\\]")
        .replace('"', '\\"')
    )
    taint_value = ",".join(sorted(label.value.upper() for label in ref.taint_labels)) or "NONE"
    return (
        f'[EVIDENCE ref={ref.ref_id} source={ref.source} taint={taint_value} '
        f'size={ref.byte_size} summary="{summary}" '
        f'Use evidence.read("{ref.ref_id}") for full content, or '
        f'evidence.promote("{ref.ref_id}") to add it to the conversation.]'
    )


class EvidenceStore:
    """Out-of-band blob store + metadata index for evidence references."""

    def __init__(
        self,
        root_dir: Path,
        *,
        salt: bytes | None = None,
        default_max_age_seconds: int = _DEFAULT_EVIDENCE_MAX_AGE_SECONDS,
        orphan_retention_seconds: int = _DEFAULT_ORPHAN_RETENTION_SECONDS,
    ) -> None:
        self._root_dir = root_dir
        self._blob_dir = root_dir / "blobs"
        self._quarantine_dir = root_dir / "quarantine"
        self._metadata_path = root_dir / _EVIDENCE_METADATA_FILENAME
        self._salt_path = root_dir / "evidence_salt"
        self._default_max_age_seconds = max(1, int(default_max_age_seconds))
        self._orphan_retention_seconds = max(1, int(orphan_retention_seconds))
        self._root_dir.mkdir(parents=True, exist_ok=True)
        self._blob_dir.mkdir(parents=True, exist_ok=True)
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_dir_permissions(self._root_dir)
        self._ensure_dir_permissions(self._blob_dir)
        self._ensure_dir_permissions(self._quarantine_dir)
        self._salt = self._load_or_create_salt(salt)
        metadata_load = self._load_metadata_index()
        self._refs = metadata_load.refs
        metadata_ready_for_cleanup = metadata_load.loaded_ok
        if metadata_load.dirty:
            metadata_ready_for_cleanup = metadata_ready_for_cleanup and (
                self._try_persist_metadata_index(
                    "sanitizing persisted evidence metadata index"
                )
            )
        if metadata_ready_for_cleanup:
            self._quarantine_orphaned_blobs()
            self._prune_quarantine()

    def store(
        self,
        session_id: SessionId,
        content: str,
        *,
        taint_labels: set[TaintLabel] | list[TaintLabel],
        source: str,
        summary: str,
        ttl_seconds: int | None = None,
    ) -> EvidenceRef:
        self._evict_for_session(session_id)
        raw = content.encode("utf-8")
        content_hash = hashlib.sha256(raw).hexdigest()
        ref_id = self._make_ref_id(session_id=session_id, content_hash=content_hash)
        session_key = self._session_key(session_id)
        blob_path = self._blob_path(content_hash)
        existing = self._refs.setdefault(session_key, {}).get(ref_id)
        if existing is not None:
            if not blob_path.exists():
                blob_path.write_text(content, encoding="utf-8")
                self._ensure_file_permissions(blob_path)
            merged = self._merge_existing_ref(
                session_key=session_key,
                ref_id=ref_id,
                existing=existing,
                taint_labels=set(taint_labels),
                source=source,
                summary=summary,
                ttl_seconds=ttl_seconds,
            )
            self._persist_metadata_index()
            return merged

        if not blob_path.exists():
            blob_path.write_text(content, encoding="utf-8")
        self._ensure_file_permissions(blob_path)
        ref = EvidenceRef(
            ref_id=ref_id,
            content_hash=content_hash,
            taint_labels=sorted(set(taint_labels)),
            source=source,
            summary=summary,
            byte_size=len(raw),
            ttl_seconds=ttl_seconds,
        )
        self._refs[session_key][ref_id] = ref
        self._persist_metadata_index()
        return ref

    def read(self, session_id: SessionId, ref_id: str) -> str | None:
        ref = self.get_ref(session_id, ref_id)
        if ref is None:
            return None
        path = self._blob_path(ref.content_hash)
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8")

    def get_ref(self, session_id: SessionId, ref_id: str) -> EvidenceRef | None:
        self._evict_for_session(session_id)
        session_key = self._session_key(session_id)
        ref = self._refs.get(session_key, {}).get(ref_id)
        if ref is None:
            return None
        if not self._blob_path(ref.content_hash).exists():
            logger.warning(
                "Dropping evidence ref %s for session %s because blob %s is missing",
                ref_id,
                session_key,
                ref.content_hash,
            )
            self._drop_ref(session_key, ref_id)
            return None
        return ref

    def validate_ref_id(self, session_id: SessionId, ref_id: str) -> bool:
        ref = self.get_ref(session_id, ref_id)
        if ref is None:
            return False
        return hmac.compare_digest(
            ref.ref_id,
            self._make_ref_id(session_id=session_id, content_hash=ref.content_hash),
        )

    def evict_expired(
        self,
        session_id: SessionId,
        *,
        max_age_seconds: int = _DEFAULT_EVIDENCE_MAX_AGE_SECONDS,
        best_effort_persist: bool = False,
    ) -> list[str]:
        session_key = self._session_key(session_id)
        refs = self._refs.get(session_key)
        if not refs:
            return []

        now = datetime.now(UTC)
        evicted: list[str] = []
        for ref_id, ref in list(refs.items()):
            age_seconds = max(0.0, (now - ref.created_at).total_seconds())
            effective_max_age = self._effective_max_age_seconds(
                max_age_seconds=max_age_seconds,
                ttl_seconds=ref.ttl_seconds,
            )
            if age_seconds <= float(effective_max_age):
                continue
            refs.pop(ref_id, None)
            evicted.append(ref_id)
            self._delete_blob_if_unreferenced(ref.content_hash)
        if not refs:
            self._refs.pop(session_key, None)
        if evicted:
            if best_effort_persist:
                self._try_persist_metadata_index("persisting implicit evidence eviction")
            else:
                self._persist_metadata_index()
        return evicted

    def _make_ref_id(self, *, session_id: SessionId, content_hash: str) -> str:
        payload = f"{self._session_key(session_id)}:{content_hash}".encode()
        digest = hmac.new(self._salt, payload, hashlib.sha256).hexdigest()[:16]
        return f"{_EVIDENCE_REF_PREFIX}{digest}"

    def _load_or_create_salt(self, salt: bytes | None) -> bytes:
        if salt is not None:
            if not self._salt_path.exists():
                self._salt_path.write_bytes(salt)
            self._ensure_file_permissions(self._salt_path)
            return salt
        if self._salt_path.exists():
            self._ensure_file_permissions(self._salt_path)
            data = self._salt_path.read_bytes()
            if len(data) == 32:
                return data
        generated = os.urandom(32)
        self._salt_path.write_bytes(generated)
        self._ensure_file_permissions(self._salt_path)
        return generated

    def _delete_blob_if_unreferenced(self, content_hash: str) -> None:
        for session_refs in self._refs.values():
            for ref in session_refs.values():
                if ref.content_hash == content_hash:
                    return
        path = self._blob_path(content_hash)
        if path.exists():
            with contextlib.suppress(OSError):
                path.unlink()

    def _blob_path(self, content_hash: str) -> Path:
        return self._blob_dir / f"{content_hash}.txt"

    def _load_metadata_index(self) -> _MetadataLoadResult:
        if not self._metadata_path.exists():
            return _MetadataLoadResult(refs={}, loaded_ok=True)
        try:
            raw = json.loads(self._metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("Failed to load persisted evidence metadata index", exc_info=True)
            return _MetadataLoadResult(refs={}, loaded_ok=False)
        if not isinstance(raw, dict):
            logger.warning("Ignoring malformed evidence metadata index")
            return _MetadataLoadResult(refs={}, loaded_ok=False)

        loaded_ok = True
        dirty = False
        loaded: dict[str, dict[str, EvidenceRef]] = {}
        for session_key, session_refs_raw in raw.items():
            if not isinstance(session_key, str) or not isinstance(session_refs_raw, dict):
                dirty = True
                continue
            session_refs: dict[str, EvidenceRef] = {}
            for ref_id, ref_raw in session_refs_raw.items():
                if not isinstance(ref_id, str):
                    dirty = True
                    continue
                try:
                    ref = EvidenceRef.model_validate(ref_raw)
                except ValidationError:
                    dirty = True
                    logger.warning(
                        "Ignoring malformed persisted evidence ref %s for session %s",
                        ref_id,
                        session_key,
                        exc_info=True,
                    )
                    continue
                if ref.ref_id != ref_id:
                    dirty = True
                    logger.warning(
                        "Ignoring persisted evidence ref with mismatched id %s for session %s",
                        ref_id,
                        session_key,
                    )
                    continue
                if not self._blob_path(ref.content_hash).exists():
                    dirty = True
                    logger.warning(
                        (
                            "Dropping persisted evidence ref %s for session %s "
                            "because blob %s is missing"
                        ),
                        ref_id,
                        session_key,
                        ref.content_hash,
                    )
                    continue
                session_refs[ref_id] = ref
            if session_refs:
                loaded[session_key] = session_refs
        return _MetadataLoadResult(refs=loaded, loaded_ok=loaded_ok, dirty=dirty)

    def _persist_metadata_index(self) -> None:
        serialized = {
            session_key: {
                ref_id: ref.model_dump(mode="json")
                for ref_id, ref in session_refs.items()
            }
            for session_key, session_refs in self._refs.items()
            if session_refs
        }
        temp_path = self._metadata_path.with_suffix(".json.tmp")
        temp_path.write_text(
            json.dumps(serialized, ensure_ascii=True, sort_keys=True),
            encoding="utf-8",
        )
        self._ensure_file_permissions(temp_path)
        temp_path.replace(self._metadata_path)
        self._ensure_file_permissions(self._metadata_path)

    def _try_persist_metadata_index(self, reason: str) -> bool:
        try:
            self._persist_metadata_index()
        except OSError:
            logger.warning("Failed to persist evidence metadata while %s", reason, exc_info=True)
            return False
        return True

    def _quarantine_orphaned_blobs(self) -> None:
        referenced_hashes = {
            ref.content_hash
            for session_refs in self._refs.values()
            for ref in session_refs.values()
        }
        for blob_path in self._blob_dir.glob("*.txt"):
            if blob_path.stem in referenced_hashes:
                continue
            self._quarantine_blob(blob_path)

    def _quarantine_blob(self, blob_path: Path) -> None:
        destination = self._quarantine_dir / blob_path.name
        if destination.exists():
            with contextlib.suppress(OSError):
                destination.unlink()
        try:
            blob_path.replace(destination)
            os.utime(destination, None)
        except OSError:
            logger.warning(
                "Failed to quarantine orphaned evidence blob %s",
                blob_path,
                exc_info=True,
            )
            return
        self._ensure_file_permissions(destination)

    def _prune_quarantine(self) -> None:
        now = datetime.now(UTC).timestamp()
        for blob_path in self._quarantine_dir.glob("*.txt"):
            try:
                age_seconds = max(0.0, now - blob_path.stat().st_mtime)
            except OSError:
                continue
            if age_seconds <= float(self._orphan_retention_seconds):
                continue
            with contextlib.suppress(OSError):
                blob_path.unlink()

    def _drop_ref(self, session_key: str, ref_id: str) -> None:
        refs = self._refs.get(session_key)
        if not refs or ref_id not in refs:
            return
        refs.pop(ref_id, None)
        if not refs:
            self._refs.pop(session_key, None)
        self._try_persist_metadata_index("dropping missing-blob evidence ref")

    def _evict_for_session(self, session_id: SessionId) -> None:
        self.evict_expired(
            session_id,
            max_age_seconds=self._default_max_age_seconds,
            best_effort_persist=True,
        )

    def _merge_existing_ref(
        self,
        *,
        session_key: str,
        ref_id: str,
        existing: EvidenceRef,
        taint_labels: set[TaintLabel],
        source: str,
        summary: str,
        ttl_seconds: int | None,
    ) -> EvidenceRef:
        merged = existing.model_copy(
            update={
                "taint_labels": sorted({*existing.taint_labels, *taint_labels}),
                "source": source or existing.source,
                "summary": summary or existing.summary,
                "ttl_seconds": self._merge_ttl_seconds(existing.ttl_seconds, ttl_seconds),
            }
        )
        self._refs[session_key][ref_id] = merged
        return merged

    @staticmethod
    def _effective_max_age_seconds(*, max_age_seconds: int, ttl_seconds: int | None) -> int:
        effective = max(1, int(max_age_seconds))
        if ttl_seconds is None:
            return effective
        return min(effective, max(1, int(ttl_seconds)))

    @staticmethod
    def _merge_ttl_seconds(existing: int | None, new: int | None) -> int | None:
        if existing is None:
            return new
        if new is None:
            return existing
        return min(existing, new)

    @staticmethod
    def _ensure_dir_permissions(path: Path) -> None:
        with contextlib.suppress(OSError):
            os.chmod(path, 0o700)

    @staticmethod
    def _ensure_file_permissions(path: Path) -> None:
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)

    @staticmethod
    def _session_key(session_id: SessionId) -> str:
        return str(session_id).strip()
