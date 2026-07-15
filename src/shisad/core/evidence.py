"""Evidence reference storage for large tainted content."""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from html.parser import HTMLParser
from http.client import InvalidURL
from pathlib import Path
from threading import Lock, RLock, Thread
from types import MappingProxyType
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteFaultInjector,
    AtomicWriteStage,
    StateLoadResult,
    StateLoadStatus,
    StatePersistenceDegradedError,
    atomic_write_bytes,
    decode_versioned_json_snapshot,
    encode_versioned_json_snapshot,
)
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
_EVIDENCE_INDEX_VERSION = 1
_CONTENT_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN_PROBE_KEY = ("__evidence_domain__", "__evidence_domain__")
_QUARANTINE_NAME_RE = re.compile(
    r"^v1\.(?P<timestamp_ns>[0-9]+)\.(?P<nonce>[0-9a-f]{32})\."
    r"(?P<content_hash>[0-9a-f]{64})\.txt$"
)
logger = logging.getLogger(__name__)


class ArtifactLifecycleState(StrEnum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"


class ArtifactEndorsementState(StrEnum):
    UNENDORSED = "unendorsed"
    USER_ENDORSED = "user_endorsed"
    SYSTEM_ENDORSED = "system_endorsed"


class ArtifactBlobCodec(Protocol):
    """Artifact blob encoding/decoding boundary."""

    name: str

    def encode(self, content: str) -> bytes: ...

    def decode(self, payload: bytes) -> str: ...


@dataclass(frozen=True)
class PlaintextArtifactBlobCodec:
    """Default artifact codec: plaintext on local disk."""

    name: str = "plaintext"

    def encode(self, content: str) -> bytes:
        return content.encode("utf-8")

    def decode(self, payload: bytes) -> str:
        return payload.decode("utf-8")


class ArtifactBlobCodecError(Exception):
    """Artifact blob codec failed without proving local blob corruption."""


@dataclass(frozen=True)
class KmsArtifactBlobCodec:
    """Remote key-boundary codec for ArtifactLedger blob payloads."""

    endpoint_url: str
    bearer_token: str = ""
    timeout_seconds: float = 10.0
    name: str = "kms_encrypted_v1"

    def encode(self, content: str) -> bytes:
        return self._request("encrypt", content.encode("utf-8"))

    def decode(self, payload: bytes) -> str:
        try:
            plaintext = self._request("decrypt", payload)
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ArtifactBlobCodecError("artifact_kms_invalid_plaintext") from exc

    def _request(self, operation: str, payload: bytes) -> bytes:
        endpoint_url = self.endpoint_url.strip()
        if not endpoint_url:
            raise ArtifactBlobCodecError("artifact_kms_unconfigured")
        request_payload = {
            "schema_version": "shisad.artifact_crypt.v1",
            "operation": operation,
            "artifact_kind": "evidence",
            "payload_b64": base64.b64encode(payload).decode("ascii"),
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        token = self.bearer_token.strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            request = Request(
                endpoint_url,
                data=json.dumps(request_payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
        except (InvalidURL, ValueError) as exc:
            raise ArtifactBlobCodecError("artifact_kms_invalid_url") from exc

        try:
            with urlopen(request, timeout=max(0.1, float(self.timeout_seconds))) as response:
                response_bytes = response.read()
        except HTTPError as exc:
            reason = "artifact_kms_http_error"
            with contextlib.suppress(Exception):
                response_body = json.loads(exc.read().decode("utf-8"))
                if isinstance(response_body, dict):
                    reason = str(
                        response_body.get("reason") or response_body.get("error") or reason
                    )
            raise ArtifactBlobCodecError(reason) from exc
        except URLError as exc:
            raise ArtifactBlobCodecError("artifact_kms_unreachable") from exc
        except TimeoutError as exc:
            raise ArtifactBlobCodecError("artifact_kms_timeout") from exc
        except ValueError as exc:
            raise ArtifactBlobCodecError("artifact_kms_invalid_url") from exc
        except OSError as exc:
            raise ArtifactBlobCodecError("artifact_kms_invalid_response") from exc

        try:
            response_body = json.loads(response_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArtifactBlobCodecError("artifact_kms_invalid_response") from exc

        if not isinstance(response_body, dict):
            raise ArtifactBlobCodecError("artifact_kms_invalid_response")
        status = str(response_body.get("status", "")).strip().lower()
        if status != "ok":
            reason = str(response_body.get("reason", "")).strip() or "artifact_kms_error"
            raise ArtifactBlobCodecError(reason)
        payload_b64 = str(response_body.get("payload_b64", "")).strip()
        if not payload_b64:
            raise ArtifactBlobCodecError("artifact_kms_invalid_response")
        try:
            return base64.b64decode(payload_b64.encode("ascii"), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ArtifactBlobCodecError("artifact_kms_invalid_response") from exc

    @staticmethod
    def request_schema_version() -> str:
        return "shisad.artifact_crypt.v1"


class EvidenceRef(BaseModel):
    """Opaque reference to tainted content stored out-of-band."""

    model_config = ConfigDict(frozen=True)

    ref_id: str
    content_hash: str
    taint_labels: tuple[TaintLabel, ...] = Field(default_factory=tuple)
    source: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    summary: str
    byte_size: int
    ttl_seconds: int | None = None
    artifact_kind: str = "evidence"
    lifecycle_state: ArtifactLifecycleState = ArtifactLifecycleState.ACTIVE
    endorsement_state: ArtifactEndorsementState = ArtifactEndorsementState.UNENDORSED
    endorsed_at: datetime | None = None
    endorsed_by: str = ""
    storage_codec: str = "plaintext"
    metadata_mac: str = ""

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> EvidenceRef:
        """Copy through validation so collection updates cannot stay mutable."""

        values = self.model_dump(mode="python")
        values.update(update or {})
        return type(self).model_validate(values)


@dataclass(frozen=True, slots=True)
class _CommittedEvidenceView:
    """Atomically replaceable, deeply immutable metadata read boundary."""

    refs: Mapping[str, Mapping[str, EvidenceRef]]
    state_load_result: StateLoadResult
    cleanup_allowed: bool
    salt: bytes
    unreadable_refs: frozenset[tuple[str, str]]


@dataclass(frozen=True)
class _BlobLoadResult:
    content: str | None
    failure_reason: str = ""
    drop_ref: bool = False


@dataclass(frozen=True)
class _UnreadableRefState:
    reason: str


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
        if (
            self._skip_depth > 0
            or normalized in _SKIP_TAGS
            or any(hint in marker_values for hint in _COOKIE_HINTS)
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
        _html_to_text(content) if _looks_like_html(content) else _compact_whitespace(content)
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

    summary = ref.summary.replace("\\", "\\\\").replace("]", "\\]").replace('"', '\\"')
    taint_value = ",".join(sorted(label.value.upper() for label in ref.taint_labels)) or "NONE"
    return (
        f"[EVIDENCE ref={ref.ref_id} source={ref.source} taint={taint_value} "
        f'size={ref.byte_size} summary="{summary}" '
        f'Use evidence.read("{ref.ref_id}") for full content, or '
        f'evidence.promote("{ref.ref_id}") to add it to the conversation.]'
    )


class ArtifactLedger:
    """Durable evidence domain with retained corruption and bounded degradation."""

    def __init__(
        self,
        root_dir: Path,
        *,
        salt: bytes | None = None,
        default_max_age_seconds: int = _DEFAULT_EVIDENCE_MAX_AGE_SECONDS,
        orphan_retention_seconds: int = _DEFAULT_ORPHAN_RETENTION_SECONDS,
        blob_codec: ArtifactBlobCodec | None = None,
    ) -> None:
        self._root_dir = Path(root_dir)
        self._blob_dir = self._root_dir / "blobs"
        self._quarantine_dir = self._root_dir / "quarantine"
        self._metadata_path = self._root_dir / _EVIDENCE_METADATA_FILENAME
        self._salt_path = self._root_dir / "evidence_salt"
        self._default_max_age_seconds = max(1, int(default_max_age_seconds))
        self._orphan_retention_seconds = max(1, int(orphan_retention_seconds))
        self._blob_codec = blob_codec or PlaintextArtifactBlobCodec()
        self._lock = RLock()
        self._atomic_fault_injector: AtomicWriteFaultInjector | None = None
        self._salt = b"\x00" * 32
        self._refs: dict[str, dict[str, EvidenceRef]] = {}
        self._temporarily_unreadable_refs: dict[str, dict[str, _UnreadableRefState]] = {}
        self._unreadable_probe_in_flight: set[tuple[str, str]] = set()
        self._unreadable_probe_guard = Lock()
        self._state_load_result = StateLoadResult(
            StateLoadStatus.CORRUPT,
            reason="uninitialized",
        )
        self._cleanup_allowed = False
        self._committed_view = _CommittedEvidenceView(
            refs=MappingProxyType({}),
            state_load_result=self._state_load_result,
            cleanup_allowed=False,
            salt=self._salt,
            unreadable_refs=frozenset(),
        )
        with self._lock:
            self._initialize_domain(configured_salt=salt)

    @property
    def state_degraded(self) -> bool:
        return self._committed_view.state_load_result.status is not StateLoadStatus.OK

    @property
    def cleanup_allowed(self) -> bool:
        return self._committed_view.cleanup_allowed

    def state_load_result(self) -> StateLoadResult:
        return self._committed_view.state_load_result

    def state_status(self) -> dict[str, object]:
        view = self._committed_view
        result = view.state_load_result
        degraded = result.status is not StateLoadStatus.OK
        problems = [result.reason or result.status.value] if degraded else []
        return {
            "status": "degraded" if degraded else "ok",
            "scope": "evidence_only",
            "problems": problems,
            "fail_closed": degraded,
            "cleanup_allowed": view.cleanup_allowed,
            "load_status": result.status.value,
            "reason": result.reason,
            "schema_version": result.schema_version,
            "legacy": result.legacy,
            "committed_ref_count": sum(len(refs) for refs in view.refs.values()),
            "remediation": (
                "Restore the exact evidence_salt, refs_index.json, and referenced blobs, "
                "or use an explicitly authorized evidence-domain reset boundary."
                if degraded
                else ""
            ),
        }

    def committed_ref_count(self) -> int:
        return sum(len(refs) for refs in self._committed_view.refs.values())

    def domain_file_count(self) -> int:
        """Return the number of regular files in the evidence domain."""

        with self._lock:
            if not self._root_dir.exists() or not self._root_dir.is_dir():
                return 0
            try:
                return sum(1 for path in self._root_dir.rglob("*") if path.is_file())
            except OSError:
                return 0

    def domain_reset_inspection(self) -> tuple[int, int]:
        """Return reset counts under the ledger lock for worker-thread callers."""

        with self._lock:
            return self.committed_ref_count(), self.domain_file_count()

    def is_empty_domain(self) -> bool:
        """Return whether the durable evidence domain is healthy and empty."""

        with self._lock:
            if self.state_degraded or self.committed_ref_count() != 0:
                return False
            if not self._metadata_path.is_file() or not self._salt_path.is_file():
                return False
            try:
                return not any(self._blob_dir.iterdir()) and not any(
                    self._quarantine_dir.iterdir()
                )
            except OSError:
                return False

    def store(
        self,
        session_id: SessionId,
        content: str,
        *,
        taint_labels: set[TaintLabel] | list[TaintLabel],
        source: str,
        summary: str,
        ttl_seconds: int | None = None,
        artifact_kind: str = "evidence",
        lifecycle_state: ArtifactLifecycleState = ArtifactLifecycleState.ACTIVE,
    ) -> EvidenceRef:
        with self._lock:
            self._require_writable("store")
            raw = content.encode("utf-8")
            content_hash = hashlib.sha256(raw).hexdigest()
            ref_id = self._make_ref_id(session_id=session_id, content_hash=content_hash)
            session_key = self._session_key(session_id)
            blob_path = self._blob_path(content_hash)
            existing = self._refs.get(session_key, {}).get(ref_id)
            rewrote_blob = False
            if existing is not None:
                blob_load = self._load_validated_blob_content(existing)
                rewrote_blob = blob_load.content is None and blob_load.drop_ref
            if not blob_path.exists() or rewrote_blob:
                try:
                    self._atomic_write(blob_path, self._blob_codec.encode(content))
                except (ArtifactBlobCodecError, AtomicWriteError):
                    self._mark_runtime_degraded("blob_publication_failed")
                    raise

            candidate = self._copy_refs(self._refs)
            session_refs = candidate.setdefault(session_key, {})
            if existing is not None:
                ref = self._merged_ref(
                    session_key=session_key,
                    existing=existing,
                    taint_labels=set(taint_labels),
                    source=source,
                    summary=summary,
                    ttl_seconds=ttl_seconds,
                    artifact_kind=artifact_kind,
                    lifecycle_state=lifecycle_state,
                    storage_codec=self._blob_codec.name if rewrote_blob else None,
                )
            else:
                ref = EvidenceRef(
                    ref_id=ref_id,
                    content_hash=content_hash,
                    taint_labels=sorted(set(taint_labels)),
                    source=source,
                    summary=summary,
                    byte_size=len(raw),
                    ttl_seconds=ttl_seconds,
                    artifact_kind=artifact_kind,
                    lifecycle_state=lifecycle_state,
                    endorsement_state=ArtifactEndorsementState.UNENDORSED,
                    storage_codec=self._blob_codec.name,
                )
                ref = self._stamp_metadata_mac(session_key, ref)
            session_refs[ref_id] = ref
            self._commit_candidate(candidate, transition="store")
            return ref

    def read(self, session_id: SessionId, ref_id: str) -> str | None:
        ref, content = self.resolve_ref_content(session_id, ref_id)
        if ref is None or content is None:
            return None
        return content

    def get_ref(self, session_id: SessionId, ref_id: str) -> EvidenceRef | None:
        ref, _ = self.resolve_ref_content(session_id, ref_id)
        return ref

    def get_ref_metadata(self, session_id: SessionId, ref_id: str) -> EvidenceRef | None:
        view = self._committed_view
        if view.state_load_result.status is not StateLoadStatus.OK:
            return None
        session_key = self._session_key(session_id)
        ref = view.refs.get(session_key, {}).get(ref_id)
        if ref is None:
            return None
        if (session_key, ref_id) in view.unreadable_refs:
            return None
        if self._is_expired(ref, max_age_seconds=self._default_max_age_seconds):
            return None
        return ref

    def resolve_ref_content(
        self,
        session_id: SessionId,
        ref_id: str,
    ) -> tuple[EvidenceRef | None, str | None]:
        with self._lock:
            return self._resolve_valid_ref(session_id, ref_id)

    def _resolve_valid_ref(
        self,
        session_id: SessionId,
        ref_id: str,
    ) -> tuple[EvidenceRef | None, str | None]:
        if self.state_degraded:
            if self._state_load_result.reason == "blob_unreadable":
                self._maybe_probe_temporarily_unreadable(session_id, ref_id)
            return None, None
        session_key = self._session_key(session_id)
        ref = self._refs.get(session_key, {}).get(ref_id)
        if ref is None:
            self._clear_temporarily_unreadable(session_key, ref_id)
            return None, None
        if self._is_expired(ref, max_age_seconds=self._default_max_age_seconds):
            self._drop_ref(session_key, ref_id)
            return None, None
        if ref.lifecycle_state != ArtifactLifecycleState.ACTIVE:
            return None, None
        blob_load = self._load_validated_blob_content(ref)
        if blob_load.content is None:
            if blob_load.drop_ref:
                logger.warning(
                    "Dropping evidence ref %s for session %s because %s",
                    ref_id,
                    session_key,
                    blob_load.failure_reason,
                )
                self._drop_ref(session_key, ref_id)
            else:
                self._mark_temporarily_unreadable(session_key, ref_id, blob_load.failure_reason)
            return None, None
        self._clear_temporarily_unreadable(session_key, ref_id)
        return ref, blob_load.content

    def validate_ref_id(self, session_id: SessionId, ref_id: str) -> bool:
        with self._lock:
            ref = self.get_ref(session_id, ref_id)
            if ref is None:
                return False
            return hmac.compare_digest(
                ref.ref_id,
                self._make_ref_id(session_id=session_id, content_hash=ref.content_hash),
            )

    def validate_ref_metadata(self, session_id: SessionId, ref_id: str) -> bool:
        view = self._committed_view
        if view.state_load_result.status is not StateLoadStatus.OK:
            if view.state_load_result.reason == "blob_unreadable":
                self._maybe_probe_temporarily_unreadable(session_id, ref_id)
            return False
        session_key = self._session_key(session_id)
        ref = view.refs.get(session_key, {}).get(ref_id)
        if ref is None or ref.lifecycle_state != ArtifactLifecycleState.ACTIVE:
            return False
        if self._is_expired(ref, max_age_seconds=self._default_max_age_seconds):
            return False
        if (session_key, ref_id) in view.unreadable_refs:
            self._maybe_probe_temporarily_unreadable(session_id, ref_id)
            return False
        return hmac.compare_digest(
            ref.ref_id,
            self._make_ref_id_with_salt(
                session_id=session_id,
                content_hash=ref.content_hash,
                salt=view.salt,
            ),
        )

    def evict_expired(
        self,
        session_id: SessionId,
        *,
        max_age_seconds: int = _DEFAULT_EVIDENCE_MAX_AGE_SECONDS,
        best_effort_persist: bool = False,
    ) -> list[str]:
        with self._lock:
            if self.state_degraded:
                return []
            session_key = self._session_key(session_id)
            session_refs = self._refs.get(session_key, {})
            evicted = [
                ref_id
                for ref_id, ref in session_refs.items()
                if self._is_expired(ref, max_age_seconds=max_age_seconds)
            ]
            if not evicted:
                return []
            try:
                removed_refs = self._commit_ref_removals(
                    [(session_key, ref_id) for ref_id in evicted],
                    transition="evict_expired",
                )
            except (AtomicWriteError, StatePersistenceDegradedError):
                if best_effort_persist:
                    return []
                raise
            return [ref.ref_id for ref in removed_refs]

    def collect_garbage(self, *, max_age_seconds: int | None = None) -> list[str]:
        with self._lock:
            if not self._cleanup_allowed:
                return []
            effective_max_age = (
                self._default_max_age_seconds
                if max_age_seconds is None
                else max(1, int(max_age_seconds))
            )
            evicted: list[str] = []
            for session_key in list(self._refs):
                evicted.extend(
                    self.evict_expired(
                        SessionId(session_key),
                        max_age_seconds=effective_max_age,
                    )
                )
            if self._cleanup_allowed:
                self._quarantine_orphaned_blobs()
                self._migrate_legacy_quarantine_entries()
                self._prune_quarantine()
            return evicted

    def endorse(
        self,
        session_id: SessionId,
        ref_id: str,
        *,
        endorsement_state: ArtifactEndorsementState,
        actor: str,
        endorsed_at: datetime | None = None,
    ) -> EvidenceRef | None:
        with self._lock:
            self._require_writable("endorse")
            session_key = self._session_key(session_id)
            ref = self._refs.get(session_key, {}).get(ref_id)
            if ref is None:
                return None
            normalized_actor = actor.strip()
            if not normalized_actor:
                raise ValueError("actor is required to endorse an artifact")
            updated = ref.model_copy(
                update={
                    "endorsement_state": endorsement_state,
                    "endorsed_at": endorsed_at or datetime.now(UTC),
                    "endorsed_by": normalized_actor,
                }
            )
            updated = self._stamp_metadata_mac(session_key, updated)
            candidate = self._copy_refs(self._refs)
            candidate[session_key][ref_id] = updated
            self._commit_candidate(candidate, transition="endorse")
            return updated

    def reset_domain(self) -> dict[str, object]:
        """Explicitly detach and destroy an evidence domain after durable replacement."""

        with self._lock:
            destroyed_ref_count = self.committed_ref_count()
            parent = self._root_dir.parent
            parent.mkdir(parents=True, exist_ok=True)
            prior_tombstones = list(parent.glob(f".{self._root_dir.name}.reset-*"))
            detached_tombstone: Path | None = None
            previous_salt = self._salt
            new_salt = os.urandom(32)
            try:
                if self._path_exists(self._root_dir):
                    detached_tombstone = parent / (
                        f".{self._root_dir.name}.reset-{uuid4().hex}"
                    )
                    os.replace(self._root_dir, detached_tombstone)
                    self._fsync_directory(parent)
                self._create_domain_files(new_salt)
            except Exception:
                rollback_ok = True
                try:
                    self._remove_path(self._root_dir)
                    if detached_tombstone is not None and self._path_exists(
                        detached_tombstone
                    ):
                        os.replace(detached_tombstone, self._root_dir)
                        self._fsync_directory(parent)
                except OSError:
                    rollback_ok = False
                self._salt = previous_salt
                if not rollback_ok:
                    self._mark_runtime_degraded("reset_rollback_failed")
                raise

            tombstones = [*prior_tombstones]
            if detached_tombstone is not None:
                tombstones.append(detached_tombstone)
            try:
                for tombstone in tombstones:
                    self._remove_path(tombstone)
                if tombstones:
                    self._fsync_directory(parent)
            except OSError:
                self._salt = new_salt
                self._refs = {}
                self._temporarily_unreadable_refs = {}
                self._mark_runtime_degraded("reset_cleanup_failed", committed_refs={})
                raise

            self._salt = new_salt
            self._refs = {}
            self._temporarily_unreadable_refs = {}
            self._state_load_result = StateLoadResult(
                StateLoadStatus.OK,
                reason="explicit_reset",
                schema_version=_EVIDENCE_INDEX_VERSION,
            )
            self._cleanup_allowed = True
            self._publish_committed({})
            return {
                "status": "ok",
                "destroyed_ref_count": destroyed_ref_count,
            }

    def _initialize_domain(self, *, configured_salt: bytes | None) -> None:
        root_status = self._probe_root()
        if root_status == "invalid":
            self._set_load_failure(StateLoadStatus.CORRUPT, "invalid_evidence_root")
            return
        reset_siblings = list(
            self._root_dir.parent.glob(f".{self._root_dir.name}.reset-*")
        )
        if reset_siblings:
            reason = (
                "reset_recovery_required"
                if root_status == "missing"
                else "reset_cleanup_required"
            )
            self._set_load_failure(StateLoadStatus.CORRUPT, reason)
            return
        if root_status in {"missing", "empty"}:
            chosen_salt = configured_salt if configured_salt is not None else os.urandom(32)
            if len(chosen_salt) != 32:
                self._set_load_failure(StateLoadStatus.CORRUPT, "invalid_salt")
                return
            self._salt = bytes(chosen_salt)
            try:
                self._create_domain_files(self._salt)
            except (AtomicWriteError, OSError):
                self._set_load_failure(StateLoadStatus.CORRUPT, "new_domain_publication_failed")
                return
            self._refs = {}
            self._state_load_result = StateLoadResult(
                StateLoadStatus.OK,
                reason="new_domain",
                schema_version=_EVIDENCE_INDEX_VERSION,
            )
            self._cleanup_allowed = True
            self._publish_committed({})
            return

        directory_reason = self._validate_existing_domain_directories()
        if directory_reason:
            self._set_load_failure(StateLoadStatus.CORRUPT, directory_reason)
            return

        salt_result = self._load_existing_salt(configured_salt)
        if salt_result is not None:
            self._set_load_failure(StateLoadStatus.CORRUPT, salt_result)
            return
        if not self._metadata_path.exists():
            self._set_load_failure(StateLoadStatus.CORRUPT, "missing_index_existing_domain")
            return
        if not self._is_regular_file(self._metadata_path):
            self._set_load_failure(StateLoadStatus.CORRUPT, "invalid_index_target")
            return
        try:
            raw_index = self._metadata_path.read_bytes()
        except OSError:
            self._set_load_failure(StateLoadStatus.CORRUPT, "index_read_failed")
            return
        load_result, payload = self._decode_index(raw_index)
        if load_result.status is not StateLoadStatus.OK:
            self._set_load_failure(
                load_result.status,
                load_result.reason,
                schema_version=load_result.schema_version,
            )
            return
        refs, unreadable, validation_reason = self._validate_complete_payload(payload)
        if validation_reason:
            self._refs = refs
            self._temporarily_unreadable_refs = unreadable
            self._set_load_failure(StateLoadStatus.CORRUPT, validation_reason)
            return
        try:
            self._ensure_domain_directories()
        except OSError:
            self._refs = refs
            self._set_load_failure(
                StateLoadStatus.CORRUPT,
                "domain_directory_prepare_failed",
            )
            return
        if load_result.legacy:
            try:
                self._persist_refs_index(refs)
            except AtomicWriteError:
                self._refs = refs
                self._set_load_failure(StateLoadStatus.CORRUPT, "legacy_migration_failed")
                return
        self._refs = refs
        self._temporarily_unreadable_refs = unreadable
        self._state_load_result = StateLoadResult(
            StateLoadStatus.OK,
            reason="loaded",
            schema_version=_EVIDENCE_INDEX_VERSION,
            legacy=load_result.legacy,
        )
        self._cleanup_allowed = True
        self._publish_committed(refs)
        self._quarantine_orphaned_blobs()
        if self._cleanup_allowed:
            self._migrate_legacy_quarantine_entries()
        if self._cleanup_allowed:
            self._prune_quarantine()

    def _probe_root(self) -> str:
        try:
            root_stat = self._root_dir.lstat()
        except FileNotFoundError:
            return "missing"
        except OSError:
            return "invalid"
        if not stat.S_ISDIR(root_stat.st_mode) or self._root_dir.is_symlink():
            return "invalid"
        try:
            return "empty" if not any(self._root_dir.iterdir()) else "existing"
        except OSError:
            return "invalid"

    def _create_domain_files(self, salt: bytes) -> None:
        self._ensure_domain_directories()
        self._fsync_directory(self._root_dir.parent)
        self._atomic_write(self._salt_path, salt)
        self._persist_refs_index({})

    def _ensure_domain_directories(self) -> None:
        self._ensure_owned_directory(self._root_dir, parents=True)
        self._ensure_owned_directory(self._blob_dir, parents=False)
        self._ensure_owned_directory(self._quarantine_dir, parents=False)

    def _validate_existing_domain_directories(self) -> str:
        for name, path in (
            ("blobs", self._blob_dir),
            ("quarantine", self._quarantine_dir),
        ):
            try:
                path_stat = path.lstat()
            except FileNotFoundError:
                return f"missing_{name}_directory"
            except OSError:
                return f"unreadable_{name}_directory"
            if not stat.S_ISDIR(path_stat.st_mode):
                return f"invalid_{name}_directory"
        return ""

    @staticmethod
    def _ensure_owned_directory(path: Path, *, parents: bool) -> None:
        try:
            path_stat = path.lstat()
        except FileNotFoundError:
            path.mkdir(parents=parents, exist_ok=False, mode=0o700)
        else:
            if not stat.S_ISDIR(path_stat.st_mode):
                raise OSError(f"evidence directory target is not a directory: {path}")
        path.chmod(0o700)

    def _load_existing_salt(self, configured_salt: bytes | None) -> str | None:
        if not self._salt_path.exists():
            return "missing_salt_existing_domain"
        if not self._is_regular_file(self._salt_path):
            return "invalid_salt_target"
        try:
            persisted_salt = self._salt_path.read_bytes()
        except OSError:
            return "salt_read_failed"
        if len(persisted_salt) != 32:
            return "invalid_salt"
        if configured_salt is not None and not hmac.compare_digest(
            persisted_salt,
            configured_salt,
        ):
            return "salt_mismatch"
        self._salt = persisted_salt
        return None

    def _decode_index(self, raw_bytes: bytes) -> tuple[StateLoadResult, object | None]:
        try:
            raw = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            return StateLoadResult(StateLoadStatus.CORRUPT, reason="invalid_json"), None
        envelope_candidate = isinstance(raw, dict) and bool(
            {"version", "checksum", "payload"}.intersection(raw)
        )
        if envelope_candidate:
            return decode_versioned_json_snapshot(
                raw_bytes,
                supported_version=_EVIDENCE_INDEX_VERSION,
            )
        return StateLoadResult(StateLoadStatus.OK, legacy=True), raw

    def _validate_complete_payload(
        self,
        payload: object,
    ) -> tuple[
        dict[str, dict[str, EvidenceRef]],
        dict[str, dict[str, _UnreadableRefState]],
        str,
    ]:
        if not isinstance(payload, dict):
            return {}, {}, "invalid_index_payload"
        loaded: dict[str, dict[str, EvidenceRef]] = {}
        unreadable: dict[str, dict[str, _UnreadableRefState]] = {}
        validation_reason = ""
        for session_key, session_refs_raw in payload.items():
            if not isinstance(session_key, str) or not session_key.strip():
                return {}, {}, "invalid_session_key"
            if not isinstance(session_refs_raw, dict):
                return {}, {}, "invalid_session_refs"
            session_refs: dict[str, EvidenceRef] = {}
            for ref_id, ref_raw in session_refs_raw.items():
                if not isinstance(ref_id, str):
                    return {}, {}, "invalid_ref_id"
                try:
                    ref = EvidenceRef.model_validate(ref_raw)
                except (TypeError, ValidationError):
                    return {}, {}, "invalid_ref_payload"
                if ref.ref_id != ref_id:
                    return {}, {}, "ref_id_mismatch"
                if _CONTENT_HASH_RE.fullmatch(ref.content_hash) is None:
                    return {}, {}, "invalid_content_hash"
                expected_ref_id = self._make_ref_id(
                    session_id=SessionId(session_key),
                    content_hash=ref.content_hash,
                )
                if not hmac.compare_digest(ref.ref_id, expected_ref_id):
                    return {}, {}, "ref_id_auth_mismatch"
                if not ref.metadata_mac:
                    return {}, {}, "metadata_mac_missing"
                if not hmac.compare_digest(
                    ref.metadata_mac,
                    self._make_metadata_mac(session_key, ref),
                ):
                    return {}, {}, "metadata_mac_mismatch"
                session_refs[ref_id] = ref
                blob_load = self._load_validated_blob_content(ref)
                if blob_load.content is None:
                    if not blob_load.drop_ref:
                        unreadable.setdefault(session_key, {})[ref_id] = _UnreadableRefState(
                            reason=blob_load.failure_reason
                        )
                    validation_reason = validation_reason or self._blob_domain_failure_reason(
                        blob_load
                    )
            if session_refs:
                loaded[session_key] = session_refs
        return loaded, unreadable, validation_reason

    def _set_load_failure(
        self,
        status: StateLoadStatus,
        reason: str,
        *,
        schema_version: int | None = None,
    ) -> None:
        self._state_load_result = StateLoadResult(
            status,
            reason=reason,
            schema_version=schema_version,
        )
        self._cleanup_allowed = False
        self._publish_committed({})

    def _mark_runtime_degraded(
        self,
        reason: str,
        *,
        committed_refs: Mapping[str, Mapping[str, EvidenceRef]] | None = None,
    ) -> None:
        self._state_load_result = StateLoadResult(
            StateLoadStatus.CORRUPT,
            reason=reason,
            schema_version=_EVIDENCE_INDEX_VERSION,
        )
        self._cleanup_allowed = False
        self._publish_committed(
            self._committed_view.refs if committed_refs is None else committed_refs
        )

    def _require_writable(self, transition: str) -> None:
        if not self.state_degraded:
            return
        raise StatePersistenceDegradedError(
            authority="evidence_domain",
            transition=transition,
            stage="load",
            reason=self._state_load_result.reason or self._state_load_result.status.value,
        )

    def _commit_candidate(
        self,
        candidate: dict[str, dict[str, EvidenceRef]],
        *,
        transition: str,
    ) -> None:
        with self._lock:
            try:
                self._persist_refs_index(candidate)
            except AtomicWriteError:
                self._mark_runtime_degraded(f"{transition}_index_publication_failed")
                raise
            self._refs = candidate
            self._publish_committed(candidate)

    def _commit_ref_removals(
        self,
        removals: list[tuple[str, str]],
        *,
        transition: str,
    ) -> list[EvidenceRef]:
        """Durably remove refs, then clear markers and delete unreferenced blobs."""

        with self._lock:
            self._require_writable(transition)
            candidate = self._copy_refs(self._refs)
            removed: list[tuple[str, str, EvidenceRef]] = []
            for session_key, ref_id in removals:
                session_refs = candidate.get(session_key)
                if session_refs is None:
                    continue
                ref = session_refs.pop(ref_id, None)
                if ref is None:
                    continue
                removed.append((session_key, ref_id, ref))
                if not session_refs:
                    candidate.pop(session_key, None)
            if not removed:
                return []

            self._commit_candidate(candidate, transition=transition)
            for session_key, ref_id, _ref in removed:
                self._clear_temporarily_unreadable(session_key, ref_id)
            for content_hash in dict.fromkeys(ref.content_hash for _, _, ref in removed):
                if not self._cleanup_allowed:
                    break
                if not self._delete_blob_if_unreferenced(content_hash):
                    break
            return [ref for _, _, ref in removed]

    def _publish_committed(
        self,
        refs: Mapping[str, Mapping[str, EvidenceRef]],
    ) -> None:
        frozen_refs = MappingProxyType(
            {
                session_key: MappingProxyType(dict(session_refs))
                for session_key, session_refs in refs.items()
            }
        )
        unreadable_refs = frozenset(
            (session_key, ref_id)
            for session_key, session_refs in self._temporarily_unreadable_refs.items()
            for ref_id in session_refs
        )
        self._committed_view = _CommittedEvidenceView(
            refs=frozen_refs,
            state_load_result=self._state_load_result,
            cleanup_allowed=self._cleanup_allowed,
            salt=bytes(self._salt),
            unreadable_refs=unreadable_refs,
        )

    @staticmethod
    def _copy_refs(
        refs: Mapping[str, Mapping[str, EvidenceRef]],
    ) -> dict[str, dict[str, EvidenceRef]]:
        return {session_key: dict(session_refs) for session_key, session_refs in refs.items()}

    def _persist_refs_index(self, refs: dict[str, dict[str, EvidenceRef]]) -> None:
        payload = {
            session_key: {
                ref_id: ref.model_dump(mode="json") for ref_id, ref in session_refs.items()
            }
            for session_key, session_refs in refs.items()
            if session_refs
        }
        self._atomic_write(
            self._metadata_path,
            encode_versioned_json_snapshot(payload, version=_EVIDENCE_INDEX_VERSION),
        )

    def _atomic_write(self, path: Path, payload: bytes) -> None:
        for stage in (AtomicWriteStage.TARGET_VALIDATE, AtomicWriteStage.DIRECTORY_PREPARE):
            try:
                if self._atomic_fault_injector is not None:
                    self._atomic_fault_injector(stage)
            except OSError as exc:
                raise AtomicWriteError(
                    path=path,
                    stage=stage,
                    publication_may_have_committed=False,
                ) from exc
        atomic_write_bytes(
            path,
            payload,
            fault_injector=self._atomic_fault_injector,
        )

    def _stamp_metadata_mac(self, session_key: str, ref: EvidenceRef) -> EvidenceRef:
        mac = self._make_metadata_mac(session_key, ref)
        if hmac.compare_digest(ref.metadata_mac, mac):
            return ref
        return ref.model_copy(update={"metadata_mac": mac})

    def _make_ref_id(self, *, session_id: SessionId, content_hash: str) -> str:
        return self._make_ref_id_with_salt(
            session_id=session_id,
            content_hash=content_hash,
            salt=self._salt,
        )

    @staticmethod
    def _make_ref_id_with_salt(
        *,
        session_id: SessionId,
        content_hash: str,
        salt: bytes,
    ) -> str:
        session_key = ArtifactLedger._session_key(session_id)
        payload = f"{session_key}:{content_hash}".encode()
        digest = hmac.new(salt, payload, hashlib.sha256).hexdigest()[:16]
        return f"{_EVIDENCE_REF_PREFIX}{digest}"

    def _make_metadata_mac(self, session_key: str, ref: EvidenceRef) -> str:
        payload = {
            "artifact_kind": ref.artifact_kind,
            "byte_size": ref.byte_size,
            "content_hash": ref.content_hash,
            "created_at": ref.created_at.isoformat(),
            "endorsement_state": ref.endorsement_state.value,
            "endorsed_at": ref.endorsed_at.isoformat() if ref.endorsed_at is not None else "",
            "endorsed_by": ref.endorsed_by,
            "lifecycle_state": ref.lifecycle_state.value,
            "ref_id": ref.ref_id,
            "session_key": session_key,
            "source": ref.source,
            "storage_codec": ref.storage_codec,
            "summary": ref.summary,
            "taint_labels": sorted(label.value for label in ref.taint_labels),
            "ttl_seconds": ref.ttl_seconds,
        }
        return hmac.new(
            self._salt,
            json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            ),
            hashlib.sha256,
        ).hexdigest()

    def _load_validated_blob_content(self, ref: EvidenceRef) -> _BlobLoadResult:
        if ref.storage_codec != self._blob_codec.name:
            return _BlobLoadResult(
                None,
                (
                    "blob storage codec mismatch "
                    f"(ref={ref.storage_codec} active={self._blob_codec.name})"
                ),
                drop_ref=False,
            )
        path = self._blob_path(ref.content_hash)
        if not self._is_regular_file(path):
            return _BlobLoadResult(None, f"blob {ref.content_hash} is missing", drop_ref=True)
        try:
            content = self._read_blob(path)
        except ArtifactBlobCodecError as exc:
            return _BlobLoadResult(None, str(exc) or "blob codec unavailable", drop_ref=False)
        except (OSError, UnicodeDecodeError, ValueError):
            return _BlobLoadResult(None, f"blob {ref.content_hash} is unreadable", drop_ref=True)
        actual_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(actual_hash, ref.content_hash):
            return _BlobLoadResult(
                None,
                f"blob {ref.content_hash} failed content hash verification",
                drop_ref=True,
            )
        return _BlobLoadResult(content)

    def _read_blob(self, path: Path) -> str:
        return self._blob_codec.decode(path.read_bytes())

    def _blob_path(self, content_hash: str) -> Path:
        return self._blob_dir / f"{content_hash}.txt"

    def _delete_blob_if_unreferenced(self, content_hash: str) -> bool:
        for session_refs in self._refs.values():
            if any(ref.content_hash == content_hash for ref in session_refs.values()):
                return True
        path = self._blob_path(content_hash)
        if not path.exists():
            return True
        if not self._cleanup_allowed:
            return False
        try:
            path.unlink()
            self._fsync_directory(self._blob_dir)
        except OSError:
            self._mark_runtime_degraded("blob_delete_failed")
            return False
        return True

    def _quarantine_orphaned_blobs(self) -> None:
        if not self._cleanup_allowed:
            return
        referenced_hashes = {
            ref.content_hash
            for session_refs in self._refs.values()
            for ref in session_refs.values()
        }
        for blob_path in self._blob_dir.glob("*.txt"):
            if blob_path.stem in referenced_hashes:
                continue
            if not self._quarantine_blob(blob_path):
                break

    def _quarantine_blob(self, source: Path) -> bool:
        content_hash = source.stem if len(source.stem) == 64 else hashlib.sha256(
            source.name.encode("utf-8")
        ).hexdigest()
        destination = self._quarantine_dir / (
            f"v1.{time.time_ns()}.{uuid4().hex}.{content_hash}.txt"
        )
        try:
            payload = source.read_bytes()
            self._atomic_write(destination, payload)
            source.unlink()
            self._fsync_directory(source.parent)
        except (AtomicWriteError, OSError):
            logger.warning("Failed to quarantine evidence blob %s", source, exc_info=True)
            self._mark_runtime_degraded("quarantine_publication_failed")
            return False
        return True

    def _migrate_legacy_quarantine_entries(self) -> None:
        if not self._cleanup_allowed:
            return
        for path in self._quarantine_dir.glob("*.txt"):
            if _QUARANTINE_NAME_RE.fullmatch(path.name):
                continue
            if not self._quarantine_blob(path):
                break

    def _prune_quarantine(self) -> None:
        if not self._cleanup_allowed:
            return
        now_ns = time.time_ns()
        for path in self._quarantine_dir.glob("*.txt"):
            match = _QUARANTINE_NAME_RE.fullmatch(path.name)
            if match is None:
                continue
            timestamp_ns = int(match.group("timestamp_ns"))
            age_seconds = max(0.0, (now_ns - timestamp_ns) / 1_000_000_000)
            if age_seconds <= float(self._orphan_retention_seconds):
                continue
            try:
                path.unlink()
                self._fsync_directory(self._quarantine_dir)
            except OSError:
                self._mark_runtime_degraded("quarantine_prune_failed")
                return

    def _drop_ref(self, session_key: str, ref_id: str) -> None:
        refs = self._refs.get(session_key)
        if not refs or ref_id not in refs:
            self._clear_temporarily_unreadable(session_key, ref_id)
            return
        try:
            self._commit_ref_removals(
                [(session_key, ref_id)],
                transition="drop_ref",
            )
        except (AtomicWriteError, StatePersistenceDegradedError):
            return

    def _mark_temporarily_unreadable(self, session_key: str, ref_id: str, reason: str) -> None:
        self._temporarily_unreadable_refs.setdefault(session_key, {})[ref_id] = _UnreadableRefState(
            reason=reason.strip() or "temporarily_unreadable"
        )
        self._publish_committed(self._committed_view.refs)

    def _clear_temporarily_unreadable(self, session_key: str, ref_id: str) -> None:
        session_refs = self._temporarily_unreadable_refs.get(session_key)
        if not session_refs:
            return
        session_refs.pop(ref_id, None)
        if not session_refs:
            self._temporarily_unreadable_refs.pop(session_key, None)
        self._publish_committed(self._committed_view.refs)

    def _is_temporarily_unreadable(self, session_key: str, ref_id: str) -> bool:
        return ref_id in self._temporarily_unreadable_refs.get(session_key, {})

    def _maybe_probe_temporarily_unreadable(self, session_id: SessionId, ref_id: str) -> None:
        session_key = self._session_key(session_id)
        view = self._committed_view
        if (session_key, ref_id) not in view.unreadable_refs:
            return
        if not self._unreadable_probe_guard.acquire(blocking=False):
            return
        try:
            if self._unreadable_probe_in_flight:
                return
            self._unreadable_probe_in_flight.add(_DOMAIN_PROBE_KEY)
        finally:
            self._unreadable_probe_guard.release()

        def _probe() -> None:
            try:
                self._probe_temporarily_unreadable_domain()
            finally:
                with self._unreadable_probe_guard:
                    self._unreadable_probe_in_flight.discard(_DOMAIN_PROBE_KEY)

        Thread(
            target=_probe,
            name="evidence-unreadable-domain-probe",
            daemon=True,
        ).start()

    def _probe_temporarily_unreadable_domain(self) -> None:
        with self._lock:
            if self._state_load_result.reason != "blob_unreadable":
                return
            unreadable: dict[str, dict[str, _UnreadableRefState]] = {}
            validation_reason = ""
            for session_key, session_refs in self._refs.items():
                for ref_id, ref in session_refs.items():
                    blob_load = self._load_validated_blob_content(ref)
                    if blob_load.content is not None:
                        continue
                    if not blob_load.drop_ref:
                        unreadable.setdefault(session_key, {})[ref_id] = _UnreadableRefState(
                            reason=blob_load.failure_reason
                        )
                    validation_reason = validation_reason or self._blob_domain_failure_reason(
                        blob_load
                    )
            self._temporarily_unreadable_refs = unreadable
            if validation_reason:
                self._state_load_result = StateLoadResult(
                    StateLoadStatus.CORRUPT,
                    reason=validation_reason,
                    schema_version=_EVIDENCE_INDEX_VERSION,
                )
                self._cleanup_allowed = False
                self._publish_committed(self._refs)
                return
            self._state_load_result = StateLoadResult(
                StateLoadStatus.OK,
                reason="blob_access_recovered",
                schema_version=_EVIDENCE_INDEX_VERSION,
            )
            self._cleanup_allowed = True
            self._publish_committed(self._refs)

    @staticmethod
    def _blob_domain_failure_reason(blob_load: _BlobLoadResult) -> str:
        if not blob_load.drop_ref:
            return "blob_unreadable"
        if "missing" in blob_load.failure_reason:
            return "blob_missing"
        if "hash" in blob_load.failure_reason:
            return "blob_hash_mismatch"
        return "blob_unreadable"

    def _merged_ref(
        self,
        *,
        session_key: str,
        existing: EvidenceRef,
        taint_labels: set[TaintLabel],
        source: str,
        summary: str,
        ttl_seconds: int | None,
        artifact_kind: str,
        lifecycle_state: ArtifactLifecycleState,
        storage_codec: str | None = None,
    ) -> EvidenceRef:
        merged_lifecycle_state = (
            ArtifactLifecycleState.QUARANTINED
            if ArtifactLifecycleState.QUARANTINED in {existing.lifecycle_state, lifecycle_state}
            else ArtifactLifecycleState.ACTIVE
        )
        merged = existing.model_copy(
            update={
                "taint_labels": sorted({*existing.taint_labels, *taint_labels}),
                "source": source or existing.source,
                "summary": summary or existing.summary,
                "ttl_seconds": self._merge_ttl_seconds(existing.ttl_seconds, ttl_seconds),
                "artifact_kind": artifact_kind or existing.artifact_kind,
                "lifecycle_state": merged_lifecycle_state,
                "storage_codec": storage_codec or existing.storage_codec or self._blob_codec.name,
            }
        )
        return self._stamp_metadata_mac(session_key, merged)

    @staticmethod
    def _is_expired(ref: EvidenceRef, *, max_age_seconds: int) -> bool:
        age_seconds = max(0.0, (datetime.now(UTC) - ref.created_at).total_seconds())
        effective = ArtifactLedger._effective_max_age_seconds(
            max_age_seconds=max_age_seconds,
            ttl_seconds=ref.ttl_seconds,
        )
        return age_seconds > float(effective)

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
    def _is_regular_file(path: Path) -> bool:
        try:
            path_stat = path.lstat()
        except OSError:
            return False
        return stat.S_ISREG(path_stat.st_mode)

    @staticmethod
    def _path_exists(path: Path) -> bool:
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        return True

    @staticmethod
    def _remove_path(path: Path) -> None:
        try:
            path_stat = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISDIR(path_stat.st_mode):
            shutil.rmtree(path)
        else:
            path.unlink()

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        directory_fd = os.open(path, flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    @staticmethod
    def _session_key(session_id: SessionId) -> str:
        return str(session_id).strip()


class EvidenceStore(ArtifactLedger):
    """Backwards-compatible alias for the artifact ledger evidence surface."""
