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
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from functools import wraps
from html.parser import HTMLParser
from http.client import InvalidURL
from pathlib import Path
from threading import RLock, Thread
from typing import Concatenate, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from shisad.core.atomic_state import (
    AtomicWriteError,
    StateLoadStatus,
    StatePersistenceDegradedError,
    atomic_write_bytes,
    load_state,
    write_state,
)
from shisad.core.storage_platform import StorageCapability, tighten_permissions
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

    ref_id: str
    content_hash: str
    taint_labels: list[TaintLabel] = Field(default_factory=list)
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


class _PersistedEvidenceRef(EvidenceRef):
    model_config = ConfigDict(extra="forbid")

    taint_labels: list[TaintLabel]
    created_at: datetime
    ttl_seconds: int | None
    artifact_kind: str
    lifecycle_state: ArtifactLifecycleState
    endorsement_state: ArtifactEndorsementState
    endorsed_at: datetime | None
    endorsed_by: str
    storage_codec: str
    metadata_mac: str


@dataclass(frozen=True)
class _MetadataLoadResult:
    refs: dict[str, dict[str, EvidenceRef]]
    loaded_ok: bool
    temporarily_unreadable: dict[str, dict[str, _UnreadableRefState]] | None = None


@dataclass(frozen=True)
class _BlobLoadResult:
    content: str | None
    failure_reason: str = ""
    drop_ref: bool = False


@dataclass(frozen=True)
class _UnreadableRefState:
    ref: EvidenceRef
    reason: str


_METADATA_ADAPTER = TypeAdapter(dict[str, dict[str, _PersistedEvidenceRef]])


class _MutationOwner(Protocol):
    @property
    def _mutation_lock(self) -> contextlib.AbstractContextManager[bool]: ...


def _serialized[Owner: _MutationOwner, **P, R](
    method: Callable[Concatenate[Owner, P], R],
) -> Callable[Concatenate[Owner, P], R]:
    @wraps(method)
    def wrapped(self: Owner, /, *args: P.args, **kwargs: P.kwargs) -> R:
        with self._mutation_lock:
            return method(self, *args, **kwargs)

    return wrapped


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
    """Structured artifact ledger for persisted evidence refs."""

    def __init__(
        self,
        root_dir: Path,
        *,
        salt: bytes | None = None,
        default_max_age_seconds: int = _DEFAULT_EVIDENCE_MAX_AGE_SECONDS,
        orphan_retention_seconds: int = _DEFAULT_ORPHAN_RETENTION_SECONDS,
        blob_codec: ArtifactBlobCodec | None = None,
    ) -> None:
        self._root_dir = root_dir
        self._blob_dir = root_dir / "blobs"
        self._quarantine_dir = root_dir / "quarantine"
        self._metadata_path = root_dir / _EVIDENCE_METADATA_FILENAME
        self._salt_path = root_dir / "evidence_salt"
        self._default_max_age_seconds = max(1, int(default_max_age_seconds))
        self._orphan_retention_seconds = max(1, int(orphan_retention_seconds))
        self._blob_codec = blob_codec or PlaintextArtifactBlobCodec()
        self._mutation_lock: contextlib.AbstractContextManager[bool] = RLock()
        self._storage_capability = StorageCapability()
        self._state_status = StateLoadStatus.MISSING
        self._state_reason = ""
        self._salt = b"\0" * 32
        self._refs: dict[str, dict[str, EvidenceRef]] = {}
        self._publication_refs: dict[str, dict[str, EvidenceRef]] | None = None
        self._temporarily_unreadable_refs: dict[str, dict[str, _UnreadableRefState]] = {}
        self._unreadable_probe_in_flight: set[tuple[str, str]] = set()
        self._root_dir.mkdir(parents=True, exist_ok=True)
        self._blob_dir.mkdir(parents=True, exist_ok=True)
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_dir_permissions(self._root_dir)
        self._ensure_dir_permissions(self._blob_dir)
        self._ensure_dir_permissions(self._quarantine_dir)
        fresh = not self._salt_path.exists() and not self._companion_state_present()
        if fresh:
            self._initialize_empty_domain(salt)
        elif self._load_existing_salt(salt):
            metadata_load = self._load_metadata_index()
            if metadata_load.loaded_ok:
                self._refs = metadata_load.refs
                self._temporarily_unreadable_refs = metadata_load.temporarily_unreadable or {}
        if self._cleanup_available():
            self._quarantine_orphaned_blobs()
            self._prune_quarantine()

    @_serialized
    def store(
        self,
        /,
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
        self._require_state("store")
        self._evict_for_session(session_id)
        raw = content.encode("utf-8")
        content_hash = hashlib.sha256(raw).hexdigest()
        ref_id = self._make_ref_id(session_id=session_id, content_hash=content_hash)
        session_key = self._session_key(session_id)
        blob_path = self._blob_path(content_hash)
        existing = self._refs.get(session_key, {}).get(ref_id)
        if existing is not None:
            blob_load = self._load_validated_blob_content(existing)
            if blob_load.content is None:
                self._degrade(f"existing evidence blob is invalid: {blob_load.failure_reason}")
                self._require_state("store")
            merged = self._merge_existing_ref(
                session_key=session_key,
                existing=existing,
                taint_labels=set(taint_labels),
                source=source,
                summary=summary,
                ttl_seconds=ttl_seconds,
                artifact_kind=artifact_kind,
                lifecycle_state=lifecycle_state,
            )
            candidate = self._copy_refs()
            candidate.setdefault(session_key, {})[ref_id] = merged
            self._publish_refs(candidate, transition="store")
            return merged

        if blob_path.exists():
            try:
                existing_content = self._read_blob(blob_path)
            except (ArtifactBlobCodecError, OSError, UnicodeDecodeError, ValueError) as exc:
                self._degrade(f"orphan evidence blob is unreadable: {type(exc).__name__}")
                self._require_state("store")
            if not hmac.compare_digest(
                hashlib.sha256(existing_content.encode("utf-8")).hexdigest(), content_hash
            ):
                self._degrade("orphan evidence blob failed content hash verification")
                self._require_state("store")
        else:
            self._write_blob(blob_path, content)
        self._ensure_file_permissions(blob_path)
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
        candidate = self._copy_refs()
        candidate.setdefault(session_key, {})[ref_id] = ref
        self._publish_refs(candidate, transition="store")
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
        if not self._state_available():
            return None
        self._evict_for_session(session_id)
        if not self._state_available():
            return None
        session_key = self._session_key(session_id)
        return self._refs.get(session_key, {}).get(ref_id)

    def resolve_ref_content(
        self,
        session_id: SessionId,
        ref_id: str,
    ) -> tuple[EvidenceRef | None, str | None]:
        return self._resolve_valid_ref(session_id, ref_id)

    def _resolve_valid_ref(
        self,
        session_id: SessionId,
        ref_id: str,
    ) -> tuple[EvidenceRef | None, str | None]:
        if not self._state_available():
            return None, None
        self._evict_for_session(session_id)
        if not self._state_available():
            return None, None
        session_key = self._session_key(session_id)
        ref = self._refs.get(session_key, {}).get(ref_id)
        unreadable = self._temporarily_unreadable_refs.get(session_key, {}).get(ref_id)
        if ref is None and unreadable is not None:
            ref = unreadable.ref
        if ref is None:
            return None, None
        if ref.lifecycle_state != ArtifactLifecycleState.ACTIVE:
            return None, None
        blob_load = self._load_validated_blob_content(ref)
        if blob_load.content is None:
            if blob_load.drop_ref:
                logger.warning(
                    "Evidence ref %s for session %s failed validation because %s",
                    ref_id,
                    session_key,
                    blob_load.failure_reason,
                )
                self._degrade(blob_load.failure_reason)
            else:
                logger.warning(
                    "Evidence ref %s for session %s is temporarily unreadable because %s",
                    ref_id,
                    session_key,
                    blob_load.failure_reason,
                )
                self._mark_temporarily_unreadable(
                    session_key,
                    ref_id,
                    ref,
                    blob_load.failure_reason,
                )
            return None, None
        self._refs.setdefault(session_key, {})[ref_id] = ref
        self._clear_temporarily_unreadable(session_key, ref_id)
        return ref, blob_load.content

    def validate_ref_id(self, session_id: SessionId, ref_id: str) -> bool:
        ref = self.get_ref(session_id, ref_id)
        if ref is None:
            return False
        return hmac.compare_digest(
            ref.ref_id,
            self._make_ref_id(session_id=session_id, content_hash=ref.content_hash),
        )

    def validate_ref_metadata(self, session_id: SessionId, ref_id: str) -> bool:
        ref = self.get_ref_metadata(session_id, ref_id)
        if ref is None:
            self._maybe_probe_temporarily_unreadable(session_id, ref_id)
            return False
        if ref.lifecycle_state != ArtifactLifecycleState.ACTIVE:
            return False
        return hmac.compare_digest(
            ref.ref_id,
            self._make_ref_id(session_id=session_id, content_hash=ref.content_hash),
        )

    @_serialized
    def evict_expired(
        self,
        /,
        session_id: SessionId,
        *,
        max_age_seconds: int = _DEFAULT_EVIDENCE_MAX_AGE_SECONDS,
        best_effort_persist: bool = False,
    ) -> list[str]:
        if not self._cleanup_available():
            return []
        session_key = self._session_key(session_id)
        refs = self._refs.get(session_key, {})
        if not refs:
            return []

        now = datetime.now(UTC)
        evicted: list[str] = []
        content_hashes: list[str] = []
        candidate = self._copy_refs()
        candidate_refs = candidate.get(session_key, {})
        for ref_id, ref in refs.items():
            age_seconds = max(0.0, (now - ref.created_at).total_seconds())
            effective_max_age = self._effective_max_age_seconds(
                max_age_seconds=max_age_seconds,
                ttl_seconds=ref.ttl_seconds,
            )
            if age_seconds <= float(effective_max_age):
                continue
            candidate_refs.pop(ref_id, None)
            evicted.append(ref_id)
            content_hashes.append(ref.content_hash)
        if not candidate_refs:
            candidate.pop(session_key, None)
        if evicted:
            try:
                self._publish_refs(candidate, transition="evict_expired")
            except StatePersistenceDegradedError:
                if best_effort_persist:
                    return []
                raise
            for ref_id in evicted:
                self._clear_temporarily_unreadable(session_key, ref_id)
            for content_hash in content_hashes:
                self._delete_blob_if_unreferenced(content_hash)
        return evicted

    @_serialized
    def collect_garbage(
        self,
        /,
        *,
        max_age_seconds: int | None = None,
    ) -> list[str]:
        if not self._cleanup_available():
            return []
        evicted: list[str] = []
        effective_max_age = (
            self._default_max_age_seconds
            if max_age_seconds is None
            else max(1, int(max_age_seconds))
        )
        for session_key in list(self._refs.keys()):
            evicted.extend(
                self.evict_expired(
                    SessionId(session_key),
                    max_age_seconds=effective_max_age,
                    best_effort_persist=True,
                )
            )
        if self._cleanup_available():
            self._quarantine_orphaned_blobs()
            self._prune_quarantine()
        return evicted

    @_serialized
    def endorse(
        self,
        /,
        session_id: SessionId,
        ref_id: str,
        *,
        endorsement_state: ArtifactEndorsementState,
        actor: str,
        endorsed_at: datetime | None = None,
    ) -> EvidenceRef | None:
        self._require_state("endorse")
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
        candidate = self._copy_refs()
        candidate[session_key][ref_id] = updated
        self._publish_refs(candidate, transition="endorse")
        return updated

    def _stamp_metadata_mac(self, session_key: str, ref: EvidenceRef) -> EvidenceRef:
        mac = self._make_metadata_mac(session_key, ref)
        if hmac.compare_digest(ref.metadata_mac, mac):
            return ref
        return ref.model_copy(update={"metadata_mac": mac})

    def _make_ref_id(self, *, session_id: SessionId, content_hash: str) -> str:
        payload = f"{self._session_key(session_id)}:{content_hash}".encode()
        digest = hmac.new(self._salt, payload, hashlib.sha256).hexdigest()[:16]
        return f"{_EVIDENCE_REF_PREFIX}{digest}"

    def _companion_state_present(self) -> bool:
        return self._metadata_path.exists() or any(
            path.is_file()
            for directory in (self._blob_dir, self._quarantine_dir)
            for path in directory.iterdir()
        )

    def _initialize_empty_domain(self, supplied_salt: bytes | None) -> None:
        candidate = supplied_salt if supplied_salt is not None else os.urandom(32)
        if len(candidate) != 32:
            self._degrade("evidence salt must contain exactly 32 bytes")
            return
        try:
            self._storage_capability = atomic_write_bytes(self._salt_path, candidate)
            self._salt = candidate
            self._ensure_file_permissions(self._salt_path)
            self._storage_capability = write_state(self._metadata_path, {})
        except (AtomicWriteError, OSError, TypeError, ValueError):
            self._degrade("evidence domain initialization did not publish safely")
            return
        self._state_status = StateLoadStatus.OK

    def _load_existing_salt(self, supplied_salt: bytes | None) -> bool:
        if not self._salt_path.exists():
            self._degrade("evidence salt is missing while companion state exists")
            return False
        try:
            stored = self._salt_path.read_bytes()
        except OSError:
            self._degrade("evidence salt could not be read")
            return False
        if len(stored) != 32:
            self._degrade("evidence salt is invalid")
            return False
        if supplied_salt is not None and (
            len(supplied_salt) != 32 or not hmac.compare_digest(stored, supplied_salt)
        ):
            self._degrade("configured evidence salt does not match persisted state")
            return False
        if not self._metadata_path.exists():
            self._degrade("evidence metadata index is missing")
            return False
        self._salt = stored
        self._ensure_file_permissions(self._salt_path)
        return True

    def _state_available(self) -> bool:
        return self._state_status is StateLoadStatus.OK

    def _cleanup_available(self) -> bool:
        return self._state_available() and not self._temporarily_unreadable_refs

    def _degrade(self, reason: str) -> None:
        self._state_status = StateLoadStatus.CORRUPT
        self._state_reason = reason.strip() or "evidence state is invalid"

    def _require_state(self, transition: str) -> None:
        if self._cleanup_available():
            return
        raise StatePersistenceDegradedError(
            authority="evidence",
            transition=transition,
            stage="state_validation",
            reason=self._state_reason or "restore known-good evidence state",
        )

    def state_health(self) -> dict[str, str]:
        status = {
            StateLoadStatus.MISSING: "missing",
            StateLoadStatus.OK: "ok",
            StateLoadStatus.CORRUPT: "corrupt",
            StateLoadStatus.UNSUPPORTED_SCHEMA: "unsupported",
        }[self._state_status]
        reason = self._state_reason
        if self._temporarily_unreadable_refs:
            status = "corrupt"
            reason = "referenced evidence blobs cannot be validated; restore codec/key access"
        return {
            "component": "evidence",
            "status": status,
            "reason": reason,
            "durability": self._storage_capability.parent_sync,
            "permissions": self._storage_capability.permissions,
            "remains_usable": "conversation, channels, and unrelated tools",
        }

    def _copy_refs(self) -> dict[str, dict[str, EvidenceRef]]:
        return {session: dict(refs) for session, refs in self._refs.items()}

    def _publish_refs(
        self, candidate: dict[str, dict[str, EvidenceRef]], *, transition: str
    ) -> None:
        self._publication_refs = candidate
        try:
            self._persist_metadata_index()
        except (AtomicWriteError, OSError, TypeError, ValueError) as exc:
            self._degrade("evidence metadata publication failed; restore known-good state")
            raise StatePersistenceDegradedError(
                authority="evidence",
                transition=transition,
                stage=str(getattr(exc, "stage", "encode")),
                reason=self._state_reason,
            ) from exc
        finally:
            self._publication_refs = None
        self._refs = candidate
        self._state_status = StateLoadStatus.OK
        self._state_reason = ""

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
        if not path.exists():
            return _BlobLoadResult(
                None,
                f"blob {ref.content_hash} is missing",
                drop_ref=True,
            )
        try:
            content = self._read_blob(path)
        except ArtifactBlobCodecError as exc:
            return _BlobLoadResult(
                None,
                str(exc) or "blob codec unavailable",
                drop_ref=False,
            )
        except (OSError, UnicodeDecodeError, ValueError):
            return _BlobLoadResult(
                None,
                f"blob {ref.content_hash} is unreadable",
                drop_ref=True,
            )
        actual_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(actual_hash, ref.content_hash):
            return _BlobLoadResult(
                None,
                f"blob {ref.content_hash} failed content hash verification",
                drop_ref=True,
            )
        return _BlobLoadResult(content)

    def _write_blob(self, path: Path, content: str) -> None:
        atomic_write_bytes(path, self._blob_codec.encode(content))

    def _read_blob(self, path: Path) -> str:
        return self._blob_codec.decode(path.read_bytes())

    def _load_metadata_index(self) -> _MetadataLoadResult:
        result = load_state(
            self._metadata_path,
            dict[str, dict[str, _PersistedEvidenceRef]],
            legacy_decoder=self._decode_legacy_metadata,
        )
        self._state_status = result.status
        if result.status is not StateLoadStatus.OK or result.value is None:
            self._state_reason = "evidence metadata index is invalid; restore known-good state"
            return _MetadataLoadResult(refs={}, loaded_ok=False)
        try:
            refs, unreadable = self._validate_metadata_payload(result.value)
        except ValueError as exc:
            self._degrade(str(exc))
            return _MetadataLoadResult(refs={}, loaded_ok=False)
        self._state_status = StateLoadStatus.OK
        self._state_reason = ""
        return _MetadataLoadResult(
            refs=refs,
            loaded_ok=True,
            temporarily_unreadable=unreadable,
        )

    def _decode_legacy_metadata(self, raw: bytes) -> dict[str, dict[str, _PersistedEvidenceRef]]:
        refs = _METADATA_ADAPTER.validate_json(raw)
        self._validate_metadata_payload(refs)
        return refs

    def _validate_metadata_payload(
        self, refs: Mapping[str, Mapping[str, EvidenceRef]]
    ) -> tuple[
        dict[str, dict[str, EvidenceRef]],
        dict[str, dict[str, _UnreadableRefState]],
    ]:
        normalized = {
            session_key: {
                ref_id: EvidenceRef.model_validate(ref.model_dump(mode="python"))
                for ref_id, ref in session_refs.items()
            }
            for session_key, session_refs in refs.items()
        }
        unreadable: dict[str, dict[str, _UnreadableRefState]] = {}
        for session_key, session_refs in normalized.items():
            if not session_key:
                raise ValueError("evidence metadata contains an empty session id")
            for ref_id, ref in session_refs.items():
                if ref.ref_id != ref_id:
                    raise ValueError("evidence metadata ref id mismatch")
                expected_ref_id = self._make_ref_id(
                    session_id=SessionId(session_key), content_hash=ref.content_hash
                )
                if not hmac.compare_digest(ref_id, expected_ref_id):
                    raise ValueError("evidence ref id failed salt validation")
                expected_mac = self._make_metadata_mac(session_key, ref)
                if not ref.metadata_mac or not hmac.compare_digest(ref.metadata_mac, expected_mac):
                    raise ValueError("evidence metadata MAC validation failed")
                blob_load = self._load_validated_blob_content(ref)
                if blob_load.content is None:
                    if blob_load.drop_ref:
                        raise ValueError(blob_load.failure_reason)
                    unreadable.setdefault(session_key, {})[ref_id] = _UnreadableRefState(
                        ref=ref,
                        reason=blob_load.failure_reason,
                    )
        for session_key, unreadable_session_refs in unreadable.items():
            for ref_id in unreadable_session_refs:
                normalized[session_key].pop(ref_id)
        return {key: value for key, value in normalized.items() if value}, unreadable

    def _persist_metadata_index(self) -> None:
        refs = self._publication_refs if self._publication_refs is not None else self._refs
        serialized = {
            session_key: {
                ref_id: ref.model_dump(mode="json") for ref_id, ref in session_refs.items()
            }
            for session_key, session_refs in refs.items()
            if session_refs
        }
        self._storage_capability = write_state(self._metadata_path, serialized)

    def _quarantine_orphaned_blobs(self) -> None:
        if not self._cleanup_available():
            return
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
        if not self._cleanup_available():
            return
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

    def _mark_temporarily_unreadable(
        self,
        session_key: str,
        ref_id: str,
        ref: EvidenceRef,
        reason: str,
    ) -> None:
        self._temporarily_unreadable_refs.setdefault(session_key, {})[ref_id] = _UnreadableRefState(
            ref=ref,
            reason=reason.strip() or "temporarily_unreadable",
        )
        session_refs = self._refs.get(session_key, {})
        session_refs.pop(ref_id, None)
        if not session_refs:
            self._refs.pop(session_key, None)

    def _clear_temporarily_unreadable(self, session_key: str, ref_id: str) -> None:
        session_refs = self._temporarily_unreadable_refs.get(session_key)
        if not session_refs:
            return
        session_refs.pop(ref_id, None)
        if not session_refs:
            self._temporarily_unreadable_refs.pop(session_key, None)

    def _maybe_probe_temporarily_unreadable(self, session_id: SessionId, ref_id: str) -> None:
        session_key = self._session_key(session_id)
        if ref_id not in self._temporarily_unreadable_refs.get(session_key, {}):
            return
        probe_key = (session_key, ref_id)
        if probe_key in self._unreadable_probe_in_flight:
            return
        self._unreadable_probe_in_flight.add(probe_key)

        def _probe() -> None:
            try:
                self.resolve_ref_content(session_id, ref_id)
            finally:
                with self._mutation_lock:
                    self._unreadable_probe_in_flight.discard(probe_key)

        Thread(
            target=_probe,
            name=f"evidence-unreadable-probe-{session_key}-{ref_id}",
            daemon=True,
        ).start()

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
        merged = self._stamp_metadata_mac(session_key, merged)
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
        tighten_permissions(path, 0o700)

    @staticmethod
    def _ensure_file_permissions(path: Path) -> None:
        tighten_permissions(path, 0o600)

    @staticmethod
    def _session_key(session_id: SessionId) -> str:
        return str(session_id).strip()


class EvidenceStore(ArtifactLedger):
    """Backwards-compatible alias for the artifact ledger evidence surface."""
