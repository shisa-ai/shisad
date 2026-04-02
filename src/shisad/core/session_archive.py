"""Session archive export/import helpers."""

from __future__ import annotations

import hashlib
import json
import uuid
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from shisad.core.session import Checkpoint, CheckpointStore, Session, SessionManager
from shisad.core.transcript import TranscriptStore
from shisad.core.types import SessionId, TaintLabel
from shisad.security.lockdown import LockdownManager

_ARCHIVE_FORMAT = "shisad_session_archive"
_ARCHIVE_VERSION = 1
_MANIFEST_PATH = "manifest.json"
_SESSION_PATH = "session.json"
_TRANSCRIPT_PATH = "transcript.json"
_CHECKPOINT_PREFIX = "checkpoints/"
_ARCHIVE_SUFFIX = ".shisad-session.zip"
_ARCHIVE_MAX_MEMBER_BYTES = 64 * 1024 * 1024
_ARCHIVE_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_ARCHIVE_MAX_MEMBER_COUNT = 2048
_ARCHIVE_READ_CHUNK_BYTES = 64 * 1024
_ZIP_FLAG_ENCRYPTED = 0x1


class SessionArchiveError(ValueError):
    """Raised when session archive export/import fails validation."""


class SessionArchiveManifest(BaseModel):
    format: str = _ARCHIVE_FORMAT
    version: int = _ARCHIVE_VERSION
    exported_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    original_session_id: str
    channel: str = ""
    user_id: str = ""
    workspace_id: str = ""
    role: str = ""
    mode: str = ""
    lockdown_level: str = ""
    capability_hash: str = ""
    transcript_entries: int = 0
    checkpoint_count: int = 0
    includes: list[str] = Field(
        default_factory=lambda: ["session", "lockdown", "transcript", "checkpoints"]
    )
    excludes: list[str] = Field(
        default_factory=lambda: ["evidence_store", "memory", "scheduler_global_state"]
    )
    entries: dict[str, str] = Field(default_factory=dict)


@dataclass(frozen=True)
class SessionArchiveExportResult:
    session_id: SessionId
    archive_path: Path
    sha256: str
    transcript_entries: int
    checkpoint_count: int


@dataclass(frozen=True)
class SessionArchiveImportResult:
    session: Session
    original_session_id: SessionId
    archive_path: Path
    checkpoint_ids: tuple[str, ...]
    transcript_entries: int


class SessionArchiveManager:
    """Exports and imports bounded single-session archives."""

    def __init__(
        self,
        *,
        session_manager: SessionManager,
        transcript_store: TranscriptStore,
        checkpoint_store: CheckpointStore,
        lockdown_manager: LockdownManager,
        archive_dir: Path,
    ) -> None:
        self._session_manager = session_manager
        self._transcript_store = transcript_store
        self._checkpoint_store = checkpoint_store
        self._lockdown_manager = lockdown_manager
        self._archive_dir = archive_dir
        self._archive_dir.mkdir(parents=True, exist_ok=True)

    def export_session(
        self,
        session_id: SessionId,
        *,
        destination: Path | None = None,
    ) -> SessionArchiveExportResult:
        record = self._session_manager.export_session_record(session_id)
        if record is None:
            raise SessionArchiveError("session_not_found")
        session_payload = record.get("session")
        if not isinstance(session_payload, dict):
            raise SessionArchiveError("invalid_session_record")
        try:
            session = Session.model_validate(session_payload)
            transcript_rows = self._transcript_rows_for(session_id)
            checkpoints = self._checkpoint_store.list_for_session(session_id)
            archive_path = destination or self._default_archive_path(session.id)
            archive_path.parent.mkdir(parents=True, exist_ok=True)

            members: dict[str, bytes] = {
                _SESSION_PATH: json.dumps(
                    record,
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                ).encode("utf-8"),
                _TRANSCRIPT_PATH: json.dumps(
                    transcript_rows,
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                ).encode("utf-8"),
            }
            for checkpoint in checkpoints:
                checkpoint_path = f"{_CHECKPOINT_PREFIX}{checkpoint.checkpoint_id}.json"
                members[checkpoint_path] = checkpoint.model_dump_json(indent=2).encode("utf-8")

            manifest = SessionArchiveManifest(
                original_session_id=str(session.id),
                channel=session.channel,
                user_id=str(session.user_id),
                workspace_id=str(session.workspace_id),
                role=session.role.value,
                mode=session.mode.value,
                lockdown_level=(
                    str(record.get("lockdown", {}).get("level", ""))
                    if isinstance(record.get("lockdown"), dict)
                    else ""
                ),
                capability_hash=_capability_hash(session_payload.get("capabilities")),
                transcript_entries=len(transcript_rows),
                checkpoint_count=len(checkpoints),
                entries={name: _sha256_bytes(data) for name, data in members.items()},
            )
            members[_MANIFEST_PATH] = manifest.model_dump_json(indent=2).encode("utf-8")

            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in sorted(members.items()):
                    archive.writestr(name, data)

            archive_sha256 = _sha256_bytes(archive_path.read_bytes())
        except SessionArchiveError:
            raise
        except (OSError, ValidationError, TypeError, ValueError) as exc:
            raise SessionArchiveError("archive_write_failed") from exc

        return SessionArchiveExportResult(
            session_id=session.id,
            archive_path=archive_path,
            sha256=archive_sha256,
            transcript_entries=len(transcript_rows),
            checkpoint_count=len(checkpoints),
        )

    def import_archive(self, archive_path: Path) -> SessionArchiveImportResult:
        members = self._load_archive_members(archive_path)
        manifest = self._validate_manifest(members)
        record = self._parse_json_member(members, _SESSION_PATH)
        if not isinstance(record, dict):
            raise SessionArchiveError("invalid_session_record")
        transcript_rows = self._parse_json_member(members, _TRANSCRIPT_PATH)
        if not isinstance(transcript_rows, list):
            raise SessionArchiveError("invalid_transcript_payload")
        if len(transcript_rows) != manifest.transcript_entries:
            raise SessionArchiveError("archive_transcript_count_mismatch")

        session_payload = record.get("session")
        if not isinstance(session_payload, dict):
            raise SessionArchiveError("invalid_session_record")
        self._validate_scope_consistency(manifest, record)

        original_session_id = SessionId(str(manifest.original_session_id))
        imported_session_id = SessionId(uuid.uuid4().hex)
        imported_checkpoint_ids: list[str] = []
        imported_session: Session | None = None
        try:
            imported_session = self._session_manager.import_session_record(
                record,
                source="archive",
                new_session_id=imported_session_id,
            )
            for row in transcript_rows:
                self._restore_transcript_row(imported_session_id, row)
            for name, data in members.items():
                if not name.startswith(_CHECKPOINT_PREFIX):
                    continue
                checkpoint = Checkpoint.model_validate_json(data.decode("utf-8"))
                rewritten_state = _rewrite_checkpoint_session_ids(
                    checkpoint.state,
                    original_session_id=original_session_id,
                    imported_session_id=imported_session_id,
                )
                imported_checkpoint = self._checkpoint_store.create(
                    imported_session,
                    state=rewritten_state,
                )
                imported_checkpoint_ids.append(imported_checkpoint.checkpoint_id)
            if len(imported_checkpoint_ids) != manifest.checkpoint_count:
                raise SessionArchiveError("archive_checkpoint_count_mismatch")
        except (OSError, ValidationError, ValueError, TypeError) as exc:
            if imported_session is not None:
                for checkpoint_id in imported_checkpoint_ids:
                    self._checkpoint_store.delete(checkpoint_id)
                self._transcript_store.delete_session(imported_session.id)
                self._lockdown_manager.clear_state(imported_session.id)
                self._session_manager.terminate(imported_session.id, reason="archive_import_failed")
            raise SessionArchiveError(str(exc)) from exc

        return SessionArchiveImportResult(
            session=imported_session,
            original_session_id=original_session_id,
            archive_path=archive_path,
            checkpoint_ids=tuple(imported_checkpoint_ids),
            transcript_entries=len(transcript_rows),
        )

    def _default_archive_path(self, session_id: SessionId) -> Path:
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        return self._archive_dir / f"{session_id}-{timestamp}{_ARCHIVE_SUFFIX}"

    def _transcript_rows_for(self, session_id: SessionId) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for entry in self._transcript_store.list_entries(session_id):
            if entry.blob_ref:
                content = self._transcript_store.read_blob(entry.blob_ref)
                if content is None:
                    raise SessionArchiveError("missing_transcript_blob")
            else:
                content = entry.content_preview
            metadata = dict(entry.metadata)
            metadata.pop("evidence_ref_id", None)
            if entry.evidence_ref_id:
                metadata["archived_evidence_ref_id"] = entry.evidence_ref_id
            rows.append(
                {
                    "role": entry.role,
                    "content": content,
                    "taint_labels": [label.value for label in entry.taint_labels],
                    "timestamp": entry.timestamp.isoformat(),
                    "metadata": metadata,
                    "content_hash": entry.content_hash,
                }
            )
        return rows

    def _load_archive_members(self, archive_path: Path) -> dict[str, bytes]:
        if not archive_path.exists():
            raise SessionArchiveError("archive_not_found")
        members: dict[str, bytes] = {}
        total_bytes = 0
        try:
            with zipfile.ZipFile(archive_path, "r") as archive:
                infos = archive.infolist()
                if len(infos) > _ARCHIVE_MAX_MEMBER_COUNT:
                    raise SessionArchiveError("archive_too_many_members")
                for info in infos:
                    name = info.filename
                    _validate_archive_member_name(name)
                    if name in members:
                        raise SessionArchiveError("duplicate_archive_member")
                    if info.flag_bits & _ZIP_FLAG_ENCRYPTED:
                        raise SessionArchiveError("encrypted_archive")
                    if info.file_size > _ARCHIVE_MAX_MEMBER_BYTES:
                        raise SessionArchiveError("archive_member_too_large")
                    total_bytes += int(info.file_size)
                    if total_bytes > _ARCHIVE_MAX_TOTAL_BYTES:
                        raise SessionArchiveError("archive_too_large")
                    members[name] = self._read_archive_member(archive, info)
        except zipfile.BadZipFile as exc:
            raise SessionArchiveError("invalid_archive") from exc
        except RuntimeError as exc:
            raise _normalize_archive_runtime_error(exc) from exc
        except NotImplementedError as exc:
            raise SessionArchiveError("invalid_archive") from exc
        except OSError as exc:
            raise SessionArchiveError("archive_read_failed") from exc
        return members

    @staticmethod
    def _read_archive_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
        total_read = 0
        chunks: list[bytes] = []
        with archive.open(info, "r") as handle:
            while True:
                chunk = handle.read(_ARCHIVE_READ_CHUNK_BYTES)
                if not chunk:
                    break
                total_read += len(chunk)
                if total_read > _ARCHIVE_MAX_MEMBER_BYTES:
                    raise SessionArchiveError("archive_member_too_large")
                chunks.append(chunk)
        return b"".join(chunks)

    def _validate_manifest(self, members: dict[str, bytes]) -> SessionArchiveManifest:
        manifest_bytes = members.get(_MANIFEST_PATH)
        if manifest_bytes is None:
            raise SessionArchiveError("missing_manifest")
        try:
            manifest = SessionArchiveManifest.model_validate_json(manifest_bytes.decode("utf-8"))
        except (ValidationError, UnicodeDecodeError, ValueError) as exc:
            raise SessionArchiveError("invalid_manifest") from exc
        if manifest.format != _ARCHIVE_FORMAT or manifest.version != _ARCHIVE_VERSION:
            raise SessionArchiveError("unsupported_archive_version")
        expected_members = set(manifest.entries)
        actual_members = set(members) - {_MANIFEST_PATH}
        if expected_members != actual_members:
            raise SessionArchiveError("manifest_member_mismatch")
        for name, expected_hash in manifest.entries.items():
            actual = members.get(name)
            if actual is None or _sha256_bytes(actual) != expected_hash:
                raise SessionArchiveError("archive_checksum_mismatch")
        return manifest

    @staticmethod
    def _parse_json_member(members: dict[str, bytes], name: str) -> Any:
        payload = members.get(name)
        if payload is None:
            raise SessionArchiveError(f"missing_{name}")
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SessionArchiveError(f"invalid_{name}") from exc

    @staticmethod
    def _validate_scope_consistency(
        manifest: SessionArchiveManifest,
        record: dict[str, Any],
    ) -> None:
        session_payload = record.get("session")
        if not isinstance(session_payload, dict):
            raise SessionArchiveError("invalid_session_record")
        if str(session_payload.get("id", "")).strip() != str(manifest.original_session_id).strip():
            raise SessionArchiveError("archive_session_id_mismatch")
        if str(session_payload.get("channel", "")).strip() != manifest.channel:
            raise SessionArchiveError("archive_channel_mismatch")
        if str(session_payload.get("user_id", "")).strip() != manifest.user_id:
            raise SessionArchiveError("archive_user_id_mismatch")
        if str(session_payload.get("workspace_id", "")).strip() != manifest.workspace_id:
            raise SessionArchiveError("archive_workspace_id_mismatch")
        if str(session_payload.get("role", "")).strip() != manifest.role:
            raise SessionArchiveError("archive_role_mismatch")
        if str(session_payload.get("mode", "")).strip() != manifest.mode:
            raise SessionArchiveError("archive_mode_mismatch")
        if manifest.capability_hash and _capability_hash(
            session_payload.get("capabilities")
        ) != str(manifest.capability_hash).strip():
            raise SessionArchiveError("archive_capability_mismatch")
        record_lockdown = record.get("lockdown")
        record_level = (
            str(record_lockdown.get("level", "")).strip()
            if isinstance(record_lockdown, dict)
            else ""
        )
        if record_level != manifest.lockdown_level:
            raise SessionArchiveError("archive_lockdown_mismatch")

    def _restore_transcript_row(self, session_id: SessionId, row: Any) -> None:
        if not isinstance(row, dict):
            raise SessionArchiveError("invalid_transcript_row")
        content = str(row.get("content", ""))
        content_hash = str(row.get("content_hash", "")).strip()
        role = str(row.get("role", "")).strip()
        timestamp = str(row.get("timestamp", "")).strip()
        if not role or not timestamp or not content_hash:
            raise SessionArchiveError("invalid_transcript_row")
        if _sha256_bytes(content.encode("utf-8")) != content_hash:
            raise SessionArchiveError("transcript_hash_mismatch")
        metadata = row.get("metadata", {})
        if not isinstance(metadata, dict):
            raise SessionArchiveError("invalid_transcript_row_metadata")
        parsed_timestamp = datetime.fromisoformat(timestamp)
        taints: set[TaintLabel] = set()
        for label in row.get("taint_labels", []):
            taints.add(TaintLabel(str(label)))
        self._transcript_store.append(
            session_id,
            role=role,
            content=content,
            taint_labels=set(taints),
            metadata=dict(metadata),
            evidence_ref_id=None,
            timestamp=parsed_timestamp,
        )


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validate_archive_member_name(name: str) -> None:
    candidate = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or name.startswith("/")
        or name.endswith("/")
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise SessionArchiveError("invalid_archive_member")
    if name in {_MANIFEST_PATH, _SESSION_PATH, _TRANSCRIPT_PATH}:
        return
    if name.startswith(_CHECKPOINT_PREFIX) and name.endswith(".json"):
        return
    raise SessionArchiveError("invalid_archive_member")


def _rewrite_checkpoint_session_ids(
    state: dict[str, Any],
    *,
    original_session_id: SessionId,
    imported_session_id: SessionId,
) -> dict[str, Any]:
    def _looks_like_session_payload(payload: dict[str, Any]) -> bool:
        return (
            payload.get("id") == str(original_session_id)
            and {"channel", "user_id", "workspace_id", "session_key"}.issubset(payload)
        )

    def _rewrite(value: Any, *, parent_key: str = "") -> Any:
        if isinstance(value, dict):
            rewritten = {
                key: _rewrite(item, parent_key=key)
                for key, item in value.items()
            }
            if _looks_like_session_payload(rewritten):
                rewritten["id"] = str(imported_session_id)
            return rewritten
        if isinstance(value, list):
            return [_rewrite(item, parent_key=parent_key) for item in value]
        if (
            isinstance(value, str)
            and parent_key == "session_id"
            and value == str(original_session_id)
        ):
            return str(imported_session_id)
        return value

    rewritten = _rewrite(state)
    if not isinstance(rewritten, dict):
        return dict(state)
    return rewritten


def _capability_hash(capabilities: Any) -> str:
    if isinstance(capabilities, set | list):
        normalized = sorted(str(item) for item in capabilities)
    elif capabilities in (None, ""):
        normalized = []
    else:
        normalized = [str(capabilities)]
    payload = json.dumps(normalized, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalize_archive_runtime_error(exc: RuntimeError) -> SessionArchiveError:
    message = str(exc).strip().lower()
    if "encrypted" in message or "password" in message:
        return SessionArchiveError("encrypted_archive")
    return SessionArchiveError("invalid_archive")
