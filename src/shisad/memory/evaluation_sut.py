"""JSONL memory evaluation SUT used by MELT."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from shisad import __version__
from shisad.core.providers.base import OpenAICompatibleProvider
from shisad.core.providers.embeddings_adapter import SyncEmbeddingsAdapter
from shisad.memory.consolidation.config import ConsolidationConfig
from shisad.memory.consolidation.worker import ConsolidationWorker
from shisad.memory.ingestion import EmbeddingFingerprint
from shisad.memory.runtime_wiring import (
    MemoryRuntimeComponents,
    build_memory_runtime_components,
    deterministic_embedding_fingerprint,
)
from shisad.memory.schema import MemoryEntry, MemorySource

CONTRACT_VERSION = "b2"
SUPPORTED_CAPABILITIES = (
    "reset",
    "time_control",
    "consolidation",
    "query_as_of",
    "structured_memory_write",
)
SOFT_UNSUPPORTED_CAPABILITIES = ("answer_generation",)
CAPABILITY_VOCABULARY = SUPPORTED_CAPABILITIES + SOFT_UNSUPPORTED_CAPABILITIES
_STATE_ROOT_MARKER = ".shisad-memory-sut-state-root"
_TOKEN_RE = re.compile(r"[a-z0-9]{2,80}", re.IGNORECASE)
_SECRET_VALUE_DELIMITER_RE = re.compile(r"[?#&;]")
_SECRET_URL_PARAM_RE = re.compile(
    r"(?:^|[?&#;])[^=&#;]*(?:api[_-]?key|secret|token|password|cookie|authorization)[^=&#;]*=",
    re.IGNORECASE,
)
_SECRET_URL_KEY_RE = re.compile(
    r"(?:api[_-]?key|secret|token|password|cookie|authorization)",
    re.IGNORECASE,
)
_URLISH_TOKEN_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+|[^\s\"'<>]*@[^\s\"'<>]+|[^\s\"'<>]*[?#&;][^\s\"'<>]+"
)


@dataclass(frozen=True)
class _OwnerScope:
    user_id: str
    workspace_id: str


@dataclass(frozen=True)
class _SutPaths:
    state_dir: Path
    config_dir: Path
    artifact_dir: Path


class _ProtocolError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class EvaluationSutSession:
    """Stateful handler for one MELT-launched shisad SUT process."""

    def __init__(self) -> None:
        self._owner: _OwnerScope | None = None
        self._paths: _SutPaths | None = None
        self._components: MemoryRuntimeComponents | None = None
        self._worker: ConsolidationWorker | None = None
        self._embedding_mode = "deterministic"
        self._embedding_fingerprint = deterministic_embedding_fingerprint()
        self._embeddings_adapter: SyncEmbeddingsAdapter | None = None
        self._config_overrides_accepted: dict[str, object] = {}
        self._config_overrides_rejected: dict[str, str] = {}
        self._public_redaction_literals: set[str] = set()

    def close(self) -> None:
        if self._embeddings_adapter is not None:
            self._embeddings_adapter.close(wait=False)
            self._embeddings_adapter = None

    def redact_public_text(self, text: str) -> str:
        return _redact_public_text(text, secret_literals=self._public_redaction_literals)

    def handle(self, message: dict[str, Any]) -> dict[str, Any]:
        op = _required_text(message, "op")
        if op == "hello":
            return self._hello(message)
        if op == "shutdown":
            self.close()
            return {"op": "shutdown_ack", "ok": True}
        if self._components is None or self._owner is None:
            raise _ProtocolError("session_not_initialized", "hello must be accepted first")
        if op == "metadata":
            return self._metadata()
        if op == "reset":
            return self._reset(message)
        if op == "ingest":
            return self._ingest(message)
        if op == "memory_write":
            return self._memory_write(message)
        if op in {"consolidate", "tick"}:
            return self._consolidate(message, response_op=f"{op}_ack")
        if op == "query":
            return self._query(message)
        if op == "answer":
            return _error_response(
                "answer_result",
                "unsupported_capability",
                "answer_generation is not supported by the shisad evaluation SUT",
            )
        raise _ProtocolError("unsupported_operation", f"unsupported operation: {op}")

    def _hello(self, message: dict[str, Any]) -> dict[str, Any]:
        requested_version = _required_text(message, "contract_version")
        if requested_version != CONTRACT_VERSION:
            return _error_response(
                "hello_ack",
                "unsupported_contract_version",
                f"unsupported contract_version {requested_version!r}; expected {CONTRACT_VERSION}",
            )
        try:
            owner = _parse_owner(message.get("owner"))
            paths = _parse_paths(message.get("paths"))
            _prepare_state_dir(paths.state_dir)
            requested = _string_list(
                message.get("capabilities_requested", []),
                "capabilities_requested",
            )
        except _ProtocolError as exc:
            return _error_response("hello_ack", exc.code, exc.message)
        unknown = sorted(set(requested) - set(CAPABILITY_VOCABULARY))
        if unknown:
            return _error_response(
                "hello_ack",
                "unknown_capability",
                f"unknown capabilities requested: {', '.join(unknown)}",
            )

        self.close()
        self._owner = owner
        self._paths = paths
        self._configure_embedding_overrides(message.get("config_overrides") or {})
        self._build_components()
        supported = [item for item in requested if item in SUPPORTED_CAPABILITIES]
        unsupported = [item for item in requested if item not in SUPPORTED_CAPABILITIES]
        return {
            "op": "hello_ack",
            "ok": True,
            "contract_version": CONTRACT_VERSION,
            "identity": _identity(),
            "capabilities_supported": supported,
            "capabilities_unsupported": unsupported,
            "envelope_metadata": self._envelope_metadata(),
            "config_overrides_accepted": self._config_overrides_accepted,
            "config_overrides_rejected": self._config_overrides_rejected,
            "session_poisoned": False,
        }

    def _metadata(self) -> dict[str, Any]:
        identity = _identity()
        return {
            "op": "metadata",
            "ok": True,
            **identity,
            "contract_version": CONTRACT_VERSION,
            "capabilities": list(SUPPORTED_CAPABILITIES),
            "capabilities_unsupported": list(SOFT_UNSUPPORTED_CAPABILITIES),
            "envelope_metadata": self._envelope_metadata(),
        }

    def _reset(self, message: dict[str, Any]) -> dict[str, Any]:
        paths = self._require_paths()
        run_id = _optional_text(message, "run_id") or ""
        _prepare_state_dir(paths.state_dir)
        _clear_directory_contents(paths.state_dir)
        self._build_components()
        return {"op": "reset_ack", "ok": True, "run_id": run_id}

    def _ingest(self, message: dict[str, Any]) -> dict[str, Any]:
        components = self._require_components()
        owner = self._require_owner()
        event_id = _required_text(message, "event_id")
        content = _required_text(message, "content")
        source_type = _optional_text(message, "source_type") or "user"
        if source_type not in {"user", "external", "tool"}:
            raise _ProtocolError(
                "invalid_source_type",
                "source_type must be user, external, or tool",
            )
        timestamp = _parse_optional_timestamp(message.get("timestamp"))
        source_id = f"melt:event:{event_id}"
        result = components.ingestion.ingest(
            source_id=source_id,
            source_type=source_type,  # type: ignore[arg-type]
            content=content,
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
            created_at=timestamp,
        )
        return {
            "op": "ack",
            "ok": True,
            "event_id": event_id,
            "source_id": result.source_id,
            "chunk_id": result.chunk_id,
            "created_at": _format_timestamp(result.created_at),
        }

    def _memory_write(self, message: dict[str, Any]) -> dict[str, Any]:
        components = self._require_components()
        owner = self._require_owner()
        entry_type = _required_text(message, "entry_type")
        key = _required_text(message, "key")
        value = message.get("value")
        if value is None:
            raise _ProtocolError("missing_field", "missing required field: value")
        source_id = _optional_text(message, "source_id") or f"melt:memory:{key}"
        timestamp = _parse_optional_timestamp(message.get("timestamp"))
        decision = components.memory_manager.write_with_provenance(
            entry_type=entry_type,
            key=key,
            value=value,
            predicate=_optional_text(message, "predicate"),
            strength=_optional_text(message, "strength") or "moderate",
            source=MemorySource(
                origin="user",
                source_id=source_id,
                extraction_method="melt_sut_structured_memory_write",
            ),
            source_origin="user_direct",
            channel_trust="command",
            confirmation_status="user_asserted",
            source_id=source_id,
            scope="user",
            confidence=float(message.get("confidence", 0.95)),
            confirmation_satisfied=True,
            supersedes=_optional_text(message, "supersedes"),
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
            created_at=timestamp,
        )
        if decision.kind != "allow" or decision.entry is None:
            return _error_response(
                "memory_write_ack",
                "memory_write_rejected",
                decision.reason or "memory write rejected",
            )
        entry = decision.entry
        return {
            "op": "memory_write_ack",
            "ok": True,
            "entry_id": entry.id,
            "source_id": entry.source_id,
            "created_at": _format_timestamp(entry.created_at),
        }

    def _consolidate(self, message: dict[str, Any], *, response_op: str) -> dict[str, Any]:
        worker = self._require_worker()
        result = worker.run_once(now=_parse_optional_timestamp(message.get("timestamp")))
        return {
            "op": response_op,
            "ok": True,
            "updated_entry_ids": result.updated_entry_ids,
            "corroborating_entry_ids": result.corroborating_entry_ids,
            "contradicted_entry_ids": result.contradicted_entry_ids,
            "merged_entry_ids": result.merged_entry_ids,
            "archive_candidate_ids": result.archive_candidate_ids,
            "quarantined_entry_ids": result.quarantined_entry_ids,
        }

    def _query(self, message: dict[str, Any]) -> dict[str, Any]:
        components = self._require_components()
        owner = self._require_owner()
        query_id = _required_text(message, "query_id")
        query = _required_text(message, "query")
        top_k = _positive_int(message.get("top_k", 5), "top_k")
        as_of = _parse_optional_timestamp(message.get("timestamp") or message.get("as_of"))
        pack = components.ingestion.compile_recall(
            query,
            limit=top_k,
            as_of=as_of,
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
        )
        evidence = [
            _retrieval_evidence(result, rank=index + 1)
            for index, result in enumerate(pack.results)
        ]
        if len(evidence) < top_k:
            evidence.extend(
                self._structured_evidence(
                    query=query,
                    as_of=as_of,
                    start_rank=len(evidence) + 1,
                    limit=top_k - len(evidence),
                )
            )
        return {
            "op": "query_result",
            "ok": True,
            "query_id": query_id,
            "answer": "",
            "evidence": evidence,
            "owner": {"user_id": owner.user_id, "workspace_id": owner.workspace_id},
            "as_of": _format_timestamp(as_of) if as_of is not None else None,
        }

    def _structured_evidence(
        self,
        *,
        query: str,
        as_of: datetime | None,
        start_rank: int,
        limit: int,
    ) -> list[dict[str, Any]]:
        components = self._require_components()
        owner = self._require_owner()
        entries = components.memory_manager.list_entries(
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
            limit=max(1, components.memory_manager.entry_count()),
        )
        evidence: list[dict[str, Any]] = []
        for entry in entries:
            if self._entry_superseded_at_or_before_as_of(entry, as_of=as_of):
                continue
            if as_of is not None and entry.created_at > as_of:
                continue
            if not _structured_entry_matches_query(entry, query):
                continue
            evidence.append(
                _memory_entry_evidence(
                    entry,
                    rank=start_rank + len(evidence),
                    entries=entries,
                    as_of=as_of,
                )
            )
            if len(evidence) >= limit:
                break
        return evidence

    def _entry_superseded_at_or_before_as_of(
        self,
        entry: MemoryEntry,
        *,
        as_of: datetime | None,
    ) -> bool:
        if entry.superseded_by is None:
            return False
        if as_of is None:
            return True
        components = self._require_components()
        owner = self._require_owner()
        successor = components.memory_manager.get_entry(
            entry.superseded_by,
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
        )
        if successor is None:
            return True
        return successor.created_at <= as_of

    def _configure_embedding_overrides(self, raw_overrides: object) -> None:
        self._embedding_mode = "deterministic"
        self._embedding_fingerprint = deterministic_embedding_fingerprint()
        self._config_overrides_accepted = {"embedding_mode": "deterministic"}
        self._config_overrides_rejected = {}
        self._public_redaction_literals = set()
        if not isinstance(raw_overrides, dict):
            self._config_overrides_rejected["config_overrides"] = "must be an object"
            return
        mode = raw_overrides.get("embedding_mode", "deterministic")
        if mode in {None, "deterministic"}:
            return
        if mode != "provider":
            self._config_overrides_rejected["embedding_mode"] = "unsupported embedding mode"
            return
        base_url = _non_empty_override(raw_overrides, "embedding_base_url")
        api_key = _non_empty_override(raw_overrides, "embedding_api_key")
        model_id = _non_empty_override(raw_overrides, "embedding_model_id")
        missing = [
            key
            for key, value in (
                ("embedding_base_url", base_url),
                ("embedding_api_key", api_key),
                ("embedding_model_id", model_id),
            )
            if value is None
        ]
        if missing:
            self._config_overrides_rejected["embedding_mode"] = (
                "provider mode requires " + ", ".join(missing)
            )
            return
        provider = OpenAICompatibleProvider(
            base_url=str(base_url),
            model_id=str(model_id),
            headers={"Authorization": f"Bearer {api_key}"},
        )
        self._public_redaction_literals.add(str(api_key))
        self._public_redaction_literals.update(_url_secret_literals(str(base_url)))
        self._embeddings_adapter = SyncEmbeddingsAdapter(provider, model_id=str(model_id))
        self._embedding_mode = "provider"
        public_base_url = _public_embedding_base_url(str(base_url))
        self._embedding_fingerprint = EmbeddingFingerprint(
            model_id=str(model_id),
            base_url=public_base_url,
        )
        self._config_overrides_accepted = {
            "embedding_mode": "provider",
            "embedding_base_url": public_base_url,
            "embedding_model_id": str(model_id),
        }

    def _build_components(self) -> None:
        paths = self._require_paths()
        owner = self._require_owner()
        paths.state_dir.mkdir(parents=True, exist_ok=True)
        paths.config_dir.mkdir(parents=True, exist_ok=True)
        paths.artifact_dir.mkdir(parents=True, exist_ok=True)
        self._components = build_memory_runtime_components(
            paths.state_dir,
            embedding_fingerprint=self._embedding_fingerprint,
            embeddings_provider=self._embeddings_adapter,
            allow_embedding_fallback=self._embedding_mode != "provider",
        )
        self._worker = ConsolidationWorker(
            self._components.memory_manager,
            config=ConsolidationConfig(),
            scope_filter={"user"},
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
            require_owner_scope=True,
        )

    def _envelope_metadata(self) -> dict[str, object]:
        return {
            "embedding_mode": self._embedding_mode,
            "embedding_model": self._embedding_fingerprint.model_id,
            "embedding_base_url": _public_embedding_base_url(
                self._embedding_fingerprint.base_url
            ),
            "embedding_fingerprint": self._embedding_fingerprint.stable_hash(),
            "llm_model": None,
            "llm_calls_per_op": {
                "hello": 0,
                "reset": 0,
                "ingest": 0,
                "memory_write": 0,
                "consolidate": 0,
                "tick": 0,
                "query": 0,
                "answer": 0,
            },
            "storage_backend": "sqlite",
            "answer_generation": "unsupported",
            "session_poisoning": "operation_errors_do_not_poison_session",
        }

    def _require_components(self) -> MemoryRuntimeComponents:
        if self._components is None:
            raise _ProtocolError("session_not_initialized", "hello must be accepted first")
        return self._components

    def _require_worker(self) -> ConsolidationWorker:
        if self._worker is None:
            raise _ProtocolError("session_not_initialized", "hello must be accepted first")
        return self._worker

    def _require_owner(self) -> _OwnerScope:
        if self._owner is None:
            raise _ProtocolError("session_not_initialized", "hello must be accepted first")
        return self._owner

    def _require_paths(self) -> _SutPaths:
        if self._paths is None:
            raise _ProtocolError("session_not_initialized", "hello must be accepted first")
        return self._paths


def run_sut_jsonl(*, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """Run the SUT JSONL loop over text streams."""

    input_stream = stdin or sys.stdin
    output_stream = stdout or sys.stdout
    session = EvaluationSutSession()
    try:
        for raw_line in input_stream:
            if not raw_line.strip():
                continue
            payload: object | None = None
            try:
                payload = json.loads(raw_line)
                if not isinstance(payload, dict):
                    raise _ProtocolError("malformed_input", "JSONL messages must be objects")
                response = session.handle(payload)
            except json.JSONDecodeError as exc:
                response = _error_response("error", "malformed_input", str(exc))
            except _ProtocolError as exc:
                response = _error_response(
                    "error",
                    exc.code,
                    session.redact_public_text(exc.message),
                )
            except Exception as exc:
                response = _error_response(
                    "error",
                    "operation_failed",
                    session.redact_public_text(str(exc)),
                )
            output_stream.write(json.dumps(response, sort_keys=True, ensure_ascii=True) + "\n")
            output_stream.flush()
            if isinstance(payload, dict) and payload.get("op") == "shutdown":
                break
    finally:
        session.close()
    return 0


def _parse_owner(value: object) -> _OwnerScope:
    if not isinstance(value, dict):
        raise _ProtocolError("owner_scope_required", "owner must be an object")
    user_id = _clean_text(value.get("user_id"))
    workspace_id = _clean_text(value.get("workspace_id"))
    if user_id is None or workspace_id is None:
        raise _ProtocolError(
            "owner_scope_requires_user_and_workspace",
            "owner scope requires both user_id and workspace_id",
        )
    return _OwnerScope(user_id=user_id, workspace_id=workspace_id)


def _parse_paths(value: object) -> _SutPaths:
    if not isinstance(value, dict):
        raise _ProtocolError("paths_required", "paths must be an object")
    state_dir = _safe_directory_path(value.get("state_dir"), "paths.state_dir")
    config_dir = _safe_directory_path(value.get("config_dir"), "paths.config_dir")
    artifact_dir = _safe_directory_path(value.get("artifact_dir"), "paths.artifact_dir")
    return _SutPaths(
        state_dir=state_dir,
        config_dir=config_dir,
        artifact_dir=artifact_dir,
    )


def _safe_directory_path(value: object, field: str) -> Path:
    raw = _clean_text(value)
    if raw is None:
        raise _ProtocolError("missing_field", f"missing required field: {field}")
    path = Path(raw).expanduser().resolve()
    if path.parent == path or path == Path.home().resolve():
        raise _ProtocolError("unsafe_path", f"unsafe SUT path for {field}: {path}")
    return path


def _clear_directory_contents(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.name == _STATE_ROOT_MARKER:
            continue
        if child.is_symlink() or child.is_file():
            child.unlink()
        elif child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink(missing_ok=True)


def _prepare_state_dir(path: Path) -> None:
    marker = path / _STATE_ROOT_MARKER
    if path.exists() and not path.is_dir():
        raise _ProtocolError("unsafe_path", f"state_dir must be a directory: {path}")
    if path.exists() and not marker.exists() and any(path.iterdir()):
        raise _ProtocolError(
            "unsafe_path",
            f"state_dir must be empty or marked as a shisad memory SUT state root: {path}",
        )
    path.mkdir(parents=True, exist_ok=True)
    marker.touch(exist_ok=True)


def _identity() -> dict[str, str]:
    return {
        "id": "shisad",
        "version": __version__,
        "commit": _git_commit(),
    }


def _git_commit() -> str:
    repo_root = Path(__file__).resolve().parents[3]
    try:
        head = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--short", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "source"
    if not head:
        return "source"
    return f"{head}-dirty" if dirty else head


def _retrieval_evidence(result: Any, *, rank: int) -> dict[str, Any]:
    return {
        "surface": "retrieval",
        "source_id": result.source_id,
        "chunk_id": result.chunk_id,
        "rank": rank,
        "created_at": _format_timestamp(result.created_at),
        "owner": {"user_id": result.user_id, "workspace_id": result.workspace_id},
        "content": result.content_sanitized,
        "scores": {
            "lexical": result.lexical_score,
            "semantic": result.semantic_score,
            "effective": result.effective_score,
        },
    }


def _memory_entry_evidence(
    entry: MemoryEntry,
    *,
    rank: int,
    entries: list[MemoryEntry] | None = None,
    as_of: datetime | None = None,
) -> dict[str, Any]:
    entries_by_id = {candidate.id: candidate for candidate in entries or []}
    metadata: dict[str, Any] = {"decay_score": entry.decay_score}
    if entry.supersedes is not None:
        metadata["supersedes"] = entry.supersedes
        superseded = entries_by_id.get(entry.supersedes)
        if superseded is not None and _memory_entry_visible_at(superseded, as_of=as_of):
            metadata["supersedes_source_id"] = superseded.source_id or superseded.id
    successor = entries_by_id.get(entry.superseded_by or "")
    if successor is not None and _memory_entry_visible_at(successor, as_of=as_of):
        metadata["superseded_by"] = entry.superseded_by
        metadata["superseded_by_source_id"] = successor.source_id or successor.id
    if entry.conflict_entry_ids:
        visible_conflicts = [
            conflict
            for conflict_id in entry.conflict_entry_ids
            if (conflict := entries_by_id.get(conflict_id)) is not None
            and _memory_entry_visible_at(conflict, as_of=as_of)
        ]
        if visible_conflicts:
            metadata["conflict_entry_ids"] = [conflict.id for conflict in visible_conflicts]
            metadata["conflict_source_ids"] = [
                conflict.source_id or conflict.id for conflict in visible_conflicts
            ]
    return {
        "surface": "structured_memory",
        "source_id": entry.source_id or entry.id,
        "entry_id": entry.id,
        "rank": rank,
        "created_at": _format_timestamp(entry.created_at),
        "owner": {"user_id": entry.user_id, "workspace_id": entry.workspace_id},
        "entry_type": entry.entry_type,
        "key": entry.key,
        "value": entry.value,
        "metadata": metadata,
    }


def _memory_entry_visible_at(entry: MemoryEntry, *, as_of: datetime | None) -> bool:
    return as_of is None or entry.created_at <= as_of


def _structured_entry_matches_query(entry: MemoryEntry, query: str) -> bool:
    query_terms = _tokens(query)
    if not query_terms:
        return False
    entry_terms = _tokens(
        " ".join(
            str(part)
            for part in (
                entry.entry_type,
                entry.key,
                entry.predicate or "",
                entry.value,
            )
        )
    )
    return bool(query_terms & entry_terms)


def _tokens(value: str) -> set[str]:
    return {match.group(0).casefold() for match in _TOKEN_RE.finditer(value)}


def _required_text(message: dict[str, Any], field: str) -> str:
    value = _clean_text(message.get(field))
    if value is None:
        raise _ProtocolError("missing_field", f"missing required field: {field}")
    return value


def _optional_text(message: dict[str, Any], field: str) -> str | None:
    return _clean_text(message.get(field))


def _clean_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _string_list(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _ProtocolError("invalid_field", f"{field} must be a list of strings")
    return [item for item in value if item]


def _positive_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise _ProtocolError("invalid_field", f"{field} must be a positive integer")
    return value


def _parse_optional_timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    raw = _clean_text(value)
    if raw is None:
        raise _ProtocolError("invalid_timestamp", "timestamp must be non-empty text")
    normalized = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise _ProtocolError("invalid_timestamp", f"invalid timestamp: {raw}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _non_empty_override(overrides: dict[str, object], key: str) -> str | None:
    value = overrides.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _public_embedding_base_url(base_url: str) -> str:
    try:
        parts = urlsplit(base_url)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return "<redacted>"
    if not parts.scheme or not parts.netloc or not hostname:
        if _has_secret_url_parts(base_url):
            return "<redacted>"
        return base_url
    if _raw_urlish_secret_literals(parts.path):
        return "<redacted>"
    netloc = hostname
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _redact_public_text(
    text: str, *, secret_literals: set[str] | frozenset[str] = frozenset()
) -> str:
    redacted = _URLISH_TOKEN_RE.sub(lambda match: _public_urlish_token(match.group(0)), text)
    for literal in sorted(secret_literals, key=len, reverse=True):
        if literal:
            redacted = redacted.replace(literal, "<redacted>")
    return redacted


def _public_urlish_token(token: str) -> str:
    if not _has_secret_url_parts(token):
        return token
    return _public_embedding_base_url(token)


def _has_secret_url_parts(value: str) -> bool:
    return (
        _has_raw_url_credentials(value)
        or bool(_SECRET_URL_PARAM_RE.search(value))
        or bool(_url_secret_literals(value))
    )


def _url_secret_literals(value: str) -> set[str]:
    literals: set[str] = set()
    literals.update(_raw_urlish_secret_literals(value))
    if "@" in value:
        authority_source = value.split("://", 1)[1] if "://" in value else value
        authority = authority_source.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        userinfo = authority.rsplit("@", 1)[0]
        if userinfo:
            literals.add(userinfo)
    try:
        parts = urlsplit(value)
    except ValueError:
        literals.update(_raw_urlish_secret_literals(value))
        return literals
    for key, inner in _decoded_url_pairs(parts.query):
        if inner and _SECRET_URL_KEY_RE.search(key):
            _add_url_secret_literal(literals, inner)
    for key, inner in _raw_url_pairs(parts.query):
        if inner and _SECRET_URL_KEY_RE.search(key):
            _add_url_secret_literal(literals, inner)
    for key, inner in _fragment_pairs(parts.fragment):
        if inner and _SECRET_URL_KEY_RE.search(key):
            _add_url_secret_literal(literals, inner)
    for key, inner in _raw_fragment_pairs(parts.fragment):
        if inner and _SECRET_URL_KEY_RE.search(key):
            _add_url_secret_literal(literals, inner)
    return literals


def _raw_urlish_secret_literals(value: str) -> set[str]:
    literals: set[str] = set()
    before_fragment, _, fragment = value.partition("#")
    for parameter_text in _raw_urlish_parameter_texts(before_fragment):
        for key, inner in _decoded_url_pairs(parameter_text):
            if inner and _SECRET_URL_KEY_RE.search(key):
                _add_url_secret_literal(literals, inner)
        for key, inner in _raw_url_pairs(parameter_text):
            if inner and _SECRET_URL_KEY_RE.search(key):
                _add_url_secret_literal(literals, inner)
    for parameter_text in _raw_urlish_parameter_texts(fragment):
        for key, inner in _decoded_url_pairs(parameter_text):
            if inner and _SECRET_URL_KEY_RE.search(key):
                _add_url_secret_literal(literals, inner)
        for key, inner in _raw_url_pairs(parameter_text):
            if inner and _SECRET_URL_KEY_RE.search(key):
                _add_url_secret_literal(literals, inner)
    for key, inner in _fragment_pairs(fragment):
        if inner and _SECRET_URL_KEY_RE.search(key):
            _add_url_secret_literal(literals, inner)
    for key, inner in _raw_fragment_pairs(fragment):
        if inner and _SECRET_URL_KEY_RE.search(key):
            _add_url_secret_literal(literals, inner)
    return literals


def _raw_urlish_parameter_texts(value: str) -> list[str]:
    texts: list[str] = []
    for marker in ("?", "&", ";"):
        start = 0
        while True:
            index = value.find(marker, start)
            if index == -1:
                break
            text = value[index + 1 :]
            if marker in {"&", ";"} and "?" in text:
                text = text.split("?", 1)[0]
            texts.append(text)
            start = index + 1
    return texts


def _decoded_url_pairs(value: str) -> list[tuple[str, str]]:
    pairs = parse_qsl(value, keep_blank_values=True)
    if ";" in value:
        pairs.extend(parse_qsl(value.replace(";", "&"), keep_blank_values=True))
    return pairs


def _raw_url_pairs(value: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for part in re.split(r"[&;]", value):
        if not part:
            continue
        key, separator, inner = part.partition("=")
        pairs.append((key, inner if separator else ""))
    return pairs


def _fragment_pairs(fragment: str) -> list[tuple[str, str]]:
    if not fragment:
        return []
    if "?" in fragment:
        return _decoded_url_pairs(fragment.split("?", 1)[1])
    return _decoded_url_pairs(fragment)


def _raw_fragment_pairs(fragment: str) -> list[tuple[str, str]]:
    if not fragment:
        return []
    if "?" in fragment:
        return _raw_url_pairs(fragment.split("?", 1)[1])
    return _raw_url_pairs(fragment)


def _add_url_secret_literal(literals: set[str], value: str) -> None:
    if not value:
        return
    literals.add(value)
    prefix = _SECRET_VALUE_DELIMITER_RE.split(value, maxsplit=1)[0]
    if prefix:
        literals.add(prefix)


def _has_raw_url_credentials(value: str) -> bool:
    if "@" not in value:
        return False
    authority_source = value.split("://", 1)[1] if "://" in value else value
    authority = authority_source.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    userinfo = authority.rsplit("@", 1)[0]
    return bool(userinfo)


def _error_response(op: str, code: str, message: str) -> dict[str, Any]:
    return {
        "op": op,
        "ok": False,
        "error": {
            "code": code,
            "message": message,
        },
    }
