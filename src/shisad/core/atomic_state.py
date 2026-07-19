from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter, ValidationError
from pydantic_core import to_jsonable_python

from shisad.core.storage_platform import (
    StorageCapability,
    combine_permission_capabilities,
    sync_parent_directory,
    tighten_permissions,
)


class AtomicWriteStage(StrEnum):
    TARGET_VALIDATE = "target_validate"
    DIRECTORY_PREPARE = "directory_prepare"
    TEMP_OPEN = "temp_open"
    WRITE = "write"
    FILE_FSYNC = "file_fsync"
    REPLACE = "replace"
    PARENT_FSYNC = "parent_fsync"


class StateLoadStatus(StrEnum):
    MISSING = "missing"
    OK = "ok"
    CORRUPT = "corrupt"
    UNSUPPORTED_SCHEMA = "unsupported_schema"


AtomicWriteFaultInjector = Callable[[AtomicWriteStage], None]
LegacyDecoder = Callable[[bytes], Any]


@dataclass(frozen=True, slots=True)
class StateLoadResult[T]:
    status: StateLoadStatus
    value: T | None = None
    reason: str = ""


class AtomicWriteError(RuntimeError):
    def __init__(
        self, *, path: Path, stage: AtomicWriteStage, publication_may_have_committed: bool
    ) -> None:
        self.path = path
        self.stage = stage
        self.publication_may_have_committed = publication_may_have_committed
        commitment = "commit uncertain" if publication_may_have_committed else "not committed"
        super().__init__(f"atomic state write failed at {stage.value} ({commitment}): {path}")


class StatePersistenceDegradedError(ValueError):
    def __init__(self, *, authority: str, transition: str, stage: str, reason: str) -> None:
        self.authority = authority
        self.transition = transition
        self.stage = stage
        self.reason = reason
        super().__init__(
            f"{authority} persistence is degraded: transition={transition} "
            f"stage={stage} reason={reason}"
        )


def _fail(path: Path, stage: AtomicWriteStage, committed: bool = False) -> AtomicWriteError:
    return AtomicWriteError(path=path, stage=stage, publication_may_have_committed=committed)


def _validate_target(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    except OSError as exc:
        raise _fail(path, AtomicWriteStage.TARGET_VALIDATE) from exc
    if not stat.S_ISREG(mode):
        raise _fail(path, AtomicWriteStage.TARGET_VALIDATE)


def atomic_write_bytes(
    path: Path,
    payload: bytes,
    *,
    fault_injector: AtomicWriteFaultInjector | None = None,
) -> StorageCapability:
    target = Path(path)
    _validate_target(target)
    parent = target.parent
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise _fail(target, AtomicWriteStage.DIRECTORY_PREPARE) from exc
    directory_permissions = tighten_permissions(parent, 0o700)
    descriptor = -1
    temporary: Path | None = None
    replaced = False
    stage = AtomicWriteStage.TEMP_OPEN
    inject = fault_injector or (lambda _stage: None)
    try:
        inject(stage)
        descriptor, name = tempfile.mkstemp(dir=parent, prefix=f".{target.name}.", suffix=".tmp")
        temporary = Path(name)
        file_permissions = tighten_permissions(temporary, 0o600)
        stage = AtomicWriteStage.WRITE
        inject(stage)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("atomic state write made no progress")
            remaining = remaining[written:]
        stage = AtomicWriteStage.FILE_FSYNC
        inject(stage)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        stage = AtomicWriteStage.REPLACE
        inject(stage)
        os.replace(temporary, target)
        replaced = True
        file_permissions = tighten_permissions(target, 0o600)
        stage = AtomicWriteStage.PARENT_FSYNC
        inject(stage)
        parent_sync = sync_parent_directory(parent)
        permissions = combine_permission_capabilities(directory_permissions, file_permissions)
        return StorageCapability(parent_sync=parent_sync, permissions=permissions)
    except OSError as exc:
        raise _fail(target, stage, replaced) from exc
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if not replaced and temporary is not None:
            with contextlib.suppress(OSError):
                temporary.unlink()


class _RejectedJSON(ValueError):
    pass


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise _RejectedJSON(f"duplicate JSON member: {key}")
        value[key] = member
    return value


def _decode_json(raw: bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise _RejectedJSON(f"non-finite JSON number: {value}")

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_json_object,
        parse_constant=reject_constant,
    )


def _canonical_payload(payload: Any) -> bytes:
    value = to_jsonable_python(payload)
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def write_state(path: Path, payload: Any) -> StorageCapability:
    payload_bytes = _canonical_payload(payload)
    envelope = {
        "schema": 1,
        "sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "payload": json.loads(payload_bytes),
    }
    return atomic_write_bytes(Path(path), _canonical_payload(envelope))


def _legacy(
    raw: bytes, path: Path, model: Any, decoder: LegacyDecoder | None
) -> StateLoadResult[Any]:
    if decoder is None:
        return StateLoadResult(status=StateLoadStatus.CORRUPT, reason="invalid state envelope")
    try:
        value = TypeAdapter(model).validate_python(decoder(raw))
        write_state(path, value)
    except Exception as exc:
        return StateLoadResult(
            status=StateLoadStatus.CORRUPT,
            reason=f"legacy state publication failed: {exc}",
        )
    return StateLoadResult(status=StateLoadStatus.OK, value=value)


def load_state(
    path: Path, model: Any, legacy_decoder: LegacyDecoder | None = None
) -> StateLoadResult[Any]:
    target = Path(path)
    try:
        raw = target.read_bytes()
    except FileNotFoundError:
        return StateLoadResult(status=StateLoadStatus.MISSING)
    except OSError as exc:
        return StateLoadResult(status=StateLoadStatus.CORRUPT, reason=str(exc))
    try:
        document = _decode_json(raw)
    except _RejectedJSON as exc:
        return StateLoadResult(status=StateLoadStatus.CORRUPT, reason=str(exc))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return _legacy(raw, target, model, legacy_decoder)
    if not isinstance(document, dict) or set(document) != {"schema", "sha256", "payload"}:
        return _legacy(raw, target, model, legacy_decoder)
    schema = document["schema"]
    if type(schema) is not int or schema != 1:
        status = (
            StateLoadStatus.UNSUPPORTED_SCHEMA
            if type(schema) is int and schema > 1
            else StateLoadStatus.CORRUPT
        )
        return StateLoadResult(status=status, reason=f"unsupported state schema: {schema}")
    try:
        payload_bytes = _canonical_payload(document["payload"])
        checksum = document["sha256"]
        expected = hashlib.sha256(payload_bytes).hexdigest()
        if not isinstance(checksum, str) or not hmac.compare_digest(checksum, expected):
            raise ValueError("state checksum mismatch")
        value = TypeAdapter(model).validate_python(document["payload"])
    except (TypeError, ValueError, ValidationError) as exc:
        return StateLoadResult(status=StateLoadStatus.CORRUPT, reason=str(exc))
    return StateLoadResult(status=StateLoadStatus.OK, value=value)
