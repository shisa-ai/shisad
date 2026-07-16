"""Restrictive same-directory atomic publication for small state snapshots."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import stat
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any


class AtomicWriteStage(StrEnum):
    """Observable publication boundaries used by typed errors and fault tests."""

    TARGET_VALIDATE = "target_validate"
    DIRECTORY_PREPARE = "directory_prepare"
    TEMP_OPEN = "temp_open"
    WRITE = "write"
    FILE_FSYNC = "file_fsync"
    REPLACE = "replace"
    PARENT_FSYNC = "parent_fsync"


AtomicWriteFaultInjector = Callable[[AtomicWriteStage], None]


class DurableAppendStage(StrEnum):
    """Observable boundaries for owner-only append publication."""

    TARGET_VALIDATE = "target_validate"
    DIRECTORY_PREPARE = "directory_prepare"
    FILE_OPEN = "file_open"
    WRITE = "write"
    FILE_FSYNC = "file_fsync"
    PARENT_FSYNC = "parent_fsync"


DurableAppendFaultInjector = Callable[[DurableAppendStage], None]


class StateLoadStatus(StrEnum):
    """Finite load outcomes for security-relevant state snapshots."""

    OK = "ok"
    MISSING = "missing"
    CORRUPT = "corrupt"
    UNSUPPORTED_SCHEMA = "unsupported_schema"


@dataclass(frozen=True, slots=True)
class StateLoadResult:
    """Typed snapshot load status without discarding the original bytes."""

    status: StateLoadStatus
    reason: str = ""
    schema_version: int | None = None
    legacy: bool = False


class AtomicWriteError(RuntimeError):
    """State publication failed at a known durability boundary."""

    def __init__(
        self,
        *,
        path: Path,
        stage: AtomicWriteStage,
        publication_may_have_committed: bool,
    ) -> None:
        self.path = path
        self.stage = stage
        self.publication_may_have_committed = publication_may_have_committed
        commitment = "commit uncertain" if publication_may_have_committed else "not committed"
        super().__init__(f"atomic state write failed at {stage.value} ({commitment}): {path}")


class DurableAppendError(RuntimeError):
    """Append publication failed at a known durability boundary."""

    def __init__(
        self,
        *,
        path: Path,
        stage: DurableAppendStage,
        publication_may_have_committed: bool,
    ) -> None:
        self.path = path
        self.stage = stage
        self.publication_may_have_committed = publication_may_have_committed
        commitment = "commit uncertain" if publication_may_have_committed else "not committed"
        super().__init__(f"durable append failed at {stage.value} ({commitment}): {path}")


class StatePersistenceDegradedError(RuntimeError):
    """A state authority is blocked until explicit process recovery."""

    def __init__(
        self,
        *,
        authority: str,
        transition: str,
        stage: str,
        reason: str,
    ) -> None:
        self.authority = authority
        self.transition = transition
        self.stage = stage
        self.reason = reason
        super().__init__(
            f"{authority} persistence is degraded: transition={transition} "
            f"stage={stage} reason={reason}"
        )


def _missing_directory_chain(path: Path) -> list[Path]:
    """Return missing directories from the requested leaf toward an existing root."""

    missing: list[Path] = []
    current = path
    while True:
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            missing.append(current)
            parent = current.parent
            if parent == current:
                break
            current = parent
            continue
        if not stat.S_ISDIR(current_stat.st_mode):
            raise OSError("state parent is not a directory")
        break
    return missing


def _fsync_directory_path(path: Path) -> None:
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, directory_flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _inject_fault(
    fault_injector: AtomicWriteFaultInjector | None,
    stage: AtomicWriteStage,
) -> None:
    if fault_injector is not None:
        fault_injector(stage)


def _validate_existing_target(path: Path) -> None:
    try:
        target_stat = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AtomicWriteError(
            path=path,
            stage=AtomicWriteStage.TARGET_VALIDATE,
            publication_may_have_committed=False,
        ) from exc
    if not stat.S_ISREG(target_stat.st_mode):
        raise AtomicWriteError(
            path=path,
            stage=AtomicWriteStage.TARGET_VALIDATE,
            publication_may_have_committed=False,
        )


def _canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _snapshot_integrity_bytes(*, version: int, payload: Any) -> bytes:
    return _canonical_json_bytes({"payload": payload, "version": version})


def encode_versioned_json_snapshot(payload: Any, *, version: int = 1) -> bytes:
    """Encode a deterministic checksum-bound JSON snapshot envelope."""

    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("snapshot version must be a positive integer")
    checksum = hashlib.sha256(
        _snapshot_integrity_bytes(version=version, payload=payload)
    ).hexdigest()
    envelope = {
        "version": version,
        "checksum": checksum,
        "payload": payload,
    }
    return (
        json.dumps(
            envelope,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def decode_versioned_json_snapshot(
    raw_bytes: bytes,
    *,
    supported_version: int = 1,
) -> tuple[StateLoadResult, Any | None]:
    """Decode a checksum-bound envelope into a typed non-throwing load result."""

    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        return StateLoadResult(StateLoadStatus.CORRUPT, reason="invalid_json"), None
    if not isinstance(raw, dict):
        return StateLoadResult(StateLoadStatus.CORRUPT, reason="invalid_envelope"), None
    version = raw.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        return StateLoadResult(StateLoadStatus.CORRUPT, reason="invalid_schema_version"), None
    if version != supported_version:
        return (
            StateLoadResult(
                StateLoadStatus.UNSUPPORTED_SCHEMA,
                reason="unsupported_schema",
                schema_version=version,
            ),
            None,
        )
    checksum = raw.get("checksum")
    if not isinstance(checksum, str) or not checksum:
        return (
            StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="missing_checksum",
                schema_version=version,
            ),
            None,
        )
    if "payload" not in raw:
        return (
            StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="missing_payload",
                schema_version=version,
            ),
            None,
        )
    payload = raw["payload"]
    try:
        integrity_input = _snapshot_integrity_bytes(version=version, payload=payload)
    except (TypeError, ValueError, RecursionError):
        return (
            StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_payload",
                schema_version=version,
            ),
            None,
        )
    if not checksum.isascii():
        return (
            StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="invalid_checksum",
                schema_version=version,
            ),
            None,
        )
    actual_checksum = hashlib.sha256(integrity_input).hexdigest()
    if not hmac.compare_digest(checksum, actual_checksum):
        return (
            StateLoadResult(
                StateLoadStatus.CORRUPT,
                reason="checksum_mismatch",
                schema_version=version,
            ),
            None,
        )
    return (
        StateLoadResult(StateLoadStatus.OK, schema_version=version),
        payload,
    )


def atomic_write_bytes(
    path: Path,
    payload: bytes,
    *,
    fault_injector: AtomicWriteFaultInjector | None = None,
    preserve_existing_parent_mode: bool = False,
) -> None:
    """Publish owner-only bytes old-or-new and fsync the containing directory.

    Existing daemon-owned parents are restricted by default. Arbitrary-path
    callers may preserve an existing parent mode; newly created parents remain
    owner-only.
    """

    target = Path(path)
    _validate_existing_target(target)
    parent = target.parent
    parent_existed = parent.exists()
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not preserve_existing_parent_mode or not parent_existed:
            parent.chmod(0o700)
    except OSError as exc:
        raise AtomicWriteError(
            path=target,
            stage=AtomicWriteStage.DIRECTORY_PREPARE,
            publication_may_have_committed=False,
        ) from exc

    temp_path = parent / f".{target.name}.{uuid.uuid4().hex}.tmp"
    file_fd = -1
    parent_fd = -1
    replaced = False
    stage = AtomicWriteStage.TEMP_OPEN
    try:
        _inject_fault(fault_injector, stage)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(temp_path, flags, 0o600)
        os.fchmod(file_fd, 0o600)

        stage = AtomicWriteStage.WRITE
        _inject_fault(fault_injector, stage)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(file_fd, remaining)
            if written <= 0:
                raise OSError("atomic state write made no progress")
            remaining = remaining[written:]

        stage = AtomicWriteStage.FILE_FSYNC
        _inject_fault(fault_injector, stage)
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = -1

        stage = AtomicWriteStage.REPLACE
        _inject_fault(fault_injector, stage)
        os.replace(temp_path, target)
        replaced = True

        stage = AtomicWriteStage.PARENT_FSYNC
        _inject_fault(fault_injector, stage)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        parent_fd = os.open(parent, directory_flags)
        os.fsync(parent_fd)
    except AtomicWriteError:
        raise
    except OSError as exc:
        raise AtomicWriteError(
            path=target,
            stage=stage,
            publication_may_have_committed=replaced,
        ) from exc
    finally:
        if file_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(file_fd)
        if parent_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(parent_fd)
        if not replaced:
            with contextlib.suppress(OSError):
                temp_path.unlink()


def durable_append_bytes(
    path: Path,
    payload: bytes,
    *,
    fault_injector: DurableAppendFaultInjector | None = None,
) -> None:
    """Append owner-only bytes and fsync before acknowledging publication.

    The containing directory is fsynced before every acknowledgement, including
    retries that may be recovering a first publication. Append failures after
    any byte is written are typed as commit-uncertain; the caller must not assume
    it is safe to retry an effect-bearing record.
    """

    target = Path(path)
    target_existed = False
    try:
        target_stat = target.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise DurableAppendError(
            path=target,
            stage=DurableAppendStage.TARGET_VALIDATE,
            publication_may_have_committed=False,
        ) from exc
    else:
        if not stat.S_ISREG(target_stat.st_mode):
            raise DurableAppendError(
                path=target,
                stage=DurableAppendStage.TARGET_VALIDATE,
                publication_may_have_committed=False,
            )
        target_existed = True

    parent = target.parent
    missing_directories: list[Path] = []
    try:
        if fault_injector is not None:
            fault_injector(DurableAppendStage.DIRECTORY_PREPARE)
        missing_directories = _missing_directory_chain(parent)
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent.chmod(0o700)
    except OSError as exc:
        raise DurableAppendError(
            path=target,
            stage=DurableAppendStage.DIRECTORY_PREPARE,
            publication_may_have_committed=False,
        ) from exc

    file_fd = -1
    created_file = False
    wrote_payload = False
    completed = False
    opened_identity: tuple[int, int] | None = None
    stage = DurableAppendStage.FILE_OPEN
    try:
        if fault_injector is not None:
            fault_injector(stage)
        flags = os.O_WRONLY | os.O_APPEND
        if not target_existed:
            flags |= os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(target, flags, 0o600)
        created_file = not target_existed
        opened_stat = os.fstat(file_fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise OSError("durable append target is not a regular file")
        opened_identity = (opened_stat.st_dev, opened_stat.st_ino)
        os.fchmod(file_fd, 0o600)

        stage = DurableAppendStage.WRITE
        if fault_injector is not None:
            fault_injector(stage)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(file_fd, remaining)
            if written <= 0:
                raise OSError("durable append made no progress")
            wrote_payload = True
            remaining = remaining[written:]

        stage = DurableAppendStage.FILE_FSYNC
        if fault_injector is not None:
            fault_injector(stage)
        os.fsync(file_fd)

        stage = DurableAppendStage.PARENT_FSYNC
        if fault_injector is not None:
            fault_injector(stage)
        _fsync_directory_path(parent)
        for created_directory in reversed(missing_directories):
            _fsync_directory_path(created_directory.parent)
        completed = True
    except DurableAppendError:
        raise
    except OSError as exc:
        raise DurableAppendError(
            path=target,
            stage=stage,
            publication_may_have_committed=wrote_payload,
        ) from exc
    finally:
        if file_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(file_fd)
        if created_file and not wrote_payload and not completed:
            current_stat: os.stat_result | None
            try:
                current_stat = target.lstat()
            except OSError:
                current_stat = None
            if current_stat is not None and opened_identity == (
                current_stat.st_dev,
                current_stat.st_ino,
            ):
                with contextlib.suppress(OSError):
                    target.unlink()
            cleanup_parent_fd = -1
            try:
                directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                directory_flags |= getattr(os, "O_CLOEXEC", 0)
                cleanup_parent_fd = os.open(parent, directory_flags)
                os.fsync(cleanup_parent_fd)
            except OSError:
                pass
            finally:
                if cleanup_parent_fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(cleanup_parent_fd)
