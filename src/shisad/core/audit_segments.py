"""Linked, bounded segment lifecycle shared by shisad audit streams."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shisad.core.storage_platform import (
    hardened_open_flags,
    sync_parent_directory,
    tighten_permissions,
)

SEGMENT_RECORD_TYPE = "shisad.audit.segment"
SEGMENT_VERSION = 1


class AuditIntegrityError(RuntimeError):
    """Retained audit bytes do not form the required verified chain."""


class AuditUnavailableError(RuntimeError):
    """The audit authority has latched unavailable."""


@dataclass(frozen=True, slots=True)
class SegmentHeader:
    stream: str
    sequence: int
    created_at: str
    previous_segment_sha256: str | None
    previous_terminal_event_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_type": SEGMENT_RECORD_TYPE,
            "version": SEGMENT_VERSION,
            "stream": self.stream,
            "sequence": self.sequence,
            "created_at": self.created_at,
            "previous_segment_sha256": self.previous_segment_sha256,
            "previous_terminal_event_hash": self.previous_terminal_event_hash,
        }


@dataclass(frozen=True, slots=True)
class SegmentInfo:
    path: Path
    sequence: int
    file_hash: str
    terminal_hash: str
    entry_count: int
    byte_count: int
    legacy: bool


@dataclass(frozen=True, slots=True)
class SegmentVerification:
    segments: tuple[SegmentInfo, ...]
    entry_count: int
    retained_bytes: int


RowVerifier = Callable[[str, str], str]
UnavailableHook = Callable[[], None]


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class AuditSegmentStore:
    """Own linked segment framing, admission, append, rotation, and retention."""

    def __init__(
        self,
        path: Path,
        *,
        stream: str,
        genesis_hash: str,
        verify_row: RowVerifier,
        max_segment_bytes: int,
        max_archives: int,
        on_unavailable: UnavailableHook | None = None,
        admit: bool = True,
    ) -> None:
        self.path = path
        self.stream = stream
        self.genesis_hash = genesis_hash
        self._verify_row = verify_row
        self.max_segment_bytes = max_segment_bytes
        self.max_archives = max_archives
        self._on_unavailable = on_unavailable
        self._state = "verified"
        self._reason_code = ""
        self._permission_capability = "unknown"
        self._parent_sync_capability = "unknown"
        self._verification = SegmentVerification((), 0, 0)
        self._read_only = not admit
        self._active_file_hasher = hashlib.sha256()

        if max_segment_bytes < 1 or max_archives < 1:
            raise ValueError("audit segment limits must be positive")
        if admit:
            self._admit()
        else:
            self._verification = self.verify(latch=False)

    @property
    def verification(self) -> SegmentVerification:
        return self._verification

    @property
    def lifecycle_status(self) -> dict[str, Any]:
        archives = max(0, len(self._verification.segments) - int(self._present(self.path)))
        return {
            "stream": self.stream,
            "state": self._state,
            "reason_code": self._reason_code,
            "verified": self._state in {"verified", "retention_degraded"},
            "segment_count": len(self._verification.segments),
            "archive_count": archives,
            "entry_count": self._verification.entry_count,
            "retained_bytes": self._verification.retained_bytes,
            "permission_capability": self._permission_capability,
            "parent_sync_capability": self._parent_sync_capability,
        }

    def ensure_available(self) -> None:
        if self._state == "unavailable":
            raise AuditUnavailableError(self._reason_code)

    def mark_unavailable(self, reason_code: str) -> None:
        if self._state == "unavailable":
            return
        self._state = "unavailable"
        self._reason_code = reason_code
        if self._on_unavailable is not None:
            self._on_unavailable()

    def verify(self, *, latch: bool = True) -> SegmentVerification:
        try:
            verified = self._verify_all()
        except (AuditIntegrityError, OSError, UnicodeError, ValueError):
            if latch:
                self.mark_unavailable("audit.verification_failed")
            raise
        self._verification = verified
        if self._read_only:
            self._inspect_read_only_state()
        else:
            self._reset_active_hasher()
        return verified

    def iter_rows(self) -> Iterator[str]:
        for info in self._verification.segments:
            yield from self._rows_for_path(info.path)

    def append(self, payload: str, terminal_hash: str) -> None:
        self.ensure_available()
        row = (payload + "\n").encode("utf-8")
        if len(row) > self.max_segment_bytes:
            self.mark_unavailable("audit.row_oversize")
            raise AuditUnavailableError("audit.row_oversize")
        try:
            self._ensure_active()
            active_size = self.path.stat().st_size
            if active_size + len(row) > self.max_segment_bytes:
                if self._active_entry_count() == 0:
                    self.mark_unavailable("audit.row_oversize")
                    raise AuditUnavailableError("audit.row_oversize")
                self._rotate()
                active_size = self.path.stat().st_size
                if active_size + len(row) > self.max_segment_bytes:
                    self.mark_unavailable("audit.row_oversize")
                    raise AuditUnavailableError("audit.row_oversize")
            active = self._verification.segments[-1]
            expected_terminal = self._verify_row(payload, active.terminal_hash)
            if expected_terminal != terminal_hash:
                self.mark_unavailable("audit.append_verification_failed")
                raise AuditUnavailableError("audit.append_verification_failed")
            self._append_bytes(row)
            self._active_file_hasher.update(row)
            updated_active = SegmentInfo(
                path=self.path,
                sequence=active.sequence,
                file_hash=self._active_file_hasher.hexdigest(),
                terminal_hash=terminal_hash,
                entry_count=active.entry_count + 1,
                byte_count=active.byte_count + len(row),
                legacy=active.legacy,
            )
            self._verification = SegmentVerification(
                (*self._verification.segments[:-1], updated_active),
                self._verification.entry_count + 1,
                self._verification.retained_bytes + len(row),
            )
            if self._state == "retention_degraded":
                self._reason_code = "audit.retention_delete_failed"
        except AuditUnavailableError:
            raise
        except AuditIntegrityError:
            self.mark_unavailable("audit.verification_failed")
            raise
        except OSError:
            self.mark_unavailable("audit.append_failed")
            raise

    def reset_for_test(self) -> None:
        """Remove this stream's segments for the existing explicit test reset."""
        for path, _sequence in self._archive_paths():
            path.unlink(missing_ok=True)
        self.path.unlink(missing_ok=True)
        self._pending_path.unlink(missing_ok=True)
        self._state = "verified"
        self._reason_code = ""
        self._verification = SegmentVerification((), 0, 0)
        self._active_file_hasher = hashlib.sha256()

    @property
    def _pending_path(self) -> Path:
        return self.path.with_name(f".{self.path.name}.next")

    def _admit(self) -> None:
        if self._present(self.path) and self._present(self._pending_path):
            raise AuditIntegrityError("unexpected pending successor beside active segment")
        self._discard_partial_unpublished_successor()
        verified = self.verify(latch=False)
        for info in verified.segments:
            self._record_permission(info.path)
        if not self._present(self.path) and (
            verified.segments or self._present(self._pending_path)
        ):
            previous = verified.segments[-1] if verified.segments else None
            self._publish_successor(previous)
            verified = self.verify(latch=False)
        self._verification = verified
        self._prune_archives()
        self._verification = self.verify(latch=False)

    def _discard_partial_unpublished_successor(self) -> None:
        if self._present(self.path) or not self._present(self._pending_path):
            return
        raw = self._pending_path.read_bytes()
        if raw and raw.endswith(b"\n"):
            return
        self._pending_path.unlink()
        self._parent_sync_capability = sync_parent_directory(self.path.parent)

    def _inspect_read_only_state(self) -> None:
        if self._state == "unavailable":
            return
        self._state = "verified"
        self._reason_code = ""
        if self._present(self._pending_path):
            self._state = "recovery_pending"
            self._reason_code = "audit.successor_recovery_pending"
            return
        if len(self._archive_paths()) > self.max_archives:
            self._state = "retention_degraded"
            self._reason_code = "audit.retention_delete_failed"

    def _reset_active_hasher(self) -> None:
        self._active_file_hasher = hashlib.sha256()
        if self._present(self.path):
            self._active_file_hasher.update(self.path.read_bytes())

    def _archive_paths(self) -> list[tuple[Path, int]]:
        pattern = re.compile(
            rf"^{re.escape(self.path.stem)}\.(\d{{20}}){re.escape(self.path.suffix)}$"
        )
        found: list[tuple[Path, int]] = []
        if not self.path.parent.exists():
            return found
        for candidate in self.path.parent.iterdir():
            match = pattern.fullmatch(candidate.name)
            if match is not None:
                found.append((candidate, int(match.group(1))))
        return sorted(found, key=lambda item: item[1])

    def _archive_path(self, sequence: int) -> Path:
        return self.path.with_name(f"{self.path.stem}.{sequence:020d}{self.path.suffix}")

    def _verify_all(self) -> SegmentVerification:
        candidates = self._archive_paths()
        if self._present(self.path):
            candidates.append((self.path, -1))
        infos: list[SegmentInfo] = []
        for path, filename_sequence in candidates:
            info = self._verify_segment(path, filename_sequence=filename_sequence)
            if infos:
                previous = infos[-1]
                if info.sequence != previous.sequence + 1:
                    raise AuditIntegrityError("missing middle audit segment")
                header = self._read_header(path)
                if header is None:
                    raise AuditIntegrityError("legacy segment may only be retained as segment zero")
                if header.previous_segment_sha256 != previous.file_hash:
                    raise AuditIntegrityError("segment file-hash link mismatch")
                if header.previous_terminal_event_hash != previous.terminal_hash:
                    raise AuditIntegrityError("segment terminal-hash link mismatch")
            elif info.sequence > 0 and self._read_header(path) is None:
                raise AuditIntegrityError("retained segment missing versioned header")
            if not infos and path == self.path and info.sequence > 0:
                raise AuditIntegrityError("active audit segment immediate predecessor is missing")
            if filename_sequence >= 0 and info.sequence != filename_sequence:
                raise AuditIntegrityError("archive filename/header sequence mismatch")
            infos.append(info)
        if infos and self._present(self.path) and candidates[-1][0] != self.path:
            raise AuditIntegrityError("active audit segment ordering is invalid")
        return SegmentVerification(
            tuple(infos),
            sum(info.entry_count for info in infos),
            sum(info.byte_count for info in infos),
        )

    def _verify_segment(self, path: Path, *, filename_sequence: int) -> SegmentInfo:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise AuditIntegrityError("audit segment is not a regular file")
        raw = path.read_bytes()
        if raw and not raw.endswith(b"\n"):
            raise AuditIntegrityError("partial audit row")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AuditIntegrityError("audit segment is not valid UTF-8") from exc
        physical_lines = text.splitlines()
        header = self._header_from_lines(physical_lines)
        legacy = header is None
        if header is not None:
            sequence = header.sequence
            previous_hash = header.previous_terminal_event_hash
            if sequence == 0:
                if header.previous_segment_sha256 is not None:
                    raise AuditIntegrityError("first segment has a predecessor file hash")
                if previous_hash != self.genesis_hash:
                    raise AuditIntegrityError("first segment has an invalid genesis link")
        else:
            sequence = 0 if filename_sequence < 0 else filename_sequence
            previous_hash = self.genesis_hash
            if sequence != 0:
                raise AuditIntegrityError("legacy segment sequence is not zero")
        count = 0
        for row in self._rows_from_lines(physical_lines):
            try:
                previous_hash = self._verify_row(row, previous_hash)
            except AuditIntegrityError:
                raise
            except Exception as exc:
                raise AuditIntegrityError(f"invalid audit entry at row {count + 1}: {exc}") from exc
            count += 1
        if filename_sequence >= 0 and count == 0:
            raise AuditIntegrityError("archived audit segment is empty")
        return SegmentInfo(
            path=path,
            sequence=sequence,
            file_hash=hashlib.sha256(raw).hexdigest(),
            terminal_hash=previous_hash,
            entry_count=count,
            byte_count=len(raw),
            legacy=legacy,
        )

    def _read_header(self, path: Path) -> SegmentHeader | None:
        return self._header_from_lines(path.read_text(encoding="utf-8").splitlines())

    def _header_from_lines(self, lines: list[str]) -> SegmentHeader | None:
        if not lines:
            return None
        try:
            value = json.loads(lines[0])
        except json.JSONDecodeError:
            return None
        if not isinstance(value, dict) or value.get("record_type") != SEGMENT_RECORD_TYPE:
            return None
        required = {
            "record_type",
            "version",
            "stream",
            "sequence",
            "created_at",
            "previous_segment_sha256",
            "previous_terminal_event_hash",
        }
        if set(value) != required or value.get("version") != SEGMENT_VERSION:
            raise AuditIntegrityError("invalid audit segment header schema")
        if value.get("stream") != self.stream:
            raise AuditIntegrityError("audit segment stream mismatch")
        sequence = value.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise AuditIntegrityError("invalid audit segment sequence")
        created_at = value.get("created_at")
        if not isinstance(created_at, str):
            raise AuditIntegrityError("invalid audit segment creation time")
        try:
            parsed = datetime.fromisoformat(created_at)
        except ValueError as exc:
            raise AuditIntegrityError("invalid audit segment creation time") from exc
        if parsed.tzinfo is None:
            raise AuditIntegrityError("audit segment creation time lacks timezone")
        predecessor = value.get("previous_segment_sha256")
        previous_terminal = value.get("previous_terminal_event_hash")
        if predecessor is not None and not self._is_hash(predecessor):
            raise AuditIntegrityError("invalid predecessor file hash")
        if not self._is_hash(previous_terminal):
            raise AuditIntegrityError("invalid predecessor terminal hash")
        assert isinstance(previous_terminal, str)
        header = SegmentHeader(
            stream=self.stream,
            sequence=sequence,
            created_at=created_at,
            previous_segment_sha256=predecessor,
            previous_terminal_event_hash=previous_terminal,
        )
        if lines[0] != _canonical_json(header.as_dict()):
            raise AuditIntegrityError("audit segment header is not canonical")
        return header

    @staticmethod
    def _is_hash(value: object) -> bool:
        return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None

    @staticmethod
    def _present(path: Path) -> bool:
        return path.exists() or path.is_symlink()

    def _rows_for_path(self, path: Path) -> Iterator[str]:
        yield from self._rows_from_lines(path.read_text(encoding="utf-8").splitlines())

    def _rows_from_lines(self, lines: list[str]) -> Iterator[str]:
        start = 1 if self._header_from_lines(lines) is not None else 0
        for line in lines[start:]:
            if not line.strip():
                raise AuditIntegrityError("blank audit row")
            yield line

    def _ensure_active(self) -> None:
        if self._present(self.path):
            return
        previous = self._verification.segments[-1] if self._verification.segments else None
        self._publish_successor(previous)
        active = self._verify_segment(self.path, filename_sequence=-1)
        self._verification = SegmentVerification(
            (*self._verification.segments, active),
            self._verification.entry_count,
            self._verification.retained_bytes + active.byte_count,
        )
        self._reset_active_hasher()

    def _publish_successor(self, previous: SegmentInfo | None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        sequence = 0 if previous is None else previous.sequence + 1
        header = SegmentHeader(
            stream=self.stream,
            sequence=sequence,
            created_at=datetime.now(UTC).isoformat(),
            previous_segment_sha256=None if previous is None else previous.file_hash,
            previous_terminal_event_hash=(
                self.genesis_hash if previous is None else previous.terminal_hash
            ),
        )
        encoded = (_canonical_json(header.as_dict()) + "\n").encode("utf-8")
        if len(encoded) >= self.max_segment_bytes:
            self.mark_unavailable("audit.header_oversize")
            raise AuditUnavailableError("audit.header_oversize")
        pending = self._pending_path
        if self._present(pending):
            pending_info = self._verify_segment(pending, filename_sequence=-1)
            if pending_info.sequence != sequence or pending_info.entry_count != 0:
                raise AuditIntegrityError("pending audit successor is invalid")
            pending_header = self._read_header(pending)
            if pending_header is None or (
                pending_header.previous_segment_sha256
                != (None if previous is None else previous.file_hash)
                or pending_header.previous_terminal_event_hash
                != (self.genesis_hash if previous is None else previous.terminal_hash)
            ):
                raise AuditIntegrityError("pending audit successor link is invalid")
        else:
            descriptor = os.open(
                pending,
                hardened_open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
                0o600,
            )
            try:
                self._write_all(descriptor, encoded)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._record_permission(pending)
        os.replace(pending, self.path)
        self._record_permission(self.path)
        self._parent_sync_capability = sync_parent_directory(self.path.parent)

    def _append_bytes(self, payload: bytes) -> None:
        descriptor = os.open(self.path, hardened_open_flags(os.O_WRONLY | os.O_APPEND))
        try:
            self._write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._record_permission(self.path)

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise OSError("short audit write")

    def _record_permission(self, path: Path) -> None:
        capability = tighten_permissions(path, 0o600)
        self._permission_capability = capability
        if capability == "failed":
            raise OSError("audit owner-only permission update failed")

    def _active_entry_count(self) -> int:
        if not self._verification.segments or not self._present(self.path):
            return 0
        active = self._verification.segments[-1]
        return active.entry_count if active.path == self.path else 0

    def _rotate(self) -> None:
        active = self._verification.segments[-1]
        if active.path != self.path:
            raise AuditIntegrityError("active audit segment unavailable for rotation")
        archive = self._archive_path(active.sequence)
        if self._present(archive):
            raise AuditIntegrityError("audit archive sequence collision")
        os.replace(self.path, archive)
        self._parent_sync_capability = sync_parent_directory(self.path.parent)
        self._publish_successor(
            SegmentInfo(
                path=archive,
                sequence=active.sequence,
                file_hash=active.file_hash,
                terminal_hash=active.terminal_hash,
                entry_count=active.entry_count,
                byte_count=active.byte_count,
                legacy=active.legacy,
            )
        )
        archived = SegmentInfo(
            path=archive,
            sequence=active.sequence,
            file_hash=active.file_hash,
            terminal_hash=active.terminal_hash,
            entry_count=active.entry_count,
            byte_count=active.byte_count,
            legacy=active.legacy,
        )
        successor = self._verify_segment(self.path, filename_sequence=-1)
        self._verification = SegmentVerification(
            (*self._verification.segments[:-1], archived, successor),
            self._verification.entry_count,
            self._verification.retained_bytes + successor.byte_count,
        )
        self._reset_active_hasher()
        self._prune_archives()

    def _prune_archives(self) -> None:
        archives = self._archive_paths()
        excess = len(archives) - self.max_archives
        if excess <= 0:
            return
        removed: set[Path] = set()
        for path, _sequence in archives[:excess]:
            try:
                path.unlink()
                removed.add(path)
                self._parent_sync_capability = sync_parent_directory(path.parent)
            except OSError:
                if removed:
                    retained = tuple(
                        info for info in self._verification.segments if info.path not in removed
                    )
                    self._verification = SegmentVerification(
                        retained,
                        sum(info.entry_count for info in retained),
                        sum(info.byte_count for info in retained),
                    )
                self._state = "retention_degraded"
                self._reason_code = "audit.retention_delete_failed"
                return
        if removed:
            retained = tuple(
                info for info in self._verification.segments if info.path not in removed
            )
            self._verification = SegmentVerification(
                retained,
                sum(info.entry_count for info in retained),
                sum(info.byte_count for info in retained),
            )
        if self._state == "retention_degraded":
            self._state = "verified"
            self._reason_code = ""
