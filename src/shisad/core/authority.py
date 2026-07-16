"""Same-host lifetime admission for daemon-owned mutable authorities."""

from __future__ import annotations

import errno
import fcntl
import json
import os
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shisad.core.config import DaemonConfig, effective_approval_factor_store_path

_REGISTRY_SCHEMA_VERSION = 1
_CLAIM_PREFIX = "claim-"
_CLAIM_SUFFIX = ".json"
_MAX_CLAIM_BYTES = 256 * 1024


class AuthorityError(RuntimeError):
    """Base class for mutable-authority admission failures."""


class AuthorityRegistryError(AuthorityError):
    """The host-global authority registry is unavailable or unsafe."""


class AuthorityConflictError(AuthorityError):
    """Another live daemon owns an overlapping mutable authority."""


class AuthorityClaimError(AuthorityError):
    """A supplied claim is missing, released, or bound to another config."""


@dataclass(frozen=True, slots=True)
class DaemonAuthorityCandidate:
    """One canonical daemon-owned mutable authority."""

    role: str
    path: Path
    device: int | None = None
    inode: int | None = None

    def to_record(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "path": os.fspath(self.path),
            "device": self.device,
            "inode": self.inode,
        }


class DaemonAuthorityClaim:
    """A process-lifetime claim held by an open, exclusively locked record."""

    __slots__ = ("_candidates", "_fd", "_record_path", "_registry_root")

    def __init__(
        self,
        *,
        candidates: tuple[DaemonAuthorityCandidate, ...],
        fd: int,
        record_path: Path,
        registry_root: Path,
    ) -> None:
        self._candidates = candidates
        self._fd: int | None = fd
        self._record_path = record_path
        self._registry_root = registry_root

    @property
    def candidates(self) -> tuple[DaemonAuthorityCandidate, ...]:
        return self._candidates

    @property
    def released(self) -> bool:
        return self._fd is None

    def verify(self, candidates: tuple[DaemonAuthorityCandidate, ...]) -> None:
        """Prove this live record owns exactly the supplied candidate set."""

        fd = self._fd
        if fd is None:
            raise AuthorityClaimError("daemon authority claim has already been released")
        expected = tuple((candidate.role, candidate.path) for candidate in self._candidates)
        supplied = tuple((candidate.role, candidate.path) for candidate in candidates)
        if supplied != expected:
            raise AuthorityClaimError("daemon authority claim does not cover this configuration")
        try:
            record_stat = os.fstat(fd)
            path_stat = self._record_path.lstat()
        except OSError as exc:
            raise AuthorityClaimError("daemon authority claim record is unavailable") from exc
        if (record_stat.st_dev, record_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
            raise AuthorityClaimError("daemon authority claim record identity changed")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise AuthorityClaimError("daemon authority claim lock is not held") from exc

    def release(self) -> None:
        """Release this claim and durably remove its registry record."""

        fd = self._fd
        if fd is None:
            return
        self._fd = None
        cleanup_error: OSError | AuthorityRegistryError | None = None
        try:
            with _registry_guard(self._registry_root):
                try:
                    path_stat = self._record_path.lstat()
                except FileNotFoundError:
                    path_stat = None
                if path_stat is not None:
                    record_stat = os.fstat(fd)
                    if (record_stat.st_dev, record_stat.st_ino) != (
                        path_stat.st_dev,
                        path_stat.st_ino,
                    ):
                        raise AuthorityRegistryError(
                            "daemon authority claim record identity changed during release"
                        )
                    self._record_path.unlink()
                    _fsync_directory(self._registry_root)
        except (OSError, AuthorityRegistryError) as exc:
            cleanup_error = exc
        finally:
            os.close(fd)
        if cleanup_error is not None:
            raise AuthorityRegistryError(
                "failed to clean daemon authority claim"
            ) from cleanup_error

    def __enter__(self) -> DaemonAuthorityClaim:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


def _canonical_path(path: Path) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        expanded = Path.cwd() / expanded
    return Path(os.path.realpath(os.fspath(expanded)))


def _candidate(role: str, path: Path) -> DaemonAuthorityCandidate:
    canonical = _canonical_path(path)
    try:
        path_stat = canonical.stat()
    except FileNotFoundError:
        device = None
        inode = None
    except OSError as exc:
        raise AuthorityRegistryError(
            f"cannot inspect daemon mutable authority {role}: {canonical}"
        ) from exc
    else:
        device = path_stat.st_dev
        inode = path_stat.st_ino
    return DaemonAuthorityCandidate(
        role=role,
        path=canonical,
        device=device,
        inode=inode,
    )


def derive_daemon_authority_candidates(
    config: DaemonConfig,
) -> tuple[DaemonAuthorityCandidate, ...]:
    """Derive the complete baseline mutable-authority set without mutation."""

    candidates = [
        _candidate("data_root", config.data_dir),
        _candidate("control_socket", config.socket_path),
        _candidate(
            "approval_factor_store",
            effective_approval_factor_store_path(data_dir=config.data_dir),
        ),
    ]
    if config.assistant_persona_soul_path is not None:
        candidates.append(_candidate("soul", config.assistant_persona_soul_path))
    return tuple(sorted(candidates, key=lambda item: (os.fspath(item.path), item.role)))


def _registry_root() -> Path:
    return Path("/tmp") / f"shisad-authority-{os.getuid()}"


def _validate_registry_directory(path: Path) -> None:
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise AuthorityRegistryError(f"cannot inspect authority registry: {path}") from exc
    if not stat.S_ISDIR(path_stat.st_mode) or path_stat.st_uid != os.getuid():
        raise AuthorityRegistryError(f"authority registry is not an owner directory: {path}")
    if stat.S_IMODE(path_stat.st_mode) != 0o700:
        try:
            path.chmod(0o700)
        except OSError as exc:
            raise AuthorityRegistryError(
                f"cannot enforce owner-only authority registry mode: {path}"
            ) from exc
        if stat.S_IMODE(path.lstat().st_mode) != 0o700:
            raise AuthorityRegistryError(
                f"authority registry mode remains unsafe after repair: {path}"
            )


def _ensure_registry_root(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise AuthorityRegistryError(f"cannot create authority registry: {path}") from exc
    _validate_registry_directory(path)


def _open_owner_file(path: Path, *, create: bool = False, exclusive: bool = False) -> int:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if create:
        flags |= os.O_CREAT
    if exclusive:
        flags |= os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        file_stat = os.fstat(fd)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != os.getuid()
            or file_stat.st_nlink != 1
        ):
            raise AuthorityRegistryError(f"authority registry file is unsafe: {path}")
        if stat.S_IMODE(file_stat.st_mode) != 0o600:
            os.fchmod(fd, 0o600)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _registry_guard(root: Path) -> Iterator[None]:
    _ensure_registry_root(root)
    guard_path = root / "registry.lock"
    try:
        guard_fd = _open_owner_file(guard_path, create=True)
    except OSError as exc:
        raise AuthorityRegistryError("cannot open daemon authority registry guard") from exc
    try:
        fcntl.flock(guard_fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(guard_fd)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_claim_record(fd: int, path: Path) -> tuple[DaemonAuthorityCandidate, ...]:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(64 * 1024, _MAX_CLAIM_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > _MAX_CLAIM_BYTES:
            raise AuthorityRegistryError(f"authority claim record is oversized: {path}")
    try:
        payload = json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorityRegistryError(f"authority claim record is corrupt: {path}") from exc
    if not isinstance(payload, dict) or payload.get("version") != _REGISTRY_SCHEMA_VERSION:
        raise AuthorityRegistryError(f"authority claim record schema is unsupported: {path}")
    raw_candidates = payload.get("candidates")
    if not isinstance(raw_candidates, list) or not raw_candidates:
        raise AuthorityRegistryError(f"authority claim record has no candidates: {path}")
    candidates: list[DaemonAuthorityCandidate] = []
    for item in raw_candidates:
        if not isinstance(item, dict):
            raise AuthorityRegistryError(f"authority claim candidate is malformed: {path}")
        role = item.get("role")
        raw_path = item.get("path")
        device = item.get("device")
        inode = item.get("inode")
        if not isinstance(role, str) or not role or not isinstance(raw_path, str) or not raw_path:
            raise AuthorityRegistryError(f"authority claim candidate is malformed: {path}")
        if device is not None and not isinstance(device, int):
            raise AuthorityRegistryError(f"authority claim device is malformed: {path}")
        if inode is not None and not isinstance(inode, int):
            raise AuthorityRegistryError(f"authority claim inode is malformed: {path}")
        candidates.append(
            DaemonAuthorityCandidate(
                role=role,
                path=Path(raw_path),
                device=device,
                inode=inode,
            )
        )
    return tuple(candidates)


def _active_claims(root: Path) -> list[tuple[Path, tuple[DaemonAuthorityCandidate, ...]]]:
    active: list[tuple[Path, tuple[DaemonAuthorityCandidate, ...]]] = []
    for path in sorted(root.glob(f"{_CLAIM_PREFIX}*{_CLAIM_SUFFIX}")):
        try:
            fd = _open_owner_file(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AuthorityRegistryError(f"cannot inspect authority claim: {path}") from exc
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise AuthorityRegistryError(
                        f"cannot inspect authority claim lock: {path}"
                    ) from exc
                active.append((path, _read_claim_record(fd, path)))
                continue
            path_stat = path.lstat()
            fd_stat = os.fstat(fd)
            if (path_stat.st_dev, path_stat.st_ino) != (fd_stat.st_dev, fd_stat.st_ino):
                raise AuthorityRegistryError(f"stale authority claim identity changed: {path}")
            path.unlink()
            _fsync_directory(root)
        finally:
            os.close(fd)
    return active


def _same_authority(
    left: DaemonAuthorityCandidate,
    right: DaemonAuthorityCandidate,
) -> bool:
    if left.path == right.path:
        return True
    return (
        left.device is not None
        and left.inode is not None
        and right.device is not None
        and right.inode is not None
        and (left.device, left.inode) == (right.device, right.inode)
    )


def acquire_daemon_authority_claim(config: DaemonConfig) -> DaemonAuthorityClaim:
    """Atomically reserve the config's baseline authority set without target mutation."""

    candidates = derive_daemon_authority_candidates(config)
    root = _registry_root()
    canonical_root = _canonical_path(root)
    for candidate in candidates:
        if (
            candidate.path == canonical_root
            or candidate.path.is_relative_to(canonical_root)
            or canonical_root.is_relative_to(candidate.path)
        ):
            raise AuthorityRegistryError(
                "daemon mutable authority overlaps host-global registry: "
                f"{candidate.role}={candidate.path} registry={canonical_root}"
            )
    with _registry_guard(root):
        for _record_path, active_candidates in _active_claims(root):
            for candidate in candidates:
                for active in active_candidates:
                    if _same_authority(candidate, active):
                        raise AuthorityConflictError(
                            "daemon mutable authority conflict: "
                            f"{candidate.role}={candidate.path} overlaps "
                            f"{active.role}={active.path}"
                        )

        record_path = root / f"{_CLAIM_PREFIX}{uuid.uuid4().hex}{_CLAIM_SUFFIX}"
        try:
            fd = _open_owner_file(record_path, create=True, exclusive=True)
        except OSError as exc:
            raise AuthorityRegistryError("cannot create daemon authority claim") from exc
        published = False
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            payload = json.dumps(
                {
                    "version": _REGISTRY_SCHEMA_VERSION,
                    "pid": os.getpid(),
                    "candidates": [candidate.to_record() for candidate in candidates],
                },
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write while publishing authority claim")
                view = view[written:]
            os.fsync(fd)
            _fsync_directory(root)
            published = True
            return DaemonAuthorityClaim(
                candidates=candidates,
                fd=fd,
                record_path=record_path,
                registry_root=root,
            )
        finally:
            if not published:
                try:
                    record_path.unlink()
                    _fsync_directory(root)
                except OSError:
                    pass
                os.close(fd)


def _ensure_owner_directory(path: Path) -> None:
    missing: list[Path] = []
    current = path
    while True:
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            missing.append(current)
            parent = current.parent
            if parent == current:
                raise AuthorityClaimError(
                    f"cannot locate existing ancestor for {path}"
                ) from None
            current = parent
            continue
        if not stat.S_ISDIR(current_stat.st_mode):
            raise AuthorityClaimError(f"daemon data path ancestor is not a directory: {current}")
        break
    for directory in reversed(missing):
        with suppress(FileExistsError):
            directory.mkdir(mode=0o700)
        directory_stat = directory.lstat()
        if not stat.S_ISDIR(directory_stat.st_mode) or directory_stat.st_uid != os.getuid():
            raise AuthorityClaimError(f"daemon data directory is not owner-controlled: {directory}")
        directory.chmod(0o700)
        _fsync_directory(directory)
        _fsync_directory(directory.parent)

    path_stat = path.lstat()
    if not stat.S_ISDIR(path_stat.st_mode) or path_stat.st_uid != os.getuid():
        raise AuthorityClaimError(f"daemon data directory is not owner-controlled: {path}")
    if stat.S_IMODE(path_stat.st_mode) != 0o700:
        path.chmod(0o700)
        _fsync_directory(path)


def initialize_claimed_daemon_authorities(
    config: DaemonConfig,
    claim: DaemonAuthorityClaim,
) -> None:
    """Initialize the data root only after verifying the complete acquired claim."""

    candidates = derive_daemon_authority_candidates(config)
    claim.verify(candidates)
    data_candidate = next(
        (candidate for candidate in candidates if candidate.role == "data_root"),
        None,
    )
    if data_candidate is None:
        raise AuthorityClaimError("daemon authority claim has no data-root candidate")
    _ensure_owner_directory(data_candidate.path)
