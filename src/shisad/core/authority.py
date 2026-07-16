"""Same-host lifetime admission for daemon-owned mutable authorities."""

from __future__ import annotations

import errno
import fcntl
import json
import logging
import os
import stat
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shisad.core.config import DaemonConfig, effective_approval_factor_store_path

_REGISTRY_SCHEMA_VERSION = 2
_CLAIM_PREFIX = "claim-"
_CLAIM_SUFFIX = ".json"
_MAX_CLAIM_BYTES = 256 * 1024
_MAX_MATCHING_ARTIFACTS = 4096
_EXTERNAL_FILE_ROLES = frozenset({"approval_factor_store", "soul"})
_TREE_ROLES = frozenset({"config_backup_root", "data_root"})
_BASELINE_ROLES = frozenset({*_TREE_ROLES, "control_socket", *_EXTERNAL_FILE_ROLES})
_SYMLINK_REJECT_ROLES = frozenset({"control_socket", *_EXTERNAL_FILE_ROLES})
_ROLE_FOOTPRINT_KIND = {
    "config_backup_root": "tree-v1",
    "data_root": "tree-v1",
    "control_socket": "exact-v1",
    "approval_factor_store": "external-file-v1",
    "soul": "external-file-v1",
}

logger = logging.getLogger(__name__)


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
    artifact_identities: tuple[tuple[int, int], ...] = ()

    def to_record(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "path": os.fspath(self.path),
            "footprint": _ROLE_FOOTPRINT_KIND[self.role],
            "device": self.device,
            "inode": self.inode,
        }


@dataclass(frozen=True, slots=True)
class _SiblingPattern:
    """Finite machine-defined sibling name family owned by one component."""

    parent: Path
    prefix: str
    suffix: str = ""
    exact: bool = False

    def matches(self, name: str) -> bool:
        if self.exact:
            return name == self.prefix
        return name.startswith(self.prefix) and name.endswith(self.suffix)


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

    def verify_covers_path(self, path: Path) -> Path:
        """Return a canonical path only when this live claim covers its tree."""

        self.verify(self._candidates)
        canonical = _canonical_path(path)
        if not any(
            candidate.role in _TREE_ROLES
            and (canonical == candidate.path or canonical.is_relative_to(candidate.path))
            for candidate in self._candidates
        ):
            raise AuthorityClaimError(
                f"daemon authority claim does not cover mutable path: {canonical}"
            )
        return canonical

    def narrow_to(self, candidates: tuple[DaemonAuthorityCandidate, ...]) -> None:
        """Atomically retain an exact subset without releasing the live record."""

        if not candidates:
            raise AuthorityClaimError("cannot narrow daemon authority claim to an empty set")
        current = {(candidate.role, candidate.path) for candidate in self._candidates}
        supplied = {(candidate.role, candidate.path) for candidate in candidates}
        if not supplied.issubset(current):
            raise AuthorityClaimError("daemon authority claim cannot expand during narrowing")
        with _registry_guard(self._registry_root):
            self.verify(self._candidates)
            fd = self._fd
            if fd is None:
                raise AuthorityClaimError("daemon authority claim has already been released")
            _write_claim_record(fd, candidates)
            self._candidates = candidates

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


def _absolute_lexical_path(path: Path) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        expanded = Path.cwd() / expanded
    return Path(os.path.abspath(os.fspath(expanded)))


def _reject_symlink_ancestry(role: str, path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            raise AuthorityRegistryError(
                f"cannot inspect daemon mutable authority {role}: {path}"
            ) from exc
        if stat.S_ISLNK(current_stat.st_mode):
            raise AuthorityRegistryError(
                f"daemon mutable authority {role} has symlink ancestry: {current}"
            )
        if current != path and not stat.S_ISDIR(current_stat.st_mode):
            raise AuthorityRegistryError(
                f"daemon mutable authority {role} has non-directory ancestry: {current}"
            )


def _external_sibling_patterns(path: Path) -> tuple[_SiblingPattern, ...]:
    parent = path.parent
    name = path.name
    return (
        _SiblingPattern(parent, f"{name}.tmp", exact=True),
        _SiblingPattern(parent, f"{name}.lock", exact=True),
        _SiblingPattern(parent, f".{name}.lock", exact=True),
        _SiblingPattern(parent, f"{name}.corrupt."),
        _SiblingPattern(parent, f"{name}.bak."),
        _SiblingPattern(parent, f"{name}.backup."),
        _SiblingPattern(parent, f"{name}.tombstone."),
        _SiblingPattern(parent, f"{name}.migrate."),
        _SiblingPattern(parent, f".{name}.", suffix=".tmp"),
        _SiblingPattern(parent, f".{name}.bak-"),
        _SiblingPattern(parent, f".{name}.tombstone-"),
        _SiblingPattern(parent, f".{name}.migrate-"),
    )


def _candidate_patterns(candidate: DaemonAuthorityCandidate) -> tuple[_SiblingPattern, ...]:
    if candidate.role not in _EXTERNAL_FILE_ROLES:
        return ()
    return _external_sibling_patterns(candidate.path)


def _external_artifact_paths(role: str, path: Path) -> tuple[Path, ...]:
    if role not in _EXTERNAL_FILE_ROLES:
        return (path,) if path.exists() else ()
    patterns = _external_sibling_patterns(path)
    artifacts: list[Path] = []
    try:
        base_stat = path.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise AuthorityRegistryError(
            f"cannot inspect daemon mutable authority {role}: {path}"
        ) from exc
    else:
        if stat.S_ISLNK(base_stat.st_mode):
            raise AuthorityRegistryError(f"daemon mutable authority {role} is a symlink: {path}")
        artifacts.append(path)

    try:
        with os.scandir(path.parent) as entries:
            for entry in entries:
                if entry.name == path.name or not any(
                    pattern.matches(entry.name) for pattern in patterns
                ):
                    continue
                artifacts.append(Path(entry.path))
                if len(artifacts) > _MAX_MATCHING_ARTIFACTS:
                    raise AuthorityRegistryError(
                        f"too many derived daemon authority artifacts for {role}: {path}"
                    )
    except FileNotFoundError:
        return tuple(artifacts)
    except AuthorityRegistryError:
        raise
    except OSError as exc:
        raise AuthorityRegistryError(
            f"cannot inspect derived daemon authority artifacts for {role}: {path.parent}"
        ) from exc
    return tuple(sorted(artifacts, key=os.fspath))


def _candidate_at_canonical_path(role: str, canonical: Path) -> DaemonAuthorityCandidate:
    artifact_identities: set[tuple[int, int]] = set()
    if role in _EXTERNAL_FILE_ROLES:
        artifact_paths = _external_artifact_paths(role, canonical)
    else:
        artifact_paths = (canonical,)
    device: int | None = None
    inode: int | None = None
    for artifact_path in artifact_paths:
        try:
            path_stat = artifact_path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AuthorityRegistryError(
                f"cannot inspect daemon mutable authority {role}: {artifact_path}"
            ) from exc
        if role in _EXTERNAL_FILE_ROLES:
            if stat.S_ISLNK(path_stat.st_mode):
                raise AuthorityRegistryError(
                    f"daemon mutable authority {role} is a symlink: {artifact_path}"
                )
            if not stat.S_ISREG(path_stat.st_mode):
                raise AuthorityRegistryError(
                    f"daemon mutable authority {role} is not a regular file: {artifact_path}"
                )
            if path_stat.st_uid != os.getuid():
                raise AuthorityRegistryError(
                    f"daemon mutable authority {role} is not owner-controlled: {artifact_path}"
                )
        artifact_identities.add((path_stat.st_dev, path_stat.st_ino))
        if artifact_path == canonical:
            device = path_stat.st_dev
            inode = path_stat.st_ino
    return DaemonAuthorityCandidate(
        role=role,
        path=canonical,
        device=device,
        inode=inode,
        artifact_identities=tuple(sorted(artifact_identities)),
    )


def _candidate(role: str, path: Path) -> DaemonAuthorityCandidate:
    lexical = _absolute_lexical_path(path)
    if role in _SYMLINK_REJECT_ROLES:
        _reject_symlink_ancestry(role, lexical)
    canonical = _canonical_path(lexical)
    return _candidate_at_canonical_path(role, canonical)


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
        footprint = item.get("footprint")
        device = item.get("device")
        inode = item.get("inode")
        if not isinstance(role, str) or not role or not isinstance(raw_path, str) or not raw_path:
            raise AuthorityRegistryError(f"authority claim candidate is malformed: {path}")
        if role not in _BASELINE_ROLES:
            raise AuthorityRegistryError(f"authority claim candidate role is unsupported: {path}")
        if footprint != _ROLE_FOOTPRINT_KIND[role]:
            raise AuthorityRegistryError(
                f"authority claim candidate footprint is unsupported: {path}"
            )
        if device is not None and not isinstance(device, int):
            raise AuthorityRegistryError(f"authority claim device is malformed: {path}")
        if inode is not None and not isinstance(inode, int):
            raise AuthorityRegistryError(f"authority claim inode is malformed: {path}")
        candidate_path = Path(raw_path)
        if not candidate_path.is_absolute() or _canonical_path(candidate_path) != candidate_path:
            raise AuthorityRegistryError(f"authority claim candidate path is unsafe: {path}")
        candidates.append(
            DaemonAuthorityCandidate(
                role=role,
                path=candidate_path,
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
                recorded = _read_claim_record(fd, path)
                active.append(
                    (
                        path,
                        tuple(
                            _candidate_at_canonical_path(candidate.role, candidate.path)
                            for candidate in recorded
                        ),
                    )
                )
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


def _paths_structurally_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _path_overlaps_pattern(path: Path, pattern: _SiblingPattern) -> bool:
    if path == pattern.parent or pattern.parent.is_relative_to(path):
        return True
    if not path.is_relative_to(pattern.parent):
        return False
    relative = path.relative_to(pattern.parent)
    return bool(relative.parts) and pattern.matches(relative.parts[0])


def _patterns_intersect(left: _SiblingPattern, right: _SiblingPattern) -> bool:
    if left.parent != right.parent:
        if left.parent.is_relative_to(right.parent):
            relative = left.parent.relative_to(right.parent)
            return bool(relative.parts) and right.matches(relative.parts[0])
        if right.parent.is_relative_to(left.parent):
            relative = right.parent.relative_to(left.parent)
            return bool(relative.parts) and left.matches(relative.parts[0])
        return False
    if left.exact:
        return right.matches(left.prefix)
    if right.exact:
        return left.matches(right.prefix)
    prefixes_compatible = left.prefix.startswith(right.prefix) or right.prefix.startswith(
        left.prefix
    )
    suffixes_compatible = left.suffix.endswith(right.suffix) or right.suffix.endswith(left.suffix)
    return prefixes_compatible and suffixes_compatible


def _authority_overlap_kind(
    left: DaemonAuthorityCandidate,
    right: DaemonAuthorityCandidate,
) -> str | None:
    if set(left.artifact_identities).intersection(right.artifact_identities):
        return "inode"
    if _paths_structurally_overlap(left.path, right.path):
        return "exact" if left.path == right.path else "ancestor"
    left_patterns = _candidate_patterns(left)
    right_patterns = _candidate_patterns(right)
    if any(_path_overlaps_pattern(right.path, pattern) for pattern in left_patterns):
        return "derived"
    if any(_path_overlaps_pattern(left.path, pattern) for pattern in right_patterns):
        return "derived"
    if any(
        _patterns_intersect(left_pattern, right_pattern)
        for left_pattern in left_patterns
        for right_pattern in right_patterns
    ):
        return "derived"
    return None


def daemon_authority_protects_path(
    candidate: DaemonAuthorityCandidate,
    path: Path,
) -> bool:
    """Return whether a write target enters one claimed structural footprint."""

    canonical = _canonical_path(path)
    if candidate.role in _TREE_ROLES:
        return canonical == candidate.path or canonical.is_relative_to(candidate.path)
    try:
        refreshed = _candidate_at_canonical_path(candidate.role, candidate.path)
        probe = _candidate_at_canonical_path("control_socket", canonical)
    except AuthorityError:
        return True
    return _authority_overlap_kind(refreshed, probe) is not None


def daemon_authority_registry_root() -> Path:
    """Return the canonical same-user registry tree protected from assistant writes."""

    return _canonical_path(_registry_root())


def _candidate_is_contained_by_data_root(
    candidate: DaemonAuthorityCandidate,
    data_root: DaemonAuthorityCandidate,
) -> bool:
    if data_root.role != "data_root" or candidate.path == data_root.path:
        return False
    if not candidate.path.is_relative_to(data_root.path):
        return False
    return all(
        pattern.parent.is_relative_to(data_root.path) for pattern in _candidate_patterns(candidate)
    )


def _validate_same_config_candidates(
    candidates: tuple[DaemonAuthorityCandidate, ...],
) -> None:
    for index, left in enumerate(candidates):
        for right in candidates[index + 1 :]:
            overlap_kind = _authority_overlap_kind(left, right)
            if overlap_kind is None:
                continue
            if _candidate_is_contained_by_data_root(left, right):
                continue
            if _candidate_is_contained_by_data_root(right, left):
                continue
            raise AuthorityConflictError(
                "unexpected cross-role daemon authority overlap "
                f"({overlap_kind}): {left.role}={left.path} and {right.role}={right.path}"
            )


def _validate_trusted_read_inputs(
    config: DaemonConfig,
    candidates: tuple[DaemonAuthorityCandidate, ...],
) -> None:
    trusted_inputs = (
        ("policy", _canonical_path(config.policy_path)),
        ("selfmod_allowed_signers", _canonical_path(config.selfmod_allowed_signers_path)),
    )
    for label, path in trusted_inputs:
        probe = _candidate_at_canonical_path("control_socket", path)
        for candidate in candidates:
            overlap_kind = _authority_overlap_kind(candidate, probe)
            if overlap_kind is not None:
                raise AuthorityConflictError(
                    "trusted read input overlaps daemon mutable authority "
                    f"({overlap_kind}): {label}={path} and "
                    f"{candidate.role}={candidate.path}"
                )


def _validate_candidate_boundaries(
    config: DaemonConfig,
    candidates: tuple[DaemonAuthorityCandidate, ...],
    registry_root: Path,
) -> None:
    _validate_same_config_candidates(candidates)
    for candidate in candidates:
        if _candidate_overlaps_tree(candidate, registry_root):
            raise AuthorityRegistryError(
                "daemon mutable authority overlaps host-global registry: "
                f"{candidate.role}={candidate.path} registry={registry_root}"
            )
    _validate_trusted_read_inputs(config, candidates)


def _candidate_overlaps_tree(candidate: DaemonAuthorityCandidate, tree_root: Path) -> bool:
    if _paths_structurally_overlap(candidate.path, tree_root):
        return True
    return any(
        _path_overlaps_pattern(tree_root, pattern) for pattern in _candidate_patterns(candidate)
    )


def _preflight_assistant_filesystem_roots(
    config: DaemonConfig,
    candidates: tuple[DaemonAuthorityCandidate, ...],
    registry_root: Path,
) -> None:
    protected_read_inputs = [
        ("policy", _canonical_path(config.policy_path)),
        ("selfmod_allowed_signers", _canonical_path(config.selfmod_allowed_signers_path)),
    ]
    for raw_root in config.assistant_fs_roots:
        assistant_root = _canonical_path(raw_root)
        for candidate in candidates:
            if _candidate_overlaps_tree(candidate, assistant_root):
                logger.warning(
                    "Assistant filesystem root overlaps protected daemon control state; "
                    "direct filesystem writes must remain blocked: root=%s authority=%s:%s",
                    assistant_root,
                    candidate.role,
                    candidate.path,
                )
        if _paths_structurally_overlap(assistant_root, registry_root):
            logger.warning(
                "Assistant filesystem root overlaps protected daemon control state; "
                "direct filesystem writes must remain blocked: root=%s authority=%s:%s",
                assistant_root,
                "authority_registry",
                registry_root,
            )
        for label, protected_path in protected_read_inputs:
            if _paths_structurally_overlap(assistant_root, protected_path):
                logger.warning(
                    "Assistant filesystem root contains protected read-only control input; "
                    "direct filesystem writes must remain blocked: root=%s authority=%s:%s",
                    assistant_root,
                    label,
                    protected_path,
                )


def _write_claim_record(
    fd: int,
    candidates: tuple[DaemonAuthorityCandidate, ...],
) -> None:
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
    if len(payload) > _MAX_CLAIM_BYTES:
        raise AuthorityRegistryError("daemon authority claim record is oversized")
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while publishing authority claim")
        view = view[written:]
    os.fsync(fd)


def _publish_claim(
    root: Path,
    candidates: tuple[DaemonAuthorityCandidate, ...],
) -> DaemonAuthorityClaim:
    record_path = root / f"{_CLAIM_PREFIX}{uuid.uuid4().hex}{_CLAIM_SUFFIX}"
    try:
        fd = _open_owner_file(record_path, create=True, exclusive=True)
    except OSError as exc:
        raise AuthorityRegistryError("cannot create daemon authority claim") from exc
    published = False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _write_claim_record(fd, candidates)
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


def _reject_active_claim_conflicts(
    root: Path,
    candidates: tuple[DaemonAuthorityCandidate, ...],
) -> None:
    for _record_path, active_candidates in _active_claims(root):
        for candidate in candidates:
            for active in active_candidates:
                overlap_kind = _authority_overlap_kind(candidate, active)
                if overlap_kind is not None:
                    raise AuthorityConflictError(
                        "daemon mutable authority conflict: "
                        f"{candidate.role}={candidate.path} overlaps "
                        f"{active.role}={active.path} ({overlap_kind})"
                    )


def acquire_daemon_authority_claim(config: DaemonConfig) -> DaemonAuthorityClaim:
    """Atomically reserve the config's baseline authority set without target mutation."""

    preliminary_candidates = derive_daemon_authority_candidates(config)
    root = _registry_root()
    canonical_root = _canonical_path(root)
    _validate_candidate_boundaries(config, preliminary_candidates, canonical_root)
    _preflight_assistant_filesystem_roots(config, preliminary_candidates, canonical_root)
    with _registry_guard(root):
        candidates = derive_daemon_authority_candidates(config)
        _validate_candidate_boundaries(config, candidates, canonical_root)
        _reject_active_claim_conflicts(root, candidates)
        return _publish_claim(root, candidates)


def _derive_fresh_config_union_candidates(
    prior_config: DaemonConfig,
    refreshed_config: DaemonConfig,
) -> tuple[DaemonAuthorityCandidate, ...]:
    candidates = [
        _candidate("data_root", prior_config.data_dir),
        _candidate("config_backup_root", prior_config.data_dir / "config-backups"),
        *derive_daemon_authority_candidates(refreshed_config),
    ]
    unique = {(candidate.role, candidate.path): candidate for candidate in candidates}
    return tuple(sorted(unique.values(), key=lambda item: (os.fspath(item.path), item.role)))


def _acquire_fresh_config_authority_claim_once(
    prior_config: DaemonConfig,
    refreshed_config: DaemonConfig,
) -> DaemonAuthorityClaim:
    root = _registry_root()
    canonical_root = _canonical_path(root)
    with _registry_guard(root):
        candidates = _derive_fresh_config_union_candidates(prior_config, refreshed_config)
        _validate_candidate_boundaries(refreshed_config, candidates, canonical_root)
        _reject_active_claim_conflicts(root, candidates)
        return _publish_claim(root, candidates)


def acquire_fresh_config_authority_claim(
    prior_config: DaemonConfig,
    refreshed_config: DaemonConfig,
    *,
    timeout_seconds: float = 5.0,
    retry_interval_seconds: float = 0.05,
) -> DaemonAuthorityClaim:
    """Reserve prior-backup and refreshed authorities as one bounded transaction."""

    preliminary_candidates = _derive_fresh_config_union_candidates(
        prior_config,
        refreshed_config,
    )
    canonical_root = _canonical_path(_registry_root())
    _validate_candidate_boundaries(refreshed_config, preliminary_candidates, canonical_root)
    _preflight_assistant_filesystem_roots(
        refreshed_config,
        preliminary_candidates,
        canonical_root,
    )
    timeout = max(0.0, timeout_seconds)
    deadline = time.monotonic() + timeout
    while True:
        try:
            return _acquire_fresh_config_authority_claim_once(prior_config, refreshed_config)
        except AuthorityConflictError as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AuthorityConflictError(
                    "timed out waiting for fresh-config daemon authorities"
                ) from exc
            time.sleep(min(max(0.001, retry_interval_seconds), remaining))


def narrow_daemon_authority_claim(
    config: DaemonConfig,
    claim: DaemonAuthorityClaim,
) -> None:
    """Retain only the refreshed config candidates on a transferred union claim."""

    candidates = derive_daemon_authority_candidates(config)
    canonical_root = _canonical_path(_registry_root())
    _validate_candidate_boundaries(config, candidates, canonical_root)
    claim.narrow_to(candidates)


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
                raise AuthorityClaimError(f"cannot locate existing ancestor for {path}") from None
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


def _restrict_external_authority_files(candidate: DaemonAuthorityCandidate) -> None:
    if candidate.role not in _EXTERNAL_FILE_ROLES:
        return
    for path in _external_artifact_paths(candidate.role, candidate.path):
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise AuthorityClaimError(
                f"cannot open claimed {candidate.role} authority: {path}"
            ) from exc
        try:
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_uid != os.getuid():
                raise AuthorityClaimError(
                    f"claimed {candidate.role} authority is not an owner file: {path}"
                )
            if stat.S_IMODE(file_stat.st_mode) != 0o600:
                os.fchmod(fd, 0o600)
                os.fsync(fd)
        except OSError as exc:
            raise AuthorityClaimError(
                f"cannot restrict claimed {candidate.role} authority: {path}"
            ) from exc
        finally:
            os.close(fd)


def verify_claimed_daemon_authorities(
    config: DaemonConfig,
    claim: DaemonAuthorityClaim,
) -> tuple[DaemonAuthorityCandidate, ...]:
    """Verify a live claim against the config without mutating any authority."""

    candidates = derive_daemon_authority_candidates(config)
    claim.verify(candidates)
    return candidates


def initialize_claimed_daemon_authorities(
    config: DaemonConfig,
    claim: DaemonAuthorityClaim,
) -> None:
    """Initialize the data root only after verifying the complete acquired claim."""

    candidates = verify_claimed_daemon_authorities(config, claim)
    data_candidate = next(
        (candidate for candidate in candidates if candidate.role == "data_root"),
        None,
    )
    if data_candidate is None:
        raise AuthorityClaimError("daemon authority claim has no data-root candidate")
    _ensure_owner_directory(data_candidate.path)
    for candidate in candidates:
        _restrict_external_authority_files(candidate)
