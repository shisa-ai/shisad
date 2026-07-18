"""Same-host lifetime admission for daemon-owned mutable authorities."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import logging
import os
import pwd
import stat
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shisad.core.atomic_state import (
    StateLoadStatus,
    atomic_write_temp_prefix,
    decode_json_document,
    validate_owner_controlled_parent_ancestry,
)
from shisad.core.config import DaemonConfig, effective_approval_factor_store_path

_REGISTRY_SCHEMA_VERSION = 2
_CLAIM_PREFIX = "claim-"
_CLAIM_SUFFIX = ".json"
_MAX_CLAIM_BYTES = 256 * 1024
_MAX_MATCHING_ARTIFACTS = 4096
_NAMESPACE_GUARD_TIMEOUT_SECONDS = 5.0
_EXTERNAL_FILE_ROLES = frozenset({"approval_factor_store", "soul"})
_TREE_ROLES = frozenset({"config_backup_root", "data_root"})
_BASELINE_ROLES = frozenset({*_TREE_ROLES, "control_socket", *_EXTERNAL_FILE_ROLES})
_SYMLINK_REJECT_ROLES = frozenset({"config_backup_root", "control_socket", *_EXTERNAL_FILE_ROLES})
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


@dataclass(slots=True)
class DaemonAuthorityLease:
    """A duplicated claim fd transferred to a contained child process."""

    fd: int
    record_path: Path
    namespace_fd: int = -1

    @property
    def closed(self) -> bool:
        return self.fd < 0

    def close(self) -> None:
        for attribute in ("fd", "namespace_fd"):
            fd = getattr(self, attribute)
            if fd < 0:
                continue
            setattr(self, attribute, -1)
            with suppress(OSError):
                os.close(fd)


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


class _NamespaceMarker:
    """Owner-authenticated filesystem marker held for one claim lifetime."""

    __slots__ = ("fd", "path")

    def __init__(self, *, fd: int, path: Path) -> None:
        self.fd = fd
        self.path = path

    def fileno(self) -> int:
        return self.fd

    def close(self) -> None:
        fd = self.fd
        self.fd = -1
        if fd >= 0:
            with suppress(OSError):
                os.close(fd)


class DaemonAuthorityClaim:
    """A process-lifetime claim held by an open, exclusively locked record."""

    __slots__ = (
        "_candidates",
        "_fd",
        "_namespace_marker",
        "_record_path",
        "_registry_root",
    )

    def __init__(
        self,
        *,
        candidates: tuple[DaemonAuthorityCandidate, ...],
        fd: int,
        namespace_marker: _NamespaceMarker,
        record_path: Path,
        registry_root: Path,
    ) -> None:
        self._candidates = candidates
        self._fd: int | None = fd
        self._namespace_marker: _NamespaceMarker | None = namespace_marker
        self._record_path = record_path
        self._registry_root = registry_root

    @property
    def candidates(self) -> tuple[DaemonAuthorityCandidate, ...]:
        return self._candidates

    @property
    def released(self) -> bool:
        return self._fd is None

    def diagnostic_status(self) -> dict[str, Any]:
        """Return redacted health for the process-lifetime authority claim."""

        problems: list[str] = []
        fd = self._fd
        claim_reference_held = fd is not None
        record_owner = "unavailable"
        record_mode = ""
        permissions_ok = False
        record_identity = "unavailable"
        lock_state = "unavailable"
        namespace_state = "unavailable"
        registry_owner = "unavailable"
        registry_mode = ""
        registry_permissions_ok = False
        record_stat: os.stat_result | None = None
        path_stat: os.stat_result | None = None

        try:
            registry_stat = self._registry_root.lstat()
        except OSError:
            problems.append("registry_root_unavailable")
        else:
            registry_owner = (
                "current_user" if registry_stat.st_uid == os.geteuid() else "unexpected_owner"
            )
            registry_mode = f"{stat.S_IMODE(registry_stat.st_mode):04o}"
            registry_permissions_ok = (
                stat.S_ISDIR(registry_stat.st_mode)
                and registry_owner == "current_user"
                and registry_mode == "0700"
            )
            if not registry_permissions_ok:
                problems.append("registry_permissions_invalid")

        if fd is None:
            problems.append("claim_reference_released")
        else:
            try:
                record_stat = os.fstat(fd)
            except OSError:
                problems.append("record_descriptor_unavailable")
            try:
                path_stat = self._record_path.lstat()
            except OSError:
                problems.append("record_path_unavailable")
            if record_stat is not None:
                record_owner = (
                    "current_user" if record_stat.st_uid == os.geteuid() else "unexpected_owner"
                )
                record_mode = f"{stat.S_IMODE(record_stat.st_mode):04o}"
                permissions_ok = record_owner == "current_user" and record_mode == "0600"
                if not permissions_ok:
                    problems.append("record_permissions_invalid")
            if record_stat is not None and path_stat is not None:
                if (record_stat.st_dev, record_stat.st_ino) == (
                    path_stat.st_dev,
                    path_stat.st_ino,
                ):
                    record_identity = "matched"
                else:
                    record_identity = "mismatched"
                    problems.append("record_identity_mismatched")

            if record_identity == "matched":
                probe_fd = -1
                try:
                    probe_fd = os.open(
                        self._record_path,
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_NONBLOCK", 0),
                    )
                    try:
                        fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except OSError as exc:
                        if exc.errno in {errno.EACCES, errno.EAGAIN}:
                            lock_state = "held"
                        else:
                            problems.append("lock_probe_failed")
                    else:
                        lock_state = "not_held"
                        problems.append("lock_not_held")
                        fcntl.flock(probe_fd, fcntl.LOCK_UN)
                except OSError:
                    problems.append("lock_probe_unavailable")
                finally:
                    if probe_fd >= 0:
                        os.close(probe_fd)

            namespace_marker = self._namespace_marker
            if namespace_marker is None:
                problems.append("namespace_reference_unavailable")
            else:
                try:
                    _verify_bound_namespace_marker(
                        namespace_marker.fileno(),
                        root=self._registry_root,
                        record_path=self._record_path,
                        error_type=AuthorityClaimError,
                    )
                except (OSError, AuthorityClaimError):
                    namespace_state = "invalid"
                    problems.append("namespace_binding_invalid")
                else:
                    namespace_state = "bound"

        status = "degraded" if problems else "ok"
        return {
            "status": status,
            "problems": problems,
            "claim_reference_held": claim_reference_held,
            "lock_state": lock_state,
            "record_owner": record_owner,
            "record_mode": record_mode,
            "expected_record_mode": "0600",
            "permissions_ok": permissions_ok,
            "record_identity": record_identity,
            "namespace_state": namespace_state,
            "registry_owner": registry_owner,
            "registry_mode": registry_mode,
            "expected_registry_mode": "0700",
            "registry_permissions_ok": registry_permissions_ok,
            "candidate_count": len(self._candidates),
            "candidate_roles": sorted(candidate.role for candidate in self._candidates),
            "paths_redacted": True,
            "remediation": (
                "Restart shisad after restoring owner-only authority registry permissions; "
                "if degradation persists, inspect the daemon authority admission logs."
                if problems
                else ""
            ),
        }

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
        namespace_marker = self._namespace_marker
        if namespace_marker is None:
            raise AuthorityClaimError("daemon authority claim namespace is unavailable")
        _verify_bound_namespace_marker(
            namespace_marker.fileno(),
            root=self._registry_root,
            record_path=self._record_path,
            error_type=AuthorityClaimError,
        )
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

    def duplicate_lease(self) -> DaemonAuthorityLease:
        """Duplicate this exact locked record for an exec-contained child."""

        with _registry_guard(self._registry_root):
            self.verify(self._candidates)
            fd = self._fd
            if fd is None:
                raise AuthorityClaimError("daemon authority claim has already been released")
            namespace_marker = self._namespace_marker
            if namespace_marker is None:
                raise AuthorityClaimError("daemon authority claim namespace is unavailable")
            return DaemonAuthorityLease(
                fd=os.dup(fd),
                record_path=self._record_path,
                namespace_fd=os.dup(namespace_marker.fileno()),
            )

    def _discard_descriptors(self) -> None:
        """Close a claim that could not cross its registry transaction boundary."""

        fd = self._fd
        self._fd = None
        if fd is not None:
            with suppress(OSError):
                os.close(fd)
        namespace_marker = self._namespace_marker
        self._namespace_marker = None
        if namespace_marker is not None:
            namespace_marker.close()

    def release(self) -> None:
        """Release this reference and remove its record after inherited holders."""

        fd = self._fd
        if fd is None:
            return
        self._fd = None
        namespace_marker = self._namespace_marker
        self._namespace_marker = None
        cleanup_error: OSError | AuthorityRegistryError | None = None
        fd_open = True
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
                    record_identity = (record_stat.st_dev, record_stat.st_ino)
                    os.close(fd)
                    fd_open = False
                    try:
                        probe_fd = _open_owner_file(self._record_path)
                    except OSError as exc:
                        raise AuthorityRegistryError(
                            "cannot re-open daemon authority claim during release"
                        ) from exc
                    try:
                        inherited_holder = False
                        try:
                            fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except OSError as exc:
                            if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                                raise AuthorityRegistryError(
                                    "cannot inspect daemon authority lease references"
                                ) from exc
                            inherited_holder = True
                        if not inherited_holder:
                            probe_stat = os.fstat(probe_fd)
                            current_stat = self._record_path.lstat()
                            if (probe_stat.st_dev, probe_stat.st_ino) != record_identity or (
                                current_stat.st_dev,
                                current_stat.st_ino,
                            ) != record_identity:
                                raise AuthorityRegistryError(
                                    "daemon authority claim record identity changed during release"
                                )
                            if namespace_marker is not None:
                                _unlink_namespace_marker(namespace_marker)
                                namespace_marker = None
                            self._record_path.unlink()
                            _fsync_directory(self._registry_root)
                    finally:
                        os.close(probe_fd)
        except (OSError, AuthorityRegistryError) as exc:
            cleanup_error = exc
        finally:
            if fd_open:
                os.close(fd)
            if namespace_marker is not None:
                namespace_marker.close()
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
        _SiblingPattern(parent, atomic_write_temp_prefix(name), suffix=".tmp"),
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
            if path_stat.st_nlink != 1:
                raise AuthorityRegistryError(
                    f"daemon mutable authority {role} is hardlinked: {artifact_path}"
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


def _candidate(
    role: str,
    path: Path,
    *,
    validate_external_parent: bool = True,
) -> DaemonAuthorityCandidate:
    lexical = _absolute_lexical_path(path)
    if role in _SYMLINK_REJECT_ROLES:
        _reject_symlink_ancestry(role, lexical)
    if role in _EXTERNAL_FILE_ROLES and validate_external_parent:
        try:
            validate_owner_controlled_parent_ancestry(lexical)
        except OSError as exc:
            raise AuthorityRegistryError(
                f"daemon mutable authority {role} has unsafe parent ancestry: {lexical}"
            ) from exc
    canonical = _canonical_path(lexical)
    return _candidate_at_canonical_path(role, canonical)


def derive_daemon_authority_candidates(
    config: DaemonConfig,
) -> tuple[DaemonAuthorityCandidate, ...]:
    """Derive the complete baseline mutable-authority set without mutation."""

    data_dir = _absolute_lexical_path(config.data_dir)
    data_candidate = _candidate("data_root", config.data_dir)

    def _map_contained(path: Path) -> tuple[Path, bool]:
        lexical = _absolute_lexical_path(path)
        if lexical.is_relative_to(data_dir):
            relative = lexical.relative_to(data_dir)
            return data_candidate.path / relative, True
        return path, False

    control_path, _control_contained = _map_contained(config.socket_path)
    candidates = [
        data_candidate,
        _candidate("control_socket", control_path),
    ]
    approval_path = effective_approval_factor_store_path(data_dir=config.data_dir)
    approval_path, approval_contained = _map_contained(approval_path)
    candidates.append(
        _candidate(
            "approval_factor_store",
            approval_path,
            validate_external_parent=not approval_contained,
        )
    )
    if config.assistant_persona_soul_path is not None:
        soul_path, soul_contained = _map_contained(config.assistant_persona_soul_path)
        candidates.append(
            _candidate(
                "soul",
                soul_path,
                validate_external_parent=not soul_contained,
            )
        )
    return tuple(sorted(candidates, key=lambda item: (os.fspath(item.path), item.role)))


def _registry_root() -> Path:
    try:
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    except KeyError as exc:
        raise AuthorityRegistryError("current user has no passwd authority namespace") from exc
    if not home.is_absolute() or home == Path(home.anchor):
        raise AuthorityRegistryError("current user home cannot host the authority namespace")
    return home / ".shisad-runtime" / "authority-registry"


def _namespace_guard_path(root: Path) -> Path:
    return root.parent / f".{root.name}.guard"


def _namespace_marker_root(root: Path) -> Path:
    return root.parent / f".{root.name}.markers"


def _identity_token(*values: object, length: int) -> str:
    payload = ":".join(str(value) for value in values).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:length]


def _registry_identity_token(path_stat: os.stat_result) -> str:
    return _identity_token(path_stat.st_dev, path_stat.st_ino, length=16)


def _claim_identity_token(path: Path, path_stat: os.stat_result) -> str:
    return _identity_token(path.name, path_stat.st_dev, path_stat.st_ino, length=24)


def _claim_namespace_path(
    root: Path,
    root_stat: os.stat_result,
    record_path: Path,
    record_stat: os.stat_result,
) -> Path:
    return _namespace_marker_root(root) / (
        f"marker-{_registry_identity_token(root_stat)}-"
        f"{_claim_identity_token(record_path, record_stat)}.lock"
    )


def _ensure_registry_runtime_parent(root: Path) -> None:
    try:
        _ensure_owner_directory(root.parent)
        _ensure_owner_directory(_namespace_marker_root(root))
    except AuthorityClaimError as exc:
        raise AuthorityRegistryError(
            "authority runtime directory is unavailable or unsafe"
        ) from exc


def _matching_namespace_marker_paths(root: Path) -> list[Path]:
    marker_root = _namespace_marker_root(root)
    paths: list[Path] = []
    try:
        with os.scandir(marker_root) as entries:
            for entry in entries:
                if not entry.name.startswith("marker-") or not entry.name.endswith(".lock"):
                    continue
                paths.append(Path(entry.path))
                if len(paths) > _MAX_MATCHING_ARTIFACTS:
                    raise AuthorityRegistryError("too many daemon authority namespace markers")
    except FileNotFoundError:
        return []
    except AuthorityRegistryError:
        raise
    except OSError as exc:
        raise AuthorityRegistryError("cannot inspect daemon authority namespace markers") from exc
    return sorted(paths, key=os.fspath)


def _active_namespace_markers(root: Path) -> set[tuple[str, str]]:
    markers: set[tuple[str, str]] = set()
    marker_root = _namespace_marker_root(root)
    for path in _matching_namespace_marker_paths(root):
        suffix = path.name.removeprefix("marker-").removesuffix(".lock")
        root_token, separator, claim_token = suffix.partition("-")
        if (
            not separator
            or len(root_token) != 16
            or len(claim_token) != 24
            or not all(character in "0123456789abcdef" for character in root_token)
            or not all(character in "0123456789abcdef" for character in claim_token)
        ):
            raise AuthorityRegistryError("authority namespace marker is malformed")
        try:
            fd = _open_owner_file(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AuthorityRegistryError("cannot inspect authority namespace marker") from exc
        try:
            path_stat = path.lstat()
            fd_stat = os.fstat(fd)
            if (path_stat.st_dev, path_stat.st_ino) != (fd_stat.st_dev, fd_stat.st_ino):
                raise AuthorityRegistryError("authority namespace marker identity changed")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise AuthorityRegistryError(
                        "cannot inspect authority namespace marker lock"
                    ) from exc
                markers.add((root_token, claim_token))
                continue
            path.unlink()
            _fsync_directory(marker_root)
        finally:
            os.close(fd)
    return markers


def _validate_namespace_markers(root: Path) -> None:
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise AuthorityRegistryError("authority registry namespace is unavailable") from exc
    root_token = _registry_identity_token(root_stat)
    markers = _active_namespace_markers(root)
    if any(marker_root != root_token for marker_root, _claim in markers):
        raise AuthorityRegistryError("authority registry namespace identity changed")

    file_tokens: set[str] = set()
    locked_tokens: set[str] = set()
    for path in sorted(root.glob(f"{_CLAIM_PREFIX}*{_CLAIM_SUFFIX}")):
        try:
            fd = _open_owner_file(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AuthorityRegistryError("cannot inspect authority claim namespace") from exc
        try:
            path_stat = path.lstat()
            fd_stat = os.fstat(fd)
            if (path_stat.st_dev, path_stat.st_ino) != (fd_stat.st_dev, fd_stat.st_ino):
                raise AuthorityRegistryError("authority claim namespace identity changed")
            token = _claim_identity_token(path, path_stat)
            file_tokens.add(token)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise AuthorityRegistryError(
                        "cannot inspect authority claim namespace lock"
                    ) from exc
                locked_tokens.add(token)
        finally:
            os.close(fd)

    marker_tokens = {claim_token for _marker_root, claim_token in markers}
    if not marker_tokens.issubset(file_tokens) or not locked_tokens.issubset(marker_tokens):
        raise AuthorityRegistryError("authority claim namespace identity changed")


def _verify_bound_namespace_marker(
    namespace_fd: int,
    *,
    root: Path,
    record_path: Path,
    error_type: type[AuthorityRegistryError] | type[AuthorityClaimError],
) -> None:
    try:
        root_stat = root.lstat()
        record_stat = record_path.lstat()
        marker_stat = os.fstat(namespace_fd)
    except OSError as exc:
        raise error_type("daemon authority namespace is unavailable") from exc
    expected = _claim_namespace_path(root, root_stat, record_path, record_stat)
    try:
        path_stat = expected.lstat()
    except OSError as exc:
        raise error_type("daemon authority namespace is unavailable") from exc
    if (
        not stat.S_ISREG(marker_stat.st_mode)
        or marker_stat.st_uid != os.geteuid()
        or marker_stat.st_nlink != 1
        or stat.S_IMODE(marker_stat.st_mode) != 0o600
        or (marker_stat.st_dev, marker_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino)
    ):
        raise error_type("daemon authority namespace identity changed")
    try:
        probe_fd = _open_owner_file(expected)
    except OSError as exc:
        raise error_type("daemon authority namespace is unavailable") from exc
    try:
        try:
            fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                return
            raise error_type("daemon authority namespace lock is unavailable") from exc
        raise error_type("daemon authority namespace lock is not held")
    finally:
        os.close(probe_fd)


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


def _create_namespace_marker(root: Path, record_path: Path, record_fd: int) -> _NamespaceMarker:
    marker_path = _claim_namespace_path(
        root,
        root.lstat(),
        record_path,
        os.fstat(record_fd),
    )
    try:
        marker_fd = _open_owner_file(marker_path, create=True, exclusive=True)
    except OSError as exc:
        raise AuthorityRegistryError("cannot create daemon authority namespace marker") from exc
    created = False
    try:
        fcntl.flock(marker_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _fsync_directory(marker_path.parent)
        created = True
        return _NamespaceMarker(fd=marker_fd, path=marker_path)
    finally:
        if not created:
            with suppress(OSError):
                marker_path.unlink()
                _fsync_directory(marker_path.parent)
            os.close(marker_fd)


def _unlink_namespace_marker(marker: _NamespaceMarker) -> None:
    marker_fd = marker.fileno()
    try:
        marker_stat = os.fstat(marker_fd)
        path_stat = marker.path.lstat()
        if (marker_stat.st_dev, marker_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
            raise AuthorityRegistryError("daemon authority namespace marker identity changed")
        marker.path.unlink()
        _fsync_directory(marker.path.parent)
    finally:
        marker.close()


@contextmanager
def _registry_guard(root: Path) -> Iterator[None]:
    _ensure_registry_runtime_parent(root)
    deadline = time.monotonic() + _NAMESPACE_GUARD_TIMEOUT_SECONDS
    guard_path = _namespace_guard_path(root)
    try:
        guard_fd = _open_owner_file(guard_path, create=True)
    except OSError as exc:
        raise AuthorityRegistryError("cannot open owner-authenticated authority guard") from exc
    acquired = False
    try:
        while not acquired:
            try:
                fcntl.flock(guard_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise AuthorityRegistryError(
                        "cannot acquire owner-authenticated authority registry guard"
                    ) from exc
                if time.monotonic() >= deadline:
                    raise AuthorityRegistryError(
                        "timed out acquiring owner-authenticated authority registry guard"
                    ) from exc
                time.sleep(0.005)
            else:
                acquired = True
        guard_stat = os.fstat(guard_fd)
        guard_path_stat = guard_path.lstat()
        if (guard_stat.st_dev, guard_stat.st_ino) != (
            guard_path_stat.st_dev,
            guard_path_stat.st_ino,
        ):
            raise AuthorityRegistryError("authority registry guard identity changed")
        _ensure_registry_root(root)
        _validate_namespace_markers(root)
        initial_stat = root.lstat()
        initial_identity = (initial_stat.st_dev, initial_stat.st_ino)
        yield
        current_stat = root.lstat()
        if (current_stat.st_dev, current_stat.st_ino) != initial_identity:
            raise AuthorityRegistryError("authority registry namespace identity changed")
        _validate_namespace_markers(root)
    finally:
        with suppress(OSError):
            fcntl.flock(guard_fd, fcntl.LOCK_UN)
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
    load_result, payload = decode_json_document(b"".join(chunks))
    if load_result.status is not StateLoadStatus.OK:
        raise AuthorityRegistryError(f"authority claim record is corrupt: {path}")
    if not isinstance(payload, dict) or payload.get("version") != _REGISTRY_SCHEMA_VERSION:
        raise AuthorityRegistryError(f"authority claim record schema is unsupported: {path}")
    if set(payload) != {"version", "pid", "candidates"}:
        raise AuthorityRegistryError(f"authority claim record is malformed: {path}")
    pid = payload["pid"]
    if type(pid) is not int or pid <= 0:
        raise AuthorityRegistryError(f"authority claim pid is malformed: {path}")
    raw_candidates = payload.get("candidates")
    if not isinstance(raw_candidates, list) or not raw_candidates:
        raise AuthorityRegistryError(f"authority claim record has no candidates: {path}")
    candidates: list[DaemonAuthorityCandidate] = []
    for item in raw_candidates:
        if not isinstance(item, dict):
            raise AuthorityRegistryError(f"authority claim candidate is malformed: {path}")
        if set(item) != {"role", "path", "footprint", "device", "inode"}:
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
        if device is not None and (type(device) is not int or device < 0):
            raise AuthorityRegistryError(f"authority claim device is malformed: {path}")
        if inode is not None and (type(inode) is not int or inode < 0):
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


def verify_inherited_daemon_authority_lease(
    lease: DaemonAuthorityLease,
    *,
    data_dir: Path,
) -> tuple[DaemonAuthorityCandidate, ...]:
    """Verify an inherited record fd covers the sidecar's exact data root."""

    if lease.closed:
        raise AuthorityClaimError("inherited daemon authority lease is closed")
    record_path = _canonical_path(lease.record_path)
    registry_root = _canonical_path(_registry_root())
    if (
        record_path.parent != registry_root
        or not record_path.name.startswith(_CLAIM_PREFIX)
        or not record_path.name.endswith(_CLAIM_SUFFIX)
    ):
        raise AuthorityClaimError("inherited daemon authority record path is invalid")
    try:
        record_stat = os.fstat(lease.fd)
        path_stat = record_path.lstat()
    except OSError as exc:
        raise AuthorityClaimError("inherited daemon authority record is unavailable") from exc
    if (record_stat.st_dev, record_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
        raise AuthorityClaimError("inherited daemon authority record identity changed")
    if (
        not stat.S_ISREG(record_stat.st_mode)
        or record_stat.st_uid != os.getuid()
        or record_stat.st_nlink != 1
        or stat.S_IMODE(record_stat.st_mode) != 0o600
    ):
        raise AuthorityClaimError("inherited daemon authority record is unsafe")
    if lease.namespace_fd < 0:
        raise AuthorityClaimError("inherited daemon authority namespace is unavailable")
    _verify_bound_namespace_marker(
        lease.namespace_fd,
        root=registry_root,
        record_path=record_path,
        error_type=AuthorityClaimError,
    )
    try:
        fcntl.flock(lease.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        raise AuthorityClaimError("inherited daemon authority lock is not held") from exc
    candidates = _read_claim_record(lease.fd, record_path)
    canonical_data_dir = _canonical_path(data_dir)
    if not any(
        candidate.role == "data_root" and candidate.path == canonical_data_dir
        for candidate in candidates
    ):
        raise AuthorityClaimError(
            "inherited daemon authority lease does not cover the exact data root"
        )
    os.set_inheritable(lease.fd, False)
    os.set_inheritable(lease.namespace_fd, False)
    return candidates


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


def _trusted_read_inputs(config: DaemonConfig) -> tuple[tuple[str, Path], ...]:
    inputs: list[tuple[str, Path]] = [
        ("policy", _canonical_path(config.policy_path)),
        (
            "selfmod_allowed_signers",
            _canonical_path(config.selfmod_allowed_signers_path),
        ),
    ]
    if config.a2a.enabled and config.a2a.identity is not None:
        inputs.append(
            (
                "a2a_private_key",
                _canonical_path(config.a2a.identity.private_key_path),
            )
        )
    return tuple(inputs)


def daemon_trusted_read_input_paths(config: DaemonConfig) -> tuple[Path, ...]:
    """Return exact read-only control inputs protected from assistant writes."""

    return tuple(path for _label, path in _trusted_read_inputs(config))


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
    for label, path in _trusted_read_inputs(config):
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
    protected_read_inputs = _trusted_read_inputs(config)
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
    namespace_marker: _NamespaceMarker | None = None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _write_claim_record(fd, candidates)
        _fsync_directory(root)
        namespace_marker = _create_namespace_marker(root, record_path, fd)
        published = True
        return DaemonAuthorityClaim(
            candidates=candidates,
            fd=fd,
            namespace_marker=namespace_marker,
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
            if namespace_marker is not None:
                with suppress(AuthorityRegistryError):
                    _unlink_namespace_marker(namespace_marker)
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
    claim: DaemonAuthorityClaim | None = None
    try:
        with _registry_guard(root):
            candidates = derive_daemon_authority_candidates(config)
            _validate_candidate_boundaries(config, candidates, canonical_root)
            _reject_active_claim_conflicts(root, candidates)
            claim = _publish_claim(root, candidates)
        return claim
    except BaseException:
        if claim is not None:
            claim._discard_descriptors()
        raise


def _derive_fresh_config_union_candidates(
    prior_config: DaemonConfig,
    refreshed_config: DaemonConfig,
) -> tuple[DaemonAuthorityCandidate, ...]:
    prior_data_root = _candidate("data_root", prior_config.data_dir)
    candidates = [
        prior_data_root,
        _candidate("config_backup_root", prior_data_root.path / "config-backups"),
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
    claim: DaemonAuthorityClaim | None = None
    try:
        with _registry_guard(root):
            candidates = _derive_fresh_config_union_candidates(prior_config, refreshed_config)
            _validate_candidate_boundaries(refreshed_config, candidates, canonical_root)
            _reject_active_claim_conflicts(root, candidates)
            claim = _publish_claim(root, candidates)
        return claim
    except BaseException:
        if claim is not None:
            claim._discard_descriptors()
        raise


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


def _shared_sticky_directory(path_stat: os.stat_result) -> bool:
    return bool(path_stat.st_mode & stat.S_ISVTX) and bool(path_stat.st_mode & 0o002)


def _authority_directory_descriptor_path(fd: int) -> Path:
    for root in (Path("/proc/self/fd"), Path("/dev/fd")):
        candidate = root / str(fd)
        if candidate.exists():
            return candidate
    raise AuthorityClaimError("verified daemon data directory descriptor path is unavailable")


def _ensure_owner_directory(path: Path) -> None:
    if not path.is_absolute():
        raise AuthorityClaimError(f"daemon data directory is not absolute: {path}")
    components = path.parts[1:]
    if not components:
        raise AuthorityClaimError("daemon data directory cannot be the filesystem root")
    expected_uid = os.getuid()
    directory_flags = getattr(os, "O_PATH", os.O_RDONLY) | getattr(
        os,
        "O_DIRECTORY",
        0,
    )
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    current = Path(path.anchor)
    current_fd = os.open(current, directory_flags)
    creation_boundary = False
    try:
        for index, component in enumerate(components):
            current /= component
            created = False
            try:
                next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            except FileNotFoundError:
                creation_boundary = True
                try:
                    os.mkdir(component, 0o700, dir_fd=current_fd)
                    created = True
                except FileExistsError:
                    pass
                try:
                    next_fd = os.open(component, directory_flags, dir_fd=current_fd)
                except OSError as exc:
                    raise AuthorityClaimError(
                        f"daemon data directory cannot be opened safely: {current}"
                    ) from exc
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise AuthorityClaimError(
                        f"daemon data path has symlink or non-directory ancestry: {current}"
                    ) from exc
                raise AuthorityClaimError(
                    f"daemon data directory cannot be opened safely: {current}"
                ) from exc
            current_stat = os.fstat(next_fd)
            try:
                if not stat.S_ISDIR(current_stat.st_mode):
                    raise AuthorityClaimError(
                        f"daemon data path ancestor is not a directory: {current}"
                    )
                is_final = index == len(components) - 1
                if is_final:
                    if current_stat.st_uid != expected_uid:
                        raise AuthorityClaimError(
                            f"daemon data directory is not owner-controlled: {current}"
                        )
                    if current_stat.st_mode & 0o022:
                        raise AuthorityClaimError(
                            f"daemon data directory is writable by another uid: {current}"
                        )
                    if stat.S_IMODE(current_stat.st_mode) != 0o700:
                        os.chmod(_authority_directory_descriptor_path(next_fd), 0o700)
                        _fsync_directory(_authority_directory_descriptor_path(next_fd))
                else:
                    if current_stat.st_uid not in {0, expected_uid}:
                        raise AuthorityClaimError(
                            f"daemon data directory ancestry is not trusted-owner: {current}"
                        )
                    if creation_boundary and current_stat.st_uid != expected_uid:
                        raise AuthorityClaimError(
                            f"created daemon data directory is not owner-controlled: {current}"
                        )
                    if current_stat.st_mode & 0o022 and not _shared_sticky_directory(current_stat):
                        raise AuthorityClaimError(
                            f"daemon data directory is writable by another uid: {current}"
                        )
                if created:
                    _fsync_directory(_authority_directory_descriptor_path(next_fd))
                    _fsync_directory(_authority_directory_descriptor_path(current_fd))
            except BaseException:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
    finally:
        os.close(current_fd)


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
            if file_stat.st_nlink != 1:
                raise AuthorityClaimError(
                    f"claimed {candidate.role} authority is hardlinked: {path}"
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
