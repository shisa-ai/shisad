"""Versioned provider-agnostic credential references and local backends."""

from __future__ import annotations

import importlib
import os
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol, Self

from filelock import FileLock, Timeout
from pydantic import BaseModel, ConfigDict, Field, model_validator

from shisad.core.atomic_state import (
    AtomicWriteError,
    StateLoadStatus,
    atomic_write_bytes,
    load_state,
    write_state,
)
from shisad.core.config import validate_credential_reference_name
from shisad.core.storage_platform import tighten_permissions

_MAX_LOCATOR_LENGTH = 128
_MAX_SECRET_BYTES = 1024 * 1024
_KEYRING_LOCATOR_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-"
)
_ENV_FIRST_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_ENV_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789")


class CredentialBackend(StrEnum):
    """Supported secret-value owners."""

    ENV = "env"
    KEYRING = "keyring"
    FILE = "file"


class CredentialReferenceError(ValueError):
    """A credential operation failed without exposing backend details."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class CredentialReferenceUnavailable(CredentialReferenceError):
    """A configured credential has no safely available value."""


class KeyringBackend(Protocol):
    """Narrow maintained-keyring surface used by the reference store."""

    def get_password(self, service_name: str, username: str) -> str | None: ...

    def set_password(self, service_name: str, username: str, password: str) -> None: ...

    def delete_password(self, service_name: str, username: str) -> None: ...


class CredentialReference(BaseModel):
    """Persisted metadata for one logical credential."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["shisad.credential_reference.v1"] = (
        "shisad.credential_reference.v1"
    )
    name: str
    backend: CredentialBackend
    locator: str

    @model_validator(mode="after")
    def _validate_metadata(self) -> Self:
        validate_credential_reference_name(self.name)
        if not self.locator or len(self.locator) > _MAX_LOCATOR_LENGTH:
            raise ValueError("credential locator must contain 1-128 characters")
        if self.backend is CredentialBackend.ENV:
            if self.locator[0] not in _ENV_FIRST_CHARS or any(
                char not in _ENV_CHARS for char in self.locator
            ):
                raise ValueError("environment credential locator is invalid")
        elif self.backend is CredentialBackend.KEYRING:
            if any(char not in _KEYRING_LOCATOR_CHARS for char in self.locator):
                raise ValueError("keyring credential locator is invalid")
        elif self.locator != self.name:
            raise ValueError("file credential locator must equal its logical name")
        return self


class CredentialStatus(BaseModel):
    """Redacted operator projection for one logical credential."""

    model_config = ConfigDict(frozen=True)

    name: str
    backend: CredentialBackend | None = None
    locator: str = ""
    configured: bool
    available: bool
    safe: bool | None
    reason: str


class _CredentialRegistryState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["shisad.credential_registry.v1"] = "shisad.credential_registry.v1"
    references: list[CredentialReference] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_names(self) -> Self:
        names = [reference.name for reference in self.references]
        if len(names) != len(set(names)):
            raise ValueError("credential registry contains duplicate logical names")
        return self


def _has_symlink_component(path: Path) -> bool:
    candidate = Path(path).expanduser()
    for component in (candidate, *candidate.parents):
        try:
            if component.is_symlink():
                return True
        except OSError:
            return True
    return False


def _posix_mode_is(path: Path, expected: int) -> bool | None:
    if os.name != "posix":
        return None
    try:
        return stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) == expected
    except (FileNotFoundError, OSError):
        return False


def _load_system_keyring() -> KeyringBackend:
    try:
        module = importlib.import_module("keyring")
        backend = module.get_keyring()
        priority = float(backend.priority)
        if priority <= 0:
            raise RuntimeError("no viable system keyring")
    except Exception:
        raise CredentialReferenceError("keyring_backend_unavailable") from None
    return module


class CredentialReferenceStore:
    """Atomic metadata registry with explicit backend-specific secret ownership."""

    def __init__(
        self,
        *,
        registry_path: Path,
        secret_root: Path,
        environ: Mapping[str, str] | None = None,
        keyring_backend: KeyringBackend | None = None,
    ) -> None:
        self.registry_path = Path(registry_path).expanduser()
        self.secret_root = Path(secret_root).expanduser()
        self._environ = os.environ if environ is None else environ
        self._keyring_backend = keyring_backend
        self._lock = FileLock(str(self.registry_path.with_suffix(".lock")), timeout=5)

    def set_reference(
        self,
        *,
        name: str,
        backend: CredentialBackend,
        locator: str = "",
        secret: str | None = None,
        replace: bool = False,
    ) -> CredentialStatus:
        """Create or explicitly replace one reference after backend publication."""

        reference = CredentialReference(
            name=name,
            backend=backend,
            locator=name if backend is CredentialBackend.FILE else locator,
        )
        if backend is CredentialBackend.ENV and secret is not None:
            raise CredentialReferenceError("env_backend_rejects_secret_value")
        if backend is not CredentialBackend.ENV:
            self._validate_secret(secret)

        with self._locked():
            state = self._load_state()
            existing = {item.name: item for item in state.references}.get(reference.name)
            if existing is not None and not replace:
                raise CredentialReferenceError("credential_reference_exists")
            if existing is not None and existing.backend is not reference.backend:
                raise CredentialReferenceError("credential_backend_change_requires_remove")
            if (
                existing is not None
                and existing.backend is CredentialBackend.KEYRING
                and existing.locator != reference.locator
            ):
                raise CredentialReferenceError("credential_locator_change_requires_remove")

            self._publish_backend(reference, secret=secret)
            references = [item for item in state.references if item.name != reference.name]
            references.append(reference)
            try:
                self._write_state(_CredentialRegistryState(references=sorted(
                    references, key=lambda item: item.name
                )))
            except CredentialReferenceError:
                if existing is None:
                    self._rollback_new_backend(reference)
                raise
            return self._status_for(reference)

    def status(self, name: str) -> CredentialStatus:
        """Return one redacted status without resolving a value to the caller."""

        normalized = validate_credential_reference_name(name)
        with self._locked():
            state = self._load_state()
            for reference in state.references:
                if reference.name == normalized:
                    return self._status_for(reference)
        return CredentialStatus(
            name=normalized,
            configured=False,
            available=False,
            safe=True,
            reason="credential_reference_not_configured",
        )

    def list_status(self) -> list[CredentialStatus]:
        """Return stable redacted statuses for every configured reference."""

        with self._locked():
            state = self._load_state()
            return [self._status_for(reference) for reference in state.references]

    def resolve(self, name: str) -> str:
        """Resolve a value for a trusted adapter-construction boundary."""

        normalized = validate_credential_reference_name(name)
        with self._locked():
            state = self._load_state()
            reference = next(
                (item for item in state.references if item.name == normalized),
                None,
            )
            if reference is None:
                raise CredentialReferenceUnavailable("credential_reference_not_configured")
            value = self._read_backend(reference)
            if value is None:
                raise CredentialReferenceUnavailable("credential_value_unavailable")
            return value

    def remove(self, name: str) -> CredentialStatus:
        """Remove backend material first, retaining metadata on backend failure."""

        normalized = validate_credential_reference_name(name)
        with self._locked():
            state = self._load_state()
            reference = next(
                (item for item in state.references if item.name == normalized),
                None,
            )
            if reference is None:
                return CredentialStatus(
                    name=normalized,
                    configured=False,
                    available=False,
                    safe=True,
                    reason="credential_reference_not_configured",
                )
            self._remove_backend(reference)
            self._write_state(
                _CredentialRegistryState(
                    references=[item for item in state.references if item.name != normalized]
                )
            )
            return CredentialStatus(
                name=normalized,
                backend=reference.backend,
                locator=reference.locator,
                configured=False,
                available=False,
                safe=True,
                reason="credential_reference_removed",
            )

    @contextmanager
    def _locked(self) -> Iterator[None]:
        try:
            self._lock.acquire(timeout=5)
        except Timeout:
            raise CredentialReferenceError("credential_registry_busy") from None
        except OSError:
            raise CredentialReferenceError("credential_registry_unavailable") from None
        try:
            yield
        finally:
            self._lock.release()

    def _load_state(self) -> _CredentialRegistryState:
        self._validate_registry_path()
        loaded = load_state(self.registry_path, _CredentialRegistryState)
        if loaded.status is StateLoadStatus.MISSING:
            return _CredentialRegistryState()
        if loaded.status is StateLoadStatus.UNSUPPORTED_SCHEMA:
            raise CredentialReferenceError("credential_registry_unsupported")
        if loaded.status is not StateLoadStatus.OK or not isinstance(
            loaded.value, _CredentialRegistryState
        ):
            raise CredentialReferenceError("credential_registry_corrupt")
        return loaded.value

    def _write_state(self, state: _CredentialRegistryState) -> None:
        self._validate_registry_path()
        try:
            capability = write_state(self.registry_path, state)
        except AtomicWriteError:
            raise CredentialReferenceError("credential_registry_write_failed") from None
        if capability.permissions == "failed":
            raise CredentialReferenceError("credential_registry_unsafe")
        if _posix_mode_is(self.registry_path, 0o600) is False:
            raise CredentialReferenceError("credential_registry_unsafe")

    def _validate_registry_path(self) -> None:
        if _has_symlink_component(self.registry_path):
            raise CredentialReferenceError("credential_registry_unsafe")
        try:
            if self.registry_path.exists():
                mode = self.registry_path.stat(follow_symlinks=False).st_mode
                if not stat.S_ISREG(mode):
                    raise CredentialReferenceError("credential_registry_unsafe")
                if _posix_mode_is(self.registry_path, 0o600) is False:
                    raise CredentialReferenceError("credential_registry_unsafe")
        except OSError:
            raise CredentialReferenceError("credential_registry_unavailable") from None

    @staticmethod
    def _validate_secret(secret: str | None) -> None:
        if secret is None or not secret:
            raise CredentialReferenceError("credential_secret_required")
        if len(secret.encode("utf-8")) > _MAX_SECRET_BYTES:
            raise CredentialReferenceError("credential_secret_too_large")

    def _publish_backend(self, reference: CredentialReference, *, secret: str | None) -> None:
        if reference.backend is CredentialBackend.ENV:
            return
        assert secret is not None
        if reference.backend is CredentialBackend.KEYRING:
            try:
                self._keyring().set_password(reference.locator, reference.name, secret)
            except CredentialReferenceError:
                raise
            except Exception:
                raise CredentialReferenceError("keyring_backend_unavailable") from None
            return
        self._write_file_secret(reference, secret)

    def _status_for(self, reference: CredentialReference) -> CredentialStatus:
        if reference.backend is CredentialBackend.FILE:
            path = self._secret_path(reference)
            safe = self._file_posture_safe(path)
            available = bool(safe and path.exists())
            reason = (
                "credential_available"
                if available
                else "credential_file_unsafe"
                if safe is False
                else "credential_value_unavailable"
            )
        elif reference.backend is CredentialBackend.KEYRING:
            try:
                available = (
                    self._keyring().get_password(reference.locator, reference.name) is not None
                )
                safe = True
                reason = "credential_available" if available else "credential_value_unavailable"
            except Exception:
                available = False
                safe = True
                reason = "keyring_backend_unavailable"
        else:
            available = bool(self._environ.get(reference.locator))
            safe = True
            reason = "credential_available" if available else "credential_value_unavailable"
        return CredentialStatus(
            name=reference.name,
            backend=reference.backend,
            locator=reference.locator,
            configured=True,
            available=available,
            safe=safe,
            reason=reason,
        )

    def _read_backend(self, reference: CredentialReference) -> str | None:
        if reference.backend is CredentialBackend.ENV:
            return self._environ.get(reference.locator) or None
        if reference.backend is CredentialBackend.KEYRING:
            try:
                return self._keyring().get_password(reference.locator, reference.name)
            except CredentialReferenceError:
                raise
            except Exception:
                raise CredentialReferenceUnavailable("keyring_backend_unavailable") from None
        path = self._secret_path(reference)
        if self._file_posture_safe(path) is not True or not path.exists():
            return None
        try:
            return path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            raise CredentialReferenceUnavailable("credential_value_unavailable") from None

    def _write_file_secret(self, reference: CredentialReference, secret: str) -> None:
        path = self._secret_path(reference)
        if _has_symlink_component(self.secret_root) or path.is_symlink():
            raise CredentialReferenceError("credential_file_unsafe")
        try:
            self.secret_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        except OSError:
            raise CredentialReferenceError("credential_file_unavailable") from None
        if tighten_permissions(self.secret_root, 0o700) == "failed":
            raise CredentialReferenceError("credential_file_unsafe")
        if _posix_mode_is(self.secret_root, 0o700) is False:
            raise CredentialReferenceError("credential_file_unsafe")
        if path.is_symlink():
            raise CredentialReferenceError("credential_file_unsafe")
        try:
            capability = atomic_write_bytes(path, secret.encode("utf-8"))
        except AtomicWriteError:
            raise CredentialReferenceError("credential_file_unsafe") from None
        if capability.permissions == "failed" or _posix_mode_is(path, 0o600) is False:
            raise CredentialReferenceError("credential_file_unsafe")

    def _secret_path(self, reference: CredentialReference) -> Path:
        path = self.secret_root / reference.locator
        try:
            root = self.secret_root.resolve(strict=False)
            resolved_parent = path.parent.resolve(strict=False)
        except (OSError, RuntimeError):
            raise CredentialReferenceError("credential_file_unsafe") from None
        if resolved_parent != root:
            raise CredentialReferenceError("credential_file_unsafe")
        return path

    def _file_posture_safe(self, path: Path) -> bool | None:
        if _has_symlink_component(self.secret_root) or path.is_symlink():
            return False
        if not path.exists():
            return _posix_mode_is(self.secret_root, 0o700) if self.secret_root.exists() else True
        try:
            if not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
                return False
        except OSError:
            return False
        root_safe = _posix_mode_is(self.secret_root, 0o700)
        file_safe = _posix_mode_is(path, 0o600)
        if root_safe is None or file_safe is None:
            return None
        return root_safe and file_safe

    def _remove_backend(self, reference: CredentialReference) -> None:
        if reference.backend is CredentialBackend.ENV:
            return
        if reference.backend is CredentialBackend.KEYRING:
            try:
                keyring = self._keyring()
                if keyring.get_password(reference.locator, reference.name) is not None:
                    keyring.delete_password(reference.locator, reference.name)
            except Exception:
                raise CredentialReferenceError("credential_backend_remove_failed") from None
            return
        path = self._secret_path(reference)
        if path.is_symlink() or (_has_symlink_component(self.secret_root) and path.exists()):
            raise CredentialReferenceError("credential_backend_remove_failed")
        try:
            path.unlink(missing_ok=True)
        except OSError:
            raise CredentialReferenceError("credential_backend_remove_failed") from None

    def _rollback_new_backend(self, reference: CredentialReference) -> None:
        with suppress(CredentialReferenceError):
            self._remove_backend(reference)

    def _keyring(self) -> KeyringBackend:
        if self._keyring_backend is None:
            self._keyring_backend = _load_system_keyring()
        return self._keyring_backend
