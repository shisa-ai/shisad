"""Bounded, restart-safe migration for the operator TOML configuration."""

from __future__ import annotations

import contextlib
import os
import tempfile
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from shisad.core.config_file import (
    ConfigFileError,
    _initialize_owner_only_generated_file,
    _tighten_descriptor_permissions,
    load_config_file,
)
from shisad.core.storage_platform import (
    combine_permission_capabilities,
    sync_parent_directory,
    tighten_permissions,
)

CURRENT_CONFIG_SCHEMA_VERSION = 1
_LEGACY_CONFIG_SCHEMA_VERSION = 0
_VERSION_PREFIX = b"schema_version = 1\n"


class ConfigUpgradeError(ConfigFileError):
    """A config upgrade cannot be planned or persisted safely."""


class ConfigUpgradeStatus(StrEnum):
    """Finite disposition for one operator config document."""

    CURRENT = "current"
    SAFE_MIGRATION = "safe_migration"


@dataclass(frozen=True, slots=True)
class ConfigUpgradePlan:
    """Read-only plan for one known config schema transition."""

    path: Path
    status: ConfigUpgradeStatus
    from_version: int
    to_version: int
    breaking: bool
    write_required: bool


@dataclass(frozen=True, slots=True)
class ConfigUpgradeResult:
    """Durable result for a current or migrated config."""

    path: Path
    changed: bool
    from_version: int
    to_version: int
    validated: bool
    backup_path: Path | None
    permissions: str
    parent_sync: str


def plan_config_upgrade(
    path: Path,
    *,
    environ: Mapping[str, str] | None = None,
) -> ConfigUpgradePlan:
    """Inspect *path* without mutating it and return the sole known plan."""

    config_path = Path(path).expanduser()
    _original, version = _inspect_config(config_path, environ=environ)
    if version == CURRENT_CONFIG_SCHEMA_VERSION:
        return ConfigUpgradePlan(
            path=config_path,
            status=ConfigUpgradeStatus.CURRENT,
            from_version=version,
            to_version=CURRENT_CONFIG_SCHEMA_VERSION,
            breaking=False,
            write_required=False,
        )
    return ConfigUpgradePlan(
        path=config_path,
        status=ConfigUpgradeStatus.SAFE_MIGRATION,
        from_version=version,
        to_version=CURRENT_CONFIG_SCHEMA_VERSION,
        breaking=False,
        write_required=True,
    )


def apply_config_upgrade(
    path: Path,
    *,
    environ: Mapping[str, str] | None = None,
) -> ConfigUpgradeResult:
    """Persist the known legacy-to-v1 migration with an exact rollback copy."""

    config_path = Path(path).expanduser()
    effective_environ = dict(os.environ if environ is None else environ)
    original, version = _inspect_config(config_path, environ=effective_environ)
    if version == CURRENT_CONFIG_SCHEMA_VERSION:
        return ConfigUpgradeResult(
            path=config_path,
            changed=False,
            from_version=version,
            to_version=version,
            validated=True,
            backup_path=None,
            permissions="not_applicable",
            parent_sync="not_applicable",
        )

    backup_path = _backup_path(config_path)
    backup_permissions, backup_parent_sync = _preserve_exact_backup(
        config_path=config_path,
        backup_path=backup_path,
        original=original,
    )
    migrated = _VERSION_PREFIX + original
    temporary_path, target_permissions = _write_validated_temporary(
        config_path,
        migrated,
        environ=effective_environ,
    )
    target_parent_sync = "not_applicable"
    try:
        if config_path.read_bytes() != original:
            raise ConfigUpgradeError(
                "selected config changed while its migration was being prepared"
            )
        try:
            os.replace(temporary_path, config_path)
        except OSError as exc:
            raise ConfigUpgradeError(
                f"cannot atomically replace selected config: {exc.__class__.__name__}"
            ) from exc
        try:
            target_parent_sync = sync_parent_directory(config_path.parent)
        except OSError as exc:
            raise ConfigUpgradeError(
                "migrated config was replaced but parent-directory sync failed; "
                f"rollback copy remains at {backup_path}: {exc.__class__.__name__}"
            ) from exc
    finally:
        with contextlib.suppress(OSError):
            temporary_path.unlink(missing_ok=True)

    try:
        load_config_file(config_path, environ=effective_environ)
    except ConfigFileError as exc:  # pragma: no cover - validated before replace
        raise ConfigUpgradeError(
            "migrated config failed post-replace validation; "
            f"rollback copy remains at {backup_path}"
        ) from exc
    return ConfigUpgradeResult(
        path=config_path,
        changed=True,
        from_version=version,
        to_version=CURRENT_CONFIG_SCHEMA_VERSION,
        validated=True,
        backup_path=backup_path,
        permissions=combine_permission_capabilities(
            backup_permissions,
            target_permissions,
        ),
        parent_sync=_combine_capability_states(
            backup_parent_sync,
            target_parent_sync,
        ),
    )


def _inspect_config(
    path: Path,
    *,
    environ: Mapping[str, str] | None,
) -> tuple[bytes, int]:
    _require_regular_config(path)
    try:
        original = path.read_bytes()
    except OSError as exc:
        raise ConfigUpgradeError(f"cannot read selected config: {exc.__class__.__name__}") from exc
    try:
        document = tomllib.loads(original.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigUpgradeError(f"invalid TOML: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigUpgradeError("TOML root must be a table")

    if "schema_version" not in document:
        version = _LEGACY_CONFIG_SCHEMA_VERSION
    else:
        raw_version = document["schema_version"]
        if type(raw_version) is not int or raw_version != CURRENT_CONFIG_SCHEMA_VERSION:
            raise ConfigUpgradeError(
                "unsupported schema_version "
                f"{raw_version!r}; this shisad supports schema_version "
                f"{CURRENT_CONFIG_SCHEMA_VERSION} and does not downgrade newer configs"
            )
        version = raw_version

    try:
        load_config_file(path, environ=environ)
    except ConfigFileError as exc:
        raise ConfigUpgradeError(f"selected config cannot be migrated safely: {exc}") from exc
    return original, version


def _require_regular_config(path: Path) -> None:
    if path.is_symlink():
        raise ConfigUpgradeError("selected config destination is a symlink")
    if not path.exists():
        raise ConfigUpgradeError("selected config file does not exist")
    if not path.is_file():
        raise ConfigUpgradeError("selected config path is not a regular file")
    if path.parent.is_symlink():
        raise ConfigUpgradeError("selected config parent is a symlink")


def _backup_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.pre-v{CURRENT_CONFIG_SCHEMA_VERSION}.bak")


def _preserve_exact_backup(
    *,
    config_path: Path,
    backup_path: Path,
    original: bytes,
) -> tuple[str, str]:
    if backup_path.exists() or backup_path.is_symlink():
        if backup_path.is_symlink() or not backup_path.is_file():
            raise ConfigUpgradeError("existing config migration backup is unsafe")
        try:
            backup = backup_path.read_bytes()
        except OSError as exc:
            raise ConfigUpgradeError(
                f"cannot read existing config migration backup: {exc.__class__.__name__}"
            ) from exc
        if backup != original:
            raise ConfigUpgradeError(
                "existing config migration backup does not match the current legacy config"
            )
        permissions = tighten_permissions(backup_path, 0o600)
        if permissions == "failed":
            raise ConfigUpgradeError("existing config migration backup is not owner-only")
        return permissions, "not_applicable"

    try:
        _initialize_owner_only_generated_file(
            backup_path,
            original,
            environ={},
            label="config migration backup",
        )
        permissions = tighten_permissions(backup_path, 0o600)
        if permissions == "failed":
            raise ConfigUpgradeError("config migration backup is not owner-only")
        parent_sync = sync_parent_directory(config_path.parent)
    except (ConfigFileError, OSError) as exc:
        raise ConfigUpgradeError(f"cannot preserve config migration backup: {exc}") from exc
    return permissions, parent_sync


def _write_validated_temporary(
    config_path: Path,
    payload: bytes,
    *,
    environ: Mapping[str, str],
) -> tuple[Path, str]:
    try:
        descriptor, raw_path = tempfile.mkstemp(
            prefix=f".{config_path.name}.migrate-",
            dir=config_path.parent,
        )
    except OSError as exc:
        raise ConfigUpgradeError(
            f"cannot prepare migrated config: {exc.__class__.__name__}"
        ) from exc
    temporary_path = Path(raw_path)
    try:
        permissions = _tighten_descriptor_permissions(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short migrated config write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        load_config_file(temporary_path, environ=environ)
    except (OSError, ConfigFileError) as exc:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        with contextlib.suppress(OSError):
            temporary_path.unlink(missing_ok=True)
        raise ConfigUpgradeError(
            f"cannot validate migrated config before replace: {exc.__class__.__name__}"
        ) from exc
    return temporary_path, permissions


def _combine_capability_states(*states: str) -> str:
    applicable = [state for state in states if state != "not_applicable"]
    if not applicable:
        return "not_applicable"
    if "failed" in applicable:
        return "failed"
    return "supported" if all(state == "supported" for state in applicable) else "unsupported"
