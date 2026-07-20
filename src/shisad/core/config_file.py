"""Typed TOML configuration loading with source and redaction metadata."""

from __future__ import annotations

import json
import os
import tomllib
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError
from pydantic_core import PydanticUndefined
from pydantic_settings import BaseSettings

from shisad.core.config import DaemonConfig, ModelConfig, SecurityConfig

_SECTIONS: dict[str, type[BaseSettings]] = {
    "daemon": DaemonConfig,
    "model": ModelConfig,
    "security": SecurityConfig,
}
_SECRET_FIELD_MARKERS = (
    "api_key",
    "token",
    "secret",
    "password",
    "credential",
    "private_key",
    "extra_headers",
    "bearer",
    "factor_store_path",
    "audit_log_path",
    "config_path",
)
_NESTED_SECRET_FIELDS = {"a2a", "mcp_servers"}


class ConfigFileError(ValueError):
    """An operator-authored configuration file is invalid or unsafe."""


@dataclass(frozen=True, slots=True)
class LoadedConfig:
    """Validated effective configuration plus per-field source metadata."""

    daemon: DaemonConfig
    model: ModelConfig
    security: SecurityConfig
    sources: dict[str, dict[str, str]]

    def redacted_projection(self) -> dict[str, dict[str, dict[str, object]]]:
        """Return stable source/value metadata without exposing secrets."""

        projection: dict[str, dict[str, dict[str, object]]] = {}
        for section in _SECTIONS:
            settings = getattr(self, section)
            values = settings.model_dump(mode="json")
            section_projection: dict[str, dict[str, object]] = {}
            for name in settings.__class__.model_fields:
                value: object = values.get(name)
                if name not in values:
                    value = getattr(settings, name)
                if (
                    name in _NESTED_SECRET_FIELDS or _field_is_secret(name)
                ) and _has_secret_value(value):
                    value = "<redacted>"
                section_projection[name] = {
                    "value": value,
                    "source": self.sources[section][name],
                }
            projection[section] = section_projection
        return projection


def load_config_file(
    path: Path,
    *,
    environ: Mapping[str, str] | None = None,
    cli_overrides: Mapping[str, Mapping[str, object]] | None = None,
    protected_roots: Sequence[Path] = (),
) -> LoadedConfig:
    """Load and validate one explicit TOML file.

    Precedence is CLI overrides, environment, TOML, then model defaults. The
    caller supplies protected roots because config parsing itself must remain
    independent of daemon state construction.
    """

    config_path = Path(path).expanduser()
    _reject_protected_path(config_path, protected_roots=protected_roots)
    try:
        raw_bytes = config_path.read_bytes()
    except FileNotFoundError:
        raise ConfigFileError("selected config file does not exist") from None
    except OSError as exc:
        raise ConfigFileError(
            f"cannot read selected config file: {exc.__class__.__name__}"
        ) from exc
    try:
        document = tomllib.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigFileError(f"invalid TOML: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigFileError("TOML root must be a table")

    allowed_top_level = {"schema_version", *_SECTIONS}
    unknown_top_level = sorted(set(document) - allowed_top_level)
    if unknown_top_level:
        raise ConfigFileError(f"unknown top-level key: {unknown_top_level[0]}")
    schema_version = document.get("schema_version", 1)
    if schema_version != 1:
        raise ConfigFileError(f"unsupported schema_version: {schema_version!r}")
    daemon_document = document.get("daemon", {})
    if isinstance(daemon_document, dict) and "config_path" in daemon_document:
        raise ConfigFileError("daemon.config_path may be selected only by CLI or environment")

    effective_env = dict(os.environ if environ is None else environ)
    overrides = dict(cli_overrides or {})
    unknown_override_sections = sorted(set(overrides) - set(_SECTIONS))
    if unknown_override_sections:
        raise ConfigFileError(f"unknown CLI override section: {unknown_override_sections[0]}")

    loaded: dict[str, BaseSettings] = {}
    sources: dict[str, dict[str, str]] = {}
    for section, model_type in _SECTIONS.items():
        raw_section = document.get(section, {})
        if not isinstance(raw_section, dict):
            raise ConfigFileError(f"{section} must be a TOML table")
        section_cli = overrides.get(section, {})
        settings, section_sources = _load_settings_section(
            section=section,
            model_type=model_type,
            toml_values=raw_section,
            environ=effective_env,
            cli_values=section_cli,
        )
        loaded[section] = settings
        sources[section] = section_sources
    sources["daemon"]["config_path"] = "explicit"

    return LoadedConfig(
        daemon=_as_type(loaded["daemon"], DaemonConfig).model_copy(
            update={"config_path": config_path.resolve(strict=False)}
        ),
        model=_as_type(loaded["model"], ModelConfig),
        security=_as_type(loaded["security"], SecurityConfig),
        sources=sources,
    )


def default_config_path(*, environ: Mapping[str, str] | None = None) -> Path:
    """Return the platform-neutral default user config path."""

    effective_env = os.environ if environ is None else environ
    xdg_config_home = str(effective_env.get("XDG_CONFIG_HOME", "")).strip()
    root = Path(xdg_config_home).expanduser() if xdg_config_home else Path.home() / ".config"
    return root / "shisad" / "config.toml"


def config_field_inventory() -> list[dict[str, str]]:
    """Return the finite advertised config surface and its runtime disposition."""

    rows: list[dict[str, str]] = []
    for section, model_type in _SECTIONS.items():
        for field in model_type.model_fields:
            status = "live"
            if section == "security" and field == "default_deny":
                status = "compatibility_only"
                consumer = "PolicyBundle.default_deny"
            elif section == "model":
                consumer = "ModelRouter"
            elif section == "security":
                consumer = "approval factor store construction"
            else:
                consumer = "DaemonConfig runtime consumers"
            rows.append(
                {
                    "section": section,
                    "field": field,
                    "status": status,
                    "consumer": consumer,
                }
            )
    return rows


def render_config_template() -> str:
    """Generate a commented TOML template from the classified live schema."""

    inventory = config_field_inventory()
    rows_by_section: dict[str, list[dict[str, str]]] = {name: [] for name in _SECTIONS}
    for row in inventory:
        rows_by_section[row["section"]].append(row)

    lines = ["schema_version = 1", ""]
    for section, model_type in _SECTIONS.items():
        defaults = model_type.model_validate(_settings_defaults(model_type)).model_dump(mode="json")
        lines.append(f"[{section}]")
        for row in rows_by_section[section]:
            field = row["field"]
            if section == "daemon" and field == "config_path":
                lines.append("# status=live consumer=config loader")
                lines.append(
                    "# config_path is selected only via --config or SHISAD_CONFIG_PATH"
                )
                continue
            value = "" if _field_is_secret(field) else defaults.get(field)
            lines.append(f"# status={row['status']} consumer={row['consumer']}")
            lines.append(f"# {field} = {_toml_literal(value)}")
        lines.append("")
    return "\n".join(lines)


def _toml_literal(value: object) -> str:
    if value is None:
        return '""'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_literal(item) for item in value) + "]"
    if isinstance(value, dict):
        entries = [
            f"{json.dumps(str(key), ensure_ascii=True)} = {_toml_literal(item)}"
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        ]
        return "{ " + ", ".join(entries) + " }"
    return json.dumps(str(value), ensure_ascii=True)


def load_effective_config(
    config_path: Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    cli_overrides: Mapping[str, Mapping[str, object]] | None = None,
    protected_roots: Sequence[Path] = (),
) -> LoadedConfig:
    """Load an explicit/env/default config, or typed defaults when absent."""

    effective_env = dict(os.environ if environ is None else environ)
    env_path_text = str(effective_env.get("SHISAD_CONFIG_PATH", "")).strip()
    explicit = config_path is not None or bool(env_path_text)
    selected = (
        Path(config_path).expanduser()
        if config_path is not None
        else Path(env_path_text).expanduser()
        if env_path_text
        else default_config_path(environ=effective_env)
    )
    if selected.exists() or explicit:
        loaded = load_config_file(
            selected,
            environ=effective_env,
            cli_overrides=cli_overrides,
            protected_roots=protected_roots,
        )
        _reject_protected_path(
            selected,
            protected_roots=(
                *protected_roots,
                loaded.daemon.data_dir,
                *loaded.daemon.assistant_fs_roots,
            ),
        )
        loaded.sources["daemon"]["config_path"] = (
            "cli"
            if config_path is not None
            else "env:SHISAD_CONFIG_PATH"
            if env_path_text
            else "default_path"
        )
        return loaded

    return _load_empty_config(environ=effective_env, cli_overrides=cli_overrides)


def _load_empty_config(
    *,
    environ: Mapping[str, str],
    cli_overrides: Mapping[str, Mapping[str, object]] | None,
) -> LoadedConfig:
    overrides = dict(cli_overrides or {})
    loaded: dict[str, BaseSettings] = {}
    sources: dict[str, dict[str, str]] = {}
    for section, model_type in _SECTIONS.items():
        settings, section_sources = _load_settings_section(
            section=section,
            model_type=model_type,
            toml_values={},
            environ=environ,
            cli_values=overrides.get(section, {}),
        )
        loaded[section] = settings
        sources[section] = section_sources
    return LoadedConfig(
        daemon=_as_type(loaded["daemon"], DaemonConfig),
        model=_as_type(loaded["model"], ModelConfig),
        security=_as_type(loaded["security"], SecurityConfig),
        sources=sources,
    )


def _load_settings_section[SettingsT: BaseSettings](
    *,
    section: str,
    model_type: type[SettingsT],
    toml_values: Mapping[str, object],
    environ: Mapping[str, str],
    cli_values: Mapping[str, object],
) -> tuple[SettingsT, dict[str, str]]:
    field_names = set(model_type.model_fields)
    unknown_toml = sorted(set(toml_values) - field_names)
    if unknown_toml:
        raise ConfigFileError(f"unknown {section} field: {unknown_toml[0]}")
    unknown_cli = sorted(set(cli_values) - field_names)
    if unknown_cli:
        raise ConfigFileError(f"unknown {section} CLI override: {unknown_cli[0]}")

    _reject_unknown_nested_values(
        values=toml_values,
        schema=model_type.model_json_schema(),
        section=section,
    )

    values: dict[str, object] = {}
    sources = {name: "default" for name in field_names}
    for name, value in toml_values.items():
        values[name] = value
        sources[name] = "toml"

    prefix = str(model_type.model_config.get("env_prefix", ""))
    environment_by_casefold = {
        str(key).casefold(): (str(key), value) for key, value in environ.items()
    }
    for name in field_names:
        canonical_key = f"{prefix}{name}".upper()
        match = environment_by_casefold.get(canonical_key.casefold())
        if match is None:
            continue
        _actual_key, value = match
        values[name] = value
        sources[name] = f"env:{canonical_key}"

    for name, value in cli_values.items():
        values[name] = value
        sources[name] = "cli"

    _reject_unknown_nested_values(
        values=values,
        schema=model_type.model_json_schema(),
        section=section,
    )

    try:
        settings_factory = cast(Any, model_type)
        return settings_factory(
            _env_prefix="__SHISAD_CONFIG_FILE_ENV_DISABLED__",
            **values,
        ), sources
    except ValidationError as exc:
        failures = []
        for error_row in exc.errors(include_url=False, include_context=False, include_input=False):
            location = ".".join(str(part) for part in error_row.get("loc", ())) or "root"
            failures.append(f"{section}.{location}:{error_row.get('type', 'invalid')}")
        summary = ", ".join(failures) or f"{section}.root:invalid"
        raise ConfigFileError(f"invalid {section} configuration: {summary}") from exc


def _settings_defaults[SettingsT: BaseSettings](
    model_type: type[SettingsT],
) -> dict[str, object]:
    defaults: dict[str, object] = {}
    for name, field in model_type.model_fields.items():
        if field.default is not PydanticUndefined:
            defaults[name] = deepcopy(field.default)
            continue
        if field.default_factory is not None:
            defaults[name] = field.get_default(call_default_factory=True, validated_data={})
            continue
        raise ConfigFileError(f"configuration field has no default: {model_type.__name__}.{name}")
    return defaults


def _reject_unknown_nested_values(
    *,
    values: Mapping[str, object],
    schema: Mapping[str, object],
    section: str,
) -> None:
    """Reject unknown model keys in native structures and nested JSON strings."""

    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        return
    for name, value in values.items():
        field_schema = properties.get(name)
        if isinstance(field_schema, Mapping):
            _reject_unknown_schema_value(
                value=value,
                schema=field_schema,
                root_schema=schema,
                path=f"{section}.{name}",
            )


def _reject_unknown_schema_value(
    *,
    value: object,
    schema: Mapping[str, object],
    root_schema: Mapping[str, object],
    path: str,
) -> None:
    if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            pass
        else:
            _reject_unknown_schema_value(
                value=decoded,
                schema=schema,
                root_schema=root_schema,
                path=path,
            )
            return
    resolved = _resolve_schema_reference(schema, root_schema=root_schema)
    selected = _select_schema_branch(value, resolved, root_schema=root_schema)
    if selected is not None:
        resolved = _resolve_schema_reference(selected, root_schema=root_schema)

    if isinstance(value, Mapping):
        properties = resolved.get("properties")
        if isinstance(properties, Mapping):
            unknown = sorted(str(key) for key in set(value) - set(properties))
            if unknown:
                raise ConfigFileError(f"unknown nested field: {path}.{unknown[0]}")
            for key, item in value.items():
                child_schema = properties.get(key)
                if isinstance(child_schema, Mapping):
                    _reject_unknown_schema_value(
                        value=item,
                        schema=child_schema,
                        root_schema=root_schema,
                        path=f"{path}.{key}",
                    )
            return
        additional = resolved.get("additionalProperties")
        if isinstance(additional, Mapping):
            for key, item in value.items():
                _reject_unknown_schema_value(
                    value=item,
                    schema=additional,
                    root_schema=root_schema,
                    path=f"{path}.{key}",
                )
        return

    if isinstance(value, list):
        item_schema = resolved.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                _reject_unknown_schema_value(
                    value=item,
                    schema=item_schema,
                    root_schema=root_schema,
                    path=f"{path}.{index}",
                )


def _resolve_schema_reference(
    schema: Mapping[str, object],
    *,
    root_schema: Mapping[str, object],
) -> Mapping[str, object]:
    reference = schema.get("$ref")
    if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
        return schema
    definitions = root_schema.get("$defs", {})
    if not isinstance(definitions, Mapping):
        return schema
    resolved = definitions.get(reference.removeprefix("#/$defs/"))
    return resolved if isinstance(resolved, Mapping) else schema


def _select_schema_branch(
    value: object,
    schema: Mapping[str, object],
    *,
    root_schema: Mapping[str, object],
) -> Mapping[str, object] | None:
    discriminator = schema.get("discriminator")
    if isinstance(value, Mapping) and isinstance(discriminator, Mapping):
        property_name = discriminator.get("propertyName")
        mapping = discriminator.get("mapping")
        if isinstance(property_name, str) and isinstance(mapping, Mapping):
            selected_ref = mapping.get(value.get(property_name))
            if isinstance(selected_ref, str):
                return _resolve_schema_reference(
                    {"$ref": selected_ref},
                    root_schema=root_schema,
                )
    branches = schema.get("anyOf") or schema.get("oneOf")
    if not isinstance(branches, list):
        return None
    expected_type = (
        "object"
        if isinstance(value, Mapping)
        else "array"
        if isinstance(value, list)
        else "null"
        if value is None
        else None
    )
    for branch in branches:
        if not isinstance(branch, Mapping):
            continue
        resolved = _resolve_schema_reference(branch, root_schema=root_schema)
        if expected_type is None or resolved.get("type") == expected_type:
            return resolved
    return None


def _field_is_secret(name: str) -> bool:
    lowered = name.casefold()
    return any(marker in lowered for marker in _SECRET_FIELD_MARKERS)


def _has_secret_value(value: object) -> bool:
    return value is not None and value != "" and value != () and value != [] and value != {}


def _reject_protected_path(path: Path, *, protected_roots: Sequence[Path]) -> None:
    candidate = path.resolve(strict=False)
    for root in protected_roots:
        resolved_root = Path(root).expanduser().resolve(strict=False)
        if candidate == resolved_root or resolved_root in candidate.parents:
            raise ConfigFileError("config path is inside a managed root")


def _as_type[SettingsT: BaseSettings](
    value: BaseSettings,
    expected: type[SettingsT],
) -> SettingsT:
    if not isinstance(value, expected):
        raise TypeError(f"expected {expected.__name__}, got {type(value).__name__}")
    return value
