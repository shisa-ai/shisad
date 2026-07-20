"""U41 red-first tests for TOML configuration and source projection."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.core.config_file import (
    ConfigFileError,
    config_field_inventory,
    load_config_file,
    load_effective_config,
    render_config_template,
)
from shisad.core.providers.routing import ModelComponent, ModelRouter


def _write_config(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_u41_config_precedence_sources_and_secret_redaction(tmp_path: Path) -> None:
    configured_data_dir = tmp_path / "from-toml"
    config_path = _write_config(
        tmp_path / "config.toml",
        f"""
schema_version = 1

[daemon]
log_level = "WARNING"
data_dir = "{configured_data_dir}"

[model]
api_key = "toml-secret"
model_id = "toml-model"

[security]
approval_factor_store_path = "/toml/factors.json"
""",
    )

    loaded = load_config_file(
        config_path,
        environ={
            "SHISAD_LOG_LEVEL": "ERROR",
            "SHISAD_MODEL_API_KEY": "env-secret",
        },
        cli_overrides={"daemon": {"log_level": "DEBUG"}},
    )

    assert loaded.daemon.log_level == "DEBUG"
    assert loaded.daemon.data_dir == configured_data_dir
    assert not configured_data_dir.exists()
    assert loaded.model.api_key == "env-secret"
    assert loaded.model.model_id == "toml-model"

    projection = loaded.redacted_projection()
    assert projection["daemon"]["log_level"] == {
        "value": "DEBUG",
        "source": "cli",
    }
    assert projection["daemon"]["data_dir"] == {
        "value": str(configured_data_dir),
        "source": "toml",
    }
    assert projection["model"]["api_key"] == {
        "value": "<redacted>",
        "source": "env:SHISAD_MODEL_API_KEY",
    }
    assert projection["security"]["approval_factor_store_path"] == {
        "value": "<redacted>",
        "source": "toml",
    }
    assert "env-secret" not in str(projection)
    assert "toml-secret" not in str(projection)
    assert projection["daemon"]["config_path"] == {
        "value": "<redacted>",
        "source": "explicit",
    }


def test_u41_unset_model_ids_preserve_preset_derived_defaults(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path / "config.toml",
        """
schema_version = 1
[model]
planner_provider_preset = "openai_default"
embeddings_provider_preset = "openai_default"
monitor_provider_preset = "anthropic_default"
""",
    )

    loaded = load_config_file(config_path, environ={})
    router = ModelRouter(loaded.model)

    assert "planner_model_id" not in loaded.model.model_fields_set
    assert "embeddings_model_id" not in loaded.model.model_fields_set
    assert "monitor_model_id" not in loaded.model.model_fields_set
    assert router.route_for(ModelComponent.PLANNER).model_id == "gpt-5.4-2026-03-05"
    assert router.route_for(ModelComponent.EMBEDDINGS).model_id == "text-embedding-3-small"
    assert router.route_for(ModelComponent.MONITOR).model_id == "claude-sonnet-4-6"


def test_u41_config_defaults_are_annotated_without_ambient_environment(tmp_path: Path) -> None:
    loaded = load_config_file(
        _write_config(tmp_path / "config.toml", "schema_version = 1\n"),
        environ={},
    )

    projection = loaded.redacted_projection()
    assert projection["daemon"]["log_level"] == {"value": "INFO", "source": "default"}
    assert projection["model"]["api_key"] == {"value": None, "source": "default"}


def test_u41_toml_does_not_interpolate_environment_placeholders(tmp_path: Path) -> None:
    loaded = load_config_file(
        _write_config(
            tmp_path / "config.toml",
            'schema_version = 1\n[daemon]\nlog_level = "${HOME}"\n',
        ),
        environ={"HOME": "/secret/home"},
    )

    assert loaded.daemon.log_level == "${HOME}"


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("schema_version = 2\n", "unsupported schema_version"),
        ("schema_version = 1\n[daemon\n", "invalid TOML"),
        ("schema_version = 1\n[daemon]\nnot_a_field = true\n", "unknown daemon field"),
        ("schema_version = 1\nvalue = \"${HOME}\"\n", "unknown top-level key"),
    ],
)
def test_u41_config_rejects_malformed_or_unknown_input(
    tmp_path: Path,
    text: str,
    error: str,
) -> None:
    with pytest.raises(ConfigFileError, match=error):
        load_config_file(_write_config(tmp_path / "config.toml", text), environ={})


def test_u41_validation_error_never_echoes_secret_input(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path / "config.toml",
        'schema_version = 1\n[model]\napi_key = { value = "never-echo-this" }\n',
    )

    with pytest.raises(ConfigFileError) as captured:
        load_config_file(config_path, environ={})

    assert "never-echo-this" not in str(captured.value)
    assert "model.api_key" in str(captured.value)


def test_u41_config_errors_do_not_echo_sensitive_paths(tmp_path: Path) -> None:
    missing = tmp_path / "operator-private" / "config.toml"

    with pytest.raises(ConfigFileError) as captured:
        load_config_file(missing, environ={})

    assert "does not exist" in str(captured.value)
    assert str(missing) not in str(captured.value)


def test_u41_nested_mcp_and_a2a_values_are_redacted(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path / "config.toml",
        """
schema_version = 1
[[daemon.mcp_servers]]
name = "demo"
transport = "stdio"
command = ["server"]
[daemon.mcp_servers.env]
TOKEN = "mcp-secret"
[daemon.a2a]
enabled = true
[daemon.a2a.identity]
agent_id = "local"
private_key_path = "/private/a2a-key"
public_key_path = "/private/a2a-key.pub"
""",
    )

    projection = load_config_file(config_path, environ={}).redacted_projection()

    assert projection["daemon"]["mcp_servers"]["value"] == "<redacted>"
    assert projection["daemon"]["a2a"]["value"] == "<redacted>"
    assert "mcp-secret" not in str(projection)
    assert "/private/a2a-key" not in str(projection)


@pytest.mark.parametrize(
    "body",
    [
        "[daemon.a2a]\nunknown = true\n",
        (
            '[[daemon.mcp_servers]]\nname = "demo"\ntransport = "stdio"\n'
            'command = ["server"]\nunknown = true\n'
        ),
        (
            '[[daemon.discord_channel_rules]]\nguild_id = "guild"\n'
            'unknown = true\n'
        ),
        '[model.planner_capabilities]\nunknown = true\n',
    ],
)
def test_u41_unknown_nested_toml_keys_fail_closed(
    tmp_path: Path,
    body: str,
) -> None:
    config_path = _write_config(
        tmp_path / "config.toml",
        f"schema_version = 1\n{body}",
    )

    with pytest.raises(ConfigFileError, match="unknown nested field"):
        load_config_file(config_path, environ={})


def test_u41_config_path_cannot_be_inside_managed_root(tmp_path: Path) -> None:
    managed_root = tmp_path / "assistant-root"
    managed_root.mkdir()
    config_path = _write_config(managed_root / "config.toml", "schema_version = 1\n")

    with pytest.raises(ConfigFileError, match="managed root"):
        load_config_file(config_path, environ={}, protected_roots=(managed_root,))


def test_u41_config_cannot_select_itself_below_effective_data_root(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    config_path = _write_config(
        data_root / "config.toml",
        f'schema_version = 1\n[daemon]\ndata_dir = "{data_root}"\n',
    )

    with pytest.raises(ConfigFileError, match="managed root"):
        load_effective_config(config_path, environ={})


def test_u41_toml_cannot_recursively_select_another_config_path(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path / "config.toml",
        'schema_version = 1\n[daemon]\nconfig_path = "/tmp/other.toml"\n',
    )

    with pytest.raises(ConfigFileError, match="selected only by CLI or environment"):
        load_config_file(config_path, environ={})


def test_u41_missing_explicit_config_is_actionable(tmp_path: Path) -> None:
    with pytest.raises(ConfigFileError, match="does not exist"):
        load_config_file(tmp_path / "missing.toml", environ={})


def test_u41_absent_default_config_uses_typed_defaults_without_creating_files(
    tmp_path: Path,
) -> None:
    config_home = tmp_path / "config-home"

    loaded = load_effective_config(environ={"XDG_CONFIG_HOME": str(config_home)})

    assert loaded.daemon.log_level == "INFO"
    assert loaded.daemon.config_path is None
    assert not config_home.exists()


def test_u41_config_inventory_has_no_unclassified_or_inert_advertised_controls() -> None:
    inventory = config_field_inventory()

    assert all(row["status"] != "unclassified" for row in inventory)
    by_name = {(row["section"], row["field"]): row for row in inventory}
    assert by_name[("security", "default_deny")]["status"] == "compatibility_only"
    assert ("daemon", "ui_theme") not in by_name
    assert ("daemon", "ui_theme_path") not in by_name
    assert by_name[("model", "planner_api_key")]["consumer"] == "ModelRouter"
    for removed in (
        "require_confirmation_for_writes",
        "egress_default_deny",
        "credential_store_path",
        "audit_log_path",
    ):
        assert ("security", removed) not in by_name
    assert ("model", "log_prompts") not in by_name


def test_u41_commented_template_is_generated_from_live_inventory() -> None:
    template = render_config_template()

    assert template.startswith("schema_version = 1\n")
    assert "[daemon]" in template
    assert "# log_level = \"INFO\"" in template
    assert "[model]" in template
    assert "# api_key = \"\"" in template
    assert "ui_theme" not in template
    assert "config_path =" not in template
    assert "config_path is selected only via --config or SHISAD_CONFIG_PATH" in template
    assert "require_confirmation_for_writes" not in template
    assert "log_prompts" not in template
