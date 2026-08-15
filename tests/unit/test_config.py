"""U41 red-first tests for TOML configuration and source projection."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.core import config_file
from shisad.core.config import DaemonConfig, ModelConfig, effective_credential_reference_paths
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


@pytest.mark.parametrize(
    ("raw_field", "ref_field"),
    [
        ("matrix_access_token", "matrix_access_token_ref"),
        ("discord_bot_token", "discord_bot_token_ref"),
        ("telegram_bot_token", "telegram_bot_token_ref"),
        ("slack_bot_token", "slack_bot_token_ref"),
        ("slack_app_token", "slack_app_token_ref"),
    ],
)
def test_o2c_channel_token_raw_and_reference_are_mutually_exclusive(
    raw_field: str,
    ref_field: str,
) -> None:
    with pytest.raises(ValueError, match="cannot use both a raw value and a credential reference"):
        DaemonConfig.model_validate({raw_field: "raw-secret", ref_field: "channel.token"})


@pytest.mark.parametrize(
    "field",
    [
        "matrix_access_token_ref",
        "discord_bot_token_ref",
        "telegram_bot_token_ref",
        "slack_bot_token_ref",
        "slack_app_token_ref",
    ],
)
def test_o2c_channel_token_reference_uses_generic_logical_name_grammar(field: str) -> None:
    assert getattr(DaemonConfig.model_validate({field: "channel.valid-token"}), field) == (
        "channel.valid-token"
    )
    with pytest.raises(ValueError, match="credential reference name is invalid"):
        DaemonConfig.model_validate({field: "../channel-secret"})


def test_o2c_slack_bot_and_app_references_must_be_distinct() -> None:
    with pytest.raises(ValueError, match="distinct"):
        DaemonConfig(
            slack_bot_token_ref="channel.slack.same",
            slack_app_token_ref="channel.slack.same",
        )


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
        ("schema_version = true\n", "unsupported schema_version"),
        ("schema_version = 1.0\n", "unsupported schema_version"),
        ("schema_version = 1\n[daemon\n", "invalid TOML"),
        ("schema_version = 1\n[daemon]\nnot_a_field = true\n", "unknown daemon field"),
        ('schema_version = 1\nvalue = "${HOME}"\n', "unknown top-level key"),
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
        ('[[daemon.discord_channel_rules]]\nguild_id = "guild"\nunknown = true\n'),
        "[model.planner_capabilities]\nunknown = true\n",
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


def test_u41_unknown_nested_environment_json_keys_fail_closed(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path / "config.toml", "schema_version = 1\n")

    with pytest.raises(ConfigFileError, match=r"unknown nested field: daemon\.a2a\.unknown"):
        load_config_file(
            config_path,
            environ={"SHISAD_A2A": '{"enabled": true, "unknown": true}'},
        )


def test_u41r_unhashable_nested_discriminator_is_actionable(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path / "config.toml", "schema_version = 1\n")

    with pytest.raises(ConfigFileError, match="invalid daemon configuration"):
        load_config_file(
            config_path,
            environ={
                "SHISAD_MCP_SERVERS": ('[{"name":"demo","transport":[],"command":["server"]}]')
            },
        )


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
    assert by_name[("daemon", "ui_theme")]["status"] == "live"
    assert by_name[("daemon", "ui_theme")]["consumer"] == "UiPosture"
    assert by_name[("daemon", "reduce_motion")]["consumer"] == "UiPosture"
    assert ("daemon", "ui_theme_path") not in by_name
    assert by_name[("model", "planner_api_key")]["consumer"] == "ModelRouter"
    assert by_name[("model", "planner_api_key_ref")]["consumer"] == "ModelRouter"
    assert by_name[("security", "credential_reference_store_path")]["consumer"] == (
        "CredentialReferenceStore"
    )
    for removed in (
        "require_confirmation_for_writes",
        "egress_default_deny",
        "credential_store_path",
        "audit_log_path",
    ):
        assert ("security", removed) not in by_name
    assert ("model", "log_prompts") not in by_name


def test_o2a_raw_model_key_and_reference_conflict() -> None:
    with pytest.raises(ValueError, match="cannot use both"):
        ModelConfig(api_key="raw-secret", api_key_ref="model.primary")
    with pytest.raises(ValueError, match="planner"):
        ModelConfig(planner_api_key="raw-secret", planner_api_key_ref="model.planner")


def test_o2a_default_credential_paths_follow_selected_data_root(tmp_path: Path) -> None:
    store_path, secret_dir = effective_credential_reference_paths(data_dir=tmp_path)

    assert store_path == tmp_path / "credential-references.json"
    assert secret_dir == tmp_path / "credentials.d"

    custom_store, custom_dir = effective_credential_reference_paths(
        data_dir=tmp_path,
        configured_store_path=tmp_path / "custom" / "refs.json",
        configured_secret_dir=tmp_path / "custom" / "secrets",
    )
    assert custom_store == tmp_path / "custom" / "refs.json"
    assert custom_dir == tmp_path / "custom" / "secrets"


def test_u41_commented_template_is_generated_from_live_inventory() -> None:
    template = render_config_template()

    assert template.startswith("schema_version = 1\n")
    assert "[daemon]" in template
    assert '# log_level = "INFO"' in template
    assert "[model]" in template
    assert '# api_key = ""' in template
    assert '# ui_theme = "shisa-dark"' in template
    assert "# reduce_motion = false" in template
    assert "ui_theme_path" not in template
    assert "config_path =" not in template
    assert "config_path is selected only via --config or SHISAD_CONFIG_PATH" in template
    assert "require_confirmation_for_writes" not in template
    assert "log_prompts" not in template


def test_f6_schema_diff_and_environment_projections_share_redaction(
    tmp_path: Path,
) -> None:
    config_path = _write_config(
        tmp_path / "config.toml",
        """
schema_version = 1
[daemon]
ui_theme = "shisa-light"
[model]
api_key = "never-project-this"
""",
    )
    loaded = load_config_file(
        config_path,
        environ={"SHISAD_REDUCE_MOTION": "true"},
    )

    schema = config_file.config_schema_projection()
    diff = config_file.config_diff_projection(loaded)
    environment = config_file.environment_projection(
        loaded,
        environ={"SHISAD_REDUCE_MOTION": "true"},
    )

    assert schema["properties"]["schema_version"]["const"] == 1
    assert schema["properties"]["daemon"]["additionalProperties"] is False
    assert "required" not in schema
    assert "config_path" not in schema["properties"]["daemon"]["properties"]
    assert schema["properties"]["daemon"]["properties"]["a2a"]["$ref"] == (
        "#/$defs/daemon__A2aConfig"
    )
    assert (
        schema["properties"]["model"]["properties"]["planner_request_parameters"]["$ref"]
        == "#/$defs/model__RequestParameters"
    )
    assert schema["$defs"]["daemon__A2aConfig"]["additionalProperties"] is False
    assert schema["$defs"]["model__RequestParameters"]["additionalProperties"] is False
    assert "ui_theme_path" not in str(schema)
    assert diff["changes"]["daemon"]["ui_theme"] == {
        "value": "shisa-light",
        "source": "toml",
    }
    assert diff["changes"]["model"]["api_key"] == {
        "value": "<redacted>",
        "source": "toml",
    }
    rows = {row["name"]: row for row in environment["variables"]}
    assert rows["SHISAD_REDUCE_MOTION"]["source"] == "env:SHISAD_REDUCE_MOTION"
    assert rows["SHISAD_MODEL_API_KEY"]["value"] == "<redacted>"
    assert "never-project-this" not in str(diff)
    assert "never-project-this" not in str(environment)


def test_f6_init_publishes_one_owner_only_template_without_overwrite(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "config-home" / "shisad" / "config.toml"

    created = config_file.initialize_config_file(
        destination,
        environ={"SHISAD_MODEL_API_KEY": "never-write-this"},
    )

    assert created == destination
    assert destination.stat().st_mode & 0o777 == 0o600
    text = destination.read_text(encoding="utf-8")
    assert text.startswith("schema_version = 1\n")
    assert "never-write-this" not in text
    with pytest.raises(ConfigFileError, match="already exists"):
        config_file.initialize_config_file(destination, environ={})


def test_f6_init_uses_the_loader_config_path_precedence(tmp_path: Path) -> None:
    environment_path = tmp_path / "environment" / "config.toml"
    explicit_path = tmp_path / "explicit" / "config.toml"
    environ = {
        "SHISAD_CONFIG_PATH": str(environment_path),
        "XDG_CONFIG_HOME": str(tmp_path / "xdg"),
    }

    assert config_file.initialize_config_file(environ=environ) == environment_path
    assert config_file.initialize_config_file(explicit_path, environ=environ) == explicit_path

    assert environment_path.exists()
    assert explicit_path.exists()
    assert not (tmp_path / "xdg" / "shisad" / "config.toml").exists()


def test_f6_init_rejects_symlink_and_managed_root_destinations(tmp_path: Path) -> None:
    target = tmp_path / "target.toml"
    target.write_text("do not replace\n", encoding="utf-8")
    linked = tmp_path / "linked.toml"
    linked.symlink_to(target)

    with pytest.raises(ConfigFileError, match="symlink"):
        config_file.initialize_config_file(linked, environ={})

    managed = tmp_path / "managed"
    with pytest.raises(ConfigFileError, match="managed root"):
        config_file.initialize_config_file(
            managed / "config.toml",
            environ={"SHISAD_DATA_DIR": str(managed)},
        )


def test_f6_init_write_failure_keeps_owner_only_path_without_racy_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "config.toml"

    def _fail_write(_descriptor: int, _payload: bytes) -> int:
        raise OSError("simulated short device failure")

    monkeypatch.setattr(config_file.os, "write", _fail_write)

    with pytest.raises(ConfigFileError, match="cannot finish selected config file"):
        config_file.initialize_config_file(destination, environ={})

    assert destination.exists()
    assert destination.stat().st_mode & 0o777 == 0o600


def test_f6_init_parent_preparation_failure_uses_config_error(tmp_path: Path) -> None:
    blocked_parent = tmp_path / "not-a-directory"
    blocked_parent.write_text("occupied\n", encoding="utf-8")

    with pytest.raises(ConfigFileError, match="cannot prepare selected config parent"):
        config_file.initialize_config_file(blocked_parent / "config.toml", environ={})
