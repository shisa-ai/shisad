"""F6 end-user CLI/config journey through the shipped Click surface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from shisad.cli.main import cli

pytestmark = pytest.mark.first_principles


def test_f6_first_use_config_journey_is_safe_and_scriptable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_home = tmp_path / "config-home"
    config_path = tmp_path / "operator" / "config.toml"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.setenv("SHISAD_CONFIG_PATH", str(config_path))
    monkeypatch.setenv("SHISAD_MODEL_API_KEY", "behavioral-secret-must-not-print")
    runner = CliRunner()

    initialized = runner.invoke(cli, ["init", "--format", "json"])
    validated = runner.invoke(cli, ["config", "validate", "--format", "json"])
    shown = runner.invoke(cli, ["config", "show", "--format", "json"])
    diffed = runner.invoke(cli, ["config", "diff", "--format", "json"])
    environment = runner.invoke(cli, ["env", "--format", "json"])

    for result in (initialized, validated, shown, diffed, environment):
        assert result.exit_code == 0, result.output
        assert "behavioral-secret-must-not-print" not in result.output
        json.loads(result.output)
    assert config_path.exists()
    assert not (config_home / "shisad" / "config.toml").exists()
    assert config_path.stat().st_mode & 0o777 == 0o600
    assert json.loads(validated.output)["valid"] is True
    assert "<redacted>" in shown.output
    assert "<redacted>" in environment.output

    secret = "sk-" + "abcdefghijklmnopqrstuvwx"
    config_path.write_text(
        f'schema_version = 1\n["{secret}"]\nvalue = true\n',
        encoding="utf-8",
    )
    failed = runner.invoke(cli, ["config", "validate", "--format", "json"])
    assert failed.exit_code == 3
    error = json.loads(failed.output)
    assert error["error_type"] == "config"
    assert error["exit_code"] == 3
    assert secret not in failed.output


def test_o1_bare_cli_welcome_routes_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_home = tmp_path / "config-home"
    config_path = config_home / "shisad" / "config.toml"
    data_dir = tmp_path / "data"
    socket_path = tmp_path / "control.sock"
    policy_path = tmp_path / "policy.yaml"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.delenv("SHISAD_CONFIG_PATH", raising=False)
    monkeypatch.delenv("SHISAD_MANAGED", raising=False)
    runner = CliRunner()

    fresh = runner.invoke(cli, [])

    assert fresh.exit_code == 0, fresh.output
    assert "Fresh install" in fresh.output
    assert "Next action: shisad init" in fresh.output
    assert not config_home.exists()
    assert not data_dir.exists()
    assert not socket_path.exists()

    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "\n".join(
            [
                "schema_version = 1",
                "[daemon]",
                f'data_dir = "{data_dir}"',
                f'socket_path = "{socket_path}"',
                f'policy_path = "{policy_path}"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    returning = runner.invoke(cli, [])

    assert returning.exit_code == 0, returning.output
    assert "Non-interactive environment" in returning.output
    assert "Daemon" in returning.output
    assert "stopped" in returning.output.lower()
    assert "Next action: shisad doctor" in returning.output
    assert not data_dir.exists()
    assert not socket_path.exists()


def test_o1_managed_bare_cli_is_read_only_and_ascii_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("schema_version = 1\n", encoding="utf-8")
    monkeypatch.setenv("SHISAD_MANAGED", "yes")
    monkeypatch.setenv("TERM", "dumb")
    monkeypatch.setenv("NO_COLOR", "1")

    result = CliRunner().invoke(cli, ["--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert "Managed environment" in result.output
    assert "Next action: shisad doctor" in result.output
    assert "Next action: shisad start" not in result.output
    assert "\x1b[" not in result.output
