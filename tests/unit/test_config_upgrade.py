"""O4A config migration and env-to-config characterization."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from shisad.cli import main as cli_main
from shisad.cli.upgrade import prepare_config_for_startup
from shisad.core import config_file, config_upgrade
from shisad.core.config_file import load_config_file
from shisad.core.config_upgrade import (
    ConfigUpgradeError,
    ConfigUpgradeStatus,
    apply_config_upgrade,
    plan_config_upgrade,
)


def test_o4a_config_upgrade_plan_is_typed_and_finite(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy.toml"
    legacy.write_text('[daemon]\nlog_level = "WARNING"\n', encoding="utf-8")
    current = tmp_path / "current.toml"
    current.write_text("schema_version = 1\n", encoding="utf-8")

    legacy_plan = plan_config_upgrade(legacy)
    current_plan = plan_config_upgrade(current)

    assert legacy_plan.status is ConfigUpgradeStatus.SAFE_MIGRATION
    assert legacy_plan.from_version == 0
    assert legacy_plan.to_version == 1
    assert legacy_plan.breaking is False
    assert legacy_plan.write_required is True
    assert current_plan.status is ConfigUpgradeStatus.CURRENT
    assert current_plan.from_version == current_plan.to_version == 1
    assert current_plan.write_required is False


@pytest.mark.parametrize(
    "text",
    [
        "schema_version = 2\n",
        "schema_version = -1\n",
        "schema_version = true\n",
        'schema_version = "1"\n',
        "[daemon\n",
    ],
)
def test_o4a_config_upgrade_refuses_unknown_or_malformed_versions_before_write(
    tmp_path: Path,
    text: str,
) -> None:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    original = path.read_bytes()

    with pytest.raises(ConfigUpgradeError):
        plan_config_upgrade(path)

    assert path.read_bytes() == original
    assert not path.with_name("config.toml.pre-v1.bak").exists()


def test_o4a_config_upgrade_preserves_exact_backup_and_validates_replacement(
    tmp_path: Path,
) -> None:
    path = tmp_path / "config.toml"
    original = b'# operator comment\n[daemon]\nlog_level = "WARNING"\n'
    path.write_bytes(original)
    path.chmod(0o644)

    result = apply_config_upgrade(path)

    assert result.changed is True
    assert result.from_version == 0
    assert result.to_version == 1
    assert result.validated is True
    assert result.backup_path == path.with_name("config.toml.pre-v1.bak")
    assert result.backup_path.read_bytes() == original
    assert result.backup_path.stat().st_mode & 0o777 == 0o600
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.read_bytes() == b"schema_version = 1\n" + original
    loaded = load_config_file(path, environ={})
    assert loaded.daemon.log_level == "WARNING"


def test_o4a_interrupted_replace_keeps_original_and_retry_reuses_exact_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "config.toml"
    original = b'[daemon]\nlog_level = "DEBUG"\n'
    path.write_bytes(original)
    real_replace = os.replace

    def _fail_replace(_source: Path | str, _target: Path | str) -> None:
        raise OSError("simulated interruption before replace")

    monkeypatch.setattr(config_upgrade.os, "replace", _fail_replace)
    with pytest.raises(ConfigUpgradeError, match="replace"):
        apply_config_upgrade(path)

    backup = path.with_name("config.toml.pre-v1.bak")
    assert path.read_bytes() == original
    assert backup.read_bytes() == original

    monkeypatch.setattr(config_upgrade.os, "replace", real_replace)
    result = apply_config_upgrade(path)

    assert result.backup_path == backup
    assert backup.read_bytes() == original
    assert path.read_bytes() == b"schema_version = 1\n" + original
    assert not list(tmp_path.glob(".config.toml.migrate-*"))


def test_o4a_config_upgrade_refuses_symlink_target_and_mismatched_backup(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.toml"
    target.write_text("[daemon]\n", encoding="utf-8")
    linked = tmp_path / "linked.toml"
    linked.symlink_to(target)

    with pytest.raises(ConfigUpgradeError, match="symlink"):
        apply_config_upgrade(linked)

    backup = target.with_name("target.toml.pre-v1.bak")
    backup.write_text("not the original\n", encoding="utf-8")
    with pytest.raises(ConfigUpgradeError, match="backup"):
        apply_config_upgrade(target)
    assert target.read_text(encoding="utf-8") == "[daemon]\n"
    assert backup.read_text(encoding="utf-8") == "not the original\n"


def test_o4a_env_selection_persists_only_nonsecret_nondefault_typed_values() -> None:
    secret = "never-persist-this-api-key"
    selection = config_file.environment_config_selection(
        {
            "SHISAD_LOG_LEVEL": "WARNING",
            "SHISAD_MODEL_MODEL_ID": "provider/model-a",
            "SHISAD_MODEL_API_KEY": secret,
            "SHISAD_DISCORD_BOT_TOKEN": "never-persist-this-bot-token",
        }
    )

    assert selection.section_overrides["daemon"]["log_level"] == "WARNING"
    assert selection.section_overrides["model"]["model_id"] == "provider/model-a"
    assert "api_key" not in selection.section_overrides["model"]
    assert "discord_bot_token" not in selection.section_overrides["daemon"]
    assert selection.omitted_secret_fields == (
        "daemon.discord_bot_token",
        "model.api_key",
    )
    rendered = config_file.render_config_template(section_overrides=selection.section_overrides)
    assert secret not in rendered
    assert "never-persist-this-bot-token" not in rendered


def test_o4a_config_upgrade_cli_dry_run_then_explicit_write(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    original = b'[daemon]\nlog_level = "WARNING"\n'
    path.write_bytes(original)
    runner = CliRunner()

    planned = runner.invoke(
        cli_main.cli,
        ["--config", str(path), "config", "upgrade", "--format", "json"],
    )

    assert planned.exit_code == 0, planned.output
    plan_payload = json.loads(planned.output)
    assert plan_payload["status"] == "safe_migration"
    assert plan_payload["changed"] is False
    assert plan_payload["write_requested"] is False
    assert path.read_bytes() == original

    applied = runner.invoke(
        cli_main.cli,
        [
            "--config",
            str(path),
            "config",
            "upgrade",
            "--write",
            "--format",
            "json",
        ],
    )

    assert applied.exit_code == 0, applied.output
    result_payload = json.loads(applied.output)
    assert result_payload["changed"] is True
    assert result_payload["validated"] is True
    assert result_payload["from_schema_version"] == 0
    assert result_payload["to_schema_version"] == 1
    assert path.read_bytes() == b"schema_version = 1\n" + original


def test_o4a_interactive_unmanaged_startup_persists_safe_migration(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("[daemon]\n", encoding="utf-8")

    result = prepare_config_for_startup(path, managed=False, interactive=True)

    assert result is not None
    assert result.persisted is True
    assert result.backup_path is not None
    assert result.backup_path.read_text(encoding="utf-8") == "[daemon]\n"
    assert path.read_text(encoding="utf-8").startswith("schema_version = 1\n")


def test_o4a_config_upgrade_cli_refusal_is_structured_and_nonmutating(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    original = "schema_version = 2\n"
    path.write_text(original, encoding="utf-8")

    result = CliRunner().invoke(
        cli_main.cli,
        ["--config", str(path), "config", "upgrade", "--format", "json"],
    )

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["error_type"] == "config_upgrade"
    assert "schema_version 1" in payload["next_action"]
    assert path.read_text(encoding="utf-8") == original
    assert not path.with_name("config.toml.pre-v1.bak").exists()
