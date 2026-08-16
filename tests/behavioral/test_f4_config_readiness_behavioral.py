"""U41 user-visible configuration and readiness behavior."""

from __future__ import annotations

import os
from pathlib import Path

from click.testing import CliRunner

from shisad.cli import main as cli_main
from shisad.core.api.schema import DoctorCheckResult
from shisad.core.config import ModelConfig
from shisad.core.providers.routing import ModelRouter
from shisad.daemon.services import _build_provider_diagnostics


def test_o4a_managed_legacy_config_stays_nonmutating_and_actionable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    for key in list(os.environ):
        if key.startswith("SHISAD_"):
            monkeypatch.delenv(key, raising=False)
    config_path = tmp_path / "config.toml"
    data_dir = tmp_path / "data"
    socket_path = tmp_path / "control.sock"
    original = (
        "# legacy operator config\n"
        "[daemon]\n"
        f'data_dir = "{data_dir}"\n'
        f'socket_path = "{socket_path}"\n'
    )
    config_path.write_text(original, encoding="utf-8")
    started = []
    monkeypatch.setattr(
        cli_main,
        "_start_daemon",
        lambda *, config, foreground, debug: started.append(config),
    )

    result = CliRunner().invoke(
        cli_main.cli,
        ["--config", str(config_path), "start", "--foreground"],
        env={"SHISAD_MANAGED": "true"},
    )

    assert result.exit_code == 0, result.output
    assert len(started) == 1
    assert started[0].data_dir == data_dir
    assert "schema 0 -> 1" in result.output
    assert "not persisted" in result.output
    assert "config upgrade --write" in result.output
    assert config_path.read_text(encoding="utf-8") == original
    assert not config_path.with_name("config.toml.pre-v1.bak").exists()


def test_u41_user_can_inspect_effective_config_without_exposing_secret(
    tmp_path: Path,
    monkeypatch,
) -> None:
    for key in (
        "SHISAD_LOG_LEVEL",
        "SHISAD_MODEL_API_KEY",
        "SHISAD_MODEL_PLANNER_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
schema_version = 1
[daemon]
log_level = "WARNING"
[model]
planner_api_key = "behavioral-placeholder-secret"
planner_remote_enabled = true
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli_main.cli,
        ["--config", str(config_path), "config", "show"],
    )

    assert result.exit_code == 0, result.output
    assert '"log_level"' in result.output
    assert '"value": "WARNING"' in result.output
    assert '"source": "toml"' in result.output
    assert "<redacted>" in result.output
    assert "behavioral-placeholder-secret" not in result.output


def test_o0_doctor_reports_actionable_provider_and_channel_degradation(monkeypatch) -> None:
    for key in (
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "OPENROUTER_API_KEY",
        "ANTHROPIC_API_KEY",
        "SHISA_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    checks = {
        "provider": _build_provider_diagnostics(
            ModelRouter(ModelConfig(planner_remote_enabled=True, planner_api_key=""))
        ),
        "channels": {"status": "absent", "next_action": "configure a channel if needed"},
    }
    monkeypatch.setattr(cli_main, "_get_config", object)
    monkeypatch.setattr(
        cli_main,
        "rpc_call",
        lambda *_args, **_kwargs: DoctorCheckResult(status="degraded", checks=checks),
    )
    result = CliRunner().invoke(cli_main.cli, ["doctor", "check"])

    assert result.exit_code == 0, result.output
    assert "missing_api_key" in result.output
    assert "configure the route credential" in result.output
    assert "configure a channel if needed" in result.output
