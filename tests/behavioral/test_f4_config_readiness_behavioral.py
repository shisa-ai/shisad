"""U41 user-visible configuration and readiness behavior."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from shisad.cli import main as cli_main
from shisad.core.api.schema import DoctorCheckResult
from shisad.core.config import ModelConfig
from shisad.core.providers.routing import ModelRouter
from shisad.daemon.services import _build_provider_diagnostics


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
