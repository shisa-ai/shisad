"""CLI provider diagnostics surface coverage for M3 S0."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from shisad.cli import main as cli_main
from shisad.core.api.schema import DoctorCheckResult
from shisad.core.config import DaemonConfig


def test_s0_doctor_check_provider_component_prints_provider_diagnostics(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)

    def _fake_rpc_call(*_args, **_kwargs):
        return DoctorCheckResult.model_validate(
            {
                "status": "ok",
                "component": "provider",
                "checks": {
                    "provider": {
                        "status": "ok",
                    "routes": {
                        "planner": {
                            "preset": "openai_default",
                            "base_url": "https://api.openai.com/v1",
                            "auth_mode": "bearer",
                            "key_source": "preset_provider:OPENAI_API_KEY",
                            "request_parameter_profile": "openai_chat_general",
                        }
                    },
                    }
                },
                "error": "",
            }
        )

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()

    result = runner.invoke(cli_main.cli, ["doctor", "check", "--component", "provider"])

    assert result.exit_code == 0
    assert "openai_default" in result.output
    assert "OPENAI_API_KEY" in result.output
