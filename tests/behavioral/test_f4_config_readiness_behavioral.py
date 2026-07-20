"""U41 user-visible configuration and readiness behavior."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from shisad.cli import main as cli_main


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
