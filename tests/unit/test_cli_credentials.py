"""O2A shipped credential administration command contracts."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from click.testing import CliRunner

from shisad.cli.main import cli


def _root_env(tmp_path: Path) -> dict[str, str]:
    return {
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "SHISAD_DATA_DIR": str(tmp_path / "data"),
        "NO_COLOR": "1",
    }


def test_o2a_cli_env_set_status_remove_is_redacted(tmp_path: Path) -> None:
    runner = CliRunner()
    env = {**_root_env(tmp_path), "OPENAI_API_KEY": "never-print-this-secret"}

    created = runner.invoke(
        cli,
        [
            "credential",
            "set",
            "model.primary",
            "--backend",
            "env",
            "--locator",
            "OPENAI_API_KEY",
            "--format",
            "json",
        ],
        env=env,
    )

    assert created.exit_code == 0, created.output
    payload = json.loads(created.output)
    assert payload == {
        "available": True,
        "backend": "env",
        "configured": True,
        "locator": "OPENAI_API_KEY",
        "name": "model.primary",
        "reason": "credential_available",
        "safe": True,
    }
    assert "never-print-this-secret" not in created.output

    status = runner.invoke(
        cli,
        ["credential", "status", "model.primary", "--format", "human"],
        env=env,
    )
    assert status.exit_code == 0, status.output
    assert "model.primary backend=env configured=yes available=yes" in status.output
    assert "never-print-this-secret" not in status.output

    removed = runner.invoke(
        cli,
        ["credential", "remove", "model.primary", "--format", "json"],
        env=env,
    )
    assert removed.exit_code == 0, removed.output
    assert json.loads(removed.output)["configured"] is False
    assert "never-print-this-secret" not in removed.output


def test_o2a_cli_managed_file_set_requires_explicit_stdin(tmp_path: Path) -> None:
    runner = CliRunner()
    env = {**_root_env(tmp_path), "SHISAD_MANAGED": "true"}

    missing = runner.invoke(
        cli,
        ["credential", "set", "model.primary", "--backend", "file"],
        env=env,
    )

    assert missing.exit_code == 3
    assert "--stdin" in missing.output

    created = runner.invoke(
        cli,
        [
            "credential",
            "set",
            "model.primary",
            "--backend",
            "file",
            "--stdin",
            "--format",
            "json",
        ],
        input="managed-secret\n",
        env=env,
    )

    assert created.exit_code == 0, created.output
    assert "managed-secret" not in created.output
    secret_file = tmp_path / "data" / "credentials.d" / "model.primary"
    assert secret_file.read_text(encoding="utf-8") == "managed-secret\n"
    assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600


def test_o2a_cli_never_accepts_secret_value_in_argv(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "credential",
            "set",
            "model.primary",
            "--backend",
            "file",
            "--value",
            "argv-secret",
        ],
        env=_root_env(tmp_path),
    )

    assert result.exit_code != 0
    assert "No such option" in result.output
    assert "--value" in result.output


def test_o2a_cli_rejects_secret_stdin_for_env_and_locator_for_file(tmp_path: Path) -> None:
    runner = CliRunner()
    env = _root_env(tmp_path)

    env_result = runner.invoke(
        cli,
        [
            "credential",
            "set",
            "model.primary",
            "--backend",
            "env",
            "--locator",
            "OPENAI_API_KEY",
            "--stdin",
        ],
        input="must-not-be-consumed",
        env=env,
    )
    file_result = runner.invoke(
        cli,
        [
            "credential",
            "set",
            "model.primary",
            "--backend",
            "file",
            "--locator",
            "/tmp/escape",
            "--stdin",
        ],
        input="must-not-be-written",
        env=env,
    )

    assert env_result.exit_code == 3
    assert "persist only the variable name" in env_result.output
    assert file_result.exit_code == 3
    assert "contained by their logical name" in file_result.output
    assert not (tmp_path / "data").exists()
