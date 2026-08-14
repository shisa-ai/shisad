"""O2A shipped credential administration command contracts."""

from __future__ import annotations

import json
import stat
from io import StringIO
from pathlib import Path

import pytest
from click.testing import CliRunner

from shisad.cli.credentials import CredentialCliError, _credential_error, _secret_input
from shisad.cli.main import cli
from shisad.security.credential_refs import CredentialReferenceError


def _root_env(tmp_path: Path) -> dict[str, str]:
    return {
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "SHISAD_DATA_DIR": str(tmp_path / "data"),
        "NO_COLOR": "1",
    }


@pytest.mark.parametrize(
    ("reason", "expected_action"),
    (
        (
            "credential_registry_unsafe",
            "chmod the credential data directory to 700, then retry",
        ),
        (
            "credential_file_unsafe",
            "repair the secret directory/file modes and types, then retry",
        ),
        (
            "credential_storage_collision",
            "separate the credential registry, lock, and secret paths",
        ),
    ),
)
def test_o2a_posture_errors_have_specific_recovery_actions(
    reason: str,
    expected_action: str,
) -> None:
    error = _credential_error(CredentialReferenceError(reason), output_format="human")

    assert error.envelope.next_action == expected_action


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
    assert stat.S_IMODE((tmp_path / "data").stat().st_mode) == 0o700

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
    assert secret_file.read_text(encoding="utf-8") == "managed-secret"
    assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    ("arguments", "invalid_value"),
    [
        (
            [
                "credential",
                "set",
                "Model.Primary",
                "--backend",
                "env",
                "--locator",
                "OPENAI_API_KEY",
            ],
            "Model.Primary",
        ),
        (
            [
                "credential",
                "set",
                "model.primary",
                "--backend",
                "env",
                "--locator",
                "openai_api_key",
            ],
            "openai_api_key",
        ),
        (["credential", "status", "Model.Primary"], "Model.Primary"),
        (["credential", "remove", "Model.Primary"], "Model.Primary"),
    ],
)
def test_o2a_cli_invalid_reference_input_uses_typed_redacted_envelope(
    tmp_path: Path,
    arguments: list[str],
    invalid_value: str,
) -> None:
    result = CliRunner().invoke(cli, arguments, env=_root_env(tmp_path))

    assert result.exit_code == 3
    assert "Likely cause: credential_reference_invalid" in result.output
    assert "Traceback" not in result.output
    assert invalid_value not in result.output
    assert not (tmp_path / "data").exists()


def test_o2a_cli_validates_file_reference_before_reading_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unexpected_secret_read(*, use_stdin: bool, output_format: str) -> str:
        raise AssertionError((use_stdin, output_format))

    monkeypatch.setattr("shisad.cli.credentials._secret_input", _unexpected_secret_read)

    result = CliRunner().invoke(
        cli,
        ["credential", "set", "Model.Primary", "--backend", "file", "--stdin"],
        input="must-not-be-consumed\n",
        env=_root_env(tmp_path),
    )

    assert result.exit_code == 3
    assert "credential_reference_invalid" in result.output
    assert "must-not-be-consumed" not in result.output
    assert not (tmp_path / "data").exists()


class _TtyInput(StringIO):
    def isatty(self) -> bool:
        return True


def test_o2a_cli_stdin_flag_rejects_tty_without_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = _TtyInput("visible-secret\n")
    monkeypatch.setattr("shisad.cli.credentials.sys.stdin", stream)

    with pytest.raises(CredentialCliError) as exc:
        _secret_input(use_stdin=True, output_format="human")

    assert exc.value.envelope.likely_cause == "credential_secret_input_tty"
    assert stream.tell() == 0


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
