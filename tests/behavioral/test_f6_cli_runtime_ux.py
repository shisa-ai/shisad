"""F6 end-user CLI/config journey through the shipped Click surface."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from shisad.channels import setup as channel_setup
from shisad.channels.base import DeliveryTarget, InMemoryChannel
from shisad.cli import onboarding
from shisad.cli.main import cli
from shisad.core.readiness import ReadinessState, ReadinessStatus
from shisad.security.policy import PolicyLoader

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


def test_o2d_noninteractive_setup_journey_publishes_valid_reference_only_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "o2d-behavioral-secret-must-not-persist"
    config_home = tmp_path / "config-home"
    config_path = config_home / "shisad" / "config.toml"
    policy_path = config_home / "shisad" / "policy.yaml"
    selection_path = tmp_path / "selection.yaml"
    selection_path.write_text(
        yaml.safe_dump(
            {
                "provider": {
                    "preset": "vllm_local_default",
                    "model_id": "local/setup-model",
                },
                "policy": {"profile": "strict"},
                "channels": [
                    {
                        "channel": "discord",
                        "bot_token_ref": "channel.discord",
                        "default_target": "12345",
                        "trusted_users": ["operator-1"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.setenv("SHISAD_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SHISAD_MANAGED", "true")
    monkeypatch.setenv("DISCORD_SETUP_TOKEN", secret)
    runner = CliRunner()

    enrolled = runner.invoke(
        cli,
        [
            "credential",
            "set",
            "channel.discord",
            "--backend",
            "env",
            "--locator",
            "DISCORD_SETUP_TOKEN",
        ],
    )
    applied = runner.invoke(
        cli,
        [
            "setup",
            "apply",
            "--selection",
            str(selection_path),
            "--skip-probes",
            "--write",
            "--format",
            "json",
        ],
    )
    validated = runner.invoke(cli, ["config", "validate", "--format", "json"])
    shown = runner.invoke(cli, ["config", "show", "--format", "json"])

    assert enrolled.exit_code == 0, enrolled.output
    assert applied.exit_code == 0, applied.output
    assert validated.exit_code == 0, validated.output
    assert shown.exit_code == 0, shown.output
    payload = json.loads(applied.output)
    assert payload["outcome"] == "completed"
    assert payload["persisted"] is True
    assert payload["provider"]["outcome"] == "skipped"
    assert payload["channels"][0]["outcome"] == "skipped"
    assert config_path.stat().st_mode & 0o777 == 0o600
    assert policy_path.stat().st_mode & 0o777 == 0o600
    config_text = config_path.read_text(encoding="utf-8")
    policy_text = policy_path.read_text(encoding="utf-8")
    loaded_policy = PolicyLoader(policy_path).load()
    all_visible = applied.output + validated.output + shown.output + config_text + policy_text
    assert secret not in all_visible
    assert 'discord_bot_token_ref = "channel.discord"' in config_text
    assert 'planner_model_id = "local/setup-model"' in config_text
    assert 'policy_path = "' in config_text
    assert json.loads(validated.output)["valid"] is True
    assert loaded_policy.version == "1"
    assert loaded_policy.default_deny is False


def test_o3a_background_first_start_reports_bounded_health_and_stops_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    socket_path = tmp_path / "control.sock"
    config_path = tmp_path / "config.toml"
    secret = "o3a-background-secret-must-not-print"
    config_path.write_text(
        "\n".join(
            [
                "schema_version = 1",
                "[daemon]",
                f'data_dir = "{data_dir}"',
                f'socket_path = "{socket_path}"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SHISAD_DATA_DIR", str(data_dir))
    monkeypatch.setenv("SHISAD_SOCKET_PATH", str(socket_path))
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("SHISAD_MODEL_API_KEY", secret)
    runner = CliRunner()

    try:
        started = runner.invoke(cli, ["--config", str(config_path), "start"])
        assert started.exit_code == 0, started.output
        assert "Daemon: started pid=" in started.output
        assert "Health:" in started.output
        assert "Readiness:" in started.output
        assert str(data_dir / "logs" / "daemon.log") in started.output
        assert secret not in started.output

        status = runner.invoke(cli, ["--config", str(config_path), "status"])
        assert status.exit_code == 0, status.output
        assert "Status: running" in status.output

        second = runner.invoke(cli, ["--config", str(config_path), "start"])
        assert second.exit_code == 0, second.output
        assert "Daemon: already running" in second.output
        assert "Daemon: started pid=" not in second.output

        stopped = runner.invoke(cli, ["--config", str(config_path), "stop"])
        assert stopped.exit_code == 0, stopped.output
        deadline = time.monotonic() + 5.0
        while socket_path.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not socket_path.exists()
        log_path = data_dir / "logs" / "daemon.log"
        assert log_path.stat().st_mode & 0o777 == 0o600
        assert log_path.parent.stat().st_mode & 0o777 == 0o700
        assert secret not in log_path.read_text(encoding="utf-8")
    finally:
        if socket_path.exists():
            runner.invoke(cli, ["--config", str(config_path), "stop"])


def test_o3b_tour_is_deterministic_and_real_demo_preserves_policy_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.cli import main as cli_main
    from shisad.cli import tour as tour_module

    config_home = tmp_path / "config-home"
    launched: list[dict[str, object]] = []
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.setattr(tour_module, "is_interactive_tour", lambda: True)
    monkeypatch.setattr(
        cli_main, "_run_chat", lambda **kwargs: launched.append(kwargs), raising=False
    )

    result = CliRunner().invoke(cli, ["tour"], input="y\n")

    assert result.exit_code == 0, result.output
    assert "auto-approved, require confirmation, be denied, or be blocked" in result.output
    assert (
        "The normal planner, policy, confirmation, and tool paths remain in effect."
        in result.output
    )
    assert launched == [
        {
            "session_id": "",
            "user": "ops",
            "workspace": "default",
            "new_session": False,
            "startup_hint": tour_module.CHAT_SUGGESTION,
        }
    ]
    assert not config_home.exists()


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
    config_home = tmp_path / "config-home"
    config_path = tmp_path / "config.toml"
    isolated_socket = tmp_path / "isolated" / "control.sock"
    ambient_runtime = tmp_path / "ambient-runtime"
    ambient_socket = ambient_runtime / "shisad" / "control.sock"
    ambient_socket.parent.mkdir(parents=True)
    ambient_socket.touch()
    config_path.write_text(
        f'schema_version = 1\n[daemon]\nsocket_path = "{isolated_socket}"\n',
        encoding="utf-8",
    )
    monkeypatch.delenv("SHISAD_SOCKET_PATH", raising=False)
    monkeypatch.delenv("SHISAD_CONFIG_PATH", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(ambient_runtime))
    monkeypatch.setenv("SHISAD_MANAGED", "yes")
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    monkeypatch.setenv("NO_COLOR", "1")
    probed: list[Path] = []

    def _ambient_probe(socket_path: Path) -> bool:
        probed.append(socket_path)
        return True

    monkeypatch.setattr(onboarding, "_sync_daemon_probe", _ambient_probe)

    result = CliRunner().invoke(cli, ["--config", str(config_path)])

    assert result.exit_code == 0, result.output
    assert "Managed environment" in result.output
    assert "Next action: shisad doctor" in result.output
    assert "Next action: shisad start" not in result.output
    assert "\x1b[" not in result.output
    assert "╭" not in result.output
    assert "WARN" in result.output
    assert probed == []
    assert not isolated_socket.exists()

    monkeypatch.setenv("SHISAD_SOCKET_PATH", str(ambient_socket))
    reachable_without_config = CliRunner().invoke(cli, [])

    assert reachable_without_config.exit_code == 0, reachable_without_config.output
    assert "Managed environment" in reachable_without_config.output
    assert "Next action: shisad status" in reachable_without_config.output
    assert "Next action: shisad start" not in reachable_without_config.output
    assert probed == [ambient_socket]
    assert not config_home.exists()


def test_o2a_credential_reference_cli_journey_is_redacted_and_reversible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    secret = "behavioral-provider-secret"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("SHISAD_DATA_DIR", str(data_dir))
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    monkeypatch.setenv("NO_COLOR", "1")
    runner = CliRunner()

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
        ],
    )
    shown = runner.invoke(cli, ["credential", "status", "model.primary"])
    removed = runner.invoke(cli, ["credential", "remove", "model.primary"])

    for result in (created, shown, removed):
        assert result.exit_code == 0, result.output
        assert secret not in result.output
        assert "model.primary" in result.output
    assert "configured=yes available=yes" in shown.output
    assert "configured=no available=no" in removed.output
    registry = data_dir / "credential-references.json"
    assert secret not in registry.read_text(encoding="utf-8")
    assert not (tmp_path / "config").exists()


def test_o2b_provider_and_policy_setup_cli_is_redacted_and_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    secret = "o2b-provider-secret-must-not-print"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("SHISAD_DATA_DIR", str(data_dir))
    monkeypatch.setenv("OPENAI_API_KEY", secret)
    monkeypatch.setenv("NO_COLOR", "1")
    runner = CliRunner()

    enrolled = runner.invoke(
        cli,
        [
            "credential",
            "set",
            "model.primary",
            "--backend",
            "env",
            "--locator",
            "OPENAI_API_KEY",
        ],
    )
    provider = runner.invoke(
        cli,
        [
            "setup",
            "provider",
            "--preset",
            "openai_default",
            "--credential-ref",
            "model.primary",
            "--skip-probe",
            "--format",
            "json",
        ],
    )
    policy = runner.invoke(
        cli,
        ["setup", "policy", "--profile", "recommended", "--format", "json"],
    )

    for result in (enrolled, provider, policy):
        assert result.exit_code == 0, result.output
        assert secret not in result.output
    provider_payload = json.loads(provider.output)
    assert provider_payload["outcome"] == "skipped"
    assert provider_payload["probe"]["verified"] is False
    assert provider_payload["config_fragment"]["planner_api_key_ref"] == "model.primary"
    policy_payload = json.loads(policy.output)
    assert policy_payload["profile"] == "recommended"
    assert policy_payload["policy"]["default_deny"] is False
    assert policy_payload["policy"]["default_require_confirmation"] is False
    assert not (tmp_path / "config").exists()
    assert not (tmp_path / "policy.yaml").exists()


def test_o2c_four_channel_setup_cli_journey_is_reference_only_and_default_deny(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    secrets = {
        "MATRIX_TEST_TOKEN": "matrix-secret-must-not-print",
        "DISCORD_TEST_TOKEN": "discord-secret-must-not-print",
        "TELEGRAM_TEST_TOKEN": "telegram-secret-must-not-print",
        "SLACK_BOT_TEST_TOKEN": "slack-bot-secret-must-not-print",
        "SLACK_APP_TEST_TOKEN": "slack-app-secret-must-not-print",
    }
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("SHISAD_DATA_DIR", str(data_dir))
    monkeypatch.setenv("NO_COLOR", "1")
    for variable, secret in secrets.items():
        monkeypatch.setenv(variable, secret)

    runner = CliRunner()
    references = {
        "channel.matrix": "MATRIX_TEST_TOKEN",
        "channel.discord": "DISCORD_TEST_TOKEN",
        "channel.telegram": "TELEGRAM_TEST_TOKEN",
        "channel.slack.bot": "SLACK_BOT_TEST_TOKEN",
        "channel.slack.app": "SLACK_APP_TEST_TOKEN",
    }
    for reference, variable in references.items():
        enrolled = runner.invoke(
            cli,
            ["credential", "set", reference, "--backend", "env", "--locator", variable],
        )
        assert enrolled.exit_code == 0, enrolled.output

    commands = [
        [
            "matrix",
            "--access-token-ref",
            "channel.matrix",
            "--homeserver",
            "https://matrix.example",
            "--user-id",
            "@bot:example",
            "--room-id",
            "!room:example",
        ],
        ["discord", "--bot-token-ref", "channel.discord"],
        ["telegram", "--bot-token-ref", "channel.telegram"],
        [
            "slack",
            "--bot-token-ref",
            "channel.slack.bot",
            "--app-token-ref",
            "channel.slack.app",
        ],
    ]
    for channel, *options in commands:
        result = runner.invoke(
            cli,
            [
                "setup",
                "channel",
                "--channel",
                channel,
                *options,
                "--skip-probe",
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["outcome"] == "skipped"
        assert payload["identity_ready"] is False
        assert "trusted" in payload["identity_next_action"]
        assert payload["probe"]["verified"] is False
        serialized = json.dumps(payload)
        for secret in secrets.values():
            assert secret not in serialized

    assert not (tmp_path / "config" / "shisad" / "config.toml").exists()


def test_o2c_explicit_cli_test_delivery_uses_the_shipped_surface_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _InjectedDiscordChannel(InMemoryChannel):
        available = True

        def __init__(self) -> None:
            super().__init__("discord")
            self.sent: list[tuple[str, DeliveryTarget | None]] = []

        async def send(
            self,
            message: str,
            *,
            target: DeliveryTarget | None = None,
            metadata: dict[str, object] | None = None,
        ) -> None:
            self.sent.append((message, target))
            await super().send(message, target=target, metadata=metadata)

        async def disconnect_strict(self) -> None:
            await self.disconnect()

        def setup_readiness(self) -> ReadinessStatus:
            return ReadinessStatus(
                state=ReadinessState.CONFIGURED,
                configured=True,
                evidence="live_probe",
                reason="channel_transport_started_not_verified",
                next_action="send an explicit test message to verify outbound delivery",
                source="channel_setup_probe",
            )

    injected = _InjectedDiscordChannel()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("SHISAD_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(
        channel_setup,
        "_build_setup_channel",
        lambda *args, **kwargs: injected,
    )

    result = CliRunner().invoke(
        cli,
        [
            "setup",
            "channel",
            "--channel",
            "discord",
            "--bot-token-ref",
            "channel.discord",
            "--trusted-user",
            "operator-123",
            "--send-test",
            "--test-target",
            "channel-456",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["outcome"] == "verified"
    assert payload["probe"]["evidence"] == "live_test_delivery"
    assert payload["identity_ready"] is True
    assert len(injected.sent) == 1
    assert injected.sent[0][0] == channel_setup.CHANNEL_SETUP_TEST_MESSAGE
    assert injected.sent[0][1] is not None
    assert injected.sent[0][1].recipient == "channel-456"
    assert "round trip" not in result.output.lower()
    assert not (tmp_path / "config" / "shisad" / "config.toml").exists()
