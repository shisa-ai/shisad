"""F6 end-user CLI/config journey through the shipped Click surface."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from click.testing import CliRunner
from textual.widgets import TextArea

from shisad.channels import setup as channel_setup
from shisad.channels.base import DeliveryTarget, InMemoryChannel
from shisad.channels.delivery import DeliveryResult
from shisad.cli import main as cli_main
from shisad.cli import onboarding
from shisad.cli.main import cli
from shisad.core.audit import AuditLog
from shisad.core.events import SessionCreated
from shisad.core.readiness import ReadinessState, ReadinessStatus
from shisad.core.types import SessionId, UserId
from shisad.daemon.handlers._impl_admin import AdminImplMixin
from shisad.security.control_plane.audit import ControlPlaneAuditLog
from shisad.security.policy import PolicyLoader
from shisad.ui import chat as chat_ui
from tests.behavioral.test_behavioral_contract import ContractHarness
from tests.helpers.behavioral import extract_tool_outputs

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


@pytest.mark.asyncio
async def test_o3b_tour_is_deterministic_and_real_demo_preserves_policy_path(
    clean_harness: ContractHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shisad.cli import main as cli_main
    from shisad.cli import tour as tour_module

    launched: list[chat_ui.ChatApp] = []
    monkeypatch.setattr(cli_main, "_get_config", lambda: clean_harness.config)
    monkeypatch.setattr(cli_main, "_inspect_tour_health", lambda: None, raising=False)
    monkeypatch.setattr(tour_module, "is_interactive_tour", lambda: True)
    monkeypatch.setattr(chat_ui.ChatApp, "run", lambda app: launched.append(app))

    result = CliRunner().invoke(cli, ["tour"], input="y\n")

    assert result.exit_code == 0, result.output
    assert "auto-approved, require confirmation, be denied, or be blocked" in result.output
    assert (
        "The normal planner, policy, confirmation, and tool paths remain in effect."
        in result.output
    )
    assert len(launched) == 1
    app = launched[0]
    assert app._startup_hint == tour_module.CHAT_SUGGESTION
    replies: list[dict[str, Any]] = []
    original_refresh = app._refresh_status_from_message_result

    def _capture_reply(reply: dict[str, Any]) -> None:
        replies.append(reply)
        original_refresh(reply)

    app._refresh_status_from_message_result = _capture_reply  # type: ignore[method-assign]
    async with app.run_test() as pilot:
        await pilot.pause()
        chat_input = app.query_one("#chat-input", TextArea)
        chat_input.load_text("read README.md")
        await app.action_submit_prompt()
        await pilot.pause()

    assert len(replies) == 1
    reply = replies[0]
    assert reply["lockdown_level"] == "normal"
    assert reply["executed_actions"] == 1
    assert reply["confirmation_required_actions"] == 0
    assert extract_tool_outputs(reply)["fs.read"][0]["ok"] is True


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


def test_o4c_backup_restore_round_trip_is_offline_verified_and_actionable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "data"
    representative = {
        "sessions/state/session.json": b'{"session":"durable"}\n',
        "checkpoints/cp.json": b'{"checkpoint":"bounded"}\n',
        "pending_actions.json": b'{"status":"outcome_unknown"}\n',
        "tasks/task.json": b'{"schedule":"daily"}\n',
        "memory_entries/memory.sqlite3": b"memory-state",
        "timeline/timeline.sqlite3": b"timeline-state",
        "channels/state/replay.sqlite3": b"replay-state",
        "channels/delivery/outbox.sqlite3": b"delivery-state",
        "audit.jsonl": b'{"event_id":"audit-1"}\n',
    }
    for relative, payload in representative.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    monkeypatch.setenv("SHISAD_DATA_DIR", str(source))
    archive = tmp_path / "operator-copy.shisad-backup"
    restored = tmp_path / "restored"
    runner = CliRunner()

    backup_result = runner.invoke(
        cli,
        ["data", "backup", str(archive), "--format", "json"],
    )
    assert backup_result.exit_code == 0, backup_result.output
    backup = json.loads(backup_result.output)
    assert backup["verified"] is True
    assert backup["sensitive_archive"] is True

    restore_result = runner.invoke(
        cli,
        ["data", "restore", str(archive), "--destination", str(restored)],
    )
    assert restore_result.exit_code == 0, restore_result.output
    for relative, payload in representative.items():
        assert (restored / relative).read_bytes() == payload
    assert "shisad start" in restore_result.output
    assert "shisad status" in restore_result.output
    assert "shisad doctor" in restore_result.output
    assert "offline health is not yet verified" in restore_result.output.lower()


def test_o4d_audit_lifecycle_is_verified_bounded_and_actionable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "data"
    monkeypatch.setenv("SHISAD_DATA_DIR", str(data_dir))
    monkeypatch.setattr("shisad.core.audit.MAX_SEGMENT_BYTES", 1_200)
    monkeypatch.setattr("shisad.security.control_plane.audit.MAX_SEGMENT_BYTES", 1_200)
    main = AuditLog(data_dir / "audit.jsonl")
    control = ControlPlaneAuditLog(data_dir / "control_plane" / "audit.jsonl")

    async def seed() -> None:
        for index in range(7):
            await main.persist(
                SessionCreated(
                    session_id=SessionId(f"audit-{index}"),
                    user_id=UserId(f"operator-{index}"),
                    actor="behavioral",
                )
            )
            control.append(
                event_type="ControlPlaneActionObserved",
                session_id=f"audit-{index}",
                actor="control-plane",
                data={"kind": "fs_read", "index": index},
            )

    asyncio.run(seed())
    runner = CliRunner()
    verified = runner.invoke(cli, ["audit", "verify", "--json"])
    queried = runner.invoke(cli, ["audit", "query", "--all", "--json"])

    assert verified.exit_code == 0, verified.output
    status = json.loads(verified.output)
    assert status["ok"] is True
    assert set(status["streams"]) == {"main", "control_plane"}
    assert all(row["verified"] is True for row in status["streams"].values())
    assert all(1 <= row["archive_count"] <= 4 for row in status["streams"].values())
    assert "path" not in verified.output
    assert queried.exit_code == 0, queried.output
    retained = json.loads(queried.output)
    assert retained[-1]["session_id"] == "audit-6"


def test_o4e_delivery_reconciliation_is_truthful_and_actionable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    delivery_id = "dly-" + "b" * 64
    entry = {
        "reservation_id": "dres-" + "a" * 64,
        "delivery_id": delivery_id,
        "kind": "channel_result",
        "target": {
            "channel": "matrix",
            "recipient": "!room:example.org",
            "workspace_hint": "workspace-1",
            "thread_id": "",
        },
        "state": "outcome_unknown",
        "reason": "provider_attempt_failed",
        "payload_digest": "c" * 64,
        "receipt": None,
        "recovery": {
            "kind": "neither",
            "guarantee_id": "",
            "reconciliation_available": False,
        },
    }
    config = cli_main.DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)

    def _fake_rpc_call(
        _config: object,
        method: str,
        _params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        if method == "delivery.list":
            payload = {"deliveries": [entry], "count": 1}
        elif method == "delivery.inspect":
            payload = {"found": True, "delivery": entry}
        else:
            assert method == "delivery.resolve"
            payload = {
                "found": True,
                "lookup_attempted": False,
                "reconciliation_status": "unsupported",
                "reason": "provider_reconciliation_unavailable",
                "instruction": (
                    "No provider lookup is available; no send was attempted. "
                    "Inspect the provider and submit a fresh request to retry."
                ),
                "delivery": entry,
            }
        assert response_model is not None
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()
    listed = runner.invoke(cli, ["delivery", "list", "--state", "outcome_unknown"])
    inspected = runner.invoke(cli, ["delivery", "inspect", delivery_id, "--json"])
    resolved = runner.invoke(cli, ["delivery", "resolve", delivery_id])

    assert listed.exit_code == 0, listed.output
    assert "state=outcome_unknown" in listed.output
    assert "reconciliation_available=false" in listed.output
    assert inspected.exit_code == 0, inspected.output
    inspected_payload = json.loads(inspected.output)
    assert "payload" not in inspected_payload["delivery"]
    assert "metadata" not in inspected_payload["delivery"]
    assert resolved.exit_code == 0, resolved.output
    assert "no send was attempted" in resolved.output.lower()
    assert "fresh request" in resolved.output.lower()


def test_o4f_channel_status_and_test_are_truthful(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = cli_main.DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    calls: list[tuple[str, dict[str, object]]] = []

    def _fake_rpc_call(
        _config: object,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        calls.append((method, dict(params or {})))
        if method == "channel.status":
            payload = {
                "channels": [
                    {
                        "channel": name,
                        "enabled": name == "discord",
                        "available": name == "discord",
                        "connected": name == "discord",
                        "state": "connected" if name == "discord" else "disabled",
                        "startup_status": "ready" if name == "discord" else "disabled",
                        "startup_reason": "",
                        "last_message_at": None,
                        "last_message_evidence": "unavailable",
                    }
                    for name in ("matrix", "discord", "telegram", "slack")
                ],
                "count": 4,
            }
        else:
            assert method == "channel.test"
            payload = {
                "channel": "discord",
                "target": "channel-456",
                "attempted": True,
                "sent": True,
                "state": "delivered",
                "reason": "provider_acknowledged",
                "outbound_acknowledged": True,
                "round_trip_verified": False,
                "replay_recommended": False,
                "reservation_id": "dres-" + "a" * 64,
                "delivery_id": "dly-" + "b" * 64,
            }
        assert response_model is not None
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    runner = CliRunner()
    status = runner.invoke(cli, ["channel", "status"])
    tested = runner.invoke(cli, ["channel", "test", "discord", "--target", "channel-456"])

    assert status.exit_code == 0, status.output
    assert "discord state=connected" in status.output
    assert "last_message=unavailable" in status.output
    assert tested.exit_code == 0, tested.output
    assert "outbound acknowledged" in tested.output.lower()
    assert "not a round-trip" in tested.output.lower()
    assert calls == [
        ("channel.status", {}),
        ("channel.test", {"channel": "discord", "target": "channel-456"}),
    ]

    class _DeliveryOwner:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        async def send(self, **kwargs: object) -> DeliveryResult:
            self.calls.append(kwargs)
            return DeliveryResult(
                attempted=True,
                sent=True,
                reason="provider_acknowledged",
                reservation_id="dres-runtime",
                delivery_id="dly-runtime",
                state="delivered",
            )

    class _RuntimeHarness(AdminImplMixin):
        @staticmethod
        def _is_admin_rpc_peer(params: object) -> bool:
            return isinstance(params, dict) and params.get("_rpc_peer") == {"uid": 0}

    delivery_owner = _DeliveryOwner()
    harness = _RuntimeHarness()
    harness._services = SimpleNamespace(  # type: ignore[attr-defined]
        delivery=delivery_owner,
        channel_startup_status={"discord": {"status": "ready", "reason_code": ""}},
    )
    harness._config = SimpleNamespace(  # type: ignore[attr-defined]
        matrix_enabled=False,
        discord_enabled=True,
        telegram_enabled=False,
        slack_enabled=False,
    )
    harness._matrix_channel = None  # type: ignore[attr-defined]
    harness._discord_channel = SimpleNamespace(available=True, connected=True)  # type: ignore[attr-defined]
    harness._telegram_channel = None  # type: ignore[attr-defined]
    harness._slack_channel = None  # type: ignore[attr-defined]
    runtime_status = asyncio.run(harness.do_channel_status({"_rpc_peer": {"uid": 0}}))
    runtime_test = asyncio.run(
        harness.do_channel_test(
            {"channel": "discord", "target": "channel-456", "_rpc_peer": {"uid": 0}}
        )
    )
    assert runtime_status["channels"][1]["last_message_evidence"] == "unavailable"
    assert runtime_test["outbound_acknowledged"] is True
    assert runtime_test["round_trip_verified"] is False
    assert delivery_owner.calls[0]["message"] == channel_setup.CHANNEL_SETUP_TEST_MESSAGE
    with pytest.raises(ValueError, match="authenticated admin"):
        asyncio.run(harness.do_channel_test({"channel": "discord", "target": "channel-456"}))


def test_o4f_pairing_operations_and_config_reconfiguration_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """schema_version = 1
# keep daemon bytes exact
[daemon]
ui_theme = "shisa-dark"

[model]
planner_model_id = "old-model"
planner_api_key_ref = "model.primary"

# keep security bytes exact
[security]
default_deny = true
""",
        encoding="utf-8",
    )
    original = config_path.read_bytes()
    runner = CliRunner()
    preview = runner.invoke(
        cli,
        [
            "--config",
            str(config_path),
            "config",
            "wizard",
            "--section",
            "model",
            "--set",
            'planner_model_id="new-model"',
            "--format",
            "json",
        ],
    )
    assert preview.exit_code == 0, preview.output
    assert json.loads(preview.output)["persisted"] is False
    assert config_path.read_bytes() == original

    published = runner.invoke(
        cli,
        [
            "--config",
            str(config_path),
            "config",
            "wizard",
            "--section",
            "model",
            "--set",
            'planner_model_id="new-model"',
            "--write",
            "--format",
            "json",
        ],
    )
    assert published.exit_code == 0, published.output
    publication = json.loads(published.output)
    assert publication["persisted"] is True
    assert publication["changed_fields"] == ["planner_model_id"]
    assert Path(publication["backup_path"]).read_bytes() == original
    rewritten = config_path.read_bytes()
    assert b'# keep daemon bytes exact\n[daemon]\nui_theme = "shisa-dark"\n' in rewritten
    assert b"# keep security bytes exact\n[security]\ndefault_deny = true\n" in rewritten
    assert b'planner_model_id = "new-model"' in rewritten
    assert "must-not-print" not in published.output

    config = cli_main.DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
    )
    monkeypatch.setattr(cli_main, "_get_config", lambda: config)
    calls: list[tuple[str, dict[str, object]]] = []

    def _fake_rpc_call(
        _config: object,
        method: str,
        params: dict[str, object] | None = None,
        *,
        response_model: type[object] | None = None,
    ) -> object:
        request = dict(params or {})
        calls.append((method, request))
        entry = {
            "channel": "discord",
            "external_user_id": "user-1",
            "workspace_hint": "guild-1",
            "reason": "identity_not_allowlisted",
            "requested_at": "2026-08-23T00:00:00+00:00",
        }
        if method == "channel.pairing_list":
            payload = {"entries": [entry], "count": 1}
        else:
            assert method == "channel.pairing_cleanup"
            write = bool(request["write"])
            payload = {
                "workspace_hint": "guild-1",
                "channel": "discord",
                "before": "2026-08-24T00:00:00+00:00",
                "dry_run": not write,
                "complete": True,
                "matched_count": 1,
                "removed_count": 1 if write else 0,
                "failed_count": 0,
                "remaining_count": 0 if write else 1,
                "durability": "supported" if write else "not_applicable",
                "entries": [entry],
                "failures": [],
            }
        assert response_model is not None
        return response_model.model_validate(payload)  # type: ignore[attr-defined]

    monkeypatch.setattr(cli_main, "rpc_call", _fake_rpc_call)
    listed = runner.invoke(
        cli,
        ["channel", "pairing-list", "--workspace", "guild-1", "--channel", "discord"],
    )
    dry = runner.invoke(
        cli,
        [
            "channel",
            "pairing-cleanup",
            "--workspace",
            "guild-1",
            "--channel",
            "discord",
            "--before",
            "2026-08-24T00:00:00+00:00",
        ],
    )
    written = runner.invoke(
        cli,
        [
            "channel",
            "pairing-cleanup",
            "--workspace",
            "guild-1",
            "--channel",
            "discord",
            "--before",
            "2026-08-24T00:00:00+00:00",
            "--write",
        ],
    )
    assert listed.exit_code == dry.exit_code == written.exit_code == 0
    assert "applied=false" in dry.output
    assert "applied=true" in written.output
    assert all(
        "pairing_requests" not in output for output in (listed.output, dry.output, written.output)
    )
    assert calls[1][1]["write"] is False
    assert calls[2][1]["write"] is True
