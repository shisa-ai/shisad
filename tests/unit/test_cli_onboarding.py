"""Unit tests for the bounded O1 onboarding command domain."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from shisad.cli import main as cli_main
from shisad.cli import onboarding
from shisad.cli.onboarding import (
    CheckRequirement,
    CheckState,
    ConfiguredPosture,
    EnvironmentFacts,
    build_preflight_report,
    classify_configured_posture,
    parse_managed_posture,
    render_welcome,
)
from shisad.ui.theme import resolve_ui_posture


def test_o4a_init_from_env_is_noninteractive_redacted_and_no_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in list(os.environ):
        if key.startswith("SHISAD_"):
            monkeypatch.delenv(key, raising=False)
    destination = tmp_path / "config.toml"
    secret = "do-not-write-this-secret"
    runner = CliRunner()

    first = runner.invoke(
        cli_main.cli,
        ["--config", str(destination), "init", "--from-env", "--format", "json"],
        env={
            "SHISAD_LOG_LEVEL": "WARNING",
            "SHISAD_MODEL_MODEL_ID": "provider/model-a",
            "SHISAD_MODEL_API_KEY": secret,
        },
    )

    assert first.exit_code == 0, first.output
    payload = json.loads(first.output)
    assert payload["mode"] == "from_env"
    assert payload["persisted_fields"] == ["daemon.log_level", "model.model_id"]
    assert payload["omitted_secret_fields"] == ["model.api_key"]
    text = destination.read_text(encoding="utf-8")
    assert 'log_level = "WARNING"' in text
    assert 'model_id = "provider/model-a"' in text
    assert secret not in text

    second = runner.invoke(
        cli_main.cli,
        ["--config", str(destination), "init", "--from-env", "--format", "json"],
        env={"SHISAD_MODEL_API_KEY": "another-secret"},
    )
    assert second.exit_code == 3
    assert secret not in second.output
    assert "another-secret" not in second.output


@pytest.mark.parametrize(
    ("config_present", "interactive", "managed", "schema_supported", "expected"),
    [
        (False, True, False, True, ConfiguredPosture.FRESH),
        (True, True, False, True, ConfiguredPosture.RETURNING),
        (False, False, False, True, ConfiguredPosture.NON_INTERACTIVE),
        (True, False, False, True, ConfiguredPosture.NON_INTERACTIVE),
        (False, True, True, True, ConfiguredPosture.MANAGED),
        (True, False, True, True, ConfiguredPosture.MANAGED),
        (True, True, False, False, ConfiguredPosture.UPGRADE_REQUIRED),
        (True, False, True, False, ConfiguredPosture.UPGRADE_REQUIRED),
    ],
)
def test_o1_detection_matrix_uses_only_finite_facts(
    config_present: bool,
    interactive: bool,
    managed: bool,
    schema_supported: bool,
    expected: ConfiguredPosture,
) -> None:
    assert (
        classify_configured_posture(
            config_present=config_present,
            interactive=interactive,
            managed=managed,
            schema_supported=schema_supported,
        )
        is expected
    )


@pytest.mark.parametrize("value", ["1", "TRUE", "yes", "On"])
def test_o1_managed_parser_accepts_only_finite_true_values(value: str) -> None:
    assert parse_managed_posture({"SHISAD_MANAGED": value}) is True


@pytest.mark.parametrize("value", ["0", "FALSE", "no", "Off", ""])
def test_o1_managed_parser_accepts_false_or_absent_values(value: str) -> None:
    assert parse_managed_posture({"SHISAD_MANAGED": value}) is False


def test_o1_invalid_managed_value_fails_closed() -> None:
    with pytest.raises(onboarding.EnvironmentDetectionError, match="SHISAD_MANAGED"):
        parse_managed_posture({"SHISAD_MANAGED": "sometimes\x1b[31m"})


@pytest.mark.parametrize("value", [" true", "true ", " false ", " ", "\t"])
def test_o1_padded_or_whitespace_managed_value_fails_closed(value: str) -> None:
    with pytest.raises(onboarding.EnvironmentDetectionError, match="SHISAD_MANAGED"):
        parse_managed_posture({"SHISAD_MANAGED": value})


def test_o1_optional_gaps_do_not_block_safe_core(tmp_path: Path) -> None:
    report = build_preflight_report(
        EnvironmentFacts(
            posture=ConfiguredPosture.RETURNING,
            config_path=tmp_path / "config.toml",
            config_present=True,
            explicit_config=False,
            interactive=True,
            managed=False,
            containerized=True,
            python_version=(3, 12, 7),
            policy_present=False,
            daemon_reachable=False,
        )
    )

    checks = {check.check_id: check for check in report.checks}
    assert checks["runtime"].requirement is CheckRequirement.REQUIRED
    assert checks["runtime"].state is CheckState.PASS
    assert checks["config"].requirement is CheckRequirement.REQUIRED
    assert checks["config"].state is CheckState.PASS
    assert checks["policy"].requirement is CheckRequirement.OPTIONAL
    assert checks["policy"].state is CheckState.DEGRADED
    assert checks["daemon"].requirement is CheckRequirement.OPTIONAL
    assert checks["daemon"].state is CheckState.DEGRADED
    assert checks["environment"].requirement is CheckRequirement.INFORMATIONAL
    assert report.blocked is False
    assert report.next_action == "shisad start --foreground"


@pytest.mark.parametrize(
    (
        "posture",
        "config_present",
        "interactive",
        "managed",
        "daemon_reachable",
        "python_version",
        "expected_action",
        "blocked",
    ),
    [
        (ConfiguredPosture.FRESH, False, True, False, False, (3, 12, 1), "shisad init", False),
        (
            ConfiguredPosture.RETURNING,
            True,
            True,
            False,
            False,
            (3, 12, 1),
            "shisad start --foreground",
            False,
        ),
        (
            ConfiguredPosture.RETURNING,
            True,
            True,
            False,
            True,
            (3, 12, 1),
            "shisad chat",
            False,
        ),
        (
            ConfiguredPosture.MANAGED,
            True,
            True,
            True,
            True,
            (3, 12, 1),
            "shisad status",
            False,
        ),
        (
            ConfiguredPosture.NON_INTERACTIVE,
            True,
            False,
            False,
            True,
            (3, 12, 1),
            "shisad status",
            False,
        ),
        (
            ConfiguredPosture.UPGRADE_REQUIRED,
            True,
            True,
            False,
            False,
            (3, 12, 1),
            "restore a supported schema_version=1 config, then run: shisad config validate",
            False,
        ),
        (
            ConfiguredPosture.FRESH,
            False,
            True,
            False,
            False,
            (3, 11, 9),
            "install Python 3.12 or newer, then run: shisad",
            True,
        ),
    ],
)
def test_o1_next_action_matrix_is_finite_and_required_failures_alone_block(
    tmp_path: Path,
    posture: ConfiguredPosture,
    config_present: bool,
    interactive: bool,
    managed: bool,
    daemon_reachable: bool,
    python_version: tuple[int, int, int],
    expected_action: str,
    blocked: bool,
) -> None:
    report = build_preflight_report(
        EnvironmentFacts(
            posture=posture,
            config_path=tmp_path / "config.toml",
            config_present=config_present,
            explicit_config=False,
            interactive=interactive,
            managed=managed,
            containerized=False,
            python_version=python_version,
            policy_present=False,
            daemon_reachable=daemon_reachable,
        )
    )

    assert report.next_action == expected_action
    assert report.blocked is blocked


def test_o1_inspection_uses_canonical_config_and_bounded_probe(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.toml"
    socket_path = tmp_path / "control.sock"
    policy_path = tmp_path / "policy.yaml"
    socket_path.touch()
    policy_path.write_text("tools: {}\n", encoding="utf-8")
    config_path.write_text(
        "\n".join(
            [
                "schema_version = 1",
                "[daemon]",
                f'socket_path = "{socket_path}"',
                f'policy_path = "{policy_path}"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    probed: list[Path] = []

    def _probe(path: Path) -> bool:
        probed.append(path)
        return True

    report = onboarding.inspect_onboarding_environment(
        config_path,
        environ={},
        interactive=True,
        containerized=False,
        daemon_probe=_probe,
    )

    assert report.facts.posture is ConfiguredPosture.RETURNING
    assert report.facts.config_path == config_path
    assert report.facts.explicit_config is True
    assert report.facts.policy_present is True
    assert report.facts.daemon_reachable is True
    assert report.next_action == "shisad chat"
    assert probed == [socket_path]


def test_o1_managed_without_config_probes_canonical_existing_socket(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "managed-control.sock"
    socket_path.touch()
    probed: list[Path] = []

    def _probe(path: Path) -> bool:
        probed.append(path)
        return True

    report = onboarding.inspect_onboarding_environment(
        None,
        environ={
            "XDG_CONFIG_HOME": str(tmp_path / "config-home"),
            "SHISAD_MANAGED": "yes",
            "SHISAD_SOCKET_PATH": str(socket_path),
            "SHISAD_POLICY_PATH": str(tmp_path / "missing-policy.yaml"),
        },
        interactive=True,
        containerized=False,
        daemon_probe=_probe,
    )

    assert report.facts.posture is ConfiguredPosture.MANAGED
    assert report.facts.config_present is False
    assert report.facts.daemon_reachable is True
    running_daemon_check = next(check for check in report.checks if check.check_id == "daemon")
    assert running_daemon_check.requirement is CheckRequirement.OPTIONAL
    assert running_daemon_check.state is CheckState.PASS
    assert running_daemon_check.detail == "running and reachable"
    assert report.next_action == "shisad status"
    assert probed == [socket_path]

    probed.clear()
    managed_stopped = onboarding.inspect_onboarding_environment(
        None,
        environ={
            "XDG_CONFIG_HOME": str(tmp_path / "managed-stopped-config-home"),
            "SHISAD_MANAGED": "yes",
            "SHISAD_SOCKET_PATH": str(socket_path),
            "SHISAD_POLICY_PATH": str(tmp_path / "missing-policy.yaml"),
        },
        interactive=True,
        containerized=False,
        daemon_probe=lambda path: probed.append(path) or False,
    )
    daemon_check = next(check for check in managed_stopped.checks if check.check_id == "daemon")

    assert managed_stopped.facts.daemon_reachable is False
    assert daemon_check.requirement is CheckRequirement.OPTIONAL
    assert daemon_check.state is CheckState.DEGRADED
    assert daemon_check.detail == "stopped or unreachable"
    assert managed_stopped.next_action == "shisad doctor"
    assert probed == [socket_path]

    probed.clear()
    missing_socket = tmp_path / "missing-control.sock"
    managed_missing_socket = onboarding.inspect_onboarding_environment(
        None,
        environ={
            "XDG_CONFIG_HOME": str(tmp_path / "managed-missing-config-home"),
            "SHISAD_MANAGED": "yes",
            "SHISAD_SOCKET_PATH": str(missing_socket),
            "SHISAD_POLICY_PATH": str(tmp_path / "missing-policy.yaml"),
        },
        interactive=True,
        containerized=False,
        daemon_probe=_probe,
    )
    missing_daemon_check = next(
        check for check in managed_missing_socket.checks if check.check_id == "daemon"
    )

    assert missing_daemon_check.requirement is CheckRequirement.OPTIONAL
    assert missing_daemon_check.state is CheckState.DEGRADED
    assert missing_daemon_check.detail == "stopped or unreachable"
    assert managed_missing_socket.next_action == "shisad doctor"
    assert probed == []

    fresh = onboarding.inspect_onboarding_environment(
        None,
        environ={
            "XDG_CONFIG_HOME": str(tmp_path / "fresh-config-home"),
            "SHISAD_SOCKET_PATH": str(socket_path),
            "SHISAD_POLICY_PATH": str(tmp_path / "missing-policy.yaml"),
        },
        interactive=True,
        containerized=False,
        daemon_probe=_probe,
    )
    fresh_daemon_check = next(check for check in fresh.checks if check.check_id == "daemon")

    assert fresh.facts.posture is ConfiguredPosture.FRESH
    assert fresh.facts.daemon_reachable is False
    assert fresh_daemon_check.requirement is CheckRequirement.INFORMATIONAL
    assert fresh_daemon_check.state is CheckState.INFO
    assert fresh_daemon_check.detail == "not checked before configuration"
    assert fresh.next_action == "shisad init"
    assert probed == []


def test_o1_container_markers_are_informational_facts(tmp_path: Path) -> None:
    marker = tmp_path / ".dockerenv"
    assert onboarding.detect_container((marker,)) is False

    marker.write_text("", encoding="utf-8")

    assert onboarding.detect_container((marker,)) is True

    report = build_preflight_report(
        EnvironmentFacts(
            posture=ConfiguredPosture.FRESH,
            config_path=tmp_path / "config.toml",
            config_present=False,
            explicit_config=False,
            interactive=True,
            managed=False,
            containerized=True,
            python_version=(3, 12, 7),
            policy_present=False,
            daemon_reachable=False,
        )
    )
    environment = next(check for check in report.checks if check.check_id == "environment")
    assert environment.requirement is CheckRequirement.INFORMATIONAL
    assert environment.state is CheckState.INFO
    assert "container marker present" in environment.detail
    assert report.facts.posture is ConfiguredPosture.FRESH
    assert report.blocked is False
    assert report.next_action == "shisad init"


def test_o1_noninteractive_and_managed_actions_remain_read_only(tmp_path: Path) -> None:
    base = dict(
        config_path=tmp_path / "config.toml",
        config_present=True,
        explicit_config=False,
        containerized=False,
        python_version=(3, 12, 7),
        policy_present=True,
        daemon_reachable=False,
    )

    noninteractive = build_preflight_report(
        EnvironmentFacts(
            **base,
            posture=ConfiguredPosture.NON_INTERACTIVE,
            interactive=False,
            managed=False,
        )
    )
    managed = build_preflight_report(
        EnvironmentFacts(
            **base,
            posture=ConfiguredPosture.MANAGED,
            interactive=True,
            managed=True,
        )
    )

    assert noninteractive.next_action == "shisad doctor"
    assert managed.next_action == "shisad doctor"
    assert "start" not in noninteractive.next_action
    assert "start" not in managed.next_action


def test_o1_renderer_preserves_semantics_with_unicode_and_ascii_fallback(
    tmp_path: Path,
) -> None:
    report = build_preflight_report(
        EnvironmentFacts(
            posture=ConfiguredPosture.RETURNING,
            config_path=tmp_path / "config.toml",
            config_present=True,
            explicit_config=False,
            interactive=True,
            managed=False,
            containerized=False,
            python_version=(3, 12, 7),
            policy_present=False,
            daemon_reachable=False,
        )
    )
    rich = resolve_ui_posture(
        environ={"TERM": "xterm-256color", "LANG": "en_US.UTF-8"},
        isatty=True,
    )
    plain = resolve_ui_posture(
        no_color=True,
        environ={"TERM": "dumb", "NO_COLOR": "1", "LANG": "C"},
        isatty=False,
    )

    rich_text = render_welcome(report, ui_posture=rich)
    plain_text = render_welcome(report, ui_posture=plain)

    assert "\x1b[" in rich_text
    assert "╭" in rich_text
    assert "⚠" in rich_text
    assert "\x1b[" not in plain_text
    assert "╭" not in plain_text
    assert "WARN" in plain_text
    for phrase in ("Preflight", "Policy", "Daemon", "Next action"):
        assert phrase in rich_text
        assert phrase in plain_text


def test_o1_interactive_non_utf_renderer_is_ascii_and_no_color(tmp_path: Path) -> None:
    report = build_preflight_report(
        EnvironmentFacts(
            posture=ConfiguredPosture.RETURNING,
            config_path=tmp_path / "config.toml",
            config_present=True,
            explicit_config=False,
            interactive=True,
            managed=False,
            containerized=False,
            python_version=(3, 12, 7),
            policy_present=False,
            daemon_reachable=False,
        )
    )
    non_utf = resolve_ui_posture(
        environ={"TERM": "xterm-256color", "LANG": "C"},
        isatty=True,
    )

    assert non_utf.capabilities.unicode is False
    assert non_utf.capabilities.color_mode != "none"
    rendered = render_welcome(report, ui_posture=non_utf)
    assert "\x1b[" not in rendered
    assert "╭" not in rendered
    assert "WARN" in rendered


@pytest.mark.parametrize(
    ("environ", "no_color"),
    [
        ({"TERM": "xterm-256color", "LANG": "en_US.UTF-8", "NO_COLOR": "1"}, False),
        ({"TERM": "xterm-256color", "LANG": "en_US.UTF-8"}, True),
    ],
)
def test_o1_explicit_no_color_renderer_is_ascii(
    tmp_path: Path,
    environ: dict[str, str],
    no_color: bool,
) -> None:
    report = build_preflight_report(
        EnvironmentFacts(
            posture=ConfiguredPosture.RETURNING,
            config_path=tmp_path / "config.toml",
            config_present=True,
            explicit_config=False,
            interactive=True,
            managed=False,
            containerized=False,
            python_version=(3, 12, 7),
            policy_present=False,
            daemon_reachable=False,
        )
    )
    posture = resolve_ui_posture(
        no_color=no_color,
        environ=environ,
        isatty=True,
    )

    assert posture.capabilities.unicode is True
    assert posture.color_enabled is False
    rendered = render_welcome(report, ui_posture=posture)
    assert "\x1b[" not in rendered
    assert "╭" not in rendered
    assert "⚠" not in rendered
    assert "WARN" in rendered


def test_o1_daemon_probe_is_bounded_and_closes_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _FakeClient:
        def __init__(self, socket_path: Path) -> None:
            assert socket_path == tmp_path / "control.sock"

        async def connect(self) -> None:
            events.append("connect")

        async def call(self, method: str) -> dict[str, str]:
            events.append(method)
            return {"status": "running"}

        async def close(self) -> None:
            events.append("close")

    monkeypatch.setattr(onboarding, "ControlClient", _FakeClient)

    assert asyncio.run(onboarding.probe_daemon(tmp_path / "control.sock", timeout=0.1)) is True
    assert events == ["connect", "daemon.status", "close"]


def test_o1_daemon_probe_preserves_running_result_when_close_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _CloseFailureClient:
        def __init__(self, _socket_path: Path) -> None:
            return None

        async def connect(self) -> None:
            events.append("connect")

        async def call(self, method: str) -> dict[str, str]:
            events.append(method)
            return {"status": "running"}

        async def close(self) -> None:
            events.append("close")
            raise OSError("connection already closed")

    monkeypatch.setattr(onboarding, "ControlClient", _CloseFailureClient)

    assert asyncio.run(onboarding.probe_daemon(tmp_path / "control.sock", timeout=0.1)) is True
    assert events == ["connect", "daemon.status", "close"]


@pytest.mark.parametrize(
    "payload",
    [None, 1, {}, {"status": None}, {"status": 1}, {"status": {}}, {"status": "ready"}],
)
def test_o1_daemon_probe_rejects_malformed_or_unknown_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    closed = False

    class _MalformedClient:
        def __init__(self, _socket_path: Path) -> None:
            return None

        async def connect(self) -> None:
            return None

        async def call(self, _method: str) -> object:
            return payload

        async def close(self) -> None:
            nonlocal closed
            closed = True

    monkeypatch.setattr(onboarding, "ControlClient", _MalformedClient)

    assert asyncio.run(onboarding.probe_daemon(tmp_path / "control.sock", timeout=0.1)) is False
    assert closed is True


def test_o1_daemon_probe_degrades_when_unix_transport_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _UnavailableClient:
        def __init__(self, _socket_path: Path) -> None:
            return None

        async def connect(self) -> None:
            raise AttributeError("module 'asyncio' has no attribute 'open_unix_connection'")

    monkeypatch.setattr(onboarding, "ControlClient", _UnavailableClient)

    assert asyncio.run(onboarding.probe_daemon(tmp_path / "control.sock")) is False


def test_o1_daemon_probe_bounds_close_after_request_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _DeadlineClient:
        def __init__(self, _socket_path: Path) -> None:
            return None

        async def connect(self) -> None:
            events.append("connect")

        async def call(self, _method: str) -> object:
            events.append("call")
            await asyncio.sleep(1)
            return {"status": "running"}

        async def close(self) -> None:
            events.append("close")
            await asyncio.sleep(1)

    async def _bounded_probe() -> bool:
        return await asyncio.wait_for(
            onboarding.probe_daemon(tmp_path / "control.sock", timeout=0.01),
            timeout=0.1,
        )

    monkeypatch.setattr(onboarding, "ControlClient", _DeadlineClient)

    assert asyncio.run(_bounded_probe()) is False
    assert events == ["connect", "call", "close"]


def test_o1_daemon_probe_times_out_and_closes_connected_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed = False

    class _SlowClient:
        def __init__(self, _socket_path: Path) -> None:
            return None

        async def connect(self) -> None:
            return None

        async def call(self, _method: str) -> dict[str, str]:
            await asyncio.sleep(1)
            return {"status": "running"}

        async def close(self) -> None:
            nonlocal closed
            closed = True

    monkeypatch.setattr(onboarding, "ControlClient", _SlowClient)

    assert asyncio.run(onboarding.probe_daemon(tmp_path / "control.sock", timeout=0.01)) is False
    assert closed is True
