"""Unit tests for the bounded O1 onboarding command domain."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

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


def test_o1_container_markers_are_informational_facts(tmp_path: Path) -> None:
    marker = tmp_path / ".dockerenv"
    assert onboarding.detect_container((marker,)) is False

    marker.write_text("", encoding="utf-8")

    assert onboarding.detect_container((marker,)) is True


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
