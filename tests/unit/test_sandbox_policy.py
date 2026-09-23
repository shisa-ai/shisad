"""M3 policy component extraction coverage."""

from __future__ import annotations

import sys

import pytest

from shisad.executors.proxy import NetworkPolicy
from shisad.executors.sandbox import (
    EnvironmentPolicy,
    SandboxConfig,
    SandboxEnforcement,
    SandboxPolicyEvaluator,
    SandboxType,
)


@pytest.mark.parametrize(
    "command",
    [
        ["grep", "-rn", "mount", "docs/"],
        ["git", "log", "--grep", "ptrace"],
        ["cat", "/tmp/mount/notes"],
        ["sh", "-c", "echo mount"],
        ["bash", "-lc", "grep ptrace notes"],
        ["sh", "script.sh", "mount"],
        ["sh", "-c", "'mount"],
        [],
    ],
)
def test_escape_signal_ignores_argument_text(command: list[str]) -> None:
    assert SandboxPolicyEvaluator().escape_signal_reason(command) is None


@pytest.mark.parametrize(
    "command",
    [
        ["mount", "-a"],
        ["/usr/bin/mount", "-a"],
        ["sh", "-c", "mount -a"],
        ["bash", "-lc", "/usr/bin/mount -a"],
    ],
)
def test_escape_signal_detects_executable(command: list[str]) -> None:
    assert SandboxPolicyEvaluator().escape_signal_reason(command) == "escape_signal:mount"


@pytest.mark.parametrize(
    ("payload", "destructive"),
    [
        ("rm -rf /workspace/out", True),
        ("git clean -fdx", True),
        ("truncate -s 0 notes.txt", True),
        ("echo hello", False),
        ("git status", False),
    ],
)
def test_shell_payload_uses_destructive_command_rules(payload: str, destructive: bool) -> None:
    assert SandboxPolicyEvaluator().is_destructive(["bash", "-lc", payload]) is destructive


def test_m3_policy_select_backend_routes_network_to_container() -> None:
    evaluator = SandboxPolicyEvaluator()
    backend = evaluator.select_backend(
        SandboxConfig(
            tool_name="http_request",
            command=[sys.executable, "-c", "print('ok')"],
            network=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
        )
    )
    assert backend == SandboxType.CONTAINER


def test_m3_policy_degraded_controls_adds_seccomp_for_security_critical() -> None:
    evaluator = SandboxPolicyEvaluator()
    base_config = SandboxConfig(
        tool_name="shell.exec",
        command=[sys.executable, "-c", "print('ok')"],
        security_critical=False,
    )
    enforcement = SandboxEnforcement(
        filesystem=True,
        network=True,
        env=True,
        seccomp=False,
        resource_limits=True,
        dns_control=True,
    )
    assert evaluator.degraded_controls(base_config, enforcement) == []

    critical = base_config.model_copy(update={"security_critical": True})
    assert evaluator.degraded_controls(critical, enforcement) == ["seccomp"]


def test_m3_policy_build_environment_failures() -> None:
    evaluator = SandboxPolicyEvaluator()
    environment, error, dropped = evaluator.build_environment(
        EnvironmentPolicy(allowed_keys=["ALLOWED"], max_keys=4, max_total_bytes=64),
        {"NOT_ALLOWED": "x"},
    )
    assert environment == {}
    assert error is None
    assert dropped == ["NOT_ALLOWED"]

    environment, error, _ = evaluator.build_environment(
        EnvironmentPolicy(allowed_keys=["A", "B"], max_keys=1, max_total_bytes=64),
        {"A": "1", "B": "2"},
    )
    assert environment == {}
    assert error == "env_too_many_keys"

    environment, error, _ = evaluator.build_environment(
        EnvironmentPolicy(allowed_keys=["LD_PRELOAD"], denied_prefixes=["LD_"]),
        {"LD_PRELOAD": "/tmp/evil.so"},
    )
    assert environment == {}
    assert error == "env_key_denied:LD_PRELOAD"


def test_m3_policy_escape_signal_and_destructive_detection() -> None:
    evaluator = SandboxPolicyEvaluator()
    assert evaluator.escape_signal_reason(["unshare", "-m"]) == "escape_signal:unshare"
    assert evaluator.is_destructive(["git", "status"]) is False
    assert evaluator.is_destructive(["git", "push", "--force"]) is True
