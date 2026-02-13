"""M3 policy component extraction coverage."""

from __future__ import annotations

import sys

from shisad.executors.proxy import NetworkPolicy
from shisad.executors.sandbox import (
    EnvironmentPolicy,
    SandboxConfig,
    SandboxEnforcement,
    SandboxPolicyEvaluator,
    SandboxType,
)


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
