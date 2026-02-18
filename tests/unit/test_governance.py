"""M4.T8-T9 and M4.T21-T24/T30-T32 governance and merge coverage."""

from __future__ import annotations

import logging

import pytest

from shisad.executors.mounts import FilesystemPolicy, MountRule
from shisad.executors.proxy import NetworkPolicy
from shisad.executors.sandbox import (
    DegradedModePolicy,
    EnvironmentPolicy,
    ResourceLimits,
    SandboxType,
)
from shisad.governance.merge import (
    PolicyMerge,
    PolicyMergeError,
    PolicyPatch,
    ToolExecutionPolicy,
    normalize_patch,
)
from shisad.governance.scopes import (
    DelegationGrant,
    ScopedPolicy,
    ScopedPolicyCompiler,
    ScopeLevel,
)
from shisad.security.policy import SandboxPolicy


def _floor_policy(
    *,
    sandbox_type: SandboxType = SandboxType.NSJAIL,
    allow_network: bool = True,
    allowed_domains: list[str] | None = None,
    security_critical: bool = True,
) -> ToolExecutionPolicy:
    return ToolExecutionPolicy(
        sandbox_type=sandbox_type,
        network=NetworkPolicy(
            allow_network=allow_network,
            allowed_domains=allowed_domains or ["api.good.com", "api.backup.com"],
            deny_private_ranges=True,
            deny_ip_literals=True,
        ),
        filesystem=FilesystemPolicy(
            mounts=[MountRule(path="/workspace/**", mode="rw")],
            denylist=["**/*.pem"],
        ),
        environment=EnvironmentPolicy(
            allowed_keys=["PATH", "TOKEN"],
            denied_prefixes=["LD_"],
            max_keys=8,
            max_total_bytes=2048,
        ),
        limits=ResourceLimits(
            cpu_shares=256,
            memory_mb=512,
            timeout_seconds=60,
            output_bytes=4096,
            pids=32,
        ),
        degraded_mode=DegradedModePolicy.FAIL_CLOSED,
        security_critical=security_critical,
    )


def test_m4_t8_policy_compiler_rejects_constraint_weakening() -> None:
    parent = ScopedPolicy(
        level=ScopeLevel.ORG,
        constraints=_floor_policy(allow_network=False, allowed_domains=[]),
        delegation=DelegationGrant(
            allow_network_toggle=False,
            allow_sandbox_downgrade=False,
        ),
    )
    child = ScopedPolicy(
        level=ScopeLevel.WORKSPACE,
        constraints=_floor_policy(allow_network=True, allowed_domains=["api.good.com"]),
    )
    with pytest.raises(PolicyMergeError, match="allow_network elevation"):
        ScopedPolicyCompiler.compile_chain([parent, child])


def test_m4_t9_effective_config_explainer_shows_correct_inheritance() -> None:
    org = ScopedPolicy(
        level=ScopeLevel.ORG,
        constraints=_floor_policy(),
        defaults={"network.allowed_domains": ["api.good.com"]},
    )
    narrowed = _floor_policy()
    narrowed.limits.timeout_seconds = 30
    workspace = ScopedPolicy(
        level=ScopeLevel.WORKSPACE,
        constraints=narrowed,
        defaults={"network.allowed_domains": ["api.good.com", "evil.com"]},
    )
    compiled = ScopedPolicyCompiler.compile_chain([org, workspace])
    explanation = ScopedPolicyCompiler.explain(compiled, field_name="limits")
    assert "workspace" in explanation
    assert compiled.defaults["network.allowed_domains"] == ["api.good.com"]


def test_m4_t21_policy_merge_intersection_most_restrictive_all_dimensions() -> None:
    server = _floor_policy(allow_network=False, security_critical=True)
    patch = PolicyPatch.model_validate(
        {
            "sandbox_type": "vm",
            "network": {
                "allow_network": True,
                "allowed_domains": ["api.good.com", "evil.com"],
                "deny_private_ranges": False,
                "deny_ip_literals": False,
            },
            "filesystem": {
                "mounts": [
                    {"path": "/workspace/project/**", "mode": "rw"},
                    {"path": "/tmp/**", "mode": "rw"},
                ],
                "denylist": ["**/*.key"],
            },
            "environment": {
                "allowed_keys": ["TOKEN", "EXTRA"],
                "denied_prefixes": ["PYTHON"],
                "max_keys": 32,
                "max_total_bytes": 999999,
            },
            "limits": {
                "memory_mb": 1024,
                "timeout_seconds": 10,
                "output_bytes": 1024,
                "pids": 128,
            },
            "degraded_mode": "fail_open",
            "security_critical": False,
        }
    )
    merged = PolicyMerge.merge(server=server, caller=patch)
    assert merged.sandbox_type == SandboxType.VM
    assert merged.network.allow_network is False
    assert merged.network.allowed_domains == []
    assert merged.network.deny_private_ranges is True
    assert merged.network.deny_ip_literals is True
    assert merged.filesystem.mounts == [MountRule(path="/workspace/project/**", mode="rw")]
    assert sorted(merged.filesystem.denylist) == ["**/*.key", "**/*.pem"]
    assert merged.environment.allowed_keys == ["TOKEN"]
    assert sorted(merged.environment.denied_prefixes) == ["LD_", "PYTHON"]
    assert merged.environment.max_keys == 8
    assert merged.environment.max_total_bytes == 2048
    assert merged.limits.memory_mb == 512
    assert merged.limits.timeout_seconds == 10
    assert merged.limits.output_bytes == 1024
    assert merged.limits.pids == 32
    assert merged.degraded_mode == DegradedModePolicy.FAIL_CLOSED
    assert merged.security_critical is True


def test_m4_t22_policy_merge_idempotent() -> None:
    server = _floor_policy()
    patch = PolicyPatch.model_validate(server.model_dump(mode="json"))
    merged = PolicyMerge.merge(server=server, caller=patch)
    assert merged == server


def test_m4_t23_policy_merge_empty_allowlist_results_in_deny_all() -> None:
    server = _floor_policy(allow_network=True, allowed_domains=["api.good.com", "api.backup.com"])
    patch = PolicyPatch.model_validate({"network": {"allowed_domains": []}})
    merged = PolicyMerge.merge(server=server, caller=patch)
    assert merged.network.allow_network is True
    assert merged.network.allowed_domains == []


def test_m4_t24_per_tool_override_widens_floor_for_specific_tool_only() -> None:
    global_floor = _floor_policy(allow_network=False, allowed_domains=[])
    override_floor = _floor_policy(allow_network=True, allowed_domains=["api.good.com"])
    caller = PolicyPatch.model_validate(
        {"network": {"allow_network": True, "allowed_domains": ["api.good.com"]}}
    )
    merged_global = PolicyMerge.merge(server=global_floor, caller=caller)
    merged_override = PolicyMerge.merge(server=override_floor, caller=caller)
    assert merged_global.network.allow_network is False
    assert merged_override.network.allow_network is True
    assert merged_override.network.allowed_domains == ["api.good.com"]


def test_m4_t30_allow_network_floor_cannot_be_elevated_by_caller() -> None:
    server = _floor_policy(allow_network=False, allowed_domains=[])
    caller = PolicyPatch.model_validate(
        {"network": {"allow_network": True, "allowed_domains": ["api.good.com"]}}
    )
    merged = PolicyMerge.merge(server=server, caller=caller)
    assert merged.network.allow_network is False
    assert merged.network.allowed_domains == []


def test_m4_t31_policy_patch_tri_state_semantics() -> None:
    omitted = normalize_patch({})
    assert omitted.model_fields_set == set()

    explicit_empty = normalize_patch({"network": {"allowed_domains": []}})
    assert explicit_empty.network is not None
    assert explicit_empty.network.allowed_domains == []
    assert "allowed_domains" in explicit_empty.network.model_fields_set

    with pytest.raises(ValueError, match="explicit null"):
        normalize_patch({"sandbox_type": None})


def test_m4_t32_structured_tool_override_migration_warns(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)
    policy = SandboxPolicy.model_validate(
        {"tool_overrides": {"shell_exec": "container"}}
    )
    assert policy.tool_overrides["shell.exec"].sandbox_type == "container"
    assert any("Deprecated sandbox.tool_overrides scalar" in rec.message for rec in caplog.records)


def test_m4_rr1_policy_merge_limits_respects_explicit_zero_values() -> None:
    server = _floor_policy()
    caller = PolicyPatch.model_validate(
        {
            "limits": {
                "cpu_shares": 0,
                "memory_mb": 0,
                "timeout_seconds": 0,
                "output_bytes": 0,
                "pids": 0,
            }
        }
    )
    merged = PolicyMerge.merge(server=server, caller=caller)
    assert merged.limits.cpu_shares == 0
    assert merged.limits.memory_mb == 0
    assert merged.limits.timeout_seconds == 0
    assert merged.limits.output_bytes == 0
    assert merged.limits.pids == 0


def test_m4_rr2_mount_intersection_does_not_match_sibling_prefixes() -> None:
    server = _floor_policy()
    server.filesystem = FilesystemPolicy(
        mounts=[MountRule(path="/workspace/a/**", mode="rw")],
        denylist=[],
    )
    caller = PolicyPatch.model_validate(
        {
            "filesystem": {
                "mounts": [{"path": "/workspace/ab/**", "mode": "rw"}],
            }
        }
    )
    merged = PolicyMerge.merge(server=server, caller=caller)
    assert merged.filesystem.mounts == []
