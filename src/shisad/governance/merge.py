"""Policy merge primitives for tool-execution floors (M4.7)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, model_validator

from shisad.executors.mounts import FilesystemPolicy, MountRule
from shisad.executors.proxy import NetworkPolicy
from shisad.executors.sandbox import (
    DegradedModePolicy,
    EnvironmentPolicy,
    ResourceLimits,
    SandboxType,
)


class PolicyMergeError(ValueError):
    """Policy merge failure."""


class _PatchBase(BaseModel):
    @model_validator(mode="after")
    def _reject_explicit_null(self) -> _PatchBase:
        for field in self.model_fields_set:
            if getattr(self, field) is None:
                raise ValueError(f"explicit null is invalid for field '{field}'")
        return self


class NetworkPolicyPatch(_PatchBase):
    allow_network: bool | None = None
    allowed_domains: list[str] | None = None
    deny_private_ranges: bool | None = None
    deny_ip_literals: bool | None = None


class FilesystemPolicyPatch(_PatchBase):
    mounts: list[dict[str, Any]] | None = None
    denylist: list[str] | None = None


class EnvironmentPolicyPatch(_PatchBase):
    allowed_keys: list[str] | None = None
    denied_prefixes: list[str] | None = None
    max_keys: int | None = None
    max_total_bytes: int | None = None


class ResourceLimitsPatch(_PatchBase):
    cpu_shares: int | None = None
    memory_mb: int | None = None
    timeout_seconds: int | None = None
    output_bytes: int | None = None
    pids: int | None = None


class PolicyPatch(_PatchBase):
    sandbox_type: str | None = None
    network: NetworkPolicyPatch | None = None
    filesystem: FilesystemPolicyPatch | None = None
    environment: EnvironmentPolicyPatch | None = None
    limits: ResourceLimitsPatch | None = None
    degraded_mode: str | None = None
    security_critical: bool | None = None


class ToolExecutionPolicy(BaseModel):
    sandbox_type: SandboxType
    network: NetworkPolicy
    filesystem: FilesystemPolicy
    environment: EnvironmentPolicy
    limits: ResourceLimits
    degraded_mode: DegradedModePolicy
    security_critical: bool = True


_SANDBOX_RANK: dict[str, int] = {
    "host": 0,
    SandboxType.CONTAINER.value: 1,
    SandboxType.NSJAIL.value: 2,
    SandboxType.VM.value: 3,
}


class PolicyMerge:
    """Most-restrictive merge where server policy is authoritative floor."""

    @classmethod
    def merge(cls, *, server: ToolExecutionPolicy, caller: PolicyPatch) -> ToolExecutionPolicy:
        sandbox_type = cls._merge_sandbox_type(server.sandbox_type, caller)
        network = cls._merge_network(server.network, caller.network)
        filesystem = cls._merge_filesystem(server.filesystem, caller.filesystem)
        environment = cls._merge_environment(server.environment, caller.environment)
        limits = cls._merge_limits(server.limits, caller.limits)
        degraded_mode = cls._merge_degraded_mode(server.degraded_mode, caller)
        security_critical = cls._merge_security_critical(server.security_critical, caller)

        return ToolExecutionPolicy(
            sandbox_type=sandbox_type,
            network=network,
            filesystem=filesystem,
            environment=environment,
            limits=limits,
            degraded_mode=degraded_mode,
            security_critical=security_critical,
        )

    @staticmethod
    def _merge_sandbox_type(server: SandboxType, caller: PolicyPatch) -> SandboxType:
        if "sandbox_type" not in caller.model_fields_set:
            return server
        requested_raw = str(caller.sandbox_type).strip()
        if requested_raw not in _SANDBOX_RANK:
            raise PolicyMergeError(f"unsupported sandbox_type '{requested_raw}'")
        if _SANDBOX_RANK[requested_raw] < _SANDBOX_RANK[server.value]:
            raise PolicyMergeError("sandbox_type weaker than server floor")
        return SandboxType(requested_raw)

    @staticmethod
    def _merge_network(server: NetworkPolicy, patch: NetworkPolicyPatch | None) -> NetworkPolicy:
        if patch is None:
            return server.model_copy(deep=True)

        allow_network = server.allow_network
        if "allow_network" in patch.model_fields_set and patch.allow_network is not None:
            allow_network = bool(server.allow_network and patch.allow_network)

        allowed_domains = list(server.allowed_domains)
        if "allowed_domains" in patch.model_fields_set and patch.allowed_domains is not None:
            caller_domains = [
                item.strip().lower()
                for item in patch.allowed_domains
                if item.strip()
            ]
            caller_set = set(caller_domains)
            server_domains = [
                item.strip().lower()
                for item in server.allowed_domains
                if item.strip()
            ]
            server_set = set(server_domains)
            if "*" in server_set:
                # Server wildcard means caller can narrow; preserve caller order.
                allowed_domains = caller_domains
            elif "*" in caller_set:
                # Caller wildcard cannot widen; preserve server floor order.
                allowed_domains = server_domains
            else:
                # Preserve server ordering for deterministic idempotent merges.
                allowed_domains = [item for item in server_domains if item in caller_set]

        deny_private_ranges = server.deny_private_ranges
        if (
            "deny_private_ranges" in patch.model_fields_set
            and patch.deny_private_ranges is not None
        ):
            deny_private_ranges = bool(server.deny_private_ranges or patch.deny_private_ranges)

        deny_ip_literals = server.deny_ip_literals
        if "deny_ip_literals" in patch.model_fields_set and patch.deny_ip_literals is not None:
            deny_ip_literals = bool(server.deny_ip_literals or patch.deny_ip_literals)

        if not allow_network:
            allowed_domains = []

        return NetworkPolicy(
            allow_network=allow_network,
            allowed_domains=allowed_domains,
            deny_private_ranges=deny_private_ranges,
            deny_ip_literals=deny_ip_literals,
        )

    @staticmethod
    def _merge_filesystem(
        server: FilesystemPolicy,
        patch: FilesystemPolicyPatch | None,
    ) -> FilesystemPolicy:
        if patch is None:
            return server.model_copy(deep=True)

        mounts = list(server.mounts)
        if "mounts" in patch.model_fields_set and patch.mounts is not None:
            requested = [
                MountRule.model_validate(item)
                for item in patch.mounts
            ]
            mounts = _intersect_mounts(server.mounts, requested)

        denylist = list(server.denylist)
        if "denylist" in patch.model_fields_set and patch.denylist is not None:
            denylist = sorted(set(server.denylist) | set(patch.denylist))

        return FilesystemPolicy(
            mounts=mounts,
            denylist=denylist,
        )

    @staticmethod
    def _merge_environment(
        server: EnvironmentPolicy,
        patch: EnvironmentPolicyPatch | None,
    ) -> EnvironmentPolicy:
        if patch is None:
            return server.model_copy(deep=True)

        allowed_keys = list(server.allowed_keys)
        if "allowed_keys" in patch.model_fields_set and patch.allowed_keys is not None:
            server_set = {item for item in server.allowed_keys}
            allowed_keys = [item for item in patch.allowed_keys if item in server_set]

        denied_prefixes = list(server.denied_prefixes)
        if "denied_prefixes" in patch.model_fields_set and patch.denied_prefixes is not None:
            denied_prefixes = sorted(set(server.denied_prefixes) | set(patch.denied_prefixes))

        max_keys = server.max_keys
        if "max_keys" in patch.model_fields_set and patch.max_keys is not None:
            max_keys = min(server.max_keys, int(patch.max_keys))

        max_total_bytes = server.max_total_bytes
        if "max_total_bytes" in patch.model_fields_set and patch.max_total_bytes is not None:
            max_total_bytes = min(server.max_total_bytes, int(patch.max_total_bytes))

        return EnvironmentPolicy(
            allowed_keys=allowed_keys,
            denied_prefixes=denied_prefixes,
            max_keys=max_keys,
            max_total_bytes=max_total_bytes,
        )

    @staticmethod
    def _merge_limits(
        server: ResourceLimits,
        patch: ResourceLimitsPatch | None,
    ) -> ResourceLimits:
        if patch is None:
            return server.model_copy(deep=True)

        return ResourceLimits(
            cpu_shares=min(server.cpu_shares, patch.cpu_shares or server.cpu_shares),
            memory_mb=min(server.memory_mb, patch.memory_mb or server.memory_mb),
            timeout_seconds=min(
                server.timeout_seconds,
                patch.timeout_seconds or server.timeout_seconds,
            ),
            output_bytes=min(server.output_bytes, patch.output_bytes or server.output_bytes),
            pids=min(server.pids, patch.pids or server.pids),
        )

    @staticmethod
    def _merge_degraded_mode(server: DegradedModePolicy, caller: PolicyPatch) -> DegradedModePolicy:
        if "degraded_mode" not in caller.model_fields_set:
            return server
        requested = DegradedModePolicy(str(caller.degraded_mode))
        if server == DegradedModePolicy.FAIL_CLOSED:
            return DegradedModePolicy.FAIL_CLOSED
        if requested == DegradedModePolicy.FAIL_CLOSED:
            return DegradedModePolicy.FAIL_CLOSED
        return DegradedModePolicy.FAIL_OPEN

    @staticmethod
    def _merge_security_critical(server: bool, caller: PolicyPatch) -> bool:
        if "security_critical" not in caller.model_fields_set:
            return server
        return bool(server or bool(caller.security_critical))

    @staticmethod
    def is_at_least_as_restrictive(
        candidate: ToolExecutionPolicy,
        floor: ToolExecutionPolicy,
    ) -> bool:
        if _SANDBOX_RANK[candidate.sandbox_type.value] < _SANDBOX_RANK[floor.sandbox_type.value]:
            return False
        if floor.network.allow_network is False and candidate.network.allow_network is True:
            return False
        floor_domains = {item.strip().lower() for item in floor.network.allowed_domains}
        candidate_domains = {item.strip().lower() for item in candidate.network.allowed_domains}
        if "*" not in floor_domains:
            if "*" in candidate_domains:
                return False
            if not candidate_domains.issubset(floor_domains):
                return False
        if candidate.limits.timeout_seconds > floor.limits.timeout_seconds:
            return False
        if candidate.limits.memory_mb > floor.limits.memory_mb:
            return False
        if candidate.limits.output_bytes > floor.limits.output_bytes:
            return False
        if (
            candidate.degraded_mode == DegradedModePolicy.FAIL_OPEN
            and floor.degraded_mode == DegradedModePolicy.FAIL_CLOSED
        ):
            return False
        return not (candidate.security_critical is False and floor.security_critical is True)


def _intersect_mounts(server: list[MountRule], caller: list[MountRule]) -> list[MountRule]:
    if not caller:
        return []
    if not server:
        return []
    intersected: list[MountRule] = []
    for requested in caller:
        for floor in server:
            if _mount_overlaps(requested.path, floor.path):
                mode = "ro" if "ro" in {requested.mode, floor.mode} else "rw"
                intersected.append(MountRule(path=requested.path, mode=mode))
                break
    return intersected


def _mount_overlaps(a: str, b: str) -> bool:
    a_base = a.replace("/**", "")
    b_base = b.replace("/**", "")
    return a_base.startswith(b_base) or b_base.startswith(a_base)


def normalize_patch(params: dict[str, Any]) -> PolicyPatch:
    """Normalize caller params into tri-state patch model."""

    payload: dict[str, Any] = {}
    for key in (
        "sandbox_type",
        "network",
        "filesystem",
        "environment",
        "limits",
        "degraded_mode",
        "security_critical",
    ):
        if key in params:
            payload[key] = params[key]
    return PolicyPatch.model_validate(payload)


@dataclass(slots=True)
class MergeComputation:
    floor: ToolExecutionPolicy
    merged: ToolExecutionPolicy
    patch: PolicyPatch
