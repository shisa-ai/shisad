"""Sandbox orchestrator for tool execution."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from functools import partial
from typing import Any

from shisad.core.session import CheckpointStore, Session
from shisad.executors.connect_path import ConnectPathProxy, ConnectPathResult, NoopConnectPathProxy
from shisad.executors.mounts import FilesystemAccessDecision, MountManager
from shisad.executors.proxy import EgressProxy, ProxyDecision
from shisad.executors.sandbox.checkpoint import (
    SandboxCheckpointComponent,
    SandboxCheckpointManager,
)
from shisad.executors.sandbox.models import (
    DegradedModePolicy,
    EnvironmentPolicy,
    ResourceLimits,
    SandboxBackend,
    SandboxConfig,
    SandboxEnforcement,
    SandboxResult,
    SandboxType,
)
from shisad.executors.sandbox.network import SandboxNetworkComponent, SandboxNetworkManager
from shisad.executors.sandbox.policy import SandboxPolicyComponent, SandboxPolicyEvaluator
from shisad.executors.sandbox.process import (
    ProcessRunResult,
    SandboxProcessComponent,
    SandboxProcessRunner,
)

logger = logging.getLogger(__name__)


class SandboxOrchestrator:
    """Selects and executes sandboxed tool calls with policy enforcement."""

    def __init__(
        self,
        *,
        proxy: EgressProxy,
        connect_path_proxy: ConnectPathProxy | None = None,
        checkpoint_store: CheckpointStore | None = None,
        audit_hook: Callable[[dict[str, object]], None] | None = None,
        policy_component: SandboxPolicyComponent | None = None,
        network_component: SandboxNetworkComponent | None = None,
        process_component: SandboxProcessComponent | None = None,
        checkpoint_component: SandboxCheckpointComponent | None = None,
    ) -> None:
        self._proxy = proxy
        self._connect_path_proxy = connect_path_proxy or NoopConnectPathProxy()
        self._checkpoint_store = checkpoint_store
        self._audit_hook = audit_hook

        self._policy = policy_component or SandboxPolicyEvaluator()
        self._network = network_component or SandboxNetworkManager(proxy)
        self._process = process_component or SandboxProcessRunner(
            connect_path_proxy=self._connect_path_proxy
        )
        self._checkpoint = checkpoint_component or SandboxCheckpointManager(
            checkpoint_store=checkpoint_store,
            audit_hook=self._audit_payload,
        )

        self._bwrap = self._process.bwrap_binary
        self._nsjail = self._process.nsjail_binary
        self._backends: dict[SandboxType, SandboxBackend] = self._process.build_default_backends()

    def connect_path_status(self) -> dict[str, object]:
        net_admin_available = getattr(self._connect_path_proxy, "net_admin_available", False)
        method = "iptables" if "Iptables" in self._connect_path_proxy.__class__.__name__ else "none"
        available = bool(net_admin_available and method != "none")
        return {
            "method": method,
            "available": available,
            "engaged": False,
            "cap_net_admin_available": bool(net_admin_available),
        }

    async def execute_async(
        self,
        config: SandboxConfig,
        *,
        session: Session | None = None,
    ) -> SandboxResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, partial(self.execute, config, session=session))

    def execute(
        self,
        config: SandboxConfig,
        *,
        session: Session | None = None,
    ) -> SandboxResult:
        if not config.command:
            return self._denied(config, reason="invalid_command")
        backend_type = self._select_backend(config)
        backend = self._backends[backend_type]
        fail_closed = self._is_fail_closed(config)
        degraded_controls = self._degraded_controls(config, backend.enforcement)
        degraded_controls = self._apply_network_boundary_degraded(
            config=config,
            backend_type=backend_type,
            enforcement=backend.enforcement,
            degraded_controls=degraded_controls,
        )
        if degraded_controls and fail_closed:
            self._audit_degraded(
                config=config,
                backend_type=backend_type,
                controls=degraded_controls,
            )
            return self._denied(
                config,
                reason="degraded_enforcement",
                backend=backend_type,
                degraded_controls=degraded_controls,
            )
        env, env_error, dropped_keys = self._build_environment(config.environment, config.env)
        if env_error is not None:
            return self._denied(
                config,
                reason=env_error,
                backend=backend_type,
                degraded_controls=degraded_controls,
            )
        if dropped_keys:
            self._audit_env_sanitized(config=config, dropped_keys=dropped_keys)
        fs_decisions, fs_reason = self._validate_filesystem(config)
        if fs_reason is not None:
            return self._denied(
                config,
                reason=fs_reason,
                backend=backend_type,
                fs_decisions=fs_decisions,
                degraded_controls=degraded_controls,
            )
        return self._execute_with_network(
            config=config,
            session=session,
            backend=backend,
            backend_type=backend_type,
            env=env,
            fs_decisions=fs_decisions,
            degraded_controls=degraded_controls,
        )

    def _execute_with_network(
        self,
        *,
        config: SandboxConfig,
        session: Session | None,
        backend: SandboxBackend,
        backend_type: SandboxType,
        env: dict[str, str],
        fs_decisions: list[FilesystemAccessDecision],
        degraded_controls: list[str],
    ) -> SandboxResult:
        network_urls = list(config.network_urls)
        network_urls.extend(self._extract_network_targets(config.command))
        if not network_urls and not config.network.allow_network and self._command_attempts_network(
            config.command
        ):
            return self._denied(
                config,
                reason="network:network_disabled",
                backend=backend_type,
                fs_decisions=fs_decisions,
                degraded_controls=degraded_controls,
            )
        network_decisions, network_reason = self._network.authorize_requests(
            tool_name=config.tool_name,
            urls=network_urls,
            policy=config.network,
            request_headers=config.request_headers,
            request_body=config.request_body,
            approved_by_pep=config.approved_by_pep,
        )
        if network_reason is not None:
            return self._denied(
                config,
                reason=f"network:{network_reason}",
                backend=backend_type,
                fs_decisions=fs_decisions,
                network_decisions=network_decisions,
                degraded_controls=degraded_controls,
            )
        command, resolved_env, inject_error = self._inject_credentials(
            command=config.command,
            env=env,
            network_decisions=network_decisions,
            approved_by_pep=config.approved_by_pep,
        )
        if inject_error is not None:
            return self._denied(
                config,
                reason=f"network:{inject_error}",
                backend=backend_type,
                fs_decisions=fs_decisions,
                network_decisions=network_decisions,
                degraded_controls=degraded_controls,
            )
        revalidate_reason = self._network.revalidate_requests(
            tool_name=config.tool_name,
            urls=network_urls,
            policy=config.network,
            prior_decisions=network_decisions,
            approved_by_pep=config.approved_by_pep,
        )
        if revalidate_reason is not None:
            return self._denied(
                config,
                reason=f"network:{revalidate_reason}",
                backend=backend_type,
                fs_decisions=fs_decisions,
                network_decisions=network_decisions,
                degraded_controls=degraded_controls,
            )
        escape_reason = self._escape_signal_reason(command)
        if escape_reason is not None:
            return self._denied_escape(
                config=config,
                backend=backend_type,
                reason=escape_reason,
                fs_decisions=fs_decisions,
                network_decisions=network_decisions,
                degraded_controls=degraded_controls,
            )
        checkpoint_id = self._checkpoint.maybe_create_pre_execution_checkpoint(
            config=config,
            command=command,
            session=session,
            is_destructive=self.is_destructive,
        )
        process = self._execute_process(
            config=config,
            backend=backend,
            command=command,
            env=resolved_env,
            network_decisions=network_decisions,
        )
        return self._result_from_process(
            config=config,
            backend_type=backend_type,
            checkpoint_id=checkpoint_id,
            fs_decisions=fs_decisions,
            network_decisions=network_decisions,
            degraded_controls=degraded_controls,
            process=process,
        )

    def _execute_process(
        self,
        *,
        config: SandboxConfig,
        backend: SandboxBackend,
        command: list[str],
        env: dict[str, str],
        network_decisions: list[ProxyDecision],
    ) -> ProcessRunResult:
        connect_path_allowed_ips = sorted(
            {
                address.strip()
                for decision in network_decisions
                for address in decision.resolved_addresses
                if address.strip()
            }
        )
        instance = backend.create(config)
        try:
            return self._run_process(
                config,
                backend=backend,
                command=command,
                env=env,
                connect_path_allowed_ips=connect_path_allowed_ips,
                enforce_connect_path=config.network.allow_network,
            )
        finally:
            backend.destroy(instance)

    def _result_from_process(
        self,
        *,
        config: SandboxConfig,
        backend_type: SandboxType,
        checkpoint_id: str,
        fs_decisions: list[FilesystemAccessDecision],
        network_decisions: list[ProxyDecision],
        degraded_controls: list[str],
        process: ProcessRunResult,
    ) -> SandboxResult:
        connect_path_result = process.connect_path_result
        if process.connect_path_degraded:
            degraded_controls = sorted({*degraded_controls, "connect_path"})
            self._audit_connect_path_degraded(
                config=config,
                connect_path_result=connect_path_result,
            )
        if process.resource_limit_warning:
            degraded_controls = sorted({*degraded_controls, "resource_limits"})
            self._audit_resource_limit_degraded(
                config=config,
                warning=process.resource_limit_warning,
            )
        if process.isolation_degraded:
            degraded_controls = sorted({*degraded_controls, "runtime_isolation"})
            self._audit_runtime_degraded(config=config, backend_type=backend_type)
        if process.blocked_reason:
            return self._denied(
                config,
                reason=process.blocked_reason,
                backend=backend_type,
                checkpoint_id=checkpoint_id,
                fs_decisions=fs_decisions,
                network_decisions=network_decisions,
                degraded_controls=degraded_controls,
                connect_path=connect_path_result,
            )
        return SandboxResult(
            allowed=True,
            exit_code=process.exit_code,
            stdout=process.stdout,
            stderr=process.stderr,
            timed_out=process.timed_out,
            truncated=process.truncated,
            reason="allowed",
            backend=backend_type,
            checkpoint_id=checkpoint_id,
            fs_decisions=fs_decisions,
            network_decisions=network_decisions,
            degraded_controls=degraded_controls,
            connect_path=connect_path_result,
            origin=dict(config.origin),
        )

    def _validate_filesystem(
        self,
        config: SandboxConfig,
    ) -> tuple[list[FilesystemAccessDecision], str | None]:
        mount_manager = MountManager(config.filesystem)
        decisions: list[FilesystemAccessDecision] = []
        for path in config.read_paths:
            decision = mount_manager.check_access(path, write=False)
            decisions.append(decision)
            if not decision.allowed:
                self._audit_fs_deny(config=config, path=path, reason=decision.reason)
                return decisions, f"filesystem:{decision.reason}"
        for path in config.write_paths:
            decision = mount_manager.check_access(path, write=True)
            decisions.append(decision)
            if not decision.allowed:
                self._audit_fs_deny(config=config, path=path, reason=decision.reason)
                return decisions, f"filesystem:{decision.reason}"
        return decisions, None

    def _apply_network_boundary_degraded(
        self,
        *,
        config: SandboxConfig,
        backend_type: SandboxType,
        enforcement: SandboxEnforcement,
        degraded_controls: list[str],
    ) -> list[str]:
        if config.network.allow_network and not enforcement.network:
            updated = sorted({*degraded_controls, "network_boundary"})
            self._audit(
                "sandbox.network_boundary_degraded",
                {
                    "tool_name": config.tool_name,
                    "backend": backend_type.value,
                    "session_id": config.session_id,
                },
            )
            return updated
        return degraded_controls

    def _is_fail_closed(self, config: SandboxConfig) -> bool:
        return config.degraded_mode == DegradedModePolicy.FAIL_CLOSED or config.security_critical

    def _denied(
        self,
        config: SandboxConfig,
        *,
        reason: str,
        backend: SandboxType | None = None,
        checkpoint_id: str = "",
        fs_decisions: list[FilesystemAccessDecision] | None = None,
        network_decisions: list[ProxyDecision] | None = None,
        degraded_controls: list[str] | None = None,
        connect_path: ConnectPathResult | None = None,
        escape_detected: bool = False,
    ) -> SandboxResult:
        return SandboxResult(
            allowed=False,
            reason=reason,
            backend=backend,
            checkpoint_id=checkpoint_id,
            escape_detected=escape_detected,
            fs_decisions=fs_decisions or [],
            network_decisions=network_decisions or [],
            degraded_controls=degraded_controls or [],
            connect_path=connect_path,
            origin=dict(config.origin),
        )

    def _denied_escape(
        self,
        *,
        config: SandboxConfig,
        backend: SandboxType,
        reason: str,
        fs_decisions: list[FilesystemAccessDecision],
        network_decisions: list[ProxyDecision],
        degraded_controls: list[str],
    ) -> SandboxResult:
        self._audit(
            "sandbox.escape_detected",
            {
                "tool_name": config.tool_name,
                "reason": reason,
                "session_id": config.session_id,
            },
        )
        return self._denied(
            config,
            reason=reason,
            backend=backend,
            escape_detected=True,
            fs_decisions=fs_decisions,
            network_decisions=network_decisions,
            degraded_controls=degraded_controls,
        )

    def _audit_degraded(
        self,
        *,
        config: SandboxConfig,
        backend_type: SandboxType,
        controls: list[str],
    ) -> None:
        self._audit(
            "sandbox.degraded",
            {
                "tool_name": config.tool_name,
                "backend": backend_type.value,
                "controls": controls,
            },
        )

    def _audit_env_sanitized(self, *, config: SandboxConfig, dropped_keys: list[str]) -> None:
        self._audit(
            "sandbox.env_sanitized",
            {
                "tool_name": config.tool_name,
                "dropped_keys": dropped_keys,
                "session_id": config.session_id,
            },
        )

    def _audit_fs_deny(self, *, config: SandboxConfig, path: str, reason: str) -> None:
        self._audit(
            "sandbox.fs_deny",
            {
                "tool_name": config.tool_name,
                "path": path,
                "reason": reason,
            },
        )

    def _audit_connect_path_degraded(
        self,
        *,
        config: SandboxConfig,
        connect_path_result: ConnectPathResult | None,
    ) -> None:
        self._audit(
            "sandbox.connect_path_degraded",
            {
                "tool_name": config.tool_name,
                "reason": (
                    connect_path_result.reason
                    if connect_path_result is not None
                    else "connect_path_unavailable"
                ),
                "method": connect_path_result.method if connect_path_result is not None else "none",
                "session_id": config.session_id,
            },
        )

    def _audit_resource_limit_degraded(self, *, config: SandboxConfig, warning: str) -> None:
        self._audit(
            "sandbox.resource_limit_degraded",
            {
                "tool_name": config.tool_name,
                "warning": warning,
                "session_id": config.session_id,
            },
        )

    def _audit_runtime_degraded(self, *, config: SandboxConfig, backend_type: SandboxType) -> None:
        self._audit(
            "sandbox.runtime_degraded",
            {
                "tool_name": config.tool_name,
                "backend": backend_type.value,
                "session_id": config.session_id,
            },
        )

    def _audit(self, action: str, payload: dict[str, object]) -> None:
        if self._audit_hook is None:
            return
        self._audit_hook({"action": action, **payload})

    def _audit_payload(self, payload: dict[str, object]) -> None:
        action = str(payload.get("action", "sandbox.checkpoint"))
        body = dict(payload)
        body.pop("action", None)
        self._audit(action, body)

    def _select_backend(self, config: SandboxConfig) -> SandboxType:
        return self._policy.select_backend(config)

    def _degraded_controls(
        self,
        config: SandboxConfig,
        enforcement: SandboxEnforcement,
    ) -> list[str]:
        return self._policy.degraded_controls(config, enforcement)

    def _build_environment(
        self,
        policy: EnvironmentPolicy,
        requested: dict[str, str],
    ) -> tuple[dict[str, str], str | None, list[str]]:
        return self._policy.build_environment(policy, requested)

    @staticmethod
    def is_destructive(command: list[str]) -> bool:
        return SandboxPolicyEvaluator().is_destructive(command)

    def _escape_signal_reason(self, command: list[str]) -> str | None:
        return self._policy.escape_signal_reason(command)

    def _extract_network_targets(self, command: list[str]) -> list[str]:
        return self._network.extract_network_targets(command)

    def _command_attempts_network(self, command: list[str]) -> bool:
        return self._network.command_attempts_network(command)

    def _inject_credentials(
        self,
        *,
        command: list[str],
        env: dict[str, str],
        network_decisions: list[ProxyDecision],
        approved_by_pep: bool,
    ) -> tuple[list[str], dict[str, str], str | None]:
        return self._network.inject_credentials(
            command=command,
            env=env,
            network_decisions=network_decisions,
            approved_by_pep=approved_by_pep,
        )

    def _run_process(
        self,
        config: SandboxConfig,
        *,
        backend: SandboxBackend,
        command: list[str],
        env: dict[str, str],
        connect_path_allowed_ips: list[str],
        enforce_connect_path: bool,
    ) -> ProcessRunResult:
        return self._process.run_process(
            config,
            backend=backend,
            command=command,
            env=env,
            connect_path_allowed_ips=connect_path_allowed_ips,
            enforce_connect_path=enforce_connect_path,
        )

    def _wrap_isolated_command(
        self,
        *,
        backend: SandboxBackend,
        config: SandboxConfig,
        command: list[str],
    ) -> list[str]:
        return self._process.wrap_isolated_command(
            backend=backend,
            config=config,
            command=command,
        )

    def _build_bwrap_command(self, *, config: SandboxConfig, command: list[str]) -> list[str]:
        process_runner = self._process
        if isinstance(process_runner, SandboxProcessRunner):
            return process_runner.build_bwrap_command(config=config, command=command)
        return list(command)

    def _build_nsjail_command(self, *, config: SandboxConfig, command: list[str]) -> list[str]:
        process_runner = self._process
        if isinstance(process_runner, SandboxProcessRunner):
            return process_runner.build_nsjail_command(config=config, command=command)
        return list(command)

    @staticmethod
    def _preexec_limits(limits: ResourceLimits) -> Any:
        return SandboxProcessRunner.preexec_limits(limits)

    @staticmethod
    def _invoke(
        command: list[str],
        *,
        env: dict[str, str],
        cwd: str | None,
        timeout_seconds: int,
        preexec: Any,
        on_started: Callable[[int], str | None] | None = None,
    ) -> tuple[str, str, int | None, bool, str | None]:
        return SandboxProcessRunner.invoke(
            command,
            env=env,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            preexec=preexec,
            on_started=on_started,
        )

    @staticmethod
    def _isolation_runtime_failed(*, exit_code: int | None, stderr: str) -> bool:
        return SandboxProcessRunner.isolation_runtime_failed(exit_code=exit_code, stderr=stderr)

    @staticmethod
    def _to_text(value: bytes | str | None) -> str:
        return SandboxProcessRunner.to_text(value)

    @staticmethod
    def _detect_usable_bwrap() -> str:
        return SandboxProcessRunner._detect_usable_bwrap()

    def _capture_filesystem_snapshot(self, paths: list[str]) -> list[dict[str, Any]]:
        return self._checkpoint.capture_filesystem_snapshot(paths)
