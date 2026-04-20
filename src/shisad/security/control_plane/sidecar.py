"""Control-plane sidecar process boundary for H1."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import signal
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, TypeVar, cast, runtime_checkable

from pydantic import BaseModel, Field, ValidationError

from shisad.core.api.transport import (
    ControlClient,
    ControlServer,
    JsonRpcCallError,
    PeerCredentials,
)
from shisad.core.config import ModelConfig
from shisad.core.errors import ShisadError
from shisad.core.log import setup_logging
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.providers.monitor_adapter import MonitorProviderAdapter
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.core.providers.routing import ModelRouter
from shisad.core.request_context import RequestContext
from shisad.core.types import Capability
from shisad.security.control_plane.consensus import ConsensusPolicy
from shisad.security.control_plane.engine import ControlPlaneEngine, ControlPlaneEvaluation
from shisad.security.control_plane.schema import ControlPlaneAction, Origin, RiskTier
from shisad.security.control_plane.sequence import SequenceFinding
from shisad.security.policy import PolicyLoader

logger = logging.getLogger(__name__)

_SIDECAR_PING_TIMEOUT_SECONDS = 0.5
_SIDECAR_CALL_TIMEOUT_SECONDS = 3.0
_SIDECAR_STARTUP_TIMEOUT_SECONDS = 15.0
_SIDECAR_TERMINATION_TIMEOUT_SECONDS = 5.0


_ResultModelT = TypeVar("_ResultModelT", bound=BaseModel)


class ControlPlaneUnavailableError(ShisadError):
    """Fail-closed error for sidecar unavailability."""

    default_reason_code = "control_plane.unavailable"
    default_message = "Control-plane sidecar unavailable; retry or restart the daemon."
    rpc_code = -32603
    expose_message = True


class ControlPlaneRpcError(ShisadError):
    """Semantic sidecar RPC error that should not be collapsed into transport loss."""

    default_reason_code = "control_plane.rpc_error"
    default_message = "Control-plane sidecar rejected the request."
    expose_message = False


@runtime_checkable
class ControlPlaneGateway(Protocol):
    """Async control-plane gateway consumed by daemon handlers."""

    async def ping(self) -> bool: ...

    async def begin_precontent_plan(
        self,
        *,
        session_id: str,
        goal: str,
        origin: Origin,
        ttl_seconds: int,
        max_actions: int,
        capabilities: set[Capability] | None = None,
        declared_resource_roots: list[str] | None = None,
    ) -> str: ...

    async def evaluate_action(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        origin: Origin,
        risk_tier: RiskTier,
        declared_domains: list[str],
        session_tainted: bool,
        trusted_input: bool,
        operator_owned_cli_input: bool = False,
        raw_user_text: str = "",
    ) -> ControlPlaneEvaluation: ...

    async def record_execution(self, *, action: ControlPlaneAction, success: bool) -> None: ...

    async def observe_denied_action(
        self,
        *,
        action: ControlPlaneAction,
        source: str,
        reason_code: str,
    ) -> list[SequenceFinding]: ...

    async def approve_stage2(
        self,
        *,
        action: ControlPlaneAction,
        approved_by: str,
    ) -> str: ...

    async def cancel_plan(self, *, session_id: str, reason: str, actor: str) -> bool: ...

    async def active_plan_hash(self, session_id: str) -> str: ...

    async def observe_runtime_network(
        self,
        *,
        origin: Origin,
        tool_name: str,
        destination_host: str,
        destination_port: int | None,
        protocol: str,
        allowed: bool,
        reason: str,
        request_size: int,
        resolved_addresses: list[str],
    ) -> None: ...


class _EmptyParams(BaseModel):
    pass


class _PingResult(BaseModel):
    ok: bool = True


class _PlanHashResult(BaseModel):
    plan_hash: str = ""


class _CancelPlanResult(BaseModel):
    cancelled: bool = False


class _AckResult(BaseModel):
    ok: bool = True


class _BeginPrecontentPlanParams(BaseModel):
    session_id: str
    goal: str
    origin: Origin
    ttl_seconds: int
    max_actions: int
    capabilities: list[Capability] = Field(default_factory=list)
    declared_resource_roots: list[str] = Field(default_factory=list)


class _EvaluateActionParams(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    origin: Origin
    risk_tier: RiskTier
    declared_domains: list[str] = Field(default_factory=list)
    session_tainted: bool = False
    trusted_input: bool = False
    operator_owned_cli_input: bool = False
    raw_user_text: str = ""


class _EvaluateActionResult(BaseModel):
    evaluation: ControlPlaneEvaluation


class _RecordExecutionParams(BaseModel):
    action: ControlPlaneAction
    success: bool


class _ApproveStage2Params(BaseModel):
    action: ControlPlaneAction
    approved_by: str


class _ObserveDeniedActionParams(BaseModel):
    action: ControlPlaneAction
    source: str
    reason_code: str


class _ObserveDeniedActionResult(BaseModel):
    findings: list[SequenceFinding] = Field(default_factory=list)


class _CancelPlanParams(BaseModel):
    session_id: str
    reason: str
    actor: str


class _ActivePlanHashParams(BaseModel):
    session_id: str


class _ObserveRuntimeNetworkParams(BaseModel):
    origin: Origin
    tool_name: str
    destination_host: str
    destination_port: int | None = None
    protocol: str
    allowed: bool
    reason: str
    request_size: int
    resolved_addresses: list[str] = Field(default_factory=list)


def _build_sidecar_monitor_provider() -> MonitorProviderAdapter | None:
    model_config = ModelConfig()
    router = ModelRouter(model_config)
    local_fallback = LocalPlannerProvider()
    if not any(route.remote_enabled for route in router.all_routes().values()):
        return None
    provider = RoutedOpenAIProvider(
        router=router,
        fallback=local_fallback,
        allow_http_localhost=model_config.allow_http_localhost,
        block_private_ranges=model_config.block_private_ranges,
        endpoint_allowlist=model_config.endpoint_allowlist or None,
    )
    if not provider.monitor_remote_enabled():
        return None
    return MonitorProviderAdapter(provider)


def _build_control_plane_engine(
    *,
    data_dir: Path,
    policy_path: Path,
    workspace_roots: list[Path] | None = None,
) -> ControlPlaneEngine:
    policy_loader = PolicyLoader(policy_path)
    policy_loader.load()
    control_plane_policy = policy_loader.policy.control_plane
    monitor_provider = _build_sidecar_monitor_provider()
    return ControlPlaneEngine.build(
        data_dir=data_dir,
        monitor_provider=monitor_provider,
        action_monitor_provider=monitor_provider,
        monitor_timeout_seconds=max(0.05, control_plane_policy.network.timeout_ms / 1000.0),
        monitor_cache_ttl_seconds=int(control_plane_policy.network.cache_ttl_seconds),
        baseline_learning_rate=float(control_plane_policy.network.baseline_learning_rate),
        high_critical_timeout_action=control_plane_policy.network.high_critical_timeout_action,
        low_medium_timeout_action=control_plane_policy.network.low_medium_timeout_action,
        trace_ttl_seconds=int(control_plane_policy.trace.ttl_seconds),
        trace_max_actions=int(control_plane_policy.trace.max_actions),
        phantom_deny_threshold=int(control_plane_policy.sequence.phantom_deny_threshold),
        phantom_deny_window_seconds=int(control_plane_policy.sequence.phantom_deny_window_seconds),
        workspace_roots=workspace_roots,
        consensus_policy=ConsensusPolicy(
            required_approvals_low=int(control_plane_policy.consensus.required_approvals_low),
            required_approvals_medium=int(control_plane_policy.consensus.required_approvals_medium),
            required_approvals_high=int(control_plane_policy.consensus.required_approvals_high),
            required_approvals_critical=int(
                control_plane_policy.consensus.required_approvals_critical
            ),
            veto_for_high_and_critical=bool(
                control_plane_policy.consensus.veto_for_high_and_critical
            ),
            voter_timeout_seconds=float(control_plane_policy.consensus.voter_timeout_seconds),
        ),
    )


class _ControlPlaneSidecarHandlers:
    def __init__(self, *, engine: ControlPlaneEngine) -> None:
        self._engine = engine

    async def handle_ping(
        self,
        params: _EmptyParams,
        ctx: RequestContext,
    ) -> _PingResult:
        _ = (params, ctx)
        return _PingResult()

    async def handle_begin_precontent_plan(
        self,
        params: _BeginPrecontentPlanParams,
        ctx: RequestContext,
    ) -> _PlanHashResult:
        _ = ctx
        plan_hash = self._engine.begin_precontent_plan(
            session_id=params.session_id,
            goal=params.goal,
            origin=params.origin,
            ttl_seconds=params.ttl_seconds,
            max_actions=params.max_actions,
            capabilities=set(params.capabilities),
            declared_resource_roots=set(params.declared_resource_roots),
        )
        return _PlanHashResult(plan_hash=plan_hash)

    async def handle_evaluate_action(
        self,
        params: _EvaluateActionParams,
        ctx: RequestContext,
    ) -> dict[str, Any]:
        _ = ctx
        evaluation = await self._engine.evaluate_action(
            tool_name=params.tool_name,
            arguments=dict(params.arguments),
            origin=params.origin,
            risk_tier=params.risk_tier,
            declared_domains=list(params.declared_domains),
            session_tainted=bool(params.session_tainted),
            trusted_input=bool(params.trusted_input),
            operator_owned_cli_input=bool(params.operator_owned_cli_input),
            raw_user_text=params.raw_user_text,
        )
        # Return a raw dict so nested default-factory fields such as action.timestamp
        # are preserved across the RPC boundary.
        return {"evaluation": evaluation.model_dump(mode="json")}

    async def handle_record_execution(
        self,
        params: _RecordExecutionParams,
        ctx: RequestContext,
    ) -> _AckResult:
        _ = ctx
        self._engine.record_execution(action=params.action, success=params.success)
        return _AckResult()

    async def handle_observe_denied_action(
        self,
        params: _ObserveDeniedActionParams,
        ctx: RequestContext,
    ) -> _ObserveDeniedActionResult:
        _ = ctx
        return _ObserveDeniedActionResult(
            findings=self._engine.observe_denied_action(
                action=params.action,
                source=params.source,
                reason_code=params.reason_code,
            )
        )

    async def handle_approve_stage2(
        self,
        params: _ApproveStage2Params,
        ctx: RequestContext,
    ) -> _PlanHashResult:
        _ = ctx
        plan_hash = self._engine.approve_stage2(
            action=params.action,
            approved_by=params.approved_by,
        )
        return _PlanHashResult(plan_hash=plan_hash)

    async def handle_cancel_plan(
        self,
        params: _CancelPlanParams,
        ctx: RequestContext,
    ) -> _CancelPlanResult:
        _ = ctx
        cancelled = self._engine.cancel_plan(
            session_id=params.session_id,
            reason=params.reason,
            actor=params.actor,
        )
        return _CancelPlanResult(cancelled=cancelled)

    async def handle_active_plan_hash(
        self,
        params: _ActivePlanHashParams,
        ctx: RequestContext,
    ) -> _PlanHashResult:
        _ = ctx
        return _PlanHashResult(plan_hash=self._engine.active_plan_hash(params.session_id))

    async def handle_observe_runtime_network(
        self,
        params: _ObserveRuntimeNetworkParams,
        ctx: RequestContext,
    ) -> _AckResult:
        _ = ctx
        self._engine.observe_runtime_network(
            origin=params.origin,
            tool_name=params.tool_name,
            destination_host=params.destination_host,
            destination_port=params.destination_port,
            protocol=params.protocol,
            allowed=params.allowed,
            reason=params.reason,
            request_size=params.request_size,
            resolved_addresses=list(params.resolved_addresses),
        )
        return _AckResult()


class ControlPlaneSidecarClient(ControlPlaneGateway):
    """Per-call JSON-RPC client for the control-plane sidecar."""

    def __init__(
        self,
        socket_path: Path,
        *,
        timeout_seconds: float = _SIDECAR_CALL_TIMEOUT_SECONDS,
    ) -> None:
        self._socket_path = socket_path
        self._timeout_seconds = timeout_seconds

    async def ping(self) -> bool:
        result = await self._call(
            "control_plane.ping",
            {},
            _PingResult,
            timeout_seconds=_SIDECAR_PING_TIMEOUT_SECONDS,
        )
        return bool(result.ok)

    async def begin_precontent_plan(
        self,
        *,
        session_id: str,
        goal: str,
        origin: Origin,
        ttl_seconds: int,
        max_actions: int,
        capabilities: set[Capability] | None = None,
        declared_resource_roots: list[str] | None = None,
    ) -> str:
        result = await self._call(
            "control_plane.begin_precontent_plan",
            _BeginPrecontentPlanParams(
                session_id=session_id,
                goal=goal,
                origin=origin,
                ttl_seconds=ttl_seconds,
                max_actions=max_actions,
                capabilities=sorted(capabilities or set(), key=str),
                declared_resource_roots=list(declared_resource_roots or ()),
            ).model_dump(mode="json"),
            _PlanHashResult,
        )
        return result.plan_hash

    async def evaluate_action(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        origin: Origin,
        risk_tier: RiskTier,
        declared_domains: list[str],
        session_tainted: bool,
        trusted_input: bool,
        operator_owned_cli_input: bool = False,
        raw_user_text: str = "",
    ) -> ControlPlaneEvaluation:
        result = await self._call(
            "control_plane.evaluate_action",
            _EvaluateActionParams(
                tool_name=tool_name,
                arguments=dict(arguments),
                origin=origin,
                risk_tier=risk_tier,
                declared_domains=list(declared_domains),
                session_tainted=session_tainted,
                trusted_input=trusted_input,
                operator_owned_cli_input=operator_owned_cli_input,
                raw_user_text=raw_user_text,
            ).model_dump(mode="json"),
            _EvaluateActionResult,
        )
        return result.evaluation

    async def record_execution(self, *, action: ControlPlaneAction, success: bool) -> None:
        await self._call(
            "control_plane.record_execution",
            _RecordExecutionParams(action=action, success=success).model_dump(mode="json"),
            _AckResult,
        )

    async def observe_denied_action(
        self,
        *,
        action: ControlPlaneAction,
        source: str,
        reason_code: str,
    ) -> list[SequenceFinding]:
        result = await self._call(
            "control_plane.observe_denied_action",
            _ObserveDeniedActionParams(
                action=action,
                source=source,
                reason_code=reason_code,
            ).model_dump(mode="json"),
            _ObserveDeniedActionResult,
        )
        return list(result.findings)

    async def approve_stage2(
        self,
        *,
        action: ControlPlaneAction,
        approved_by: str,
    ) -> str:
        result = await self._call(
            "control_plane.approve_stage2",
            _ApproveStage2Params(action=action, approved_by=approved_by).model_dump(mode="json"),
            _PlanHashResult,
        )
        return result.plan_hash

    async def cancel_plan(self, *, session_id: str, reason: str, actor: str) -> bool:
        result = await self._call(
            "control_plane.cancel_plan",
            _CancelPlanParams(session_id=session_id, reason=reason, actor=actor).model_dump(
                mode="json"
            ),
            _CancelPlanResult,
        )
        return bool(result.cancelled)

    async def active_plan_hash(self, session_id: str) -> str:
        result = await self._call(
            "control_plane.active_plan_hash",
            _ActivePlanHashParams(session_id=session_id).model_dump(mode="json"),
            _PlanHashResult,
        )
        return result.plan_hash

    async def observe_runtime_network(
        self,
        *,
        origin: Origin,
        tool_name: str,
        destination_host: str,
        destination_port: int | None,
        protocol: str,
        allowed: bool,
        reason: str,
        request_size: int,
        resolved_addresses: list[str],
    ) -> None:
        await self._call(
            "control_plane.observe_runtime_network",
            _ObserveRuntimeNetworkParams(
                origin=origin,
                tool_name=tool_name,
                destination_host=destination_host,
                destination_port=destination_port,
                protocol=protocol,
                allowed=allowed,
                reason=reason,
                request_size=request_size,
                resolved_addresses=list(resolved_addresses),
            ).model_dump(mode="json"),
            _AckResult,
        )

    async def _call(
        self,
        method: str,
        params: dict[str, Any],
        result_model: type[_ResultModelT],
        *,
        timeout_seconds: float | None = None,
    ) -> _ResultModelT:
        client = ControlClient(self._socket_path)
        timeout = timeout_seconds or self._timeout_seconds
        try:
            await asyncio.wait_for(client.connect(), timeout=timeout)
            payload = await asyncio.wait_for(client.call(method, params), timeout=timeout)
            return result_model.model_validate(payload)
        except JsonRpcCallError as exc:
            raise ControlPlaneRpcError(
                message=exc.message,
                reason_code=exc.reason_code,
                details={
                    "method": method,
                    "rpc_code": exc.code,
                    **({"rpc_details": exc.details} if exc.details else {}),
                },
                rpc_code=exc.code,
            ) from exc
        except (
            ConnectionError,
            FileNotFoundError,
            OSError,
            TimeoutError,
            ValidationError,
        ) as exc:
            raise ControlPlaneUnavailableError(
                reason_code="control_plane.unavailable",
                details={"method": method},
            ) from exc
        finally:
            with contextlib.suppress(OSError, RuntimeError):
                await client.close()


@dataclass(slots=True)
class ControlPlaneSidecarHandle:
    socket_path: Path
    process: asyncio.subprocess.Process
    client: ControlPlaneSidecarClient
    startup_timeout_seconds: float = _SIDECAR_STARTUP_TIMEOUT_SECONDS
    termination_timeout_seconds: float = _SIDECAR_TERMINATION_TIMEOUT_SECONDS

    async def close(self) -> None:
        if self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(
                    self.process.wait(),
                    timeout=self.termination_timeout_seconds,
                )
            except TimeoutError:
                self.process.kill()
                await self.process.wait()
        if self.socket_path.exists():
            with contextlib.suppress(OSError):
                self.socket_path.unlink()


async def start_control_plane_sidecar(
    *,
    data_dir: Path,
    policy_path: Path,
    assistant_fs_roots: list[Path] | None = None,
    startup_timeout_seconds: float = _SIDECAR_STARTUP_TIMEOUT_SECONDS,
) -> ControlPlaneSidecarHandle:
    socket_path = data_dir / "control_plane" / "sidecar.sock"
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "shisad.security.control_plane.sidecar",
        "--socket-path",
        str(socket_path),
        "--data-dir",
        str(data_dir),
        "--policy-path",
        str(policy_path),
        "--parent-pid",
        str(os.getpid()),
        *[
            token
            for root in (assistant_fs_roots or [])
            for token in ("--assistant-fs-root", str(root))
        ],
    )
    handle = ControlPlaneSidecarHandle(
        socket_path=socket_path,
        process=process,
        client=ControlPlaneSidecarClient(socket_path),
        startup_timeout_seconds=float(startup_timeout_seconds),
    )
    try:
        await _wait_for_sidecar_ready(handle)
    except Exception:
        await handle.close()
        raise
    return handle


async def _wait_for_sidecar_ready(handle: ControlPlaneSidecarHandle) -> None:
    deadline = asyncio.get_running_loop().time() + handle.startup_timeout_seconds
    last_error: Exception | None = None
    while asyncio.get_running_loop().time() < deadline:
        if handle.process.returncode is not None:
            raise ControlPlaneUnavailableError(
                message=(
                    "Control-plane sidecar exited during startup; "
                    f"returncode={handle.process.returncode}"
                ),
                reason_code="control_plane.startup_failed",
                details={"returncode": handle.process.returncode},
            )
        try:
            if await handle.client.ping():
                return
        except (ControlPlaneRpcError, ControlPlaneUnavailableError) as exc:
            last_error = exc
        await asyncio.sleep(0.05)
    if last_error is not None:
        raise ControlPlaneUnavailableError(
            message="Control-plane sidecar did not become ready before timeout.",
            reason_code="control_plane.startup_timeout",
        ) from last_error
    raise ControlPlaneUnavailableError(
        message="Control-plane sidecar did not create a ready socket before timeout.",
        reason_code="control_plane.startup_timeout",
    )


async def _watch_parent(parent_pid: int, shutdown_event: asyncio.Event) -> None:
    if parent_pid <= 0:
        return
    while not shutdown_event.is_set():
        await asyncio.sleep(1.0)
        if os.getppid() != parent_pid:
            logger.warning("Control-plane sidecar exiting after parent process disappeared")
            shutdown_event.set()
            return


async def _run_sidecar(
    *,
    socket_path: Path,
    data_dir: Path,
    policy_path: Path,
    parent_pid: int,
    assistant_fs_roots: list[Path] | None = None,
) -> None:
    setup_logging(level=os.getenv("SHISAD_LOG_LEVEL", "INFO"))
    engine = _build_control_plane_engine(
        data_dir=data_dir,
        policy_path=policy_path,
        workspace_roots=assistant_fs_roots,
    )
    server = ControlServer(
        socket_path,
        peer_authorizer=lambda _method_name, peer: _is_authorized_sidecar_peer(
            peer=peer,
            expected_parent_pid=parent_pid,
        ),
    )
    handlers = _ControlPlaneSidecarHandlers(engine=engine)
    shutdown_event = asyncio.Event()

    def _request_shutdown() -> None:
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(signum, _request_shutdown)

    server.register_method(
        "control_plane.ping",
        cast(Any, handlers.handle_ping),
        params_model=_EmptyParams,
    )
    server.register_method(
        "control_plane.begin_precontent_plan",
        cast(Any, handlers.handle_begin_precontent_plan),
        params_model=_BeginPrecontentPlanParams,
    )
    server.register_method(
        "control_plane.evaluate_action",
        cast(Any, handlers.handle_evaluate_action),
        params_model=_EvaluateActionParams,
    )
    server.register_method(
        "control_plane.record_execution",
        cast(Any, handlers.handle_record_execution),
        params_model=_RecordExecutionParams,
    )
    server.register_method(
        "control_plane.observe_denied_action",
        cast(Any, handlers.handle_observe_denied_action),
        params_model=_ObserveDeniedActionParams,
    )
    server.register_method(
        "control_plane.approve_stage2",
        cast(Any, handlers.handle_approve_stage2),
        params_model=_ApproveStage2Params,
    )
    server.register_method(
        "control_plane.cancel_plan",
        cast(Any, handlers.handle_cancel_plan),
        params_model=_CancelPlanParams,
    )
    server.register_method(
        "control_plane.active_plan_hash",
        cast(Any, handlers.handle_active_plan_hash),
        params_model=_ActivePlanHashParams,
    )
    server.register_method(
        "control_plane.observe_runtime_network",
        cast(Any, handlers.handle_observe_runtime_network),
        params_model=_ObserveRuntimeNetworkParams,
    )

    await server.start()
    watcher = asyncio.create_task(_watch_parent(parent_pid, shutdown_event))
    try:
        await shutdown_event.wait()
    finally:
        watcher.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await watcher
        await server.stop()


def _is_authorized_sidecar_peer(*, peer: PeerCredentials, expected_parent_pid: int) -> bool:
    if expected_parent_pid <= 0:
        return False
    if peer.uid != os.getuid():
        return False
    return peer.pid == expected_parent_pid


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="shisad control-plane sidecar")
    parser.add_argument("--socket-path", required=True)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--policy-path", required=True)
    parser.add_argument("--parent-pid", type=int, default=0)
    parser.add_argument("--assistant-fs-root", action="append", default=[])
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        asyncio.run(
            _run_sidecar(
                socket_path=Path(args.socket_path),
                data_dir=Path(args.data_dir),
                policy_path=Path(args.policy_path),
                parent_pid=int(args.parent_pid),
                assistant_fs_roots=[Path(item) for item in args.assistant_fs_root],
            )
        )
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
