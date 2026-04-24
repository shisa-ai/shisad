"""Daemon service construction and lifecycle helpers."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlparse

from shisad.assistant.msgvault import MsgvaultToolkit
from shisad.channels.base import Channel
from shisad.channels.delivery import ChannelDeliveryService
from shisad.channels.identity import ChannelIdentityMap
from shisad.channels.ingress import ChannelIngressProcessor
from shisad.channels.state import ChannelStateStore
from shisad.coding.manager import CodingAgentManager
from shisad.core.api.transport import ControlServer
from shisad.core.audit import AuditLog
from shisad.core.config import (
    DaemonConfig,
    ModelConfig,
    effective_approval_factor_store_path,
)
from shisad.core.events import EventBus
from shisad.core.evidence import ArtifactBlobCodec, ArtifactLedger, KmsArtifactBlobCodec
from shisad.core.host_matching import host_matches
from shisad.core.planner import Planner
from shisad.core.providers.base import validate_endpoint
from shisad.core.providers.capabilities import AuthMode
from shisad.core.providers.embeddings_adapter import SyncEmbeddingsAdapter
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.providers.monitor_adapter import MonitorProviderAdapter
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.core.providers.routing import ModelComponent, ModelRouter, provider_preset_label
from shisad.core.session import CheckpointStore, Session, SessionManager
from shisad.core.soul import load_effective_persona_text
from shisad.core.tools.builtin.alarm import AlarmTool
from shisad.core.tools.builtin.shell_exec import ShellExecTool
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.trace import TraceRecorder
from shisad.core.transcript import TranscriptStore
from shisad.core.types import Capability, CredentialRef, SessionId, TaintLabel, ToolName
from shisad.daemon.approval_web import ApprovalWebService
from shisad.daemon.event_wiring import DaemonEventWiring
from shisad.executors.connect_path import IptablesConnectPathProxy
from shisad.executors.proxy import EgressProxy
from shisad.executors.sandbox import SandboxOrchestrator
from shisad.interop.a2a_ingress import A2aRuntime
from shisad.interop.a2a_ratelimit import A2aRateLimiter
from shisad.interop.a2a_registry import A2aRegistry, load_local_identity
from shisad.interop.mcp_client import McpClientManager
from shisad.memory.ingestion import EmbeddingFingerprint, IngestionPipeline, RetrieveRagTool
from shisad.memory.ingress import IngressContextRegistry
from shisad.memory.manager import MemoryManager
from shisad.scheduler.manager import SchedulerManager
from shisad.security.control_plane.sidecar import (
    ControlPlaneGateway,
    ControlPlaneSidecarHandle,
    start_control_plane_sidecar,
)
from shisad.security.credentials import CredentialConfig, InMemoryCredentialStore
from shisad.security.firewall import ContentFirewall
from shisad.security.firewall.classifier import (
    PromptGuardSettings,
    PromptGuardThresholds,
    build_promptguard_classifier,
)
from shisad.security.firewall.output import OutputFirewall
from shisad.security.lockdown import LockdownManager
from shisad.security.monitor import ActionMonitor
from shisad.security.pep import PEP
from shisad.security.policy import PolicyLoader
from shisad.security.ratelimit import RateLimitConfig, RateLimiter
from shisad.security.risk import RiskCalibrator, RiskPolicyVersion
from shisad.selfmod import SelfModificationManager
from shisad.skills.manager import SkillManager

if TYPE_CHECKING:
    from shisad.assistant.realitycheck import RealityCheckToolkit
    from shisad.channels.discord import DiscordChannel
    from shisad.channels.matrix import MatrixChannel
    from shisad.channels.slack import SlackChannel
    from shisad.channels.telegram import TelegramChannel
    from shisad.executors.browser import BrowserSandbox

logger = logging.getLogger(__name__)


def _wipe_dir_contents(directory: Path) -> None:
    """Remove all files and subdirectories inside *directory* without removing it."""
    import shutil

    if not directory.is_dir():
        return
    for child in directory.iterdir():
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def _count_files(directory: Path) -> int:
    """Count files inside *directory* (non-recursive)."""
    if not directory.is_dir():
        return 0
    return sum(1 for child in directory.iterdir() if child.is_file())


def _count_files_recursive(directory: Path) -> int:
    """Count files inside *directory* recursively."""
    if not directory.is_dir():
        return 0
    return sum(1 for child in directory.rglob("*") if child.is_file())


def _unlink_if_exists(path: Path) -> bool:
    """Remove a file if present and report whether it was removed."""
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True


_CHANNEL_TRUST_DEFAULTS: dict[str, str] = {
    "cli": "trusted",
    "matrix": "untrusted",
    "discord": "untrusted",
    "telegram": "untrusted",
    "slack": "untrusted",
}


def _normalize_tool_destination(destination: str) -> str:
    raw = destination.strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    # Accept host-only metadata for backward compatibility.
    if not parsed.hostname and not parsed.scheme:
        fallback = urlparse(f"https://{raw}")
        return (fallback.hostname or "").lower()
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    protocol = (parsed.scheme or "").lower()
    try:
        port = parsed.port
    except ValueError:
        return ""
    if port is None and protocol in {"http", "https"}:
        port = 80 if protocol == "http" else 443
    if protocol and port is not None:
        return f"{protocol}://{host}:{port}"
    return host


def _warn_on_evidence_kms_endpoint_config(config: DaemonConfig) -> None:
    endpoint = config.evidence_kms_url.strip()
    if not endpoint:
        return
    errors = validate_endpoint(
        endpoint,
        allow_http_localhost=True,
        block_private_ranges=False,
    )
    if errors:
        logger.warning(
            "Evidence artifact-KMS endpoint '%s' may be misconfigured: %s",
            endpoint,
            "; ".join(errors),
        )

    parsed = urlparse(endpoint)
    hostname = (parsed.hostname or "").strip().lower()
    if (
        parsed.scheme == "http"
        and hostname
        and hostname not in {"localhost", "127.0.0.1", "::1"}
        and config.evidence_kms_bearer_token.strip()
    ):
        logger.warning(
            (
                "Evidence artifact-KMS bearer token is configured for non-loopback "
                "HTTP endpoint '%s'; use HTTPS to avoid sending the token without "
                "TLS protection."
            ),
            endpoint,
        )


def _warn_on_provider_route_gaps(router: ModelRouter) -> None:
    embeddings_route = router.route_for(ModelComponent.EMBEDDINGS)
    if not embeddings_route.remote_enabled:
        logger.warning(
            "Embeddings route not configured; vector recall is off. "
            "Recall will use deterministic local lexical fallback until an "
            "embeddings route is configured."
        )


def _promptguard_degraded_hint(reason: str) -> str:
    if reason == "promptguard_runtime_missing":
        return "install shisad[promptguard] to enable model-backed PromptGuard"
    if reason == "promptguard_onnx_model_missing":
        return "configure a PromptGuard model path or leave best_effort posture explicitly"
    return "check PromptGuard configuration or set posture=best_effort intentionally"


class _LazyBrowserSandbox:
    def __init__(
        self,
        *,
        output_firewall: OutputFirewall,
        screenshots_dir: Path,
    ) -> None:
        self._output_firewall = output_firewall
        self._screenshots_dir = screenshots_dir
        self._impl: Any | None = None

    def _load(self) -> Any:
        if self._impl is None:
            from shisad.executors.browser import BrowserSandbox, BrowserSandboxPolicy

            self._impl = BrowserSandbox(
                output_firewall=self._output_firewall,
                screenshots_dir=self._screenshots_dir,
                policy=BrowserSandboxPolicy(clipboard="enabled"),
            )
        return self._impl

    @property
    def policy(self) -> Any:
        return self._load().policy

    def paste(self, text: str, *, taint_labels: set[TaintLabel] | None = None) -> Any:
        return self._load().paste(text, taint_labels=taint_labels)

    def store_screenshot(self, **kwargs: Any) -> Any:
        return self._load().store_screenshot(**kwargs)


def _build_browser_sandbox(
    *,
    config: DaemonConfig,
    output_firewall: OutputFirewall,
) -> Any:
    screenshots_dir = config.data_dir / "screenshots"
    if config.browser_enabled:
        from shisad.executors.browser import BrowserSandbox, BrowserSandboxPolicy

        return BrowserSandbox(
            output_firewall=output_firewall,
            screenshots_dir=screenshots_dir,
            policy=BrowserSandboxPolicy(clipboard="enabled"),
        )
    return _LazyBrowserSandbox(
        output_firewall=output_firewall,
        screenshots_dir=screenshots_dir,
    )


def _realitycheck_disabled_status(
    *,
    config: DaemonConfig,
    allowed_domains: list[str],
) -> dict[str, Any]:
    resolved_repo: Path | None = None
    try:
        resolved_repo = config.realitycheck_repo_root.expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        resolved_repo = None

    configured_roots: list[Path] = []
    for item in config.realitycheck_data_roots:
        if not str(item).strip():
            continue
        try:
            configured_roots.append(item.expanduser().resolve(strict=False))
        except (OSError, RuntimeError, ValueError):
            continue

    existing_roots: list[Path] = []
    for item in configured_roots:
        try:
            if item.exists() and item.is_dir():
                existing_roots.append(item)
        except (OSError, ValueError):
            continue

    endpoint = config.realitycheck_endpoint_url.strip()
    parsed_endpoint = urlparse(endpoint) if endpoint else None
    endpoint_host = (parsed_endpoint.hostname or "").lower() if parsed_endpoint else ""
    endpoint_allowlisted = (not config.realitycheck_endpoint_enabled) or (
        bool(endpoint_host) and any(host_matches(endpoint_host, rule) for rule in allowed_domains)
    )
    return {
        "status": "disabled",
        "enabled": False,
        "surface_enabled": False,
        "repo_root": str(resolved_repo) if resolved_repo is not None else "",
        "repo_exists": bool(
            resolved_repo is not None and resolved_repo.exists() and resolved_repo.is_dir()
        ),
        "data_roots": [str(item) for item in configured_roots],
        "data_roots_existing": [str(item) for item in existing_roots],
        "endpoint_enabled": config.realitycheck_endpoint_enabled,
        "endpoint_url": endpoint,
        "endpoint_host": endpoint_host,
        "endpoint_allowlisted": endpoint_allowlisted,
        "problems": [],
    }


class _LazyRealityCheckToolkit:
    def __init__(
        self,
        *,
        config: DaemonConfig,
        allowed_domains: list[str],
    ) -> None:
        self._config = config
        self._allowed_domains = list(allowed_domains)
        self._impl: Any | None = None
        self._disabled_status: dict[str, Any] | None = None

    def _load(self) -> Any:
        if self._impl is None:
            from shisad.assistant.realitycheck import RealityCheckToolkit

            self._impl = RealityCheckToolkit(
                enabled=self._config.realitycheck_enabled,
                repo_root=self._config.realitycheck_repo_root,
                data_roots=list(self._config.realitycheck_data_roots),
                endpoint_enabled=self._config.realitycheck_endpoint_enabled,
                endpoint_url=self._config.realitycheck_endpoint_url,
                allowed_domains=self._allowed_domains,
                timeout_seconds=self._config.realitycheck_timeout_seconds,
                max_read_bytes=self._config.realitycheck_max_read_bytes,
                max_search_files=self._config.realitycheck_search_max_files,
            )
        return self._impl

    def doctor_status(self) -> dict[str, Any]:
        if not self._config.realitycheck_enabled:
            if self._disabled_status is None:
                self._disabled_status = _realitycheck_disabled_status(
                    config=self._config,
                    allowed_domains=self._allowed_domains,
                )
            return dict(self._disabled_status)
        return dict(self._load().doctor_status())

    def search(self, **kwargs: Any) -> dict[str, Any]:
        return dict(self._load().search(**kwargs))

    def read_source(self, **kwargs: Any) -> dict[str, Any]:
        return dict(self._load().read_source(**kwargs))


def _build_realitycheck_toolkit(
    *,
    config: DaemonConfig,
    allowed_domains: list[str],
) -> Any:
    if config.realitycheck_enabled:
        from shisad.assistant.realitycheck import RealityCheckToolkit

        return RealityCheckToolkit(
            enabled=config.realitycheck_enabled,
            repo_root=config.realitycheck_repo_root,
            data_roots=list(config.realitycheck_data_roots),
            endpoint_enabled=config.realitycheck_endpoint_enabled,
            endpoint_url=config.realitycheck_endpoint_url,
            allowed_domains=allowed_domains,
            timeout_seconds=config.realitycheck_timeout_seconds,
            max_read_bytes=config.realitycheck_max_read_bytes,
            max_search_files=config.realitycheck_search_max_files,
        )
    return _LazyRealityCheckToolkit(config=config, allowed_domains=allowed_domains)


@dataclass(slots=True)
class DaemonServices:
    """Container for initialized daemon subsystems."""

    config: DaemonConfig
    audit_log: AuditLog
    event_bus: EventBus
    policy_loader: PolicyLoader
    model_config: ModelConfig
    router: ModelRouter
    transcript_root: Path
    transcript_store: TranscriptStore
    evidence_store: ArtifactLedger
    trace_recorder: TraceRecorder | None
    checkpoint_store: CheckpointStore
    risk_calibrator: RiskCalibrator
    server: ControlServer
    event_wiring: DaemonEventWiring
    session_manager: SessionManager
    firewall: ContentFirewall
    output_firewall: OutputFirewall
    browser_sandbox: BrowserSandbox
    channel_ingress: ChannelIngressProcessor
    identity_map: ChannelIdentityMap
    channels: dict[str, Channel]
    delivery: ChannelDeliveryService
    approval_web: ApprovalWebService
    channel_state_store: ChannelStateStore
    matrix_channel: MatrixChannel | None
    discord_channel: DiscordChannel | None
    telegram_channel: TelegramChannel | None
    slack_channel: SlackChannel | None
    provider: LocalPlannerProvider | RoutedOpenAIProvider
    monitor_provider: MonitorProviderAdapter | None
    embeddings_adapter: SyncEmbeddingsAdapter
    credential_store: InMemoryCredentialStore
    egress_proxy: EgressProxy
    connect_path_proxy: IptablesConnectPathProxy
    sandbox: SandboxOrchestrator
    ingestion: IngestionPipeline
    memory_manager: MemoryManager
    scheduler: SchedulerManager
    skill_manager: SkillManager
    coding_manager: CodingAgentManager
    selfmod_manager: SelfModificationManager
    mcp_manager: McpClientManager | None
    a2a_registry: A2aRegistry | None
    a2a_runtime: A2aRuntime | None
    msgvault_toolkit: MsgvaultToolkit
    realitycheck_toolkit: RealityCheckToolkit
    realitycheck_status: dict[str, Any]
    lockdown_manager: LockdownManager
    rate_limiter: RateLimiter
    monitor: ActionMonitor
    control_plane: ControlPlaneGateway
    control_plane_sidecar: ControlPlaneSidecarHandle | None
    provenance_status: dict[str, Any]
    registry: ToolRegistry
    alarm_tool: AlarmTool
    pep: PEP
    planner: Planner
    shutdown_event: asyncio.Event
    planner_model_id: str
    model_routes: dict[str, str]
    provider_diagnostics: dict[str, Any]
    memory_ingress_registry: IngressContextRegistry
    internal_ingress_marker: object
    identity_default_trust_baseline: dict[str, str]
    identity_allowlists_baseline: dict[str, frozenset[str]]
    active_rpc_calls: int = field(default=0)
    rpc_state_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    reset_in_progress: bool = field(default=False)

    @classmethod
    async def build(cls, config: DaemonConfig) -> DaemonServices:
        """Construct all runtime services in a deterministic order."""
        audit_log = AuditLog(config.data_dir / "audit.jsonl")
        event_bus = EventBus(persister=audit_log)

        policy_loader = PolicyLoader(config.policy_path)
        policy_loader.load()
        policy_loader.register_reload_signal()

        model_config = ModelConfig()
        router = ModelRouter(model_config)
        _validate_model_endpoints(model_config, router)
        _validate_security_route_pins(model_config, router)

        transcript_root = config.data_dir / "sessions"
        transcript_store = TranscriptStore(transcript_root)
        _warn_on_evidence_kms_endpoint_config(config)
        evidence_blob_codec: ArtifactBlobCodec | None = (
            cast(
                ArtifactBlobCodec,
                KmsArtifactBlobCodec(
                    endpoint_url=config.evidence_kms_url,
                    bearer_token=config.evidence_kms_bearer_token,
                    timeout_seconds=config.evidence_kms_timeout_seconds,
                ),
            )
            if config.evidence_kms_url.strip()
            else None
        )
        evidence_store = ArtifactLedger(
            transcript_root / "evidence",
            blob_codec=evidence_blob_codec,
        )
        trace_recorder: TraceRecorder | None = None
        if config.trace_enabled:
            trace_recorder = TraceRecorder(config.data_dir / "traces")
        risk_calibrator = RiskCalibrator(
            policy_path=config.data_dir / "risk" / "policy.json",
            observations_path=config.data_dir / "risk" / "observations.jsonl",
        )
        risk_policy = risk_calibrator.load_policy()
        policy_loader.policy.risk_policy.version = risk_policy.version
        policy_loader.policy.risk_policy.auto_approve_threshold = (
            risk_policy.thresholds.auto_approve_threshold
        )
        policy_loader.policy.risk_policy.block_threshold = risk_policy.thresholds.block_threshold

        server = ControlServer(config.socket_path)
        event_wiring = DaemonEventWiring(event_bus=event_bus, server=server)
        event_bus.subscribe_all(event_wiring.forward_event_to_subscribers)
        internal_ingress_marker = object()
        approval_web = ApprovalWebService(
            origin=config.approval_origin,
            bind_host=config.approval_bind_host,
            bind_port=config.approval_bind_port,
            link_ttl_seconds=config.approval_link_ttl_seconds,
            rate_limit_window_seconds=config.approval_rate_limit_window_seconds,
            rate_limit_max_attempts=config.approval_rate_limit_max_attempts,
        )
        session_manager: SessionManager | None = None
        channels: dict[str, Channel] = {}
        matrix_channel: MatrixChannel | None = None
        discord_channel: DiscordChannel | None = None
        telegram_channel: TelegramChannel | None = None
        slack_channel: SlackChannel | None = None
        embeddings_adapter: SyncEmbeddingsAdapter | None = None
        control_plane_sidecar: ControlPlaneSidecarHandle | None = None
        mcp_manager: McpClientManager | None = None
        a2a_runtime: A2aRuntime | None = None
        startup_complete = False

        try:

            def _lockdown_snapshot_provider(session: Session) -> dict[str, Any]:
                return {"lockdown": lockdown_manager.snapshot(session.id)}

            def _restore_lockdown_snapshot(
                session: Session,
                record: dict[str, Any],
                _source: str,
            ) -> None:
                lockdown_manager.rehydrate(session.id, record.get("lockdown"))

            def _persist_lockdown_snapshot(session_id: SessionId, _state: object) -> None:
                if session_manager is None or session_manager.get(session_id) is None:
                    return
                session_manager.persist(session_id)

            lockdown_manager = LockdownManager(
                notification_hook=event_wiring.lockdown_notify,
                state_change_hook=_persist_lockdown_snapshot,
            )
            event_wiring.bind_lockdown_manager(lockdown_manager)
            session_manager = SessionManager(
                audit_hook=event_wiring.audit_session_event,
                state_dir=config.data_dir / "sessions" / "state",
                default_capabilities=set(policy_loader.policy.default_capabilities),
                supplemental_state_provider=_lockdown_snapshot_provider,
                supplemental_state_restorer=_restore_lockdown_snapshot,
            )
            checkpoint_store = CheckpointStore(
                config.data_dir / "checkpoints",
                supplemental_state_provider=_lockdown_snapshot_provider,
            )
            semantic_policy = policy_loader.policy.content_firewall.semantic_classifier
            semantic_classifier, semantic_status = build_promptguard_classifier(
                PromptGuardSettings(
                    posture=semantic_policy.posture,
                    model_path=semantic_policy.model_path,
                    allowed_signers_path=str(config.selfmod_allowed_signers_path),
                    thresholds=PromptGuardThresholds(
                        medium=semantic_policy.medium_threshold,
                        high=semantic_policy.high_threshold,
                        critical=semantic_policy.critical_threshold,
                    ),
                )
            )
            if (
                semantic_status.status == "unavailable"
                and semantic_status.reason != "model_path_unconfigured"
            ):
                logger.warning(
                    "PromptGuard degraded at startup; posture=%s reason_code=%s hint=%s",
                    semantic_status.posture,
                    semantic_status.reason,
                    _promptguard_degraded_hint(semantic_status.reason),
                )
            firewall = ContentFirewall(
                semantic_classifier=semantic_classifier,
                semantic_classifier_status=semantic_status,
            )
            try:
                firewall.validate_yara_backend()
            except RuntimeError as exc:
                raise ValueError(
                    "Content firewall requires textguard YARA mode, but the bundled "
                    "YARA backend is unavailable"
                ) from exc
            output_firewall = OutputFirewall(
                safe_domains=policy_loader.policy.safe_output_domains
                or ["api.example.com", "example.com"],
                alert_hook=event_wiring.audit_output_event,
            )
            browser_sandbox = _build_browser_sandbox(
                config=config,
                output_firewall=output_firewall,
            )
            channel_ingress = ChannelIngressProcessor(firewall)
            identity_map = ChannelIdentityMap(default_trust=_CHANNEL_TRUST_DEFAULTS)
            for channel_name, entries in config.channel_identity_allowlist.items():
                identity_map.configure_allowlist(
                    channel=channel_name,
                    external_user_ids={item for item in entries if item},
                )

            matrix_channel = await _build_matrix_channel(config)
            if matrix_channel is not None:
                channels["matrix"] = matrix_channel
                for user_id in config.matrix_trusted_users:
                    if user_id.strip():
                        identity_map.allow_identity(
                            channel="matrix",
                            external_user_id=user_id.strip(),
                        )

            discord_channel = await _build_discord_channel(config)
            if discord_channel is not None:
                channels["discord"] = discord_channel
                for user_id in config.discord_trusted_users:
                    if user_id.strip():
                        identity_map.allow_identity(
                            channel="discord",
                            external_user_id=user_id.strip(),
                        )

            telegram_channel = await _build_telegram_channel(config)
            if telegram_channel is not None:
                channels["telegram"] = telegram_channel
                for user_id in config.telegram_trusted_users:
                    if user_id.strip():
                        identity_map.allow_identity(
                            channel="telegram",
                            external_user_id=user_id.strip(),
                        )

            slack_channel = await _build_slack_channel(config)
            if slack_channel is not None:
                channels["slack"] = slack_channel
                for user_id in config.slack_trusted_users:
                    if user_id.strip():
                        identity_map.allow_identity(
                            channel="slack",
                            external_user_id=user_id.strip(),
                        )

            delivery = ChannelDeliveryService(channels)
            channel_state_store = ChannelStateStore(config.data_dir / "channels" / "state")

            local_fallback = LocalPlannerProvider()
            provider: LocalPlannerProvider | RoutedOpenAIProvider = local_fallback
            monitor_provider: MonitorProviderAdapter | None = None
            provider_diagnostics = _build_provider_diagnostics(router)
            _log_provider_route_summary(router)
            _warn_on_provider_route_gaps(router)
            if any(route.remote_enabled for route in router.all_routes().values()):
                provider = RoutedOpenAIProvider(
                    router=router,
                    fallback=local_fallback,
                    allow_http_localhost=model_config.allow_http_localhost,
                    block_private_ranges=model_config.block_private_ranges,
                    endpoint_allowlist=model_config.endpoint_allowlist or None,
                )
            if isinstance(provider, RoutedOpenAIProvider) and provider.monitor_remote_enabled():
                monitor_provider = MonitorProviderAdapter(provider)

            embeddings_route = router.route_for(ModelComponent.EMBEDDINGS)
            embeddings_adapter = SyncEmbeddingsAdapter(
                provider,
                model_id=embeddings_route.model_id,
            )
            credential_store = InMemoryCredentialStore()
            credential_store.set_approval_store_path(
                effective_approval_factor_store_path(data_dir=config.data_dir)
            )
            _register_route_credentials(credential_store=credential_store, router=router)
            egress_proxy = EgressProxy(credential_store=credential_store)
            connect_path_proxy = IptablesConnectPathProxy()
            if not connect_path_proxy.net_admin_available:
                logger.warning(
                    "[shisad] Connect-path enforcement unavailable: CAP_NET_ADMIN not granted. "
                    "Network-enabled sandbox processes have unrestricted IP-level access. "
                    "Pre-execution DNS and domain policy checks are still enforced. "
                    "Note: CAP_NET_ADMIN is necessary but not sufficient; connect-path also "
                    "requires isolated target network namespaces at execution time."
                )
            sandbox = SandboxOrchestrator(
                proxy=egress_proxy,
                connect_path_proxy=connect_path_proxy,
                checkpoint_store=checkpoint_store,
            )
            memory_storage_root = config.data_dir / "memory_entries"
            ingestion = IngestionPipeline(
                memory_storage_root,
                firewall=firewall,
                embedding_fingerprint=EmbeddingFingerprint(
                    model_id=embeddings_route.model_id,
                    base_url=embeddings_route.base_url,
                ),
                embeddings_provider=embeddings_adapter,
                legacy_storage_dir=config.data_dir / "memory",
                audit_hook=event_wiring.audit_memory_event,
            )
            memory_manager = MemoryManager(
                memory_storage_root,
                audit_hook=event_wiring.audit_memory_event,
            )
            memory_ingress_registry = IngressContextRegistry()
            scheduler = SchedulerManager(storage_dir=config.data_dir / "tasks")
            msgvault_toolkit = MsgvaultToolkit(
                enabled=config.msgvault_enabled,
                command=config.msgvault_command,
                home=config.msgvault_home,
                timeout_seconds=config.msgvault_timeout_seconds,
                max_results=config.msgvault_max_results,
                max_body_bytes=config.msgvault_max_body_bytes,
                account_allowlist=list(config.msgvault_account_allowlist),
            )
            realitycheck_domains = [
                item for item in config.realitycheck_allowed_domains if item.strip()
            ]
            if not realitycheck_domains:
                realitycheck_domains = [
                    rule.host.strip() for rule in policy_loader.policy.egress if rule.host.strip()
                ]
            realitycheck_toolkit = _build_realitycheck_toolkit(
                config=config,
                allowed_domains=realitycheck_domains,
            )
            realitycheck_status = realitycheck_toolkit.doctor_status()
            rate_limiter = RateLimiter(
                RateLimitConfig(
                    window_seconds=policy_loader.policy.rate_limits.window_seconds,
                    per_tool=policy_loader.policy.rate_limits.per_tool,
                    per_user=policy_loader.policy.rate_limits.per_user,
                    per_session=policy_loader.policy.rate_limits.per_session,
                    burst_multiplier=policy_loader.policy.rate_limits.burst_multiplier,
                    burst_window_seconds=policy_loader.policy.rate_limits.burst_window_seconds,
                ),
                anomaly_hook=event_wiring.on_ratelimit,
            )
            monitor = ActionMonitor()
            control_plane_sidecar = await start_control_plane_sidecar(
                data_dir=config.data_dir,
                policy_path=config.policy_path,
                assistant_fs_roots=list(config.assistant_fs_roots),
                startup_timeout_seconds=config.control_plane_startup_timeout_seconds,
            )
            control_plane = control_plane_sidecar.client

            provenance_status = {
                "available": False,
                "version": "",
                "source_commit": "",
                "manifest_hash": "",
                "drift": [],
                "reason": "local_security_assets_removed_textguard_bundled_rules",
            }

            search_backend_destination = _normalize_tool_destination(config.web_search_backend_url)
            browser_destinations = [
                item.strip() for item in config.browser_allowed_domains if item.strip()
            ]
            if not browser_destinations:
                browser_destinations = [
                    item.strip() for item in config.web_allowed_domains if item.strip()
                ]
            registry, alarm_tool = _build_tool_registry(
                event_bus,
                web_search_destination=search_backend_destination,
                browser_surface_enabled=bool(config.browser_enabled),
                browser_destinations=browser_destinations,
                realitycheck_surface_enabled=bool(
                    realitycheck_status.get("surface_enabled", False)
                ),
                realitycheck_endpoint_enabled=bool(
                    realitycheck_status.get("endpoint_enabled", False)
                ),
                realitycheck_endpoint_host=str(
                    realitycheck_status.get("endpoint_host", "")
                ).strip(),
            )
            if config.mcp_servers:
                mcp_manager = McpClientManager(
                    server_configs=list(config.mcp_servers),
                    tool_registry=registry,
                )
                await mcp_manager.connect_all()
            pep = PEP(
                policy_loader.policy,
                registry,
                evidence_store=evidence_store,
                credential_store=credential_store,
                credential_audit_hook=event_wiring.audit_credential_use,
                mcp_trusted_servers=set(config.mcp_trusted_servers),
            )
            planner_route = router.route_for(ModelComponent.PLANNER)
            effective_persona_text = load_effective_persona_text(config)
            planner = Planner(
                provider,
                pep,
                persona_tone=config.assistant_persona_tone,
                custom_persona_text=effective_persona_text,
                capabilities=planner_route.capabilities,
                tool_registry=registry,
                schema_strict_mode=bool(model_config.planner_schema_strict_mode),
            )
            skill_manager = SkillManager(
                storage_dir=config.data_dir / "skills",
                policy=policy_loader.policy.skills,
                tool_registry=registry,
            )
            await _flush_skill_registration_events(event_bus=event_bus, skill_manager=skill_manager)
            coding_manager = CodingAgentManager(
                repo_root=config.coding_repo_root,
                data_dir=config.data_dir,
                registry_overrides=config.coding_agent_registry_overrides,
            )
            selfmod_manager = SelfModificationManager(
                root=config.data_dir / "selfmod",
                allowed_signers_path=config.selfmod_allowed_signers_path,
                skill_manager=skill_manager,
                planner=planner,
                default_persona_tone=config.assistant_persona_tone,
                default_persona_text=effective_persona_text,
            )
            shutdown_event = asyncio.Event()
            planner_model_id = planner_route.model_id
            model_routes = {
                component.value: router.route_for(component).base_url
                for component in ModelComponent
            }
            identity_default_trust_baseline = dict(identity_map._default_trust)
            identity_allowlists_baseline = {
                channel: frozenset(values) for channel, values in identity_map._allowlists.items()
            }
            services = cls(
                config=config,
                audit_log=audit_log,
                event_bus=event_bus,
                policy_loader=policy_loader,
                model_config=model_config,
                router=router,
                transcript_root=transcript_root,
                transcript_store=transcript_store,
                evidence_store=evidence_store,
                trace_recorder=trace_recorder,
                checkpoint_store=checkpoint_store,
                risk_calibrator=risk_calibrator,
                server=server,
                event_wiring=event_wiring,
                session_manager=session_manager,
                firewall=firewall,
                output_firewall=output_firewall,
                browser_sandbox=browser_sandbox,
                channel_ingress=channel_ingress,
                identity_map=identity_map,
                channels=channels,
                delivery=delivery,
                approval_web=approval_web,
                channel_state_store=channel_state_store,
                matrix_channel=matrix_channel,
                discord_channel=discord_channel,
                telegram_channel=telegram_channel,
                slack_channel=slack_channel,
                provider=provider,
                monitor_provider=monitor_provider,
                embeddings_adapter=embeddings_adapter,
                credential_store=credential_store,
                egress_proxy=egress_proxy,
                connect_path_proxy=connect_path_proxy,
                sandbox=sandbox,
                ingestion=ingestion,
                memory_manager=memory_manager,
                scheduler=scheduler,
                skill_manager=skill_manager,
                coding_manager=coding_manager,
                selfmod_manager=selfmod_manager,
                mcp_manager=mcp_manager,
                a2a_registry=None,
                a2a_runtime=None,
                msgvault_toolkit=msgvault_toolkit,
                realitycheck_toolkit=realitycheck_toolkit,
                realitycheck_status=realitycheck_status,
                lockdown_manager=lockdown_manager,
                rate_limiter=rate_limiter,
                monitor=monitor,
                control_plane=control_plane,
                control_plane_sidecar=control_plane_sidecar,
                provenance_status=provenance_status,
                registry=registry,
                alarm_tool=alarm_tool,
                pep=pep,
                planner=planner,
                shutdown_event=shutdown_event,
                planner_model_id=planner_model_id,
                model_routes=model_routes,
                provider_diagnostics=provider_diagnostics,
                memory_ingress_registry=memory_ingress_registry,
                internal_ingress_marker=internal_ingress_marker,
                identity_default_trust_baseline=identity_default_trust_baseline,
                identity_allowlists_baseline=identity_allowlists_baseline,
            )
            if config.a2a.enabled:
                if config.a2a.identity is None:
                    raise ValueError("A2A is enabled but no local identity is configured")
                local_identity = load_local_identity(config.a2a.identity)
                services.a2a_registry = A2aRegistry.from_config(config.a2a)
                from shisad.daemon.control_handlers import DaemonControlHandlers

                handlers = DaemonControlHandlers(services=services)
                a2a_runtime = A2aRuntime(
                    local_identity=local_identity,
                    registry=services.a2a_registry,
                    firewall=firewall,
                    session_create=handlers.handle_session_create,
                    session_message=handlers.handle_session_message,
                    listen_config=config.a2a.listen,
                    rate_limiter=A2aRateLimiter(config.a2a.rate_limits),
                    event_bus=event_bus,
                )
                await a2a_runtime.start()
                services.a2a_runtime = a2a_runtime
            startup_complete = True
            return services
        finally:
            if not startup_complete:
                if a2a_runtime is not None:
                    with contextlib.suppress(OSError, RuntimeError):
                        await a2a_runtime.close()
                if embeddings_adapter is not None:
                    with contextlib.suppress(OSError, RuntimeError):
                        embeddings_adapter.close(wait=False)
                if mcp_manager is not None:
                    with contextlib.suppress(OSError, RuntimeError):
                        await mcp_manager.shutdown()
                for channel in channels.values():
                    with contextlib.suppress(OSError, RuntimeError):
                        await channel.disconnect()
                if control_plane_sidecar is not None:
                    with contextlib.suppress(OSError, RuntimeError):
                        await control_plane_sidecar.close()
                with contextlib.suppress(OSError, RuntimeError):
                    await server.stop()

    async def reset_test_state(self) -> dict[str, Any]:
        """Clear mutable runtime state for test isolation.

        Wipes mutable runtime state while preserving the daemon process,
        control-plane sidecar, tool registry, firewall, and other static
        runtime wiring.

        Returns a summary dict with counts of cleared items.

        **Not for production use.**
        """
        if not self.config.test_mode:
            raise RuntimeError("daemon.reset is unavailable outside explicit test mode")
        inflight_embeddings = len(getattr(self.embeddings_adapter, "_inflight", ()))
        if inflight_embeddings > 0:
            raise RuntimeError("Cannot reset test state while embeddings requests are in flight")

        cleared: dict[str, int] = {}

        # -- Sessions --
        cleared["sessions"] = len(self.session_manager._sessions)
        self.session_manager._sessions.clear()
        if self.session_manager._state_dir is not None:
            _wipe_dir_contents(self.session_manager._state_dir)

        # -- Scheduler --
        cleared["scheduler_tasks"] = len(self.scheduler._tasks)
        cleared["scheduler_pending_confirmations"] = sum(
            len(rows) for rows in self.scheduler._pending_confirmations.values()
        )
        self.scheduler._tasks.clear()
        self.scheduler._pending_confirmations.clear()
        if self.scheduler._tasks_file is not None:
            _unlink_if_exists(self.scheduler._tasks_file)
        if self.scheduler._pending_file is not None:
            _unlink_if_exists(self.scheduler._pending_file)

        # -- Memory --
        cleared["memory_entries"] = len(self.memory_manager._entries)
        self.memory_manager.reset_storage()

        # -- Lockdown --
        cleared["lockdown_states"] = len(self.lockdown_manager._states)
        self.lockdown_manager._states.clear()

        # -- Rate limiter --
        cleared["rate_limiter_windows"] = (
            len(self.rate_limiter._by_tool)
            + len(self.rate_limiter._by_user)
            + len(self.rate_limiter._by_session)
            + len(self.rate_limiter._by_tool_burst)
        )
        self.rate_limiter._by_tool.clear()
        self.rate_limiter._by_user.clear()
        self.rate_limiter._by_session.clear()
        self.rate_limiter._by_tool_burst.clear()

        # -- Audit log --
        cleared["audit_entries"] = self.audit_log.entry_count
        from shisad.core.audit import _GENESIS_HASH

        self.audit_log._previous_hash = _GENESIS_HASH
        self.audit_log._entry_count = 0
        if self.audit_log._log_path.exists():
            self.audit_log._log_path.write_text("", encoding="utf-8")

        # -- Checkpoints --
        cleared["checkpoints"] = _count_files_recursive(self.checkpoint_store._dir)
        _wipe_dir_contents(self.checkpoint_store._dir)

        # -- Channel state --
        cleared["channel_state_channels"] = len(self.channel_state_store._seen_ids)
        channel_state_root = self.channel_state_store._root_dir
        cleared["channel_state_files"] = _count_files_recursive(channel_state_root)
        self.channel_state_store._seen_ids.clear()
        self.channel_state_store._seen_id_sets.clear()
        self.channel_state_store._journal_appends_since_compaction.clear()
        self.channel_state_store._loaded_channels.clear()
        self.channel_state_store._compaction_warning_logged.clear()
        _wipe_dir_contents(channel_state_root)

        # -- Transcripts --
        cleared["transcripts"] = _count_files_recursive(
            self.transcript_store._transcript_dir
        ) + _count_files_recursive(self.transcript_store._blob_dir)
        _wipe_dir_contents(self.transcript_store._transcript_dir)
        _wipe_dir_contents(self.transcript_store._blob_dir)

        # -- Evidence --
        cleared["evidence_refs"] = len(self.evidence_store._refs)
        cleared["evidence_files"] = _count_files_recursive(self.evidence_store._blob_dir) + int(
            self.evidence_store._metadata_path.exists()
        )
        self.evidence_store._refs.clear()
        self.evidence_store._temporarily_unreadable_refs.clear()
        _wipe_dir_contents(self.evidence_store._blob_dir)
        _wipe_dir_contents(self.evidence_store._quarantine_dir)
        _unlink_if_exists(self.evidence_store._metadata_path)

        # -- Ingestion --
        cleared["ingestion_records"] = self.ingestion.persisted_artifact_count()
        cleared["ingestion_vectors"] = self.ingestion.search_index_count()
        cleared["ingestion_keys"] = len(self.ingestion._key_metadata_by_id)
        cleared["ingestion_artifacts"] = self.ingestion.persisted_artifact_count()
        self.ingestion.reset_storage()

        # -- Self-modification --
        cleared["selfmod_entries"] = len(self.selfmod_manager._inventory.skills) + len(
            self.selfmod_manager._inventory.behavior_packs
        )
        cleared["selfmod_artifacts"] = (
            _count_files_recursive(self.selfmod_manager._proposal_dir)
            + _count_files_recursive(self.selfmod_manager._change_dir)
            + _count_files_recursive(self.selfmod_manager._artifact_root)
            + int(self.selfmod_manager._inventory_path.exists())
            + int(self.selfmod_manager._incident_path.exists())
        )
        self.selfmod_manager._inventory = self.selfmod_manager._inventory.__class__()
        _wipe_dir_contents(self.selfmod_manager._proposal_dir)
        _wipe_dir_contents(self.selfmod_manager._change_dir)
        _wipe_dir_contents(self.selfmod_manager._artifact_root)
        _unlink_if_exists(self.selfmod_manager._inventory_path)
        _unlink_if_exists(self.selfmod_manager._incident_path)
        self.selfmod_manager._proposal_dir.mkdir(parents=True, exist_ok=True)
        self.selfmod_manager._change_dir.mkdir(parents=True, exist_ok=True)
        self.selfmod_manager._artifact_root.mkdir(parents=True, exist_ok=True)
        self.selfmod_manager._apply_behavior_overlay()

        # -- Skills --
        cleared["skill_entries"] = len(self.skill_manager._inventory)
        cleared["skill_tool_registrations"] = sum(
            len(items) for items in self.skill_manager._skill_tool_map.values()
        )
        cleared["skill_pending_events"] = len(self.skill_manager._pending_registration_events)
        for skill_name in list(self.skill_manager._skill_tool_map):
            self.skill_manager._unregister_skill_tools(skill_name)
        self.skill_manager._inventory.clear()
        self.skill_manager._pending_registration_events.clear()
        _wipe_dir_contents(self.skill_manager._storage_dir)

        # -- Credentials / approvals --
        approval_store_path = self.credential_store._approval_store_path
        approval_store_artifacts = 0
        if approval_store_path is not None:
            approval_store_artifacts += int(approval_store_path.exists())
            approval_store_artifacts += len(
                list(approval_store_path.parent.glob(f"{approval_store_path.name}.corrupt.*"))
            )
        cleared["approval_factors"] = len(self.credential_store._approval_factors)
        cleared["signer_keys"] = len(self.credential_store._signer_keys)
        cleared["approval_store_artifacts"] = approval_store_artifacts
        self.credential_store._approval_factors.clear()
        self.credential_store._signer_keys.clear()
        self.credential_store._local_fido2_realm_id = None
        if approval_store_path is not None:
            _unlink_if_exists(approval_store_path)
            corrupt_glob = f"{approval_store_path.name}.corrupt.*"
            for artifact in approval_store_path.parent.glob(corrupt_glob):
                artifact.unlink(missing_ok=True)

        # -- Channel identity map --
        cleared["identity_bindings"] = len(self.identity_map._map)
        cleared["identity_pairing_requests"] = len(self.identity_map._pairing_requests)
        self.identity_map._map.clear()
        self.identity_map._pairing_requests.clear()
        self.identity_map._default_trust = dict(self.identity_default_trust_baseline)
        self.identity_map._allowlists = {
            channel: set(values) for channel, values in self.identity_allowlists_baseline.items()
        }

        # -- Trace capture --
        trace_dir = (
            self.trace_recorder._traces_dir
            if self.trace_recorder is not None
            else self.config.data_dir / "traces"
        )
        cleared["trace_files"] = _count_files_recursive(trace_dir)
        _wipe_dir_contents(trace_dir)

        # -- Session archives --
        session_archive_dir = self.config.data_dir / "session_archives"
        cleared["session_archives"] = _count_files_recursive(session_archive_dir)
        _wipe_dir_contents(session_archive_dir)

        # -- Risk calibrator --
        cleared["risk_observations"] = int(self.risk_calibrator.observations_path.exists())
        cleared["risk_policies"] = int(self.risk_calibrator.policy_path.exists())
        _unlink_if_exists(self.risk_calibrator.observations_path)
        _unlink_if_exists(self.risk_calibrator.policy_path)
        default_risk_policy = RiskPolicyVersion()
        self.policy_loader.policy.risk_policy.version = default_risk_policy.version
        self.policy_loader.policy.risk_policy.auto_approve_threshold = (
            default_risk_policy.thresholds.auto_approve_threshold
        )
        self.policy_loader.policy.risk_policy.block_threshold = (
            default_risk_policy.thresholds.block_threshold
        )

        logger.info("Test state reset: %s", cleared)
        return {"status": "reset", "cleared": cleared}

    async def shutdown(self) -> None:
        """Close async/sync resources in reverse runtime order."""
        shutdown_ops: list[tuple[str, Any]] = []

        embeddings_adapter = getattr(self, "embeddings_adapter", None)
        if embeddings_adapter is not None:
            shutdown_ops.append(
                (
                    "embeddings_adapter",
                    asyncio.to_thread(embeddings_adapter.close, wait=True),
                )
            )

        mcp_manager = getattr(self, "mcp_manager", None)
        a2a_runtime = getattr(self, "a2a_runtime", None)
        if a2a_runtime is not None:
            shutdown_ops.append(("a2a_runtime", a2a_runtime.close()))

        disconnected_ids: set[int] = set()
        channels = getattr(self, "channels", {})
        if isinstance(channels, dict):
            for channel_name, channel in channels.items():
                if id(channel) in disconnected_ids:
                    continue
                disconnected_ids.add(id(channel))
                shutdown_ops.append((f"channel:{channel_name}", channel.disconnect()))

        for label in ("matrix", "discord", "telegram", "slack"):
            channel = getattr(self, f"{label}_channel", None)
            if channel is None or id(channel) in disconnected_ids:
                continue
            disconnected_ids.add(id(channel))
            shutdown_ops.append((f"channel:{label}", channel.disconnect()))

        sidecar = getattr(self, "control_plane_sidecar", None)
        if sidecar is not None:
            shutdown_ops.append(("control_plane_sidecar", sidecar.close()))

        approval_web = getattr(self, "approval_web", None)
        if approval_web is not None:
            shutdown_ops.append(("approval_web", approval_web.stop()))

        server = getattr(self, "server", None)
        if server is not None:
            shutdown_ops.append(("control_server", server.stop()))

        results = await asyncio.gather(
            *(operation for _, operation in shutdown_ops),
            return_exceptions=True,
        )
        for (label, _operation), result in zip(shutdown_ops, results, strict=True):
            if isinstance(result, BaseException):
                if result.__class__.__name__ == "CancelledError":
                    continue
                logger.error(
                    "Error stopping daemon service %s",
                    label,
                    exc_info=(type(result), result, result.__traceback__),
                )

        if mcp_manager is not None:
            try:
                await mcp_manager.shutdown()
            except BaseException as result:
                if result.__class__.__name__ == "CancelledError":
                    return
                logger.error(
                    "Error stopping daemon service %s",
                    "mcp_manager",
                    exc_info=(type(result), result, result.__traceback__),
                )


async def _build_matrix_channel(config: DaemonConfig) -> MatrixChannel | None:
    if not config.matrix_enabled:
        return None
    from shisad.channels.matrix import MatrixChannel, MatrixConfig

    required = {
        "matrix_homeserver": config.matrix_homeserver,
        "matrix_user_id": config.matrix_user_id,
        "matrix_access_token": config.matrix_access_token,
        "matrix_room_id": config.matrix_room_id,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError(
            "Matrix channel is enabled but missing required config fields: " + ", ".join(missing)
        )
    matrix_channel = MatrixChannel(
        MatrixConfig(
            homeserver=config.matrix_homeserver,
            user_id=config.matrix_user_id,
            access_token=config.matrix_access_token,
            room_id=config.matrix_room_id,
            enable_e2ee=config.matrix_e2ee,
            room_workspace_map=dict(config.matrix_room_workspace_map),
            trusted_users=set(config.matrix_trusted_users),
        )
    )
    await matrix_channel.connect()
    return matrix_channel


async def _build_discord_channel(config: DaemonConfig) -> DiscordChannel | None:
    if not config.discord_enabled:
        return None
    from shisad.channels.discord import DiscordChannel, DiscordConfig

    if not config.discord_bot_token:
        raise ValueError(
            "Discord channel is enabled but missing required config field: discord_bot_token"
        )
    channel = DiscordChannel(
        DiscordConfig(
            bot_token=config.discord_bot_token,
            default_channel_id=config.discord_default_channel_id,
            guild_workspace_map=dict(config.discord_guild_workspace_map),
            trusted_users=set(config.discord_trusted_users),
            channel_rules=list(config.discord_channel_rules),
        )
    )
    await channel.connect()
    return channel


async def _build_telegram_channel(config: DaemonConfig) -> TelegramChannel | None:
    if not config.telegram_enabled:
        return None
    from shisad.channels.telegram import TelegramChannel, TelegramConfig

    if not config.telegram_bot_token:
        raise ValueError(
            "Telegram channel is enabled but missing required config field: telegram_bot_token"
        )
    channel = TelegramChannel(
        TelegramConfig(
            bot_token=config.telegram_bot_token,
            default_chat_id=config.telegram_default_chat_id,
            chat_workspace_map=dict(config.telegram_chat_workspace_map),
            trusted_users=set(config.telegram_trusted_users),
        )
    )
    await channel.connect()
    return channel


async def _build_slack_channel(config: DaemonConfig) -> SlackChannel | None:
    if not config.slack_enabled:
        return None
    from shisad.channels.slack import SlackChannel, SlackConfig

    missing: list[str] = []
    if not config.slack_bot_token:
        missing.append("slack_bot_token")
    if not config.slack_app_token:
        missing.append("slack_app_token")
    if missing:
        raise ValueError(
            "Slack channel is enabled but missing required config fields: " + ", ".join(missing)
        )
    channel = SlackChannel(
        SlackConfig(
            bot_token=config.slack_bot_token,
            app_token=config.slack_app_token,
            default_channel_id=config.slack_default_channel_id,
            team_workspace_map=dict(config.slack_team_workspace_map),
            trusted_users=set(config.slack_trusted_users),
        )
    )
    await channel.connect()
    return channel


def _build_tool_registry(
    event_bus: EventBus,
    *,
    web_search_destination: str = "",
    browser_surface_enabled: bool = False,
    browser_destinations: list[str] | None = None,
    realitycheck_surface_enabled: bool = False,
    realitycheck_endpoint_enabled: bool = False,
    realitycheck_endpoint_host: str = "",
) -> tuple[ToolRegistry, AlarmTool]:
    registry = ToolRegistry()
    registry.register(RetrieveRagTool.tool_definition())
    registry.register(ShellExecTool.tool_definition())
    registry.register(
        ToolDefinition(
            name=ToolName("http.request"),
            description="HTTP request runtime tool for sandbox egress policy testing.",
            parameters=[
                ToolParameter(
                    name="command",
                    type="array",
                    required=True,
                    items_type="string",
                    items_semantic_type="command_token",
                ),
                ToolParameter(
                    name="network_urls",
                    type="array",
                    required=False,
                    items_type="string",
                    items_semantic_type="url",
                ),
                ToolParameter(name="request_headers", type="object", required=False),
                ToolParameter(name="request_body", type="string", required=False),
            ],
            capabilities_required=[Capability.HTTP_REQUEST],
            sandbox_type="container",
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("file.read"),
            description="File read runtime tool for sandbox filesystem policy testing.",
            parameters=[
                ToolParameter(
                    name="command",
                    type="array",
                    required=True,
                    items_type="string",
                    items_semantic_type="command_token",
                ),
                ToolParameter(
                    name="read_paths",
                    type="array",
                    required=False,
                    items_type="string",
                    items_semantic_type="workspace_path",
                ),
            ],
            capabilities_required=[Capability.FILE_READ],
            sandbox_type="nsjail",
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("file.write"),
            description="File write runtime tool for sandbox filesystem policy testing.",
            parameters=[
                ToolParameter(
                    name="command",
                    type="array",
                    required=True,
                    items_type="string",
                    items_semantic_type="command_token",
                ),
                ToolParameter(
                    name="write_paths",
                    type="array",
                    required=False,
                    items_type="string",
                    items_semantic_type="workspace_path",
                ),
            ],
            capabilities_required=[Capability.FILE_WRITE],
            sandbox_type="nsjail",
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("web.search"),
            description=(
                "Search the web for current information. Use for weather, news,"
                " live data, or any query requiring up-to-date results."
            ),
            parameters=[
                ToolParameter(name="query", type="string", required=True),
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.HTTP_REQUEST],
            destinations=[web_search_destination] if web_search_destination else [],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("web.fetch"),
            description="Fetch URL with structured evidence payload.",
            parameters=[
                ToolParameter(name="url", type="string", required=True, semantic_type="url"),
                ToolParameter(name="snapshot", type="boolean", required=False),
                ToolParameter(name="max_bytes", type="integer", required=False),
            ],
            capabilities_required=[Capability.HTTP_REQUEST],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("email.search"),
            description=(
                "Search the local msgvault email archive. Use only for user-requested "
                "email lookup, triage, and summarization."
            ),
            parameters=[
                ToolParameter(name="query", type="string", required=True),
                ToolParameter(name="limit", type="integer", required=False),
                ToolParameter(name="offset", type="integer", required=False),
                ToolParameter(
                    name="account",
                    type="string",
                    required=False,
                    semantic_type="email_address",
                ),
            ],
            capabilities_required=[Capability.EMAIL_READ],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("email.read"),
            description=(
                "Read one message from the local msgvault email archive by msgvault "
                "message id or source message id."
            ),
            parameters=[
                ToolParameter(name="message_id", type="string", required=True),
                ToolParameter(
                    name="account",
                    type="string",
                    required=False,
                    semantic_type="email_address",
                ),
            ],
            capabilities_required=[Capability.EMAIL_READ],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("attachment.ingest"),
            description=(
                "Ingest a local image or voice recording by allowlisted path. "
                "Returns a tainted manifest evidence ref; unsafe media is quarantined."
            ),
            parameters=[
                ToolParameter(
                    name="path",
                    type="string",
                    required=True,
                    semantic_type="workspace_path",
                ),
                ToolParameter(name="mime_type", type="string", required=False),
                ToolParameter(name="filename", type="string", required=False),
                ToolParameter(name="transcript_text", type="string", required=False),
                ToolParameter(name="max_bytes", type="integer", required=False),
            ],
            capabilities_required=[Capability.FILE_READ, Capability.MEMORY_WRITE],
            require_confirmation=False,
        )
    )
    if browser_surface_enabled:
        browser_scope = [item for item in (browser_destinations or []) if item.strip()]
        registry.register(
            ToolDefinition(
                name=ToolName("browser.navigate"),
                description=(
                    "Navigate the sandboxed browser to a URL and return visible page content."
                ),
                parameters=[
                    ToolParameter(name="url", type="string", required=True, semantic_type="url"),
                ],
                capabilities_required=[Capability.HTTP_REQUEST],
                destinations=browser_scope,
                require_confirmation=False,
            )
        )
        registry.register(
            ToolDefinition(
                name=ToolName("browser.read_page"),
                description="Read the current sandboxed browser page.",
                parameters=[],
                capabilities_required=[Capability.HTTP_REQUEST],
                destinations=browser_scope,
                require_confirmation=False,
            )
        )
        registry.register(
            ToolDefinition(
                name=ToolName("browser.screenshot"),
                description="Capture a screenshot of the current sandboxed browser page.",
                parameters=[],
                capabilities_required=[Capability.HTTP_REQUEST],
                destinations=browser_scope,
                require_confirmation=False,
            )
        )
        registry.register(
            ToolDefinition(
                name=ToolName("browser.click"),
                description="Click an element in the sandboxed browser.",
                parameters=[
                    ToolParameter(name="target", type="string", required=True),
                    ToolParameter(name="description", type="string", required=False),
                    ToolParameter(
                        name="destination",
                        type="string",
                        required=False,
                        semantic_type="url",
                    ),
                ],
                capabilities_required=[Capability.HTTP_REQUEST],
                destinations=browser_scope,
                require_confirmation=True,
            )
        )
        registry.register(
            ToolDefinition(
                name=ToolName("browser.type_text"),
                description="Fill text into an element in the sandboxed browser.",
                parameters=[
                    ToolParameter(name="target", type="string", required=True),
                    ToolParameter(name="text", type="string", required=True),
                    ToolParameter(name="is_sensitive", type="boolean", required=False),
                    ToolParameter(name="submit", type="boolean", required=False),
                    ToolParameter(
                        name="destination",
                        type="string",
                        required=False,
                        semantic_type="url",
                    ),
                ],
                capabilities_required=[Capability.HTTP_REQUEST],
                destinations=browser_scope,
                require_confirmation=True,
            )
        )
        registry.register(
            ToolDefinition(
                name=ToolName("browser.end_session"),
                description="Close the current sandboxed browser session.",
                parameters=[],
                capabilities_required=[Capability.HTTP_REQUEST],
                destinations=browser_scope,
                require_confirmation=False,
            )
        )
    registry.register(
        ToolDefinition(
            name=ToolName("fs.list"),
            description="Read-first filesystem listing primitive.",
            parameters=[
                ToolParameter(
                    name="path",
                    type="string",
                    required=False,
                    semantic_type="workspace_path",
                ),
                ToolParameter(name="recursive", type="boolean", required=False),
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.FILE_READ],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("fs.read"),
            description="Read-first filesystem read primitive.",
            parameters=[
                ToolParameter(
                    name="path",
                    type="string",
                    required=True,
                    semantic_type="workspace_path",
                ),
                ToolParameter(name="max_bytes", type="integer", required=False),
            ],
            capabilities_required=[Capability.FILE_READ],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("fs.write"),
            description="Filesystem write primitive requiring explicit confirmation.",
            parameters=[
                ToolParameter(
                    name="path",
                    type="string",
                    required=True,
                    semantic_type="workspace_path",
                ),
                ToolParameter(name="content", type="string", required=True),
                ToolParameter(name="confirm", type="boolean", required=False),
            ],
            capabilities_required=[Capability.FILE_WRITE],
            require_confirmation=True,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("git.status"),
            description="Read-only git status primitive.",
            parameters=[
                ToolParameter(
                    name="repo_path",
                    type="string",
                    required=False,
                    semantic_type="workspace_path",
                ),
            ],
            capabilities_required=[Capability.FILE_READ],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("git.diff"),
            description="Read-only git diff primitive.",
            parameters=[
                ToolParameter(
                    name="repo_path",
                    type="string",
                    required=False,
                    semantic_type="workspace_path",
                ),
                ToolParameter(name="ref", type="string", required=False),
                ToolParameter(name="max_lines", type="integer", required=False),
            ],
            capabilities_required=[Capability.FILE_READ],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("git.log"),
            description="Read-only git log primitive.",
            parameters=[
                ToolParameter(
                    name="repo_path",
                    type="string",
                    required=False,
                    semantic_type="workspace_path",
                ),
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.FILE_READ],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("note.create"),
            description=(
                "Store a user note for later retrieval. "
                "Use this when the user asks to remember, save, or add a note."
            ),
            parameters=[
                ToolParameter(
                    name="content",
                    type="string",
                    description="Full note text to store.",
                    required=True,
                ),
                ToolParameter(
                    name="key",
                    type="string",
                    description="Optional short label for the note.",
                    required=False,
                ),
            ],
            capabilities_required=[Capability.MEMORY_WRITE],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("note.list"),
            description=(
                "List the user's saved notes. "
                "Use this when the user asks to list or show notes instead of "
                "answering from memory."
            ),
            parameters=[
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.MEMORY_READ],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("note.search"),
            description=(
                "Search saved notes by keyword. "
                "Use this when the user asks to find or search notes instead of "
                "answering from memory."
            ),
            parameters=[
                ToolParameter(
                    name="query",
                    type="string",
                    description="Keyword or phrase to look for in saved notes.",
                    required=True,
                ),
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.MEMORY_READ],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("todo.create"),
            description="Create a todo item the user can track later.",
            parameters=[
                ToolParameter(name="title", type="string", required=True),
                ToolParameter(name="details", type="string", required=False),
                ToolParameter(name="due_date", type="string", required=False),
            ],
            capabilities_required=[Capability.MEMORY_WRITE],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("todo.list"),
            description=(
                "List the user's tracked todo items. "
                "Use this when the user asks to list or show todos instead of "
                "answering from memory."
            ),
            parameters=[
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.MEMORY_READ],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("todo.complete"),
            description=(
                "Mark a todo as done by id or title. "
                "Use this when the user asks to mark, complete, or finish a todo."
            ),
            parameters=[
                ToolParameter(
                    name="selector",
                    type="string",
                    description="Todo id or title text that identifies the item to complete.",
                    required=True,
                ),
            ],
            capabilities_required=[Capability.MEMORY_WRITE],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("reminder.create"),
            description=(
                "Schedule a one-time reminder. Use this when the user asks to remind them later. "
                "Use `when` like `in 2 minutes`, `in 30 seconds`, or `at 3pm`."
            ),
            parameters=[
                ToolParameter(
                    name="message",
                    type="string",
                    description="Reminder text to deliver back to the user.",
                    required=True,
                ),
                ToolParameter(
                    name="when",
                    type="string",
                    description="Natural-language delivery time such as `in 2 minutes`.",
                    required=True,
                ),
                ToolParameter(name="name", type="string", required=False),
            ],
            capabilities_required=[Capability.MEMORY_WRITE, Capability.MESSAGE_SEND],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("reminder.list"),
            description=(
                "List the user's scheduled reminders. "
                "Use this when the user asks to list or show reminders instead of "
                "answering from memory."
            ),
            parameters=[
                ToolParameter(name="limit", type="integer", required=False),
            ],
            capabilities_required=[Capability.MEMORY_READ],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("message.send"),
            description="Background/runtime message delivery primitive.",
            parameters=[
                ToolParameter(name="channel", type="string", required=True),
                ToolParameter(
                    name="recipient",
                    type="string",
                    required=True,
                    semantic_type="recipient",
                ),
                ToolParameter(name="message", type="string", required=True),
                ToolParameter(name="workspace_hint", type="string", required=False),
                ToolParameter(
                    name="thread_id",
                    type="string",
                    required=False,
                    semantic_type="thread_id",
                ),
            ],
            capabilities_required=[Capability.MESSAGE_SEND],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("evidence.read"),
            description=(
                "Read the full content of a stored evidence reference for the current turn."
            ),
            parameters=[
                ToolParameter(
                    name="ref_id",
                    type="string",
                    required=True,
                    semantic_type="evidence_ref",
                ),
            ],
            capabilities_required=[Capability.MEMORY_READ],
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("evidence.promote"),
            description=(
                "Promote stored evidence into persistent conversation context after user approval."
            ),
            parameters=[
                ToolParameter(
                    name="ref_id",
                    type="string",
                    required=True,
                    semantic_type="evidence_ref",
                ),
            ],
            capabilities_required=[Capability.MEMORY_READ],
            require_confirmation=False,
        )
    )
    if realitycheck_surface_enabled:
        realitycheck_caps: list[Capability] = [Capability.FILE_READ]
        realitycheck_destinations: list[str] = []
        if realitycheck_endpoint_enabled:
            realitycheck_caps.append(Capability.HTTP_REQUEST)
            if realitycheck_endpoint_host:
                realitycheck_destinations = [realitycheck_endpoint_host]
        registry.register(
            ToolDefinition(
                name=ToolName("realitycheck.search"),
                description="Reality Check scoped search with provenance/taint output.",
                parameters=[
                    ToolParameter(name="query", type="string", required=True),
                    ToolParameter(name="limit", type="integer", required=False),
                    ToolParameter(name="mode", type="string", required=False),
                ],
                capabilities_required=realitycheck_caps,
                destinations=realitycheck_destinations,
                require_confirmation=False,
            )
        )
        registry.register(
            ToolDefinition(
                name=ToolName("realitycheck.read"),
                description="Reality Check scoped source read primitive.",
                parameters=[
                    ToolParameter(name="path", type="string", required=True),
                    ToolParameter(name="max_bytes", type="integer", required=False),
                ],
                capabilities_required=[Capability.FILE_READ],
                require_confirmation=False,
            )
        )
    alarm_tool = AlarmTool(event_bus)
    registry.register(alarm_tool.tool_definition())
    return registry, alarm_tool


def _build_provider_diagnostics(router: ModelRouter) -> dict[str, Any]:
    routes: dict[str, Any] = {}
    problems: list[str] = []
    for component in ModelComponent:
        route = router.route_for(component)
        requires_key = route.auth_mode != AuthMode.NONE
        has_key = bool(route.api_key)
        if route.remote_enabled and requires_key and not has_key:
            problems.append(f"{component.value}_missing_api_key")
        routes[component.value] = {
            "preset": route.provider_preset.value,
            "preset_label": provider_preset_label(route),
            "preset_source": route.provider_preset_source,
            "base_url": route.base_url,
            "endpoint_family": route.endpoint_family.value,
            "remote_enabled": route.remote_enabled,
            "remote_enabled_source": route.remote_enabled_source,
            "auth_mode": route.auth_mode.value,
            "auth_header_name": route.auth_header_name,
            "key_source": route.api_key_source,
            "request_parameter_profile": route.request_parameter_profile,
            "request_parameter_profile_source": route.request_parameter_profile_source,
            "request_parameter_profile_reason": route.request_parameter_profile_reason,
            "effective_request_parameters": dict(route.effective_request_payload),
            "mapped_request_fields": list(route.mapped_request_fields),
            "rejected_request_fields": list(route.rejected_request_fields),
            "extra_headers": sorted(route.extra_headers.keys()),
        }
    return {
        "status": "misconfigured" if problems else "ok",
        "problems": sorted(set(problems)),
        "routes": routes,
        "key_gated_acceptance": _key_gated_acceptance_matrix(),
    }


def _key_gated_acceptance_matrix() -> dict[str, dict[str, str]]:
    rows = {
        "openai": {
            "key_env": "OPENAI_API_KEY",
            "model_id": "gpt-5.4-2026-03-05",
            "scope": "route_configurable",
        },
        "openrouter": {
            "key_env": "OPENROUTER_API_KEY",
            "model_id": "qwen/qwen3.5-397b-a17b",
            "scope": "route_configurable",
        },
        "google_openai": {
            "key_env": "GEMINI_API_KEY",
            "model_id": "gemini-3.1-pro-preview",
            "scope": "route_configurable",
        },
        "shisa_default": {
            "key_env": "SHISA_API_KEY",
            "model_id": "shisa-ai/shisa-v2.1-unphi4-14b",
            "scope": "planner_only",
            "note": (
                "implicit remote-enable applies to planner route only when "
                "SHISA defaults are unchanged"
            ),
        },
    }
    matrix: dict[str, dict[str, str]] = {}
    for name, row in rows.items():
        key_env = row["key_env"]
        present = bool(os.getenv(key_env, "").strip())
        matrix[name] = {
            "status": "eligible (key env present)" if present else "N/A (key missing)",
            "evidence": "env_presence_only",
            "key_env": key_env,
            "model_id": row["model_id"],
            "scope": row["scope"],
        }
        note = row.get("note")
        if isinstance(note, str) and note.strip():
            matrix[name]["note"] = note
    return matrix


def _register_route_credentials(
    *,
    credential_store: InMemoryCredentialStore,
    router: ModelRouter,
) -> None:
    seen: set[tuple[str, str, str, str]] = set()
    for component in ModelComponent:
        route = router.route_for(component)
        if not route.remote_enabled:
            continue
        if route.auth_mode == AuthMode.NONE:
            continue
        key = (route.api_key or "").strip()
        if not key:
            continue
        hostname = (urlparse(route.base_url).hostname or "").strip().lower()
        if not hostname:
            continue
        signature = (
            key,
            hostname,
            route.auth_mode.value,
            route.auth_header_name,
        )
        if signature in seen:
            continue
        seen.add(signature)

        header_name = route.auth_header_name
        header_prefix = "Bearer "
        if route.auth_mode == AuthMode.HEADER:
            header_prefix = ""

        ref_hash = hashlib.sha256(
            f"{hostname}:{route.auth_mode.value}:{route.auth_header_name}:{key}".encode()
        ).hexdigest()[:12]
        credential_store.register(
            CredentialRef(f"model_route_{ref_hash}"),
            key,
            CredentialConfig(
                allowed_hosts=[hostname],
                header_name=header_name,
                header_prefix=header_prefix,
            ),
        )


def _log_provider_route_summary(router: ModelRouter) -> None:
    for component in ModelComponent:
        route = router.route_for(component)
        preset_label = provider_preset_label(route)
        logger.info(
            (
                "Model route resolved: component=%s preset=%s raw_preset=%s preset_source=%s "
                "base_url=%s endpoint_family=%s remote_enabled=%s remote_source=%s "
                "auth_mode=%s key_source=%s request_profile=%s profile_source=%s"
            ),
            component.value,
            preset_label,
            route.provider_preset.value,
            route.provider_preset_source,
            route.base_url,
            route.endpoint_family.value,
            route.remote_enabled,
            route.remote_enabled_source,
            route.auth_mode.value,
            route.api_key_source,
            route.request_parameter_profile,
            route.request_parameter_profile_source,
        )


def _validate_model_endpoints(model_config: ModelConfig, router: ModelRouter) -> None:
    for component in ModelComponent:
        route = router.route_for(component)
        errors = validate_endpoint(
            route.base_url,
            allow_http_localhost=model_config.allow_http_localhost,
            block_private_ranges=model_config.block_private_ranges,
            endpoint_allowlist=model_config.endpoint_allowlist or None,
        )
        if errors:
            raise ValueError(
                f"Invalid {component.value} model endpoint '{route.base_url}': {'; '.join(errors)}"
            )


async def _flush_skill_registration_events(
    *,
    event_bus: EventBus,
    skill_manager: SkillManager,
) -> None:
    for event in skill_manager.drain_registration_events():
        try:
            await event_bus.publish(event)
        except Exception as exc:
            logger.warning(
                "Failed to persist skill registration diagnostic for %s: %s",
                event.tool_name,
                exc,
            )


def _validate_security_route_pins(model_config: ModelConfig, router: ModelRouter) -> None:
    if not model_config.enforce_security_route_pinning:
        return
    monitor_route = router.route_for(ModelComponent.MONITOR)
    planner_route = router.route_for(ModelComponent.PLANNER)
    if model_config.pinned_monitor_model_id and (
        monitor_route.model_id != model_config.pinned_monitor_model_id
    ):
        raise ValueError(
            "Security monitor route model id mismatch: "
            f"expected {model_config.pinned_monitor_model_id}, got {monitor_route.model_id}"
        )
    if model_config.pinned_planner_model_id and (
        planner_route.model_id != model_config.pinned_planner_model_id
    ):
        raise ValueError(
            "Security planner route model id mismatch: "
            f"expected {model_config.pinned_planner_model_id}, got {planner_route.model_id}"
        )
