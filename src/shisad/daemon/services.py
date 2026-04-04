"""Daemon service construction and lifecycle helpers."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shisad.assistant.realitycheck import RealityCheckToolkit
from shisad.channels.base import Channel
from shisad.channels.delivery import ChannelDeliveryService
from shisad.channels.discord import DiscordChannel, DiscordConfig
from shisad.channels.identity import ChannelIdentityMap
from shisad.channels.ingress import ChannelIngressProcessor
from shisad.channels.matrix import MatrixChannel, MatrixConfig
from shisad.channels.slack import SlackChannel, SlackConfig
from shisad.channels.state import ChannelStateStore
from shisad.channels.telegram import TelegramChannel, TelegramConfig
from shisad.coding.manager import CodingAgentManager
from shisad.core.api.transport import ControlServer
from shisad.core.audit import AuditLog
from shisad.core.config import DaemonConfig, ModelConfig
from shisad.core.events import EventBus
from shisad.core.evidence import ArtifactLedger
from shisad.core.planner import Planner
from shisad.core.providers.base import validate_endpoint
from shisad.core.providers.capabilities import AuthMode
from shisad.core.providers.embeddings_adapter import SyncEmbeddingsAdapter
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.providers.monitor_adapter import MonitorProviderAdapter
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.core.providers.routing import ModelComponent, ModelRouter
from shisad.core.session import CheckpointStore, Session, SessionManager
from shisad.core.tools.builtin.alarm import AlarmTool
from shisad.core.tools.builtin.shell_exec import ShellExecTool
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.trace import TraceRecorder
from shisad.core.transcript import TranscriptStore
from shisad.core.types import Capability, CredentialRef, SessionId, ToolName
from shisad.daemon.event_wiring import DaemonEventWiring
from shisad.executors.browser import BrowserSandbox, BrowserSandboxPolicy
from shisad.executors.connect_path import IptablesConnectPathProxy
from shisad.executors.proxy import EgressProxy
from shisad.executors.sandbox import SandboxOrchestrator
from shisad.memory.ingestion import EmbeddingFingerprint, IngestionPipeline, RetrieveRagTool
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
from shisad.security.provenance import SecurityAssetManifest, load_manifest, verify_assets
from shisad.security.ratelimit import RateLimitConfig, RateLimiter
from shisad.security.risk import RiskCalibrator
from shisad.selfmod import SelfModificationManager
from shisad.skills.manager import SkillManager

logger = logging.getLogger(__name__)

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
    internal_ingress_marker: object

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
        evidence_store = ArtifactLedger(transcript_root / "evidence")
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
        session_manager: SessionManager | None = None
        channels: dict[str, Channel] = {}
        matrix_channel: MatrixChannel | None = None
        discord_channel: DiscordChannel | None = None
        telegram_channel: TelegramChannel | None = None
        slack_channel: SlackChannel | None = None
        embeddings_adapter: SyncEmbeddingsAdapter | None = None
        control_plane_sidecar: ControlPlaneSidecarHandle | None = None
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
                    "PromptGuard degraded at startup; posture=%s reason_code=%s",
                    semantic_status.posture,
                    semantic_status.reason,
                )
            firewall = ContentFirewall(
                semantic_classifier=semantic_classifier,
                semantic_classifier_status=semantic_status,
            )
            if policy_loader.policy.yara_required and firewall.classifier_mode != "yara":
                raise ValueError(
                    "Policy requires yara mode, but classifier is not running with yara-python"
                )
            output_firewall = OutputFirewall(
                safe_domains=policy_loader.policy.safe_output_domains
                or ["api.example.com", "example.com"],
                alert_hook=event_wiring.audit_output_event,
            )
            browser_sandbox = BrowserSandbox(
                output_firewall=output_firewall,
                screenshots_dir=config.data_dir / "screenshots",
                policy=BrowserSandboxPolicy(clipboard="enabled"),
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
            ingestion = IngestionPipeline(
                config.data_dir / "memory",
                firewall=firewall,
                embedding_fingerprint=EmbeddingFingerprint(
                    model_id=embeddings_route.model_id,
                    base_url=embeddings_route.base_url,
                ),
                embeddings_provider=embeddings_adapter,
            )
            memory_manager = MemoryManager(
                config.data_dir / "memory_entries",
                audit_hook=event_wiring.audit_memory_event,
            )
            scheduler = SchedulerManager(storage_dir=config.data_dir / "tasks")
            realitycheck_domains = [
                item for item in config.realitycheck_allowed_domains if item.strip()
            ]
            if not realitycheck_domains:
                realitycheck_domains = [
                    rule.host.strip() for rule in policy_loader.policy.egress if rule.host.strip()
                ]
            realitycheck_toolkit = RealityCheckToolkit(
                enabled=config.realitycheck_enabled,
                repo_root=config.realitycheck_repo_root,
                data_roots=list(config.realitycheck_data_roots),
                endpoint_enabled=config.realitycheck_endpoint_enabled,
                endpoint_url=config.realitycheck_endpoint_url,
                allowed_domains=realitycheck_domains,
                timeout_seconds=config.realitycheck_timeout_seconds,
                max_read_bytes=config.realitycheck_max_read_bytes,
                max_search_files=config.realitycheck_search_max_files,
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
            )
            control_plane = control_plane_sidecar.client

            provenance_manifest_path = (
                Path(__file__).resolve().parents[1] / "security" / "rules" / "provenance.json"
            )
            provenance_root = Path(__file__).resolve().parents[1] / "security" / "rules"
            provenance_status, _ = _load_provenance(provenance_manifest_path, provenance_root)

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
            pep = PEP(
                policy_loader.policy,
                registry,
                evidence_store=evidence_store,
                credential_store=credential_store,
                credential_audit_hook=event_wiring.audit_credential_use,
            )
            planner_route = router.route_for(ModelComponent.PLANNER)
            planner = Planner(
                provider,
                pep,
                persona_tone=config.assistant_persona_tone,
                custom_persona_text=config.assistant_persona_custom_text,
                capabilities=planner_route.capabilities,
                tool_registry=registry,
                schema_strict_mode=bool(model_config.planner_schema_strict_mode),
            )
            skill_manager = SkillManager(
                storage_dir=config.data_dir / "skills",
                policy=policy_loader.policy.skills,
                tool_registry=registry,
            )
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
                default_persona_text=config.assistant_persona_custom_text,
            )
            shutdown_event = asyncio.Event()
            planner_model_id = planner_route.model_id
            model_routes = {
                component.value: router.route_for(component).base_url
                for component in ModelComponent
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
                internal_ingress_marker=internal_ingress_marker,
            )
            startup_complete = True
            return services
        finally:
            if not startup_complete:
                if embeddings_adapter is not None:
                    with contextlib.suppress(OSError, RuntimeError):
                        embeddings_adapter.close(wait=False)
                for channel in channels.values():
                    with contextlib.suppress(OSError, RuntimeError):
                        await channel.disconnect()
                if control_plane_sidecar is not None:
                    with contextlib.suppress(OSError, RuntimeError):
                        await control_plane_sidecar.close()
                with contextlib.suppress(OSError, RuntimeError):
                    await server.stop()

    async def shutdown(self) -> None:
        """Close async/sync resources in reverse runtime order."""
        try:
            self.embeddings_adapter.close(wait=True)
        except (OSError, RuntimeError):
            logger.exception("Error closing embeddings adapter")
        disconnected_ids: set[int] = set()
        channels = getattr(self, "channels", {})
        if isinstance(channels, dict):
            for channel in channels.values():
                try:
                    await channel.disconnect()
                    disconnected_ids.add(id(channel))
                except (OSError, RuntimeError):
                    logger.exception("Error disconnecting channel")

        matrix_channel = getattr(self, "matrix_channel", None)
        if matrix_channel is not None and id(matrix_channel) not in disconnected_ids:
            try:
                await matrix_channel.disconnect()
            except (OSError, RuntimeError):
                logger.exception("Error disconnecting matrix channel")
        discord_channel = getattr(self, "discord_channel", None)
        if discord_channel is not None and id(discord_channel) not in disconnected_ids:
            try:
                await discord_channel.disconnect()
            except (OSError, RuntimeError):
                logger.exception("Error disconnecting discord channel")
        telegram_channel = getattr(self, "telegram_channel", None)
        if telegram_channel is not None and id(telegram_channel) not in disconnected_ids:
            try:
                await telegram_channel.disconnect()
            except (OSError, RuntimeError):
                logger.exception("Error disconnecting telegram channel")
        slack_channel = getattr(self, "slack_channel", None)
        if slack_channel is not None and id(slack_channel) not in disconnected_ids:
            try:
                await slack_channel.disconnect()
            except (OSError, RuntimeError):
                logger.exception("Error disconnecting slack channel")
        shutdown_tasks: list[asyncio.Task[None]] = []
        sidecar = getattr(self, "control_plane_sidecar", None)
        if sidecar is not None:
            shutdown_tasks.append(asyncio.create_task(sidecar.close()))
        shutdown_tasks.append(asyncio.create_task(self.server.stop()))
        results = await asyncio.gather(*shutdown_tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException):
                if result.__class__.__name__ == "CancelledError":
                    continue
                logger.error(
                    "Error stopping daemon service",
                    exc_info=(type(result), result, result.__traceback__),
                )


async def _build_matrix_channel(config: DaemonConfig) -> MatrixChannel | None:
    if not config.matrix_enabled:
        return None
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
        )
    )
    await channel.connect()
    return channel


async def _build_telegram_channel(config: DaemonConfig) -> TelegramChannel | None:
    if not config.telegram_enabled:
        return None
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
        logger.info(
            (
                "Model route resolved: component=%s preset=%s preset_source=%s "
                "base_url=%s endpoint_family=%s remote_enabled=%s remote_source=%s "
                "auth_mode=%s key_source=%s request_profile=%s profile_source=%s"
            ),
            component.value,
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


def _load_provenance(
    manifest_path: Path,
    root: Path,
) -> tuple[dict[str, Any], SecurityAssetManifest | None]:
    if not manifest_path.exists():
        return (
            {
                "available": False,
                "version": "",
                "source_commit": "",
                "manifest_hash": "",
                "drift": [],
            },
            None,
        )
    manifest = load_manifest(manifest_path)
    drift = verify_assets(root, manifest)
    return (
        {
            "available": True,
            "version": manifest.version,
            "source_commit": manifest.source_commit,
            "manifest_hash": manifest.digest()[:16],
            "drift": drift,
        },
        manifest,
    )
