"""Daemon service construction and lifecycle helpers."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shisad.channels.base import Channel
from shisad.channels.delivery import ChannelDeliveryService
from shisad.channels.discord import DiscordChannel, DiscordConfig
from shisad.channels.identity import ChannelIdentityMap
from shisad.channels.ingress import ChannelIngressProcessor
from shisad.channels.matrix import MatrixChannel, MatrixConfig
from shisad.channels.slack import SlackChannel, SlackConfig
from shisad.channels.state import ChannelStateStore
from shisad.channels.telegram import TelegramChannel, TelegramConfig
from shisad.core.api.transport import ControlServer
from shisad.core.audit import AuditLog
from shisad.core.config import DaemonConfig, ModelConfig
from shisad.core.events import EventBus
from shisad.core.planner import Planner
from shisad.core.providers.base import validate_endpoint
from shisad.core.providers.embeddings_adapter import SyncEmbeddingsAdapter
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.providers.monitor_adapter import MonitorProviderAdapter
from shisad.core.providers.routed_openai import RoutedOpenAIProvider
from shisad.core.providers.routing import ModelComponent, ModelRouter
from shisad.core.session import CheckpointStore, SessionManager
from shisad.core.tools.builtin.alarm import AlarmTool
from shisad.core.tools.builtin.shell_exec import ShellExecTool
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.trace import TraceRecorder
from shisad.core.transcript import TranscriptStore
from shisad.core.types import Capability, CredentialRef, ToolName
from shisad.daemon.event_wiring import DaemonEventWiring
from shisad.executors.browser import BrowserSandbox, BrowserSandboxPolicy
from shisad.executors.connect_path import IptablesConnectPathProxy
from shisad.executors.proxy import EgressProxy
from shisad.executors.sandbox import SandboxOrchestrator
from shisad.memory.ingestion import EmbeddingFingerprint, IngestionPipeline, RetrieveRagTool
from shisad.memory.manager import MemoryManager
from shisad.scheduler.manager import SchedulerManager
from shisad.security.control_plane.consensus import ConsensusPolicy
from shisad.security.control_plane.engine import ControlPlaneEngine
from shisad.security.credentials import CredentialConfig, InMemoryCredentialStore
from shisad.security.firewall import ContentFirewall
from shisad.security.firewall.output import OutputFirewall
from shisad.security.lockdown import LockdownManager
from shisad.security.monitor import ActionMonitor
from shisad.security.pep import PEP
from shisad.security.policy import PolicyLoader
from shisad.security.provenance import SecurityAssetManifest, load_manifest, verify_assets
from shisad.security.ratelimit import RateLimitConfig, RateLimiter
from shisad.security.risk import RiskCalibrator
from shisad.skills.manager import SkillManager

logger = logging.getLogger(__name__)

_CHANNEL_TRUST_DEFAULTS: dict[str, str] = {
    "cli": "trusted",
    "matrix": "untrusted",
    "discord": "untrusted",
    "telegram": "untrusted",
    "slack": "untrusted",
}


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
    lockdown_manager: LockdownManager
    rate_limiter: RateLimiter
    monitor: ActionMonitor
    control_plane: ControlPlaneEngine
    provenance_status: dict[str, Any]
    registry: ToolRegistry
    alarm_tool: AlarmTool
    pep: PEP
    planner: Planner
    shutdown_event: asyncio.Event
    planner_model_id: str
    model_routes: dict[str, str]
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
        trace_recorder: TraceRecorder | None = None
        if config.trace_enabled:
            trace_recorder = TraceRecorder(config.data_dir / "traces")
        checkpoint_store = CheckpointStore(config.data_dir / "checkpoints")
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
        channels: dict[str, Channel] = {}
        matrix_channel: MatrixChannel | None = None
        discord_channel: DiscordChannel | None = None
        telegram_channel: TelegramChannel | None = None
        slack_channel: SlackChannel | None = None
        embeddings_adapter: SyncEmbeddingsAdapter | None = None
        startup_complete = False

        try:
            session_manager = SessionManager(audit_hook=event_wiring.audit_capability_event)
            firewall = ContentFirewall()
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

            api_key_candidate = model_config.api_key
            if api_key_candidate is None:
                api_key_candidate = os.getenv("SHISA_API_KEY", "")
            shisa_api_key = api_key_candidate.strip()
            local_fallback = LocalPlannerProvider()
            provider: LocalPlannerProvider | RoutedOpenAIProvider = local_fallback
            monitor_provider: MonitorProviderAdapter | None = None
            remote_enabled = os.getenv("SHISAD_MODEL_REMOTE_ENABLED", "").strip().lower() in {
                "1",
                "true",
                "yes",
            }
            planner_url = router.route_for(ModelComponent.PLANNER).base_url
            planner_host = (urlparse(planner_url).hostname or "").lower()
            use_shisa_default_host = planner_host == "api.shisa.ai"
            if shisa_api_key and (remote_enabled or use_shisa_default_host):
                provider = RoutedOpenAIProvider(
                    router=router,
                    api_key=shisa_api_key,
                    fallback=local_fallback,
                )
            if isinstance(provider, RoutedOpenAIProvider):
                monitor_provider = MonitorProviderAdapter(provider)

            embeddings_route = router.route_for(ModelComponent.EMBEDDINGS)
            embeddings_adapter = SyncEmbeddingsAdapter(
                provider,
                model_id=embeddings_route.model_id,
            )
            credential_store = InMemoryCredentialStore()
            if shisa_api_key:
                credential_store.register(
                    CredentialRef("shisa_primary"),
                    shisa_api_key,
                    CredentialConfig(allowed_hosts=["api.shisa.ai"]),
                )
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
            skill_manager = SkillManager(
                storage_dir=config.data_dir / "skills",
                policy=policy_loader.policy.skills,
            )
            lockdown_manager = LockdownManager(notification_hook=event_wiring.lockdown_notify)
            event_wiring.bind_lockdown_manager(lockdown_manager)
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
            control_plane_policy = policy_loader.policy.control_plane
            control_plane = ControlPlaneEngine.build(
                data_dir=config.data_dir,
                monitor_provider=monitor_provider,
                monitor_timeout_seconds=max(
                    0.05, control_plane_policy.network.timeout_ms / 1000.0
                ),
                monitor_cache_ttl_seconds=int(control_plane_policy.network.cache_ttl_seconds),
                baseline_learning_rate=float(
                    control_plane_policy.network.baseline_learning_rate
                ),
                high_critical_timeout_action=control_plane_policy.network.high_critical_timeout_action,
                low_medium_timeout_action=control_plane_policy.network.low_medium_timeout_action,
                trace_ttl_seconds=int(control_plane_policy.trace.ttl_seconds),
                trace_max_actions=int(control_plane_policy.trace.max_actions),
                consensus_policy=ConsensusPolicy(
                    required_approvals_low=int(
                        control_plane_policy.consensus.required_approvals_low
                    ),
                    required_approvals_medium=int(
                        control_plane_policy.consensus.required_approvals_medium
                    ),
                    required_approvals_high=int(
                        control_plane_policy.consensus.required_approvals_high
                    ),
                    required_approvals_critical=int(
                        control_plane_policy.consensus.required_approvals_critical
                    ),
                    veto_for_high_and_critical=bool(
                        control_plane_policy.consensus.veto_for_high_and_critical
                    ),
                    voter_timeout_seconds=float(
                        control_plane_policy.consensus.voter_timeout_seconds
                    ),
                ),
            )

            provenance_manifest_path = (
                Path(__file__).resolve().parents[1] / "security" / "rules" / "provenance.json"
            )
            provenance_root = Path(__file__).resolve().parents[1] / "security" / "rules"
            provenance_status, _ = _load_provenance(provenance_manifest_path, provenance_root)

            registry, alarm_tool = _build_tool_registry(event_bus)
            pep = PEP(
                policy_loader.policy,
                registry,
                credential_audit_hook=event_wiring.audit_credential_use,
            )
            planner = Planner(provider, pep)
            shutdown_event = asyncio.Event()
            planner_model_id = router.route_for(ModelComponent.PLANNER).model_id
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
                lockdown_manager=lockdown_manager,
                rate_limiter=rate_limiter,
                monitor=monitor,
                control_plane=control_plane,
                provenance_status=provenance_status,
                registry=registry,
                alarm_tool=alarm_tool,
                pep=pep,
                planner=planner,
                shutdown_event=shutdown_event,
                planner_model_id=planner_model_id,
                model_routes=model_routes,
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
        try:
            await self.server.stop()
        except (OSError, RuntimeError):
            logger.exception("Error stopping control server")


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
            "Matrix channel is enabled but missing required config fields: "
            + ", ".join(missing)
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
            "Discord channel is enabled but missing required config field: "
            "discord_bot_token"
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


def _build_tool_registry(event_bus: EventBus) -> tuple[ToolRegistry, AlarmTool]:
    registry = ToolRegistry()
    registry.register(RetrieveRagTool.tool_definition())
    registry.register(ShellExecTool.tool_definition())
    registry.register(
        ToolDefinition(
            name=ToolName("shell.exec"),
            description="Legacy shell execution alias routed via sandbox runtime.",
            parameters=[
                ToolParameter(
                    name="command",
                    type="array",
                    description="Command token list to execute",
                    required=True,
                ),
                ToolParameter(name="read_paths", type="array", required=False),
                ToolParameter(name="write_paths", type="array", required=False),
                ToolParameter(name="network_urls", type="array", required=False),
                ToolParameter(name="env", type="object", required=False),
                ToolParameter(name="cwd", type="string", required=False),
            ],
            capabilities_required=[Capability.SHELL_EXEC],
            sandbox_type="nsjail",
            require_confirmation=False,
        )
    )
    registry.register(
        ToolDefinition(
            name=ToolName("http_request"),
            description="HTTP request runtime tool for sandbox egress policy testing.",
            parameters=[
                ToolParameter(name="command", type="array", required=True),
                ToolParameter(name="network_urls", type="array", required=False),
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
                ToolParameter(name="command", type="array", required=True),
                ToolParameter(name="read_paths", type="array", required=False),
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
                ToolParameter(name="command", type="array", required=True),
                ToolParameter(name="write_paths", type="array", required=False),
            ],
            capabilities_required=[Capability.FILE_WRITE],
            sandbox_type="nsjail",
            require_confirmation=False,
        )
    )
    alarm_tool = AlarmTool(event_bus)
    registry.register(alarm_tool.tool_definition())
    return registry, alarm_tool


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
                f"Invalid {component.value} model endpoint '{route.base_url}': "
                f"{'; '.join(errors)}"
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
