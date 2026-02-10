"""Daemon runner — main event loop for shisad."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import shlex
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from shisad.channels.identity import ChannelIdentityMap
from shisad.channels.ingress import ChannelIngressProcessor
from shisad.channels.matrix import MatrixChannel, MatrixConfig
from shisad.core.api.schema import (
    ActionDecisionParams,
    ActionPendingParams,
    AuditQueryParams,
    BrowserPasteParams,
    BrowserScreenshotParams,
    ChannelIngestParams,
    LockdownSetParams,
    MemoryEntryParams,
    MemoryExportParams,
    MemoryIngestParams,
    MemoryListParams,
    MemoryRetrieveParams,
    MemoryRotateKeyParams,
    MemoryWriteParams,
    NoParams,
    PolicyExplainParams,
    SessionCreateParams,
    SessionGrantCapabilitiesParams,
    SessionMessageParams,
    SessionRestoreParams,
    SessionRollbackParams,
    SkillInstallParams,
    SkillProfileParams,
    SkillReviewParams,
    TaskCreateParams,
    TaskDisableParams,
    TaskPendingConfirmationsParams,
    TaskTriggerEventParams,
    ToolExecuteParams,
)
from shisad.core.api.transport import ControlServer
from shisad.core.audit import AuditLog
from shisad.core.config import DaemonConfig, ModelConfig
from shisad.core.events import (
    CapabilityGranted,
    CredentialAccessed,
    EventBus,
    LockdownChanged,
    MemoryEntryDeleted,
    MemoryEntryStored,
    OutputFirewallAlert,
    RateLimitTriggered,
)
from shisad.core.planner import Planner
from shisad.core.providers.base import (
    EmbeddingResponse,
    Message,
    OpenAICompatibleProvider,
    ProviderResponse,
    validate_endpoint,
)
from shisad.core.providers.routing import ModelComponent, ModelRouter
from shisad.core.session import CheckpointStore, SessionManager
from shisad.core.tools.builtin.alarm import AlarmTool
from shisad.core.tools.builtin.shell_exec import ShellExecTool
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.transcript import TranscriptStore
from shisad.core.types import Capability, CredentialRef, SessionId, ToolName
from shisad.daemon.control_handlers import DaemonControlHandlers
from shisad.executors.browser import BrowserSandbox, BrowserSandboxPolicy
from shisad.executors.connect_path import NoopConnectPathProxy
from shisad.executors.proxy import EgressProxy
from shisad.executors.sandbox import SandboxOrchestrator
from shisad.memory.ingestion import EmbeddingFingerprint, IngestionPipeline, RetrieveRagTool
from shisad.memory.manager import MemoryManager
from shisad.scheduler.manager import SchedulerManager
from shisad.security.credentials import CredentialConfig, InMemoryCredentialStore
from shisad.security.firewall import ContentFirewall
from shisad.security.firewall.output import OutputFirewall
from shisad.security.lockdown import LockdownManager
from shisad.security.monitor import ActionMonitor
from shisad.security.pep import PEP, CredentialUseAttempt
from shisad.security.policy import PolicyLoader
from shisad.security.provenance import SecurityAssetManifest, load_manifest, verify_assets
from shisad.security.ratelimit import RateLimitConfig, RateLimiter, RateLimitEvent
from shisad.security.risk import RiskCalibrator
from shisad.skills.manager import SkillManager

logger = logging.getLogger(__name__)

_CHANNEL_TRUST_DEFAULTS: dict[str, str] = {
    "cli": "trusted",
    "matrix": "untrusted",
}


class _LocalPlannerProvider:
    """Local fallback planner provider for daemon operation."""

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        _ = tools
        user_content = messages[-1].content if messages else ""
        normalized_content = user_content.replace("^", "")
        goal_text = normalized_content
        goal_match = re.search(
            r"=== USER GOAL ===\n.*?\n(.*?)\n\n=== EXTERNAL CONTENT",
            normalized_content,
            flags=re.DOTALL,
        )
        if goal_match:
            goal_text = goal_match.group(1).strip()
        goal_lower = goal_text.lower()
        actions: list[dict[str, Any]] = []

        anomaly_triggers = (
            "report anomaly",
            "security incident",
            "possible compromise",
            "suspicious behavior",
        )
        if "retrieve:" in goal_lower or "retrieve evidence" in goal_lower:
            query = goal_text.split(":", 1)[-1].strip() or goal_text[:180]
            actions.append(
                {
                    "action_id": "local-retrieve-1",
                    "tool_name": "retrieve_rag",
                    "arguments": {
                        "query": query,
                        "limit": 5,
                    },
                    "reasoning": "Retrieve supporting evidence for user request",
                    "data_sources": ["memory_index"],
                }
            )

        run_match = re.search(
            r"\b(?:run|execute)\s*:\s*(.+)",
            goal_text,
            flags=re.DOTALL | re.IGNORECASE,
        )
        if run_match:
            command_text = run_match.group(1).strip()
            command_tokens: list[str]
            try:
                command_tokens = shlex.split(command_text)
            except ValueError:
                command_tokens = []
            if command_tokens:
                actions.append(
                    {
                        "action_id": "local-shell-1",
                        "tool_name": "shell_exec",
                        "arguments": {
                            "command": command_tokens,
                        },
                        "reasoning": "Run explicit command requested by user via sandbox runtime",
                        "data_sources": ["user_signal"],
                    }
                )

        if any(token in goal_lower for token in anomaly_triggers):
            actions.append(
                {
                    "action_id": "local-anomaly-1",
                    "tool_name": "report_anomaly",
                    "arguments": {
                        "anomaly_type": "runtime_alert",
                        "description": "User signaled suspicious behavior requiring review.",
                        "recommended_action": "quarantine",
                        "confidence": 0.9,
                    },
                    "reasoning": "Local deterministic safety trigger for anomaly reporting",
                    "data_sources": ["user_signal"],
                }
            )

        payload = {
            "assistant_response": f"Safe summary: {user_content[:300]}",
            "actions": actions,
        }
        return ProviderResponse(
            message=Message(role="assistant", content=json.dumps(payload)),
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )

    async def embeddings(
        self,
        input_texts: list[str],
        *,
        model_id: str | None = None,
    ) -> EmbeddingResponse:
        _ = model_id
        vectors: list[list[float]] = []
        for text in input_texts:
            digest = hashlib.sha256(text.encode("utf-8")).digest()
            vectors.append([digest[i] / 255.0 for i in range(12)])
        return EmbeddingResponse(vectors=vectors, model="local-stub", usage={"total_tokens": 0})


class _RoutedOpenAIProvider:
    """OpenAI-compatible provider bound to router component routes."""

    def __init__(
        self,
        *,
        router: ModelRouter,
        api_key: str,
        fallback: _LocalPlannerProvider | None = None,
    ) -> None:
        headers = {"Authorization": f"Bearer {api_key}"}
        planner_route = router.route_for(ModelComponent.PLANNER)
        embeddings_route = router.route_for(ModelComponent.EMBEDDINGS)
        self._planner_provider = OpenAICompatibleProvider(
            base_url=planner_route.base_url,
            model_id=planner_route.model_id,
            headers=headers,
        )
        self._embeddings_provider = OpenAICompatibleProvider(
            base_url=embeddings_route.base_url,
            model_id=embeddings_route.model_id,
            headers=headers,
        )
        self._embeddings_model_id = embeddings_route.model_id
        self._fallback = fallback

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        try:
            return await self._planner_provider.complete(messages, tools)
        except Exception:
            if self._fallback is None:
                raise
            logger.warning("Remote planner provider failed; falling back to local provider")
            return await self._fallback.complete(messages, tools)

    async def embeddings(
        self,
        input_texts: list[str],
        *,
        model_id: str | None = None,
    ) -> EmbeddingResponse:
        target_model = model_id or self._embeddings_model_id
        try:
            return await self._embeddings_provider.embeddings(input_texts, model_id=target_model)
        except Exception:
            if self._fallback is None:
                raise
            logger.warning("Remote embeddings provider failed; falling back to local provider")
            return await self._fallback.embeddings(input_texts, model_id=target_model)


class _EmbeddingsProvider(Protocol):
    async def embeddings(
        self,
        input_texts: list[str],
        *,
        model_id: str | None = None,
    ) -> EmbeddingResponse: ...


class _SyncEmbeddingsAdapter:
    """Threaded adapter to use async provider embeddings from sync retrieval code."""

    def __init__(self, provider: _EmbeddingsProvider, *, model_id: str) -> None:
        self._provider = provider
        self._model_id = model_id
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="shisad-embed")

    def embed(self, input_texts: list[str]) -> list[list[float]]:
        future = self._executor.submit(self._run_embed, list(input_texts))
        return future.result(timeout=15.0)

    def _run_embed(self, input_texts: list[str]) -> list[list[float]]:
        response = asyncio.run(self._provider.embeddings(input_texts, model_id=self._model_id))
        return response.vectors

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


def _validate_model_endpoints(model_config: ModelConfig, router: ModelRouter) -> None:
    """Validate configured model endpoints before daemon startup."""
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


async def run_daemon(config: DaemonConfig) -> None:
    """Run the shisad daemon."""
    logging.basicConfig(level=getattr(logging, config.log_level.upper(), logging.INFO))

    audit_path = config.data_dir / "audit.jsonl"
    audit_log = AuditLog(audit_path)
    event_bus = EventBus(persister=audit_log)

    policy_loader = PolicyLoader(config.policy_path)
    policy_loader.load()
    policy_loader.register_reload_signal()

    model_config = ModelConfig()
    router = ModelRouter(model_config)
    _validate_model_endpoints(model_config, router)

    transcript_root = config.data_dir / "sessions"
    transcript_store = TranscriptStore(transcript_root)
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

    async def _forward_event_to_subscribers(event: Any) -> None:
        payload = event.model_dump(mode="json")
        payload["event_type"] = type(event).__name__
        await server.broadcast_event(payload)

    event_bus.subscribe_all(_forward_event_to_subscribers)
    _internal_ingress_marker = object()

    def _publish_async(event: Any) -> None:
        task = asyncio.create_task(event_bus.publish(event))
        event_type = type(event).__name__

        def _done_callback(done_task: asyncio.Task[None]) -> None:
            try:
                done_task.result()
            except Exception:
                logger.exception("Async event publish failed for %s", event_type)

        task.add_done_callback(_done_callback)

    def _audit_capability_event(action: str, data: dict[str, Any]) -> None:
        if action != "session.capability_granted":
            return
        _publish_async(
            CapabilityGranted(
                session_id=SessionId(str(data.get("session_id", ""))),
                actor="session_manager",
                capabilities=list(data.get("granted", [])),
                granted_by=str(data.get("actor", "")),
                reason=str(data.get("reason", "")),
            )
        )

    def _audit_credential_use(attempt: CredentialUseAttempt) -> None:
        _publish_async(
            CredentialAccessed(
                session_id=None,
                actor="pep",
                credential_ref=str(attempt.credential_ref),
                destination_host=attempt.destination_host,
                allowed=attempt.allowed,
                reason=attempt.reason,
            )
        )

    def _audit_memory_event(action: str, data: dict[str, Any]) -> None:
        if action == "memory.write":
            _publish_async(
                MemoryEntryStored(
                    session_id=None,
                    actor="memory_manager",
                    memory_id=str(data.get("entry_id", "")),
                    key=str(data.get("key", "")),
                    source_origin=str(data.get("source_origin", "")),
                )
            )
        elif action == "memory.delete":
            _publish_async(
                MemoryEntryDeleted(
                    session_id=None,
                    actor="memory_manager",
                    memory_id=str(data.get("entry_id", "")),
                )
            )

    def _audit_output_event(data: dict[str, Any]) -> None:
        context = data.get("context", {})
        if isinstance(context, dict):
            raw_session_id = str(context.get("session_id", "")).strip()
        else:
            raw_session_id = ""
        session_id = SessionId(raw_session_id) if raw_session_id else None
        _publish_async(
            OutputFirewallAlert(
                session_id=session_id,
                actor="output_firewall",
                blocked=bool(data.get("blocked", False)),
                require_confirmation=bool(data.get("require_confirmation", False)),
                reason_codes=[str(item) for item in data.get("reason_codes", [])],
                secret_findings=[str(item) for item in data.get("secret_findings", [])],
            )
        )

    def _lockdown_notify(session_id: SessionId, message: str) -> None:
        state = lockdown_manager.state_for(session_id)
        _publish_async(
            LockdownChanged(
                session_id=session_id,
                actor="lockdown",
                level=state.level.value,
                reason=state.reason,
                trigger=state.trigger,
            )
        )
        logger.warning("lockdown notification: %s", message)

    def _on_ratelimit(event: RateLimitEvent) -> None:
        _publish_async(
            RateLimitTriggered(
                session_id=SessionId(event.session_id),
                actor="ratelimiter",
                tool_name=ToolName(event.tool_name),
                reason=event.reason,
                count=event.count,
            )
        )
        lockdown_manager.trigger(
            SessionId(event.session_id),
            trigger="rate_limit",
            reason=f"{event.reason} ({event.count})",
        )

    session_manager = SessionManager(audit_hook=_audit_capability_event)
    firewall = ContentFirewall()
    if policy_loader.policy.yara_required and firewall.classifier_mode != "yara":
        raise ValueError(
            "Policy requires yara mode, but classifier is not running with yara-python"
        )
    output_firewall = OutputFirewall(
        safe_domains=policy_loader.policy.safe_output_domains or ["api.example.com", "example.com"],
        alert_hook=_audit_output_event,
    )
    browser_sandbox = BrowserSandbox(
        output_firewall=output_firewall,
        screenshots_dir=config.data_dir / "screenshots",
        policy=BrowserSandboxPolicy(clipboard="enabled"),
    )
    channel_ingress = ChannelIngressProcessor(firewall)
    identity_map = ChannelIdentityMap(default_trust=_CHANNEL_TRUST_DEFAULTS)
    matrix_channel: MatrixChannel | None = None
    if config.matrix_enabled:
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

    api_key_candidate = model_config.api_key
    if api_key_candidate is None:
        api_key_candidate = os.getenv("SHISA_API_KEY", "")
    shisa_api_key = api_key_candidate.strip()
    local_fallback = _LocalPlannerProvider()
    provider: _LocalPlannerProvider | _RoutedOpenAIProvider = local_fallback
    remote_enabled = os.getenv("SHISAD_MODEL_REMOTE_ENABLED", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    planner_url = router.route_for(ModelComponent.PLANNER).base_url
    planner_host = (urlparse(planner_url).hostname or "").lower()
    use_shisa_default_host = planner_host == "api.shisa.ai"
    if shisa_api_key and (remote_enabled or use_shisa_default_host):
        provider = _RoutedOpenAIProvider(
            router=router,
            api_key=shisa_api_key,
            fallback=local_fallback,
        )

    embeddings_route = router.route_for(ModelComponent.EMBEDDINGS)
    embeddings_adapter = _SyncEmbeddingsAdapter(
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
    connect_path_proxy = NoopConnectPathProxy()
    if not connect_path_proxy.net_admin_available:
        logger.warning(
            "[shisad] Connect-path enforcement unavailable: CAP_NET_ADMIN not granted. "
            "Network-enabled sandbox processes have unrestricted IP-level access. "
            "Pre-execution DNS and domain policy checks are still enforced. "
            "To enable: run daemon with CAP_NET_ADMIN or as root."
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
        audit_hook=_audit_memory_event,
    )
    scheduler = SchedulerManager(storage_dir=config.data_dir / "tasks")
    skill_manager = SkillManager(
        storage_dir=config.data_dir / "skills",
        policy=policy_loader.policy.skills,
    )
    lockdown_manager = LockdownManager(notification_hook=_lockdown_notify)
    rate_limiter = RateLimiter(
        RateLimitConfig(
            window_seconds=policy_loader.policy.rate_limits.window_seconds,
            per_tool=policy_loader.policy.rate_limits.per_tool,
            per_user=policy_loader.policy.rate_limits.per_user,
            per_session=policy_loader.policy.rate_limits.per_session,
            burst_multiplier=policy_loader.policy.rate_limits.burst_multiplier,
            burst_window_seconds=policy_loader.policy.rate_limits.burst_window_seconds,
        ),
        anomaly_hook=_on_ratelimit,
    )
    monitor = ActionMonitor()

    provenance_manifest_path = (
        Path(__file__).resolve().parents[1] / "security" / "rules" / "provenance.json"
    )
    provenance_root = Path(__file__).resolve().parents[1] / "security" / "rules"
    provenance_status, _ = _load_provenance(provenance_manifest_path, provenance_root)

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

    pep = PEP(
        policy_loader.policy,
        registry,
        credential_audit_hook=_audit_credential_use,
    )
    planner = Planner(provider, pep)

    shutdown_event = asyncio.Event()
    model_routes = {
        component.value: router.route_for(component).base_url for component in ModelComponent
    }
    handlers = DaemonControlHandlers(
        config=config,
        audit_log=audit_log,
        event_bus=event_bus,
        policy_loader=policy_loader,
        planner=planner,
        registry=registry,
        alarm_tool=alarm_tool,
        session_manager=session_manager,
        transcript_store=transcript_store,
        transcript_root=transcript_root,
        checkpoint_store=checkpoint_store,
        firewall=firewall,
        output_firewall=output_firewall,
        channel_ingress=channel_ingress,
        identity_map=identity_map,
        matrix_channel=matrix_channel,
        lockdown_manager=lockdown_manager,
        rate_limiter=rate_limiter,
        monitor=monitor,
        risk_calibrator=risk_calibrator,
        ingestion=ingestion,
        memory_manager=memory_manager,
        scheduler=scheduler,
        skill_manager=skill_manager,
        sandbox=sandbox,
        browser_sandbox=browser_sandbox,
        shutdown_event=shutdown_event,
        provenance_status=provenance_status,
        model_routes=model_routes,
        classifier_mode=firewall.classifier_mode,
        internal_ingress_marker=_internal_ingress_marker,
    )

    server.register_method(
        "session.create",
        handlers.handle_session_create,
        params_model=SessionCreateParams,
    )
    server.register_method(
        "session.message",
        handlers.handle_session_message,
        params_model=SessionMessageParams,
    )
    server.register_method("session.list", handlers.handle_session_list, params_model=NoParams)
    server.register_method(
        "session.restore",
        handlers.handle_session_restore,
        params_model=SessionRestoreParams,
    )
    server.register_method(
        "session.rollback",
        handlers.handle_session_rollback,
        admin_only=True,
        params_model=SessionRollbackParams,
    )
    server.register_method(
        "session.grant_capabilities",
        handlers.handle_session_grant_capabilities,
        admin_only=True,
        params_model=SessionGrantCapabilitiesParams,
    )
    server.register_method("daemon.status", handlers.handle_daemon_status, params_model=NoParams)
    server.register_method(
        "policy.explain",
        handlers.handle_policy_explain,
        params_model=PolicyExplainParams,
    )
    server.register_method(
        "daemon.shutdown",
        handlers.handle_daemon_shutdown,
        params_model=NoParams,
    )
    server.register_method(
        "audit.query",
        handlers.handle_audit_query,
        params_model=AuditQueryParams,
    )
    server.register_method(
        "memory.ingest",
        handlers.handle_memory_ingest,
        admin_only=True,
        params_model=MemoryIngestParams,
    )
    server.register_method(
        "memory.retrieve",
        handlers.handle_memory_retrieve,
        params_model=MemoryRetrieveParams,
    )
    server.register_method(
        "memory.write",
        handlers.handle_memory_write,
        admin_only=True,
        params_model=MemoryWriteParams,
    )
    server.register_method(
        "memory.list",
        handlers.handle_memory_list,
        params_model=MemoryListParams,
    )
    server.register_method("memory.get", handlers.handle_memory_get, params_model=MemoryEntryParams)
    server.register_method(
        "memory.delete",
        handlers.handle_memory_delete,
        admin_only=True,
        params_model=MemoryEntryParams,
    )
    server.register_method(
        "memory.export",
        handlers.handle_memory_export,
        params_model=MemoryExportParams,
    )
    server.register_method(
        "memory.verify",
        handlers.handle_memory_verify,
        admin_only=True,
        params_model=MemoryEntryParams,
    )
    server.register_method(
        "memory.rotate_key",
        handlers.handle_memory_rotate_key,
        admin_only=True,
        params_model=MemoryRotateKeyParams,
    )
    server.register_method(
        "skill.review",
        handlers.handle_skill_review,
        admin_only=True,
        params_model=SkillReviewParams,
    )
    server.register_method(
        "skill.install",
        handlers.handle_skill_install,
        admin_only=True,
        params_model=SkillInstallParams,
    )
    server.register_method(
        "skill.profile",
        handlers.handle_skill_profile,
        admin_only=True,
        params_model=SkillProfileParams,
    )
    server.register_method(
        "task.create",
        handlers.handle_task_create,
        admin_only=True,
        params_model=TaskCreateParams,
    )
    server.register_method("task.list", handlers.handle_task_list, params_model=NoParams)
    server.register_method(
        "task.disable",
        handlers.handle_task_disable,
        admin_only=True,
        params_model=TaskDisableParams,
    )
    server.register_method(
        "task.trigger_event",
        handlers.handle_task_trigger_event,
        admin_only=True,
        params_model=TaskTriggerEventParams,
    )
    server.register_method(
        "task.pending_confirmations",
        handlers.handle_task_pending_confirmations,
        admin_only=True,
        params_model=TaskPendingConfirmationsParams,
    )
    server.register_method(
        "action.pending",
        handlers.handle_action_pending,
        admin_only=True,
        params_model=ActionPendingParams,
    )
    server.register_method(
        "action.confirm",
        handlers.handle_action_confirm,
        admin_only=True,
        params_model=ActionDecisionParams,
    )
    server.register_method(
        "action.reject",
        handlers.handle_action_reject,
        admin_only=True,
        params_model=ActionDecisionParams,
    )
    server.register_method(
        "lockdown.set",
        handlers.handle_lockdown_set,
        admin_only=True,
        params_model=LockdownSetParams,
    )
    server.register_method(
        "risk.calibrate",
        handlers.handle_risk_calibrate,
        admin_only=True,
        params_model=NoParams,
    )
    server.register_method(
        "channel.ingest",
        handlers.handle_channel_ingest,
        admin_only=True,
        params_model=ChannelIngestParams,
    )
    server.register_method(
        "tool.execute",
        handlers.handle_tool_execute,
        admin_only=True,
        params_model=ToolExecuteParams,
    )
    server.register_method(
        "browser.paste",
        handlers.handle_browser_paste,
        admin_only=True,
        params_model=BrowserPasteParams,
    )
    server.register_method(
        "browser.screenshot",
        handlers.handle_browser_screenshot,
        admin_only=True,
        params_model=BrowserScreenshotParams,
    )

    async def _matrix_receive_pump() -> None:
        if matrix_channel is None:
            return
        while not shutdown_event.is_set():
            try:
                message = await asyncio.wait_for(matrix_channel.receive(), timeout=0.5)
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Matrix receive loop error")
                await asyncio.sleep(0.2)
                continue

            try:
                await handlers.handle_channel_ingest({"message": message.model_dump(mode="json")})
            except Exception:
                logger.exception("Matrix ingress processing failed")

    await server.start()
    logger.info("shisad daemon started")
    matrix_pump_task: asyncio.Task[None] | None = None
    if matrix_channel is not None:
        matrix_pump_task = asyncio.create_task(_matrix_receive_pump())

    try:
        await shutdown_event.wait()
    finally:
        if matrix_pump_task is not None:
            matrix_pump_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await matrix_pump_task
        embeddings_adapter.close()
        if matrix_channel is not None:
            await matrix_channel.disconnect()
        await server.stop()
        logger.info("shisad daemon stopped")
