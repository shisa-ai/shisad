"""Daemon runner — main event loop for shisad.

Wires up control API, policy, planner, firewall, transcript store, and PEP.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from shisad.core.api.transport import ControlServer
from shisad.core.audit import AuditLog
from shisad.core.config import DaemonConfig
from shisad.core.events import (
    CapabilityGranted,
    EventBus,
    SessionCreated,
    ToolProposed,
    ToolRejected,
)
from shisad.core.planner import Planner
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.session import SessionManager
from shisad.core.tools.registry import ToolRegistry
from shisad.core.transcript import TranscriptStore
from shisad.core.types import Capability, SessionId, UserId, WorkspaceId
from shisad.memory.ingestion import IngestionPipeline, RetrieveRagTool
from shisad.security.firewall import ContentFirewall
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyLoader

logger = logging.getLogger(__name__)


class _LocalPlannerProvider:
    """Local fallback planner provider for daemon operation.

    Produces strict JSON response without side effects. Real provider routing
    is added in later milestones.
    """

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        user_content = messages[-1].content if messages else ""
        payload = {
            "assistant_response": f"Safe summary: {user_content[:300]}",
            "actions": [],
        }
        return ProviderResponse(
            message=Message(role="assistant", content=json.dumps(payload)),
            finish_reason="stop",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )


async def run_daemon(config: DaemonConfig) -> None:
    """Run the shisad daemon."""
    logging.basicConfig(level=getattr(logging, config.log_level.upper(), logging.INFO))

    # --- Initialize subsystems ---

    audit_path = config.data_dir / "audit.jsonl"
    audit_log = AuditLog(audit_path)
    event_bus = EventBus(persister=audit_log)

    policy_loader = PolicyLoader(config.policy_path)
    policy_loader.load()
    policy_loader.register_reload_signal()

    transcript_root = config.data_dir / "sessions"
    transcript_store = TranscriptStore(transcript_root)

    def _audit_capability_event(action: str, data: dict[str, Any]) -> None:
        logger.info("%s: %s", action, data)
        if action != "session.capability_granted":
            return
        event = CapabilityGranted(
            session_id=SessionId(str(data.get("session_id", ""))),
            actor="session_manager",
            capabilities=list(data.get("granted", [])),
            granted_by=str(data.get("actor", "")),
            reason=str(data.get("reason", "")),
        )
        task = asyncio.create_task(event_bus.publish(event))
        task.add_done_callback(lambda _task: None)

    session_manager = SessionManager(audit_hook=_audit_capability_event)
    firewall = ContentFirewall()

    ingestion = IngestionPipeline(config.data_dir / "memory")
    registry = ToolRegistry()
    registry.register(RetrieveRagTool.tool_definition())

    pep = PEP(policy_loader.policy, registry)
    planner = Planner(_LocalPlannerProvider(), pep)

    shutdown_event = asyncio.Event()
    server = ControlServer(config.socket_path)

    # --- Control API handlers ---

    async def handle_session_create(params: dict[str, Any]) -> dict[str, Any]:
        session = session_manager.create(
            channel=params.get("channel", "cli"),
            user_id=UserId(params.get("user_id", "")),
            workspace_id=WorkspaceId(params.get("workspace_id", "")),
        )
        await event_bus.publish(
            SessionCreated(
                session_id=session.id,
                user_id=session.user_id,
                workspace_id=session.workspace_id,
                actor="control_api",
            )
        )
        return {"session_id": session.id}

    async def handle_session_message(params: dict[str, Any]) -> dict[str, Any]:
        sid = SessionId(params.get("session_id", ""))
        content = params.get("content", "")
        session = session_manager.get(sid)
        if session is None:
            raise ValueError(f"Unknown session: {sid}")

        channel = params.get("channel", "cli")
        user_id = UserId(params.get("user_id", session.user_id))
        workspace_id = WorkspaceId(params.get("workspace_id", session.workspace_id))
        if not session_manager.validate_identity_binding(
            sid,
            channel=channel,
            user_id=user_id,
            workspace_id=workspace_id,
        ):
            raise ValueError("Session identity binding mismatch")

        firewall_result = firewall.inspect(content)
        transcript_store.append(
            sid,
            role="user",
            content=firewall_result.sanitized_text,
            taint_labels=set(firewall_result.taint_labels),
        )

        context = PolicyContext(
            capabilities=session.capabilities,
            taint_labels=set(firewall_result.taint_labels),
            workspace_id=session.workspace_id,
            user_id=session.user_id,
        )

        planner_result = await planner.propose(firewall_result.sanitized_text, context)

        rejected = 0
        for evaluated in planner_result.evaluated:
            await event_bus.publish(
                ToolProposed(
                    session_id=sid,
                    actor="planner",
                    tool_name=evaluated.proposal.tool_name,
                    arguments=evaluated.proposal.arguments,
                )
            )
            if evaluated.decision.kind.value == "reject":
                rejected += 1
                await event_bus.publish(
                    ToolRejected(
                        session_id=sid,
                        actor="pep",
                        tool_name=evaluated.proposal.tool_name,
                        reason=evaluated.decision.reason,
                    )
                )

        transcript_store.append(
            sid,
            role="assistant",
            content=planner_result.output.assistant_response,
            taint_labels=set(),
        )

        return {
            "session_id": sid,
            "response": planner_result.output.assistant_response,
            "risk_score": firewall_result.risk_score,
            "blocked_actions": rejected,
            "transcript_root": str(transcript_root),
        }

    async def handle_session_list(params: dict[str, Any]) -> dict[str, Any]:
        sessions = session_manager.list_active()
        return {
            "sessions": [
                {
                    "id": s.id,
                    "state": s.state,
                    "user_id": s.user_id,
                    "workspace_id": s.workspace_id,
                    "channel": s.channel,
                    "session_key": s.session_key,
                    "created_at": s.created_at.isoformat(),
                }
                for s in sessions
            ]
        }

    async def handle_session_grant_capabilities(params: dict[str, Any]) -> dict[str, Any]:
        sid = SessionId(params.get("session_id", ""))
        actor = params.get("actor", "control_api")
        reason = params.get("reason", "")
        raw_caps = params.get("capabilities", [])
        capabilities = {Capability(value) for value in raw_caps}
        granted = session_manager.grant_capabilities(
            sid,
            capabilities,
            actor=actor,
            reason=reason,
        )
        return {"session_id": sid, "granted": granted, "capabilities": sorted(raw_caps)}

    async def handle_daemon_status(params: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": "running",
            "sessions_active": len(session_manager.list_active()),
            "audit_entries": audit_log.entry_count,
            "policy_hash": policy_loader.file_hash[:12] if policy_loader.file_hash else "default",
            "tools_registered": [tool.name for tool in registry.list_tools()],
        }

    async def handle_daemon_shutdown(params: dict[str, Any]) -> dict[str, Any]:
        shutdown_event.set()
        return {"status": "shutting_down"}

    async def handle_audit_query(params: dict[str, Any]) -> dict[str, Any]:
        results = audit_log.query(
            event_type=params.get("event_type"),
            session_id=params.get("session_id"),
            limit=params.get("limit", 100),
        )
        return {"events": results, "total": len(results)}

    async def handle_memory_ingest(params: dict[str, Any]) -> dict[str, Any]:
        result = ingestion.ingest(
            source_id=params.get("source_id", ""),
            source_type=params.get("source_type", "user"),
            content=params.get("content", ""),
        )
        return result.model_dump(mode="json")

    async def handle_memory_retrieve(params: dict[str, Any]) -> dict[str, Any]:
        query = params.get("query", "")
        limit = int(params.get("limit", 5))
        results = ingestion.retrieve(query, limit=limit)
        return {
            "results": [item.model_dump(mode="json") for item in results],
            "count": len(results),
        }

    server.register_method("session.create", handle_session_create)
    server.register_method("session.message", handle_session_message)
    server.register_method("session.list", handle_session_list)
    server.register_method("session.grant_capabilities", handle_session_grant_capabilities)
    server.register_method("daemon.status", handle_daemon_status)
    server.register_method("daemon.shutdown", handle_daemon_shutdown)
    server.register_method("audit.query", handle_audit_query)
    server.register_method("memory.ingest", handle_memory_ingest)
    server.register_method("memory.retrieve", handle_memory_retrieve)

    await server.start()
    logger.info("shisad daemon started")

    try:
        await shutdown_event.wait()
    finally:
        await server.stop()
        logger.info("shisad daemon stopped")
