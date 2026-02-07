"""Daemon runner — main event loop for shisad.

Wires up the control API, event bus, audit log, session manager,
and policy loader. Handles graceful shutdown.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from shisad.core.api.transport import ControlServer
from shisad.core.audit import AuditLog
from shisad.core.config import DaemonConfig
from shisad.core.events import EventBus, SessionCreated
from shisad.core.session import SessionManager
from shisad.core.types import SessionId, UserId, WorkspaceId
from shisad.security.policy import PolicyLoader

logger = logging.getLogger(__name__)


async def run_daemon(config: DaemonConfig) -> None:
    """Run the shisad daemon."""
    logging.basicConfig(level=getattr(logging, config.log_level.upper(), logging.INFO))

    # --- Initialize subsystems ---

    # Audit log (persistence backend for events)
    audit_path = config.data_dir / "audit.jsonl"
    audit_log = AuditLog(audit_path)

    # Event bus (wired to audit log)
    event_bus = EventBus(persister=audit_log)

    # Policy loader
    policy_loader = PolicyLoader(config.policy_path)
    policy_loader.load()
    policy_loader.register_reload_signal()

    # Session manager
    session_manager = SessionManager()

    # Shutdown event
    shutdown_event = asyncio.Event()

    # --- Control API ---

    server = ControlServer(config.socket_path)

    # Register methods
    async def handle_session_create(params: dict[str, Any]) -> dict[str, Any]:
        session = session_manager.create(
            user_id=UserId(params.get("user_id", "")),
            workspace_id=WorkspaceId(params.get("workspace_id", "")),
        )
        await event_bus.publish(
            SessionCreated(
                session_id=session.id,
                user_id=session.user_id,
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
        # Stub response for M0 — real planner integration comes in M1
        return {"session_id": sid, "response": f"[stub] Received: {content}"}

    async def handle_session_list(params: dict[str, Any]) -> dict[str, Any]:
        sessions = session_manager.list_active()
        return {
            "sessions": [
                {
                    "id": s.id,
                    "state": s.state,
                    "user_id": s.user_id,
                    "created_at": s.created_at.isoformat(),
                }
                for s in sessions
            ]
        }

    async def handle_daemon_status(params: dict[str, Any]) -> dict[str, Any]:
        return {
            "status": "running",
            "sessions_active": len(session_manager.list_active()),
            "audit_entries": audit_log.entry_count,
            "policy_hash": policy_loader.file_hash[:12] if policy_loader.file_hash else "default",
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

    server.register_method("session.create", handle_session_create)
    server.register_method("session.message", handle_session_message)
    server.register_method("session.list", handle_session_list)
    server.register_method("daemon.status", handle_daemon_status)
    server.register_method("daemon.shutdown", handle_daemon_shutdown)
    server.register_method("audit.query", handle_audit_query)

    # --- Start ---

    await server.start()
    logger.info("shisad daemon started")

    try:
        await shutdown_event.wait()
    finally:
        await server.stop()
        logger.info("shisad daemon stopped")
