"""Admin/control-plane handler implementations."""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast

from shisad.channels.base import ChannelMessage, DeliveryTarget
from shisad.core.events import (
    AnomalyReported,
    ChannelDeliveryAttempted,
    ChannelPairingProposalGenerated,
    ChannelPairingRequested,
    LockdownChanged,
)
from shisad.core.types import SessionId, ToolName, UserId, WorkspaceId
from shisad.daemon.handlers._mixin_typing import HandlerMixinBase
from shisad.executors.sandbox import SandboxType
from shisad.governance.scopes import ScopedPolicy, ScopedPolicyCompiler, ScopeLevel

logger = logging.getLogger(__name__)

_DOCTOR_COMPONENTS: tuple[str, ...] = (
    "dependencies",
    "policy",
    "channels",
    "sandbox",
    "realitycheck",
)


class AdminImplMixin(HandlerMixinBase):
    async def do_daemon_status(self, params: Mapping[str, Any]) -> dict[str, Any]:
        _ = params
        return {
            "status": "running",
            "sessions_active": len(self._session_manager.list_active()),
            "audit_entries": self._audit_log.entry_count,
            "policy_hash": (
                self._policy_loader.file_hash[:12] if self._policy_loader.file_hash else "default"
            ),
            "tools_registered": [tool.name for tool in self._registry.list_tools()],
            "model_routes": dict(self._model_routes),
            "classifier_mode": self._classifier_mode,
            "yara_required": self._policy_loader.policy.yara_required,
            "risk_policy_version": self._policy_loader.policy.risk_policy.version,
            "risk_thresholds": {
                "auto_approve": self._policy_loader.policy.risk_policy.auto_approve_threshold,
                "block": self._policy_loader.policy.risk_policy.block_threshold,
            },
            "channels": {
                "matrix": {
                    "enabled": self._config.matrix_enabled,
                    "available": self._matrix_channel.available if self._matrix_channel else False,
                    "connected": self._matrix_channel.connected if self._matrix_channel else False,
                    "e2ee_enabled": (
                        self._matrix_channel.e2ee_enabled if self._matrix_channel else False
                    ),
                },
                "discord": {
                    "enabled": self._config.discord_enabled,
                    "available": (
                        self._discord_channel.available if self._discord_channel else False
                    ),
                    "connected": (
                        self._discord_channel.connected if self._discord_channel else False
                    ),
                },
                "telegram": {
                    "enabled": self._config.telegram_enabled,
                    "available": (
                        self._telegram_channel.available if self._telegram_channel else False
                    ),
                    "connected": (
                        self._telegram_channel.connected if self._telegram_channel else False
                    ),
                },
                "slack": {
                    "enabled": self._config.slack_enabled,
                    "available": self._slack_channel.available if self._slack_channel else False,
                    "connected": self._slack_channel.connected if self._slack_channel else False,
                },
            },
            "delivery": self._delivery.health_status(),
            "executors": {
                "sandbox_backends": [item.value for item in SandboxType],
                "connect_path": self._sandbox.connect_path_status(),
                "browser": self._browser_sandbox.policy.model_dump(mode="json"),
            },
            "realitycheck": self._realitycheck_toolkit.doctor_status(),
            "provenance": self._provenance_status,
        }

    async def do_policy_explain(self, params: Mapping[str, Any]) -> dict[str, Any]:
        sid_raw = params.get("session_id")
        sid = SessionId(str(sid_raw)) if sid_raw else SessionId("")
        tool_name_raw = str(params.get("tool_name") or "").strip()
        action = str(params.get("action", "")).strip()
        if not tool_name_raw and action.startswith("tool:"):
            tool_name_raw = action.split(":", 1)[1].strip()

        tool_name = ToolName(tool_name_raw or "shell_exec")
        tool_def = self._registry.get_tool(tool_name)
        floor = self._compute_tool_policy_floor(tool_name=tool_name, tool_definition=tool_def)
        compiled = ScopedPolicyCompiler.compile_chain(
            [
                ScopedPolicy(
                    level=ScopeLevel.ORG,
                    constraints=floor,
                    defaults={"action": action},
                    preferences={},
                )
            ]
        )
        return {
            "session_id": str(sid),
            "tool_name": str(tool_name),
            "action": action,
            "effective_policy": compiled.effective.model_dump(mode="json"),
            "control_plane": self._policy_loader.policy.control_plane.model_dump(mode="json"),
            "contributors": {key: value.value for key, value in compiled.contributors.items()},
        }

    async def do_daemon_shutdown(self, params: Mapping[str, Any]) -> dict[str, Any]:
        _ = params
        self._shutdown_event.set()
        return {"status": "shutting_down"}
    async def do_doctor_check(self, params: Mapping[str, Any]) -> dict[str, Any]:
        component = str(params.get("component", "all")).strip().lower() or "all"
        component_factories = {
            "dependencies": self._doctor_dependencies_status,
            "policy": self._doctor_policy_status,
            "channels": self._doctor_channels_status,
            "sandbox": self._doctor_sandbox_status,
            "realitycheck": self._realitycheck_toolkit.doctor_status,
        }

        def _run_component(name: str) -> dict[str, Any]:
            factory = component_factories[name]
            try:
                payload = factory()
            except Exception as exc:
                logger.exception("doctor check component failed: %s", name)
                return {
                    "status": "error",
                    "problems": [f"component_failed:{exc.__class__.__name__}"],
                }
            if not isinstance(payload, Mapping):
                return {
                    "status": "error",
                    "problems": ["component_returned_non_mapping"],
                }
            normalized = dict(payload)
            if "status" not in normalized:
                normalized["status"] = "error"
            if "problems" not in normalized:
                normalized["problems"] = []
            return normalized

        checks: dict[str, Any] = {}
        if component == "all":
            for key in _DOCTOR_COMPONENTS:
                checks[key] = _run_component(key)
        elif component in component_factories:
            checks[component] = _run_component(component)
        else:
            return {
                "status": "error",
                "component": component,
                "checks": {},
                "error": "unsupported_component",
            }
        check_states = [
            str(item.get("status", "error"))
            for item in checks.values()
            if isinstance(item, Mapping)
        ]
        overall = "ok"
        if any(state in {"misconfigured", "degraded", "error"} for state in check_states):
            overall = "degraded"
        return {
            "status": overall,
            "component": component,
            "checks": checks,
            "error": "",
        }
    async def do_lockdown_set(self, params: Mapping[str, Any]) -> dict[str, Any]:
        sid = SessionId(str(params.get("session_id", "")))
        action = str(params.get("action", "caution"))
        reason = str(params.get("reason", "manual"))
        normalized = action.strip().lower()
        if normalized in {"resume", "normal", "clear"}:
            state = self._lockdown_manager.resume(sid, reason=reason)
        else:
            state = self._lockdown_manager.set_level(
                sid,
                level=self._lockdown_manager.level_for_action(normalized, trigger="manual"),
                reason=reason,
                trigger="manual",
            )
        await self._event_bus.publish(
            LockdownChanged(
                session_id=sid,
                actor="lockdown",
                level=state.level.value,
                reason=state.reason,
                trigger=state.trigger,
            )
        )
        state = self._lockdown_manager.state_for(sid)
        return {"session_id": sid, "level": state.level.value, "reason": state.reason}

    async def do_risk_calibrate(self, params: Mapping[str, Any]) -> dict[str, Any]:
        _ = params
        updated = self._risk_calibrator.calibrate()
        self._policy_loader.policy.risk_policy.version = updated.version
        self._policy_loader.policy.risk_policy.auto_approve_threshold = (
            updated.thresholds.auto_approve_threshold
        )
        self._policy_loader.policy.risk_policy.block_threshold = updated.thresholds.block_threshold
        return cast(dict[str, Any], updated.model_dump(mode="json"))

    async def do_channel_pairing_propose(self, params: Mapping[str, Any]) -> dict[str, Any]:
        limit = max(1, int(params.get("limit", 100)))
        channel_filter = str(params.get("channel") or "").strip().lower()
        workspace_filter = str(params.get("workspace_hint") or "").strip()
        rows, invalid_entries = self._load_pairing_request_artifacts(limit=max(limit * 5, limit))
        deduped: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for row in rows:
            channel = str(row.get("channel", "")).strip().lower()
            external_user_id = str(row.get("external_user_id", "")).strip()
            workspace_hint = str(row.get("workspace_hint", "")).strip()
            if channel_filter and channel != channel_filter:
                continue
            if workspace_filter and workspace_hint != workspace_filter:
                continue
            key = (channel, external_user_id)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(
                {
                    "channel": channel,
                    "external_user_id": external_user_id,
                    "workspace_hint": workspace_hint,
                    "reason": str(row.get("reason", "identity_not_allowlisted")),
                }
            )
            if len(deduped) >= limit:
                break

        config_patch: dict[str, list[str]] = {}
        for item in deduped:
            channel = item["channel"]
            config_patch.setdefault(channel, [])
            config_patch[channel].append(item["external_user_id"])
        for channel, external_user_ids in list(config_patch.items()):
            config_patch[channel] = sorted({value for value in external_user_ids if value.strip()})

        proposal_id = uuid.uuid4().hex
        generated_at = datetime.now(UTC).isoformat()
        proposal_dir = self._config.data_dir / "proposals" / "channel_pairing"
        proposal_dir.mkdir(parents=True, exist_ok=True)
        proposal_path = proposal_dir / f"{proposal_id}.json"
        proposal_payload = {
            "proposal_id": proposal_id,
            "generated_at": generated_at,
            "source": "pairing_requests_artifact",
            "filters": {
                "channel": channel_filter,
                "workspace_hint": workspace_filter,
                "limit": limit,
            },
            "entries": deduped,
            "invalid_entries": invalid_entries,
            "config_patch": {"channel_identity_allowlist": config_patch},
            "applied": False,
        }
        proposal_path.write_text(
            json.dumps(proposal_payload, ensure_ascii=True, indent=2),
            encoding="utf-8",
        )
        await self._event_bus.publish(
            ChannelPairingProposalGenerated(
                session_id=None,
                actor="control_api",
                proposal_id=proposal_id,
                proposal_path=str(proposal_path),
                entries_count=len(deduped),
            )
        )
        return {
            "proposal_id": proposal_id,
            "proposal_path": str(proposal_path),
            "generated_at": generated_at,
            "entries": deduped,
            "invalid_entries": invalid_entries,
            "count": len(deduped),
            "config_patch": config_patch,
            "applied": False,
        }

    async def do_channel_ingest(self, params: Mapping[str, Any]) -> dict[str, Any]:
        message = ChannelMessage.model_validate(params.get("message", {}))
        if self._matrix_channel is not None and message.channel == "matrix":
            room_hint = message.workspace_hint or self._config.matrix_room_id
            message = message.model_copy(
                update={"workspace_hint": self._matrix_channel.workspace_for_room(room_hint)}
            )
        elif self._discord_channel is not None and message.channel == "discord":
            discord_workspace = self._discord_channel.workspace_for_guild(message.workspace_hint)
            message = message.model_copy(
                update={"workspace_hint": discord_workspace}
            )
        elif self._telegram_channel is not None and message.channel == "telegram":
            telegram_workspace = self._telegram_channel.workspace_for_chat(message.workspace_hint)
            message = message.model_copy(
                update={"workspace_hint": telegram_workspace}
            )
        elif self._slack_channel is not None and message.channel == "slack":
            slack_workspace = self._slack_channel.workspace_for_team(message.workspace_hint)
            message = message.model_copy(
                update={"workspace_hint": slack_workspace}
            )

        if not self._identity_map.is_allowed(
            channel=message.channel,
            external_user_id=message.external_user_id,
        ):
            pairing, is_new = self._identity_map.record_pairing_request(
                channel=message.channel,
                external_user_id=message.external_user_id,
                workspace_hint=message.workspace_hint,
                reason="identity_not_allowlisted",
            )
            if is_new:
                self._record_pairing_request_artifact(
                    channel=pairing.channel,
                    external_user_id=pairing.external_user_id,
                    workspace_hint=pairing.workspace_hint,
                    reason=pairing.reason,
                )
                await self._event_bus.publish(
                    ChannelPairingRequested(
                        actor="channel_ingest",
                        channel=pairing.channel,
                        external_user_id=pairing.external_user_id,
                        workspace_hint=pairing.workspace_hint,
                        reason=pairing.reason,
                    )
                )
            return {
                "session_id": "",
                "response": (
                    "Identity is not allowlisted for this channel. "
                    "Pairing request recorded for trusted admin review."
                ),
                "plan_hash": None,
                "risk_score": 0.0,
                "blocked_actions": 0,
                "confirmation_required_actions": 0,
                "executed_actions": 0,
                "checkpoint_ids": [],
                "checkpoints_created": 0,
                "transcript_root": str(self._transcript_root),
                "lockdown_level": "normal",
                "trust_level": "untrusted",
                "pending_confirmation_ids": [],
                "output_policy": {},
                "ingress_risk": 0.0,
                "delivery": {
                    "attempted": False,
                    "sent": False,
                    "reason": "identity_not_allowlisted",
                    "target": {},
                },
            }

        declared_trust = self._identity_map.trust_for_channel(message.channel)
        if self._is_verified_channel_identity(
            channel=message.channel,
            external_user_id=message.external_user_id,
        ):
            declared_trust = "trusted"
        if not declared_trust:
            declared_trust = "untrusted"

        identity = self._identity_map.resolve(
            channel=message.channel,
            external_user_id=message.external_user_id,
        )
        if identity is None:
            self._identity_map.bind(
                channel=message.channel,
                external_user_id=message.external_user_id,
                user_id=UserId(message.external_user_id),
                workspace_id=WorkspaceId(message.workspace_hint or message.channel),
                trust_level=declared_trust,
            )
            identity = self._identity_map.resolve(
                channel=message.channel,
                external_user_id=message.external_user_id,
            )
        elif declared_trust != identity.trust_level:
            self._identity_map.bind(
                channel=message.channel,
                external_user_id=message.external_user_id,
                user_id=identity.user_id,
                workspace_id=identity.workspace_id,
                trust_level=declared_trust,
            )
            identity = self._identity_map.resolve(
                channel=message.channel,
                external_user_id=message.external_user_id,
            )
        if identity is None:
            raise ValueError("failed to resolve channel identity")

        trusted_input = identity.trust_level.strip().lower() in {"trusted", "verified", "internal"}
        _sanitized, result = self._channel_ingress.process(message, trusted_input=trusted_input)
        delivery_target = DeliveryTarget(
            channel=message.channel,
            recipient=message.reply_target or message.external_user_id,
            workspace_hint=message.workspace_hint,
            thread_id=message.thread_id,
        )
        sid = SessionId(str(params.get("session_id", "")))
        if not sid or self._session_manager.get(sid) is None:
            existing = self._session_manager.find_by_binding(
                channel=message.channel,
                user_id=identity.user_id,
                workspace_id=identity.workspace_id,
            )
            if existing is not None:
                sid = existing.id
        if not sid or self._session_manager.get(sid) is None:
            created = await self.do_session_create(
                {
                    "channel": message.channel,
                    "user_id": identity.user_id,
                    "workspace_id": identity.workspace_id,
                    "trust_level": identity.trust_level,
                    "_internal_ingress_marker": self._internal_ingress_marker,
                    "_delivery_target": delivery_target.model_dump(mode="json"),
                }
            )
            sid = SessionId(created["session_id"])
        response = await self.do_session_message(
            {
                "session_id": sid,
                "channel": message.channel,
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "content": message.content,
                "trust_level": identity.trust_level,
                "_internal_ingress_marker": self._internal_ingress_marker,
                "_firewall_result": result.model_dump(mode="json"),
                "_delivery_target": delivery_target.model_dump(mode="json"),
                "_channel_message_id": message.message_id,
            }
        )
        delivery_result = await self._delivery.send(
            target=delivery_target,
            message=str(response.get("response", "")),
        )
        response["delivery"] = delivery_result.as_dict()
        await self._event_bus.publish(
            ChannelDeliveryAttempted(
                session_id=sid,
                actor="channel_delivery",
                channel=delivery_target.channel,
                recipient=delivery_target.recipient,
                workspace_hint=delivery_target.workspace_hint,
                thread_id=delivery_target.thread_id,
                sent=delivery_result.sent,
                reason=delivery_result.reason,
            )
        )
        if not delivery_result.sent:
            await self._event_bus.publish(
                AnomalyReported(
                    session_id=sid,
                    actor="channel_delivery",
                    severity="warning",
                    description=(
                        f"Failed to deliver channel response via {message.channel} "
                        f"({delivery_result.reason})"
                    ),
                    recommended_action="check_channel_connectivity",
                )
            )
        response["ingress_risk"] = result.risk_score
        return cast(dict[str, Any], response)
