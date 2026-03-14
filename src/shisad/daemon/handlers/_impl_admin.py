"""Admin/control-plane handler implementations."""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from shisad.channels.base import ChannelMessage, DeliveryTarget
from shisad.core.events import (
    AnomalyReported,
    ChannelDeliveryAttempted,
    ChannelPairingProposalGenerated,
    ChannelPairingRequested,
    LockdownChanged,
)
from shisad.core.tools.names import canonical_tool_name_typed
from shisad.core.types import SessionId, UserId, WorkspaceId
from shisad.daemon.handlers._mixin_typing import HandlerMixinBase
from shisad.devloop import assess_milestone_readiness
from shisad.executors.sandbox import SandboxType
from shisad.governance.scopes import ScopedPolicy, ScopedPolicyCompiler, ScopeLevel

logger = logging.getLogger(__name__)

_DOCTOR_COMPONENTS: tuple[str, ...] = (
    "dependencies",
    "provider",
    "policy",
    "channels",
    "sandbox",
    "realitycheck",
)


def _normalized_text_sequence(raw_values: Any) -> tuple[str, ...]:
    if not isinstance(raw_values, list):
        return ()
    values: list[str] = []
    for item in raw_values:
        normalized = str(item).strip()
        if normalized:
            values.append(normalized)
    return tuple(values)


def _review_findings_from_summary(summary: str) -> list[str]:
    findings: list[str] = []
    for raw_line in summary.splitlines():
        candidate = raw_line.strip().lstrip("-* ").strip()
        if candidate:
            findings.append(candidate)
    return findings


class AdminImplMixin(HandlerMixinBase):
    async def _run_dev_coding_task(
        self,
        *,
        params: Mapping[str, Any],
        operation: str,
        task_description: str,
        file_refs: tuple[str, ...],
        task_kind: str,
        read_only: bool,
    ) -> dict[str, Any]:
        rpc_peer = params.get("_rpc_peer")
        session_payload: dict[str, Any] = {
            "channel": "cli",
            "user_id": "ops",
            "workspace_id": "default",
        }
        if isinstance(rpc_peer, Mapping):
            session_payload["_rpc_peer"] = dict(rpc_peer)

        created = await self.do_session_create(session_payload)
        command_session_id = str(created.get("session_id", "")).strip()
        if not command_session_id:
            raise RuntimeError(f"dev.{operation} failed to create a command session")

        try:
            delegated_task: dict[str, Any] = {
                "enabled": True,
                "executor": "coding_agent",
                "task_description": task_description,
                "file_refs": list(file_refs),
                "task_kind": task_kind,
                "read_only": read_only,
                "handoff_mode": "summary_only",
            }
            preferred_agent = str(params.get("agent", "")).strip()
            if preferred_agent:
                delegated_task["preferred_agent"] = preferred_agent
            fallback_agents = _normalized_text_sequence(params.get("fallback_agents"))
            if fallback_agents:
                delegated_task["fallback_agents"] = list(fallback_agents)
            capabilities = _normalized_text_sequence(params.get("capabilities"))
            if capabilities:
                delegated_task["capabilities"] = list(capabilities)
            max_turns = params.get("max_turns")
            if max_turns is not None:
                delegated_task["max_turns"] = int(max_turns)
            max_budget = params.get("max_budget_usd")
            if max_budget is not None:
                delegated_task["max_budget_usd"] = float(max_budget)
            model = str(params.get("model", "")).strip()
            if model:
                delegated_task["model"] = model
            reasoning_effort = str(params.get("reasoning_effort", "")).strip()
            if reasoning_effort:
                delegated_task["reasoning_effort"] = reasoning_effort
            timeout_sec = params.get("timeout_sec")
            if timeout_sec is not None:
                delegated_task["timeout_sec"] = float(timeout_sec)

            message_payload: dict[str, Any] = {
                "session_id": command_session_id,
                "content": f"Run dev.{operation} through a delegated coding-agent task.",
                "channel": "cli",
                "user_id": session_payload["user_id"],
                "workspace_id": session_payload["workspace_id"],
                "task": delegated_task,
            }
            if isinstance(rpc_peer, Mapping):
                message_payload["_rpc_peer"] = dict(rpc_peer)

            response = await self.do_session_message(message_payload)
        finally:
            terminate_payload: dict[str, Any] = {
                "session_id": command_session_id,
                "reason": f"dev_{operation}_complete",
                "channel": "cli",
                "user_id": session_payload["user_id"],
                "workspace_id": session_payload["workspace_id"],
            }
            if isinstance(rpc_peer, Mapping):
                terminate_payload["_rpc_peer"] = dict(rpc_peer)
            try:
                await self.do_session_terminate(terminate_payload)
            except Exception:
                logger.warning(
                    "Failed to terminate dev.%s command session %s",
                    operation,
                    command_session_id,
                    exc_info=True,
                )

        task_result = response.get("task_result")
        if not isinstance(task_result, Mapping):
            raise RuntimeError(f"dev.{operation} did not return a delegated task result")
        result = dict(task_result)
        result["operation"] = operation
        return result

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
            "selfmod": self._selfmod_manager.status(),
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

        tool_name = canonical_tool_name_typed(tool_name_raw or "shell.exec")
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

    async def do_admin_selfmod_propose(self, params: Mapping[str, Any]) -> dict[str, Any]:
        artifact_path_raw = str(params.get("artifact_path", "")).strip()
        if not artifact_path_raw:
            raise ValueError("artifact_path is required")
        artifact_path = Path(artifact_path_raw)
        proposal = self._selfmod_manager.propose(artifact_path)
        return cast(dict[str, Any], proposal.model_dump(mode="json"))

    async def do_admin_selfmod_apply(self, params: Mapping[str, Any]) -> dict[str, Any]:
        proposal_id = str(params.get("proposal_id", "")).strip()
        if not proposal_id:
            raise ValueError("proposal_id is required")
        result = self._selfmod_manager.apply(
            proposal_id,
            confirm=bool(params.get("confirm", False)),
        )
        return cast(dict[str, Any], result.model_dump(mode="json"))

    async def do_admin_selfmod_rollback(self, params: Mapping[str, Any]) -> dict[str, Any]:
        change_id = str(params.get("change_id", "")).strip()
        if not change_id:
            raise ValueError("change_id is required")
        result = self._selfmod_manager.rollback(change_id)
        return cast(dict[str, Any], result.model_dump(mode="json"))

    async def do_dev_implement(self, params: Mapping[str, Any]) -> dict[str, Any]:
        task = str(params.get("task", "")).strip()
        if not task:
            raise ValueError("task is required")
        return await self._run_dev_coding_task(
            params=params,
            operation="implement",
            task_description=task,
            file_refs=_normalized_text_sequence(params.get("file_refs")),
            task_kind="implement",
            read_only=False,
        )

    async def do_dev_review(self, params: Mapping[str, Any]) -> dict[str, Any]:
        scope = str(params.get("scope", "")).strip()
        if not scope:
            raise ValueError("scope is required")
        result = await self._run_dev_coding_task(
            params=params,
            operation="review",
            task_description=scope,
            file_refs=_normalized_text_sequence(params.get("file_refs")),
            task_kind="review",
            read_only=True,
        )
        result["findings"] = _review_findings_from_summary(str(result.get("summary", "")))
        return result

    async def do_dev_remediate(self, params: Mapping[str, Any]) -> dict[str, Any]:
        findings = str(params.get("findings", "")).strip()
        if not findings:
            raise ValueError("findings is required")
        return await self._run_dev_coding_task(
            params=params,
            operation="remediate",
            task_description=f"Remediate the following findings:\n{findings}",
            file_refs=_normalized_text_sequence(params.get("file_refs")),
            task_kind="implement",
            read_only=False,
        )

    async def do_dev_close(self, params: Mapping[str, Any]) -> dict[str, Any]:
        milestone = str(params.get("milestone", "")).strip()
        if not milestone:
            raise ValueError("milestone is required")
        implementation_path_raw = str(params.get("implementation_path", "")).strip()
        if implementation_path_raw:
            implementation_path = Path(implementation_path_raw)
            if not implementation_path.is_absolute():
                implementation_path = self._config.coding_repo_root / implementation_path
        else:
            implementation_path = (
                self._config.coding_repo_root / "docs" / "v0.4" / "IMPLEMENTATION.md"
            )
        report = assess_milestone_readiness(
            implementation_path=implementation_path,
            milestone=milestone,
        )
        return {
            "milestone": report.milestone,
            "implementation_path": str(report.implementation_path),
            "ready": report.ready,
            "section_found": report.section_found,
            "runtime_wiring_recorded": report.runtime_wiring_recorded,
            "validation_recorded": report.validation_recorded,
            "docs_parity_recorded": report.docs_parity_recorded,
            "worklog_updated": report.worklog_updated,
            "review_status_recorded": report.review_status_recorded,
            "punchlist_complete": report.punchlist_complete,
            "acceptance_checklist_complete": report.acceptance_checklist_complete,
            "missing_evidence": list(report.missing_evidence),
            "unchecked_items": list(report.unchecked_items),
            "open_finding_ids": list(report.open_finding_ids),
        }

    async def do_doctor_check(self, params: Mapping[str, Any]) -> dict[str, Any]:
        component = str(params.get("component", "all")).strip().lower() or "all"
        component_factories = {
            "dependencies": self._doctor_dependencies_status,
            "provider": self._doctor_provider_status,
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
