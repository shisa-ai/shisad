"""Admin/control-plane handler implementations."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, cast
from urllib.parse import unquote

from shisad.channels.base import ChannelMessage, DeliveryTarget
from shisad.channels.discord_policy import DiscordChannelPolicy, DiscordChannelPolicyDecision
from shisad.core.events import (
    AnomalyReported,
    ChannelDeliveryAttempted,
    ChannelPairingProposalGenerated,
    ChannelPairingRequested,
    LockdownChanged,
    SessionMessageReceived,
)
from shisad.core.soul import (
    load_effective_persona_text,
    load_soul_text,
    soul_content_warnings,
    soul_text_sha256,
    write_soul_text,
)
from shisad.core.tools.names import canonical_tool_name_typed
from shisad.core.types import Capability, SessionId, TaintLabel, UserId, WorkspaceId
from shisad.daemon.handlers._mixin_typing import HandlerMixinBase
from shisad.devloop import assess_milestone_readiness
from shisad.executors.sandbox import SandboxType
from shisad.governance.scopes import ScopedPolicy, ScopedPolicyCompiler, ScopeLevel
from shisad.memory.ingress import (
    DerivationPath,
    ScopeKind,
    mint_explicit_user_memory_ingress_context,
)
from shisad.memory.participation import (
    ChannelParticipationStateValue,
    ChannelSummaryValue,
    InboxItemValue,
    PersonNoteValue,
    ResponseFeedbackEventValue,
    TrackedThreadState,
    channel_participation_key,
    channel_summary_key,
    compose_channel_binding,
    inbox_item_key,
    normalize_structured_memory_value,
    person_note_key,
    response_feedback_key,
)
from shisad.memory.remap import digest_memory_value, legacy_source_view_origin
from shisad.memory.schema import MemorySource

logger = logging.getLogger(__name__)

_DOCTOR_COMPONENTS: tuple[str, ...] = (
    "dependencies",
    "provider",
    "policy",
    "channels",
    "sandbox",
    "realitycheck",
)

_PUBLIC_DISCORD_TOOL_ALLOWLIST: frozenset[str] = frozenset(
    {
        "web.search",
        "web.fetch",
        "realitycheck.search",
        "realitycheck.read",
    }
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


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _is_public_channel_trust(trust_level: str) -> bool:
    return trust_level.strip().lower() in {"public", "trusted_guest"}


def _is_owner_like_channel_trust(trust_level: str) -> bool:
    return trust_level.strip().lower() in {"trusted", "verified", "internal", "owner"}


def _discord_policy_from_config(config: Any) -> DiscordChannelPolicy:
    return DiscordChannelPolicy(tuple(getattr(config, "discord_channel_rules", []) or ()))


def _channel_policy_payload(
    *,
    decision: DiscordChannelPolicyDecision,
    guild_id: str,
    channel_id: str,
    proactive: bool = False,
    ephemeral_session: bool = False,
    owner_private_context_excluded: bool = False,
    reason: str = "",
) -> dict[str, Any]:
    return {
        "guild_id": guild_id,
        "channel_id": channel_id,
        "engagement_mode": decision.engagement_mode,
        "trust_level": decision.trust_level,
        "allowed_tools": list(decision.allowed_tools),
        "public_access": bool(decision.public_access),
        "denied": bool(decision.denied),
        "reason": reason or decision.reason,
        "proactive": proactive,
        "cooldown_seconds": float(decision.cooldown_seconds),
        "ephemeral_session": ephemeral_session,
        "owner_private_context_excluded": owner_private_context_excluded,
    }


def _review_findings_from_summary(summary: str) -> list[str]:
    findings: list[str] = []
    for raw_line in summary.splitlines():
        candidate = raw_line.strip().lstrip("-* ").strip()
        if candidate:
            findings.append(candidate)
    return findings


def _is_legacy_bare_channel_id(value: str) -> bool:
    normalized = str(value).strip()
    return (
        bool(normalized)
        and ":" not in normalized
        and "/" not in normalized
        and "\\" not in normalized
    )


def _migrated_channel_memory_key(
    *,
    entry_type: str,
    key: str,
    value: Mapping[str, Any],
    structured_channel_id: str,
) -> str:
    if entry_type == "person_note":
        return person_note_key(
            channel_id=structured_channel_id,
            external_user_id=str(value.get("external_user_id") or "").strip(),
        )
    if entry_type == "channel_summary":
        return channel_summary_key(
            channel_id=structured_channel_id,
            summary_kind=str(value.get("summary_kind") or "topic").strip() or "topic",
        )
    if entry_type == "channel_participation":
        prefix = "channel-participation:"
        encoded_parts = key[len(prefix) :].split(":") if key.startswith(prefix) else []
        thread_id = unquote(encoded_parts[1]).strip() if len(encoded_parts) > 1 else ""
        return channel_participation_key(
            channel_id=structured_channel_id,
            thread_id=thread_id or None,
        )
    return key


class AdminImplMixin(HandlerMixinBase):
    _KEYED_CHANNEL_STATE_ENTRY_TYPES: ClassVar[set[str]] = {
        "channel_participation",
        "person_note",
        "channel_summary",
    }

    def _channel_memory_owner_id(self, *, channel: str) -> str:
        trusted_users_attr = {
            "discord": "discord_trusted_users",
            "slack": "slack_trusted_users",
            "matrix": "matrix_trusted_users",
            "telegram": "telegram_trusted_users",
        }.get(channel.strip().lower(), "")
        if trusted_users_attr:
            raw_users = getattr(self._config, trusted_users_attr, []) or []
            for raw_user in raw_users:
                owner_id = str(raw_user).strip()
                if owner_id:
                    return owner_id
        return "owner"

    def _find_current_memory_entry(self, *, entry_type: str, key: str) -> Any | None:
        memory_manager = getattr(self, "_memory_manager", None)
        if memory_manager is None:
            return None
        for entry in memory_manager.list_entries(
            entry_type=entry_type,
            limit=max(1, len(memory_manager._entries)),
        ):
            if entry.key == key and entry.superseded_by is None:
                return entry
        return None

    def _has_pending_review_memory_entry(self, *, entry_type: str, key: str) -> bool:
        memory_manager = getattr(self, "_memory_manager", None)
        if memory_manager is None:
            return False
        for entry in memory_manager.list_entries(
            entry_type=entry_type,
            include_pending_review=True,
            limit=max(1, len(memory_manager._entries)),
        ):
            if (
                entry.key == key
                and entry.superseded_by is None
                and str(entry.confirmation_status) == "pending_review"
            ):
                return True
        return False

    def _migrate_legacy_channel_bindings(
        self,
        *,
        channel: str,
        workspace_hint: str,
        legacy_channel_id: str,
        structured_channel_id: str,
    ) -> None:
        memory_manager = getattr(self, "_memory_manager", None)
        if memory_manager is None or not legacy_channel_id or not structured_channel_id:
            return
        limit = max(1, len(memory_manager._entries))
        for entry in memory_manager.list_entries(
            entry_type="inbox_item",
            limit=limit,
        ):
            if entry.superseded_by is not None or not isinstance(entry.value, Mapping):
                continue
            raw_channel_id = str(entry.value.get("channel_id") or "").strip()
            if raw_channel_id != legacy_channel_id or not _is_legacy_bare_channel_id(
                raw_channel_id
            ):
                continue
            recovered_workspace = self._legacy_channel_entry_workspace_hint(
                channel=channel,
                entry=entry,
            )
            if recovered_workspace != workspace_hint:
                continue
            updated_value = dict(entry.value)
            updated_value["channel_id"] = structured_channel_id
            entry.value = InboxItemValue.model_validate(updated_value).model_dump(mode="python")
            memory_manager._persist_entry(entry)

    def _legacy_channel_entry_workspace_hint(self, *, channel: str, entry: Any) -> str | None:
        source_id = str(getattr(entry, "source_id", "") or "").strip()
        normalized_channel = channel.strip().lower()
        prefix = f"{normalized_channel}:"
        if not source_id.lower().startswith(prefix):
            return None
        message_id = source_id[len(prefix) :].strip()
        if not message_id:
            return None
        return self._workspace_hint_for_channel_message(
            channel=normalized_channel,
            message_id=message_id,
        )

    def _workspace_hint_for_channel_message(self, *, channel: str, message_id: str) -> str | None:
        transcript_store = getattr(self, "_transcript_store", None)
        if transcript_store is None or not message_id:
            return None

        stub_entries = getattr(transcript_store, "entries", None)
        if isinstance(stub_entries, list):
            for row in stub_entries:
                if not isinstance(row, Mapping):
                    continue
                metadata = row.get("metadata", {})
                if not isinstance(metadata, Mapping):
                    continue
                if str(metadata.get("channel_message_id") or "").strip() != message_id:
                    continue
                delivery_target = metadata.get("delivery_target", {})
                if not isinstance(delivery_target, Mapping):
                    continue
                if str(delivery_target.get("channel") or "").strip().lower() != channel:
                    continue
                if "workspace_hint" not in delivery_target:
                    return None
                return str(delivery_target.get("workspace_hint") or "").strip()

        transcript_dir = getattr(transcript_store, "_transcript_dir", None)
        if not isinstance(transcript_dir, Path) or not transcript_dir.exists():
            return None
        for path in transcript_dir.glob("*.jsonl"):
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in lines:
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(payload, Mapping):
                    continue
                metadata = payload.get("metadata", {})
                if not isinstance(metadata, Mapping):
                    continue
                if str(metadata.get("channel_message_id") or "").strip() != message_id:
                    continue
                delivery_target = metadata.get("delivery_target", {})
                if not isinstance(delivery_target, Mapping):
                    continue
                if str(delivery_target.get("channel") or "").strip().lower() != channel:
                    continue
                if "workspace_hint" not in delivery_target:
                    return None
                return str(delivery_target.get("workspace_hint") or "").strip()
        return None

    def _find_legacy_channel_memory_entry(
        self,
        *,
        entry_type: str,
        key: str,
        channel: str,
        workspace_hint: str,
        structured_channel_id: str,
    ) -> Any | None:
        memory_manager = getattr(self, "_memory_manager", None)
        if memory_manager is None:
            return None
        for entry in memory_manager.list_entries(
            entry_type=entry_type,
            limit=max(1, len(memory_manager._entries)),
        ):
            if entry.key != key or entry.superseded_by is not None:
                continue
            recovered_workspace = self._legacy_channel_entry_workspace_hint(
                channel=channel,
                entry=entry,
            )
            if recovered_workspace == workspace_hint:
                if isinstance(entry.value, Mapping):
                    updated_value = dict(entry.value)
                    updated_value["channel_id"] = structured_channel_id
                    migrated_key = _migrated_channel_memory_key(
                        entry_type=entry.entry_type,
                        key=entry.key,
                        value=updated_value,
                        structured_channel_id=structured_channel_id,
                    )
                    if (
                        entry.entry_type in self._KEYED_CHANNEL_STATE_ENTRY_TYPES
                        and self._has_pending_review_memory_entry(
                            entry_type=entry.entry_type,
                            key=migrated_key,
                        )
                    ):
                        return None
                    entry.value = normalize_structured_memory_value(entry.entry_type, updated_value)
                    entry.key = migrated_key
                    memory_manager._persist_entry(entry)
                return entry
        return None

    def _persist_channel_memory_records(
        self,
        *,
        message: ChannelMessage,
        trust_level: str,
        firewall_result: Any,
    ) -> None:
        memory_manager = getattr(self, "_memory_manager", None)
        if memory_manager is None:
            return

        metadata = dict(message.metadata or {})
        channel_id = (
            str(metadata.get("discord_channel_id") or "").strip()
            or message.reply_target.strip()
            or message.external_user_id.strip()
        )
        guild_id = (
            str(metadata.get("discord_guild_id") or "").strip() or message.workspace_hint.strip()
        )
        thread_id = message.thread_id.strip()
        structured_channel_id = (
            compose_channel_binding(
                channel=message.channel,
                workspace_hint=message.workspace_hint,
                channel_id=channel_id,
            )
            if channel_id
            else ""
        )
        self._migrate_legacy_channel_bindings(
            channel=message.channel,
            workspace_hint=message.workspace_hint,
            legacy_channel_id=channel_id,
            structured_channel_id=structured_channel_id,
        )
        sender_display_name = (
            str(metadata.get("display_name") or metadata.get("author_display_name") or "").strip()
            or None
        )
        owner_like = _is_owner_like_channel_trust(trust_level)
        interaction_type = str(metadata.get("interaction_type") or "").strip().lower()
        taint_labels = list(getattr(firewall_result, "taint_labels", []) or [])
        sanitized_text = str(getattr(firewall_result, "sanitized_text", "") or "").strip()

        def persist_record(
            *,
            entry_type: str,
            key: str,
            value: Any,
            scope: ScopeKind,
            supersedes: str | None = None,
        ) -> None:
            ingress_context = mint_explicit_user_memory_ingress_context(
                self._memory_ingress_registry,
                channel=message.channel,
                trust_level=trust_level,
                session_id="",
                message_id=message.message_id or key,
                content=sanitized_text or json.dumps(value, ensure_ascii=True, default=str),
                taint_labels=taint_labels,
                scope=scope,
            )
            if ingress_context is None:
                return
            content_digest = self._memory_ingress_registry.validate_binding(
                ingress_context,
                content_digest=digest_memory_value(value),
                derivation_path=DerivationPath.EXTRACTED,
                parent_digest=ingress_context.content_digest,
            )
            source = MemorySource(
                origin=legacy_source_view_origin(ingress_context.source_origin),
                source_id=ingress_context.source_id,
                extraction_method="channel.ingest.structured",
            )
            decision = memory_manager.write_with_provenance(
                entry_type=entry_type,
                key=key,
                value=value,
                source=source,
                source_origin=ingress_context.source_origin,
                channel_trust=ingress_context.channel_trust,
                confirmation_status=ingress_context.confirmation_status,
                source_id=ingress_context.source_id,
                scope=scope,
                confidence=0.5,
                confirmation_satisfied=True,
                taint_labels=list(ingress_context.taint_labels),
                ingress_handle_id=ingress_context.handle_id,
                content_digest=content_digest,
                supersedes=supersedes,
            )
            if decision.kind != "allow":
                logger.warning(
                    "Failed to persist structured channel memory",
                    extra={
                        "entry_type": entry_type,
                        "key": key,
                        "reason": decision.reason,
                        "channel": message.channel,
                    },
                )

        if channel_id and not owner_like and interaction_type != "observed":
            owner_id = self._channel_memory_owner_id(channel=message.channel)
            inbox_key = inbox_item_key(
                owner_id=owner_id,
                item_id=message.message_id.strip() or _short_hash(sanitized_text or channel_id),
            )
            inbox_value = InboxItemValue(
                owner_id=owner_id,
                sender_id=message.external_user_id,
                sender_display_name=sender_display_name,
                channel_id=structured_channel_id,
                channel_name=str(metadata.get("channel_name") or "").strip() or None,
                message_type=_channel_inbox_message_type(sanitized_text),
                body=sanitized_text,
                received_at=message.received_at,
            ).model_dump(mode="python")
            persist_record(
                entry_type="inbox_item",
                key=inbox_key,
                value=inbox_value,
                scope="user",
            )

        if channel_id:
            participation_key = channel_participation_key(
                channel_id=structured_channel_id,
                thread_id=thread_id or None,
            )
            if self._has_pending_review_memory_entry(
                entry_type="channel_participation",
                key=participation_key,
            ):
                logger.warning(
                    "Skipping structured channel memory write due to pending-review collision",
                    extra={
                        "entry_type": "channel_participation",
                        "key": participation_key,
                        "channel": message.channel,
                    },
                )
            else:
                prior_participation = self._find_current_memory_entry(
                    entry_type="channel_participation",
                    key=participation_key,
                )
                if prior_participation is None:
                    prior_participation = self._find_legacy_channel_memory_entry(
                        entry_type="channel_participation",
                        key=channel_participation_key(
                            channel_id=channel_id,
                            thread_id=thread_id or None,
                        ),
                        channel=message.channel,
                        workspace_hint=message.workspace_hint,
                        structured_channel_id=structured_channel_id,
                    )
                if prior_participation is not None:
                    current_participation = ChannelParticipationStateValue.model_validate(
                        prior_participation.value
                    )
                else:
                    current_participation = ChannelParticipationStateValue(
                        channel_id=structured_channel_id,
                        guild_id=guild_id,
                    )
                participants: set[str] = set()
                tracked_threads = list(current_participation.tracked_threads)
                thread_binding = thread_id or channel_id
                updated_threads: list[TrackedThreadState] = []
                replaced = False
                for tracked_thread in tracked_threads:
                    if tracked_thread.thread_id != thread_binding:
                        updated_threads.append(tracked_thread)
                        continue
                    participants.update(tracked_thread.participants)
                    participants.add(message.external_user_id)
                    updated_threads.append(
                        tracked_thread.model_copy(
                            update={
                                "last_activity": message.received_at,
                                "participants": sorted(participants),
                            }
                        )
                    )
                    replaced = True
                if not replaced:
                    participants.add(message.external_user_id)
                    updated_threads.append(
                        TrackedThreadState(
                            thread_id=thread_binding,
                            last_activity=message.received_at,
                            participants=sorted(participants),
                        )
                    )
                participation_value = current_participation.model_copy(
                    update={
                        "channel_id": structured_channel_id,
                        "guild_id": guild_id,
                        "tracked_threads": updated_threads,
                    }
                ).model_dump(mode="python")
                persist_record(
                    entry_type="channel_participation",
                    key=participation_key,
                    value=participation_value,
                    scope="channel",
                    supersedes=(
                        prior_participation.id if prior_participation is not None else None
                    ),
                )

        if channel_id and not owner_like:
            note_key = person_note_key(
                channel_id=structured_channel_id,
                external_user_id=message.external_user_id,
            )
            if self._has_pending_review_memory_entry(
                entry_type="person_note",
                key=note_key,
            ):
                logger.warning(
                    "Skipping structured channel memory write due to pending-review collision",
                    extra={
                        "entry_type": "person_note",
                        "key": note_key,
                        "channel": message.channel,
                    },
                )
            else:
                prior_note = self._find_current_memory_entry(
                    entry_type="person_note",
                    key=note_key,
                )
                if prior_note is None:
                    prior_note = self._find_legacy_channel_memory_entry(
                        entry_type="person_note",
                        key=person_note_key(
                            channel_id=channel_id,
                            external_user_id=message.external_user_id,
                        ),
                        channel=message.channel,
                        workspace_hint=message.workspace_hint,
                        structured_channel_id=structured_channel_id,
                    )
                if prior_note is not None:
                    current_note = PersonNoteValue.model_validate(prior_note.value)
                else:
                    current_note = PersonNoteValue(
                        external_user_id=message.external_user_id,
                        display_name=sender_display_name or message.external_user_id,
                        channel_id=structured_channel_id,
                    )
                note_value = current_note.model_copy(
                    update={
                        "display_name": sender_display_name or current_note.display_name,
                        "total_interactions": current_note.total_interactions + 1,
                        "last_interaction": message.received_at,
                        "interaction_summary": sanitized_text[:240],
                    }
                ).model_dump(mode="python")
                persist_record(
                    entry_type="person_note",
                    key=note_key,
                    value=note_value,
                    scope="channel",
                    supersedes=prior_note.id if prior_note is not None else None,
                )

        summary_text = str(metadata.get("summary_text") or "").strip()
        if channel_id and summary_text:
            summary_kind = str(metadata.get("summary_kind") or "topic").strip() or "topic"
            summary_key = channel_summary_key(
                channel_id=structured_channel_id,
                summary_kind=summary_kind,
            )
            if self._has_pending_review_memory_entry(
                entry_type="channel_summary",
                key=summary_key,
            ):
                logger.warning(
                    "Skipping structured channel memory write due to pending-review collision",
                    extra={
                        "entry_type": "channel_summary",
                        "key": summary_key,
                        "channel": message.channel,
                    },
                )
            else:
                prior_summary = self._find_current_memory_entry(
                    entry_type="channel_summary",
                    key=summary_key,
                )
                if prior_summary is None:
                    prior_summary = self._find_legacy_channel_memory_entry(
                        entry_type="channel_summary",
                        key=channel_summary_key(channel_id=channel_id, summary_kind=summary_kind),
                        channel=message.channel,
                        workspace_hint=message.workspace_hint,
                        structured_channel_id=structured_channel_id,
                    )
                summary_value = ChannelSummaryValue(
                    channel_id=structured_channel_id,
                    guild_id=guild_id,
                    summary_kind=summary_kind,
                    summary_text=summary_text,
                    window_end=message.received_at,
                    source_message_ids=[message.message_id] if message.message_id else [],
                ).model_dump(mode="python")
                persist_record(
                    entry_type="channel_summary",
                    key=summary_key,
                    value=summary_value,
                    scope="channel",
                    supersedes=prior_summary.id if prior_summary is not None else None,
                )

        feedback_signal = str(metadata.get("feedback_signal") or "").strip().lower()
        feedback_target_message_id = str(
            metadata.get("feedback_target_message_id") or metadata.get("target_message_id") or ""
        ).strip()
        if channel_id and feedback_signal and feedback_target_message_id:
            feedback_key = response_feedback_key(
                channel_id=structured_channel_id,
                message_id=feedback_target_message_id,
                actor_external_user_id=message.external_user_id,
                signal=feedback_signal,
            )
            feedback_value = ResponseFeedbackEventValue(
                channel_id=structured_channel_id,
                target_message_id=feedback_target_message_id,
                actor_external_user_id=message.external_user_id,
                signal=feedback_signal,
                emoji=str(metadata.get("feedback_emoji") or "").strip() or None,
                valence=str(metadata.get("feedback_valence") or "none").strip() or "none",
                observed_at=message.received_at,
                was_proactive=(
                    bool(metadata.get("feedback_was_proactive"))
                    if "feedback_was_proactive" in metadata
                    else None
                ),
                thread_id=thread_id or None,
            ).model_dump(mode="python")
            persist_record(
                entry_type="response_feedback",
                key=feedback_key,
                value=feedback_value,
                scope="channel",
            )

    def _effective_channel_tools(self, allowed_tools: tuple[str, ...]) -> tuple[str, ...]:
        effective: list[str] = []
        seen: set[str] = set()
        for raw_tool in allowed_tools:
            canonical = canonical_tool_name_typed(raw_tool)
            if str(canonical) not in _PUBLIC_DISCORD_TOOL_ALLOWLIST:
                continue
            resolved = self._registry.resolve_name(canonical)
            if resolved is None:
                continue
            tool_name = str(resolved)
            if tool_name in seen:
                continue
            seen.add(tool_name)
            effective.append(tool_name)
        return tuple(sorted(effective))

    def _channel_capabilities_for_tools(self, allowed_tools: tuple[str, ...]) -> list[str]:
        capabilities: set[Capability] = set()
        for tool_name in allowed_tools:
            resolved = self._registry.resolve_name(canonical_tool_name_typed(tool_name))
            if resolved is None:
                continue
            definition = self._registry.get_tool(resolved)
            if definition is not None:
                capabilities.update(definition.capabilities_required)
        return sorted(cap.value for cap in capabilities)

    def _proactive_cooldown_key(
        self,
        *,
        channel: str,
        guild_id: str,
        channel_id: str,
    ) -> str:
        return f"{channel}:{guild_id}:{channel_id}"

    def _proactive_cooldown_active(
        self,
        *,
        key: str,
        cooldown_seconds: float,
        now: datetime,
    ) -> bool:
        if cooldown_seconds <= 0:
            return False
        last = cast(datetime | None, self._channel_proactive_last_sent_at.get(key))
        if last is None:
            return False
        elapsed_seconds = (now - last).total_seconds()
        return elapsed_seconds < cooldown_seconds

    async def _record_channel_observation(
        self,
        *,
        message: ChannelMessage,
        identity_user_id: UserId,
        identity_workspace_id: WorkspaceId,
        trust_level: str,
        firewall_result: Any,
        delivery_target: DeliveryTarget,
        channel_policy: dict[str, Any],
        reason: str,
        ephemeral_session: bool,
    ) -> dict[str, Any]:
        created = await self.do_session_create(
            {
                "channel": message.channel,
                "user_id": identity_user_id,
                "workspace_id": identity_workspace_id,
                "trust_level": trust_level,
                "_internal_ingress_marker": self._internal_ingress_marker,
                "_delivery_target": delivery_target.model_dump(mode="json"),
                "_capabilities": [],
                "_tool_allowlist": [],
                "_channel_policy": channel_policy,
            }
        )
        sid = SessionId(str(created["session_id"]))
        taint_labels = set(firewall_result.taint_labels)
        if _is_public_channel_trust(trust_level):
            taint_labels.add(TaintLabel.UNTRUSTED)
        self._transcript_store.append(
            sid,
            role="user",
            content=firewall_result.sanitized_text,
            taint_labels=taint_labels,
            metadata={
                "channel": message.channel,
                "session_mode": "default",
                "channel_message_id": message.message_id,
                "delivery_target": delivery_target.model_dump(mode="json"),
                "interaction_type": "observed",
                "passive_reason": reason,
                "channel_policy": channel_policy,
            },
        )
        await self._event_bus.publish(
            SessionMessageReceived(
                session_id=sid,
                actor=str(identity_user_id) or "user",
                content_hash=_short_hash(message.content),
                channel=message.channel,
                user_id=str(identity_user_id),
                workspace_id=str(identity_workspace_id),
                trust_level=trust_level,
                taint_labels=sorted(label.value for label in taint_labels),
                risk_score=firewall_result.risk_score,
            )
        )
        if ephemeral_session:
            self._session_manager.terminate(sid, reason=f"channel_observation:{reason}")
        return {
            "session_id": sid,
            "response": "",
            "plan_hash": None,
            "risk_score": firewall_result.risk_score,
            "blocked_actions": 0,
            "confirmation_required_actions": 0,
            "executed_actions": 0,
            "checkpoint_ids": [],
            "checkpoints_created": 0,
            "transcript_root": str(self._transcript_root),
            "lockdown_level": "normal",
            "trust_level": trust_level,
            "pending_confirmation_ids": [],
            "output_policy": {},
            "ingress_risk": firewall_result.risk_score,
            "delivery": {
                "attempted": False,
                "sent": False,
                "reason": reason,
                "target": delivery_target.model_dump(mode="json"),
            },
            "channel_policy": channel_policy,
        }

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
        a2a_runtime = getattr(self._services, "a2a_runtime", None)
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
            "content_firewall": self._firewall.status_snapshot(),
            "yara_required": True,
            "yara_policy_required": self._policy_loader.policy.yara_required,
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
            "a2a": a2a_runtime.status() if a2a_runtime is not None else {"enabled": False},
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

    async def do_daemon_reset(self, params: Mapping[str, Any]) -> dict[str, Any]:
        _ = params
        return cast(dict[str, Any], await self.reset_test_state())

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

    def _soul_config_path(self) -> Path | None:
        return cast(Path | None, getattr(self._config, "assistant_persona_soul_path", None))

    def _soul_max_bytes(self) -> int:
        return int(getattr(self._config, "assistant_persona_soul_max_bytes", 64 * 1024))

    def _require_trusted_admin_command(self, params: Mapping[str, Any]) -> None:
        internal_marker = getattr(self, "_internal_ingress_marker", None)
        internal_ingress = params.get("_internal_ingress_marker")
        if internal_marker is not None and internal_ingress is internal_marker:
            raise ValueError("SOUL.md access requires trusted admin command ingress")
        checker = getattr(self, "_is_admin_rpc_peer", None)
        if callable(checker) and bool(checker(params)):
            return
        peer = params.get("_rpc_peer", {})
        if isinstance(peer, Mapping):
            uid = peer.get("uid")
            if isinstance(uid, int) and uid in {0, os.getuid()}:
                return
        raise ValueError("SOUL.md access requires trusted admin command ingress")

    def _refresh_soul_persona_defaults(self) -> str:
        effective_text = load_effective_persona_text(self._config)
        tone = str(getattr(self._config, "assistant_persona_tone", "neutral"))
        selfmod_manager = getattr(self, "_selfmod_manager", None)
        overlay_refreshed = False
        if selfmod_manager is not None:
            if hasattr(selfmod_manager, "_default_persona_tone"):
                selfmod_manager._default_persona_tone = tone
            if hasattr(selfmod_manager, "_default_persona_text"):
                selfmod_manager._default_persona_text = effective_text
            apply_overlay = getattr(selfmod_manager, "_apply_behavior_overlay", None)
            if callable(apply_overlay):
                apply_overlay()
                overlay_refreshed = True
        if not overlay_refreshed:
            setter = getattr(self._planner, "set_persona_defaults", None)
            if callable(setter):
                setter(tone=tone, custom_text=effective_text)
        return effective_text

    async def do_admin_soul_read(self, params: Mapping[str, Any]) -> dict[str, Any]:
        self._require_trusted_admin_command(params)
        soul_path = self._soul_config_path()
        if soul_path is None:
            return {
                "configured": False,
                "path": "",
                "content": "",
                "sha256": "",
                "bytes": 0,
                "warnings": [],
                "reason": "soul_path_unconfigured",
            }
        soul_exists = soul_path.exists()
        content = load_soul_text(soul_path, max_bytes=self._soul_max_bytes())
        return {
            "configured": True,
            "path": str(soul_path),
            "content": content,
            "sha256": soul_text_sha256(content) if soul_exists else "",
            "bytes": len(content.encode("utf-8")),
            "warnings": list(soul_content_warnings(content)),
            "reason": "ok",
        }

    async def do_admin_soul_update(self, params: Mapping[str, Any]) -> dict[str, Any]:
        self._require_trusted_admin_command(params)
        soul_path = self._soul_config_path()
        if soul_path is None:
            return {
                "updated": False,
                "path": "",
                "sha256": "",
                "bytes": 0,
                "warnings": [],
                "reason": "soul_path_unconfigured",
            }
        content = str(params.get("content", ""))
        expected_sha256 = str(params.get("expected_sha256", "") or "").strip()
        if expected_sha256:
            soul_exists = soul_path.exists()
            current = load_soul_text(soul_path, max_bytes=self._soul_max_bytes())
            current_sha256 = soul_text_sha256(current) if soul_exists else ""
            if current_sha256 != expected_sha256:
                return {
                    "updated": False,
                    "path": str(soul_path),
                    "sha256": current_sha256,
                    "bytes": len(current.encode("utf-8")),
                    "warnings": list(soul_content_warnings(current)),
                    "reason": "sha256_mismatch",
                }
        result = write_soul_text(soul_path, content, max_bytes=self._soul_max_bytes())
        self._refresh_soul_persona_defaults()
        return {
            "updated": True,
            "path": str(result.path),
            "sha256": result.sha256,
            "bytes": result.bytes_written,
            "warnings": list(result.warnings),
            "reason": "ok",
        }

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

    async def do_lockdown_status(self, params: Mapping[str, Any]) -> dict[str, Any]:
        session_filter = str(params.get("session_id") or "").strip()
        include_all = bool(params.get("all", False))
        active_sessions = {
            str(session.id): session for session in self._session_manager.list_active()
        }
        explicit_states = {
            str(state.session_id): state
            for state in self._lockdown_manager.explicit_states()
        }

        if session_filter:
            session_ids = (
                [session_filter]
                if session_filter in active_sessions or session_filter in explicit_states
                else []
            )
        elif include_all:
            session_ids = sorted(set(active_sessions) | set(explicit_states))
        else:
            session_ids = sorted(
                sid
                for sid, state in explicit_states.items()
                if state.level.value != "normal"
            )

        statuses: list[dict[str, Any]] = []
        for raw_sid in session_ids:
            sid = SessionId(raw_sid)
            session = active_sessions.get(raw_sid)
            stored_state = explicit_states.get(raw_sid)
            state = self._lockdown_manager.peek_state_for(sid)
            state_has_explicit_transition = (
                stored_state is not None
                and (
                    stored_state.level.value != "normal"
                    or bool(stored_state.reason)
                    or bool(stored_state.trigger)
                )
            )
            statuses.append(
                {
                    "session_id": raw_sid,
                    "level": state.level.value,
                    "reason": state.reason,
                    "trigger": state.trigger,
                    "updated_at": (
                        stored_state.updated_at.isoformat()
                        if state_has_explicit_transition
                        else None
                    ),
                    "active": session is not None,
                    "user_id": str(session.user_id) if session is not None else "",
                    "workspace_id": str(session.workspace_id) if session is not None else "",
                    "channel": str(session.channel) if session is not None else "",
                    "mode": str(session.mode.value) if session is not None else "default",
                }
            )
        return {"statuses": statuses, "count": len(statuses)}

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
        metadata = dict(message.metadata or {})
        raw_workspace_hint = message.workspace_hint
        discord_decision = DiscordChannelPolicyDecision()
        discord_guild_id = ""
        discord_channel_id = ""
        if self._matrix_channel is not None and message.channel == "matrix":
            room_hint = message.workspace_hint or self._config.matrix_room_id
            message = message.model_copy(
                update={"workspace_hint": self._matrix_channel.workspace_for_room(room_hint)}
            )
        elif message.channel == "discord":
            if "discord_guild_id" in metadata:
                discord_guild_id = str(metadata.get("discord_guild_id") or "").strip()
            else:
                discord_guild_id = raw_workspace_hint.strip()
            if "discord_channel_id" in metadata:
                discord_channel_id = str(metadata.get("discord_channel_id") or "").strip()
            else:
                discord_channel_id = message.reply_target.strip()
            if self._discord_channel is not None:
                discord_workspace = self._discord_channel.workspace_for_guild(discord_guild_id)
                discord_decision = self._discord_channel.policy_decision_for(
                    guild_id=discord_guild_id,
                    channel_id=discord_channel_id,
                    external_user_id=message.external_user_id,
                )
            else:
                discord_workspace = discord_guild_id or message.workspace_hint
                discord_decision = _discord_policy_from_config(self._config).resolve(
                    guild_id=discord_guild_id,
                    channel_id=discord_channel_id,
                    external_user_id=message.external_user_id,
                )
            metadata.setdefault("discord_guild_id", discord_guild_id)
            metadata.setdefault("discord_channel_id", discord_channel_id)
            message = message.model_copy(
                update={"workspace_hint": discord_workspace, "metadata": metadata}
            )
        elif self._telegram_channel is not None and message.channel == "telegram":
            telegram_workspace = self._telegram_channel.workspace_for_chat(message.workspace_hint)
            message = message.model_copy(update={"workspace_hint": telegram_workspace})
        elif self._slack_channel is not None and message.channel == "slack":
            slack_workspace = self._slack_channel.workspace_for_team(message.workspace_hint)
            message = message.model_copy(update={"workspace_hint": slack_workspace})

        allowed_by_identity = self._identity_map.is_allowed(
            channel=message.channel,
            external_user_id=message.external_user_id,
        )
        if message.channel == "discord" and discord_decision.denied:
            return {
                "session_id": "",
                "response": "Discord channel policy denies this channel or user.",
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
                    "reason": "channel_policy_denied",
                    "target": {},
                },
                "channel_policy": _channel_policy_payload(
                    decision=discord_decision,
                    guild_id=discord_guild_id,
                    channel_id=discord_channel_id,
                    reason="channel_policy_denied",
                ),
            }

        public_policy_access = (
            message.channel == "discord"
            and discord_decision.public_access
            and discord_decision.reason in {"public_grant", "trusted_guest_grant"}
        )
        if not allowed_by_identity and not public_policy_access:
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
                "channel_policy": _channel_policy_payload(
                    decision=discord_decision,
                    guild_id=discord_guild_id,
                    channel_id=discord_channel_id,
                    reason="identity_not_allowlisted",
                )
                if message.channel == "discord"
                else {},
            }

        declared_trust = self._identity_map.trust_for_channel(message.channel)
        if public_policy_access:
            declared_trust = discord_decision.trust_level
        elif self._is_verified_channel_identity(
            channel=message.channel,
            external_user_id=message.external_user_id,
        ):
            declared_trust = "owner"
        if not declared_trust:
            declared_trust = "untrusted"

        identity = None
        if allowed_by_identity:
            identity = self._identity_map.resolve(
                channel=message.channel,
                external_user_id=message.external_user_id,
            )
        if identity is None and not public_policy_access:
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
        elif (
            identity is not None
            and not public_policy_access
            and declared_trust != identity.trust_level
        ):
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
        if public_policy_access:
            identity_user_id = UserId(message.external_user_id)
            identity_workspace_id = WorkspaceId(message.workspace_hint or message.channel)
            identity_trust_level = declared_trust
        elif identity is not None:
            identity_user_id = identity.user_id
            identity_workspace_id = identity.workspace_id
            identity_trust_level = identity.trust_level
        else:
            raise ValueError("failed to resolve channel identity")

        trusted_input = identity_trust_level.strip().lower() in {
            "trusted",
            "verified",
            "internal",
            "owner",
        }
        _sanitized, result = self._channel_ingress.process(message, trusted_input=trusted_input)
        delivery_target = DeliveryTarget(
            channel=message.channel,
            recipient=message.reply_target or message.external_user_id,
            workspace_hint=message.workspace_hint,
            thread_id=message.thread_id,
        )
        public_session = _is_public_channel_trust(identity_trust_level)
        effective_channel_tools = (
            self._effective_channel_tools(discord_decision.allowed_tools) if public_session else ()
        )
        effective_discord_decision = DiscordChannelPolicyDecision(
            engagement_mode=discord_decision.engagement_mode,
            public_access=discord_decision.public_access,
            trust_level=discord_decision.trust_level,
            allowed_tools=effective_channel_tools,
            denied=discord_decision.denied,
            reason=discord_decision.reason,
            cooldown_seconds=discord_decision.cooldown_seconds,
            relevance_keywords=discord_decision.relevance_keywords,
            proactive_marker=discord_decision.proactive_marker,
        )
        channel_policy_payload = (
            _channel_policy_payload(
                decision=effective_discord_decision,
                guild_id=discord_guild_id,
                channel_id=discord_channel_id,
                ephemeral_session=public_session,
                owner_private_context_excluded=public_session,
            )
            if message.channel == "discord"
            else {}
        )
        observed_message = str(metadata.get("interaction_type", "")).strip() == "observed"
        proactive_eligible = bool(metadata.get("proactive_eligible", False))
        proactive = bool(observed_message and proactive_eligible)
        self._persist_channel_memory_records(
            message=message,
            trust_level=identity_trust_level,
            firewall_result=result,
        )
        if observed_message and not proactive:
            reason = str(metadata.get("passive_reason", "")).strip() or "passive_observe"
            channel_policy_payload["reason"] = reason
            channel_policy_payload["ephemeral_session"] = True
            return await self._record_channel_observation(
                message=message,
                identity_user_id=identity_user_id,
                identity_workspace_id=identity_workspace_id,
                trust_level=identity_trust_level,
                firewall_result=result,
                delivery_target=delivery_target,
                channel_policy=channel_policy_payload,
                reason=reason,
                ephemeral_session=True,
            )
        cooldown_key = self._proactive_cooldown_key(
            channel=message.channel,
            guild_id=discord_guild_id,
            channel_id=discord_channel_id,
        )
        if proactive and self._proactive_cooldown_active(
            key=cooldown_key,
            cooldown_seconds=float(discord_decision.cooldown_seconds),
            now=datetime.now(UTC),
        ):
            channel_policy_payload["reason"] = "proactive_cooldown"
            channel_policy_payload["proactive"] = False
            channel_policy_payload["ephemeral_session"] = True
            return await self._record_channel_observation(
                message=message,
                identity_user_id=identity_user_id,
                identity_workspace_id=identity_workspace_id,
                trust_level=identity_trust_level,
                firewall_result=result,
                delivery_target=delivery_target,
                channel_policy=channel_policy_payload,
                reason="proactive_cooldown",
                ephemeral_session=True,
            )
        channel_policy_payload["proactive"] = proactive

        sid = SessionId(str(params.get("session_id", "")))
        if public_session:
            sid = SessionId("")
        if not sid or self._session_manager.get(sid) is None:
            existing = self._session_manager.find_by_binding(
                channel=message.channel,
                user_id=identity_user_id,
                workspace_id=identity_workspace_id,
            )
            if existing is not None and not public_session:
                sid = existing.id
        if not sid or self._session_manager.get(sid) is None:
            session_payload: dict[str, Any] = {
                "channel": message.channel,
                "user_id": identity_user_id,
                "workspace_id": identity_workspace_id,
                "trust_level": identity_trust_level,
                "_internal_ingress_marker": self._internal_ingress_marker,
                "_delivery_target": delivery_target.model_dump(mode="json"),
            }
            if public_session:
                session_payload["_capabilities"] = self._channel_capabilities_for_tools(
                    effective_channel_tools
                )
                session_payload["_tool_allowlist"] = list(effective_channel_tools)
                session_payload["_channel_policy"] = channel_policy_payload
            created = await self.do_session_create(session_payload)
            sid = SessionId(created["session_id"])
        explicit_memory_ingress_context = mint_explicit_user_memory_ingress_context(
            self._memory_ingress_registry,
            channel=message.channel,
            trust_level=identity_trust_level,
            session_id=str(sid),
            message_id=message.message_id,
            content=result.sanitized_text,
            taint_labels=list(result.taint_labels),
        )
        session_message_payload: dict[str, Any] = {
            "session_id": sid,
            "channel": message.channel,
            "user_id": identity_user_id,
            "workspace_id": identity_workspace_id,
            "content": message.content,
            "trust_level": identity_trust_level,
            "_internal_ingress_marker": self._internal_ingress_marker,
            "_firewall_result": result.model_dump(mode="json"),
            "_delivery_target": delivery_target.model_dump(mode="json"),
            "_channel_message_id": message.message_id,
        }
        if explicit_memory_ingress_context is not None:
            session_message_payload["_explicit_memory_ingress_context"] = (
                explicit_memory_ingress_context.handle_id
            )
        response = await self.do_session_message(session_message_payload)
        if proactive:
            marker = discord_decision.proactive_marker.strip() or "[proactive]"
            response_text = str(response.get("response", "")).strip()
            if response_text and not response_text.startswith(marker):
                response["response"] = f"{marker} {response_text}"
        delivery_result = await self._delivery.send(
            target=delivery_target,
            message=str(response.get("response", "")),
        )
        if proactive:
            self._channel_proactive_last_sent_at[cooldown_key] = datetime.now(UTC)
        response["delivery"] = delivery_result.as_dict()
        response["channel_policy"] = channel_policy_payload
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
        if public_session:
            self._session_manager.terminate(sid, reason="public_channel_ephemeral")
        return cast(dict[str, Any], response)


def _channel_inbox_message_type(content: str) -> str:
    normalized = content.strip().lower()
    if not normalized:
        return "message_for_owner"
    if "schedule" in normalized or "calendar" in normalized or "meet" in normalized:
        return "scheduling_request"
    if normalized.endswith("?"):
        return "question"
    if normalized.startswith("todo ") or normalized.startswith("please "):
        return "task"
    return "message_for_owner"
