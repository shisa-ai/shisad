"""Memory/note/todo handler implementations."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast

from shisad.core.types import Capability
from shisad.daemon.handlers._csv import render_csv_row
from shisad.daemon.handlers._mixin_typing import HandlerMixinBase
from shisad.memory.consolidation import ConsolidationRunResult, ConsolidationWorker
from shisad.memory.graph import build_knowledge_graph
from shisad.memory.ingress import DerivationPath, IngressContext
from shisad.memory.remap import (
    digest_memory_value,
    legacy_source_view_origin,
    resolve_legacy_source_origin,
)
from shisad.memory.schema import MemoryEntry, MemorySource
from shisad.memory.surfaces.active_attention import entry_passes_context_filters
from shisad.memory.surfaces.thread_resume import build_thread_packet, thread_selection_metrics
from shisad.memory.trust import backfill_legacy_triple

_CONTROL_API_AUTHENTICATED_WRITE = "_control_api_authenticated_write"
_DEFAULT_MEMORY_GRAPH_SCOPES = frozenset({"user"})
_THREAD_CONTEXT_DEFAULT_SCOPE_FILTER = frozenset({"session", "project", "user", "channel"})
_THREAD_OPEN_STATES = frozenset({"active", "waiting", "blocked"})
_THREAD_LIST_STATES = frozenset({"open", "active", "waiting", "blocked", "stale", "closed", "all"})
logger = logging.getLogger(__name__)
_MEMORY_WRITE_REJECT_HINTS: dict[str, tuple[str, str]] = {
    "preference_predicate_required": (
        "Preference and soft-constraint memory entries require a predicate.",
        "Pass --predicate in function-call form, for example: prefers(response_style).",
    ),
    "preference_predicate_invalid": (
        "Preference predicates must use function-call form and avoid policy-like names.",
        "Use lowercase func(arg), for example: prefers(response_style) or avoids(food).",
    ),
    "predicate_requires_preference_entry_type": (
        "Only preference and soft_constraint entries accept a predicate.",
        "Remove --predicate or write the memory as --type preference/soft_constraint.",
    ),
    "supersedes_target_not_found": (
        "The superseded memory entry was not found or is already deleted.",
        "Run shisad memory list --json --user <user> --workspace <workspace> "
        "and pass an active entry id to --supersede. Add --include-unowned only "
        "when replacing a legacy ownerless row.",
    ),
    "supersedes_target_mismatch": (
        "The replacement must use the same entry type and key as the superseded entry.",
        "Use the original entry's type/key or create a new memory entry instead.",
    ),
    "owner_scope_requires_user_and_workspace": (
        "Owner-scoped personal memory writes require both user_id and workspace_id.",
        "Retry from a session with a real owner scope, or omit both fields for an "
        "explicit unowned maintenance write.",
    ),
}


class MemoryImplMixin(HandlerMixinBase):
    @staticmethod
    def _coerce_source_id(value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def _is_internal_ingress_request(self, params: Mapping[str, Any]) -> bool:
        internal_marker = getattr(self, "_internal_ingress_marker", None)
        return (
            internal_marker is not None
            and params.get("_internal_ingress_marker") is internal_marker
        )

    @staticmethod
    def _canonical_ingress_content(value: Any) -> str | bytes:
        if isinstance(value, (str, bytes)):
            return value
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )

    @staticmethod
    def _source_id_for_control_write(params: Mapping[str, Any]) -> str:
        source = params.get("source")
        if isinstance(source, Mapping):
            source_id = MemoryImplMixin._coerce_source_id(source.get("source_id"))
            if source_id:
                return source_id
        source_id = MemoryImplMixin._coerce_source_id(params.get("source_id"))
        return source_id or "cli"

    @staticmethod
    def _firewall_taint_labels(params: Mapping[str, Any]) -> list[Any]:
        firewall_result = params.get("_firewall_result")
        if not isinstance(firewall_result, Mapping):
            return []
        taints = firewall_result.get("taint_labels")
        if not isinstance(taints, list):
            return []
        return [item for item in taints if isinstance(item, str)]

    @staticmethod
    def _scope_filter_from_params(
        params: Mapping[str, Any],
        *,
        default: frozenset[str] | None = _DEFAULT_MEMORY_GRAPH_SCOPES,
    ) -> set[str] | None:
        raw = params.get("scope_filter")
        if raw is None:
            return set(default) if default is not None else None
        if not isinstance(raw, list):
            return set()
        return {str(item).strip() for item in raw if str(item).strip()}

    @staticmethod
    def _owner_tuple_from_params(params: Mapping[str, Any]) -> tuple[str | None, str | None]:
        user_id = MemoryImplMixin._normalize_owner_value(params.get("user_id"))
        workspace_id = MemoryImplMixin._normalize_owner_value(params.get("workspace_id"))
        if bool(user_id) != bool(workspace_id):
            return None, None
        return user_id, workspace_id

    @staticmethod
    def _required_owner_tuple_from_params(params: Mapping[str, Any]) -> tuple[str, str]:
        user_id, workspace_id = MemoryImplMixin._owner_tuple_from_params(params)
        if user_id is None or workspace_id is None:
            raise ValueError("user_id and workspace_id are required")
        return user_id, workspace_id

    @staticmethod
    def _normalize_owner_value(value: Any) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized or None

    def _list_memory_entries_for_scope(
        self,
        *,
        scope_filter: set[str] | None,
        user_id: str | None,
        workspace_id: str | None,
        include_quarantined: bool = False,
        include_pending_review: bool = False,
    ) -> list[Any]:
        if user_id is None or workspace_id is None:
            return []
        entries = cast(
            list[Any],
            self._memory_manager.list_entries(
                limit=max(1, len(getattr(self._memory_manager, "_entries", {}))),
                include_quarantined=include_quarantined,
                include_pending_review=include_pending_review,
                user_id=user_id,
                workspace_id=workspace_id,
            ),
        )
        if scope_filter is None:
            return entries
        return [entry for entry in entries if entry.scope in scope_filter]

    @staticmethod
    def _legacy_confirmation_satisfied(params: Mapping[str, Any], context: Any) -> bool:
        if bool(params.get("_confirmation_satisfied_override", False)):
            return True
        return context.confirmation_status in {
            "user_asserted",
            "user_confirmed",
            "user_corrected",
            "pep_approved",
        }

    def _mint_legacy_compat_ingress(
        self,
        params: Mapping[str, Any],
        *,
        source: MemorySource,
        value: Any,
    ) -> Any:
        source_origin = resolve_legacy_source_origin(
            source.origin,
            source_id=source.source_id,
            extraction_method=source.extraction_method,
        )
        source_origin, channel_trust, confirmation_status = backfill_legacy_triple(
            source_origin=source_origin
        )
        return self._memory_ingress_registry.mint(
            source_origin=source_origin,
            channel_trust=channel_trust,
            confirmation_status=confirmation_status,
            scope="user",
            source_id=source.source_id or self._source_id_for_control_write(params),
            content=self._canonical_ingress_content(value),
            taint_labels=self._firewall_taint_labels(params),
        )

    @staticmethod
    def _retrieval_source_type_for_ingress(source_origin: str) -> str:
        if source_origin in {"user_direct", "user_confirmed", "user_corrected"}:
            return "user"
        if source_origin in {"tool_output", "consolidation_derived"}:
            return "tool"
        return "external"

    @staticmethod
    def _control_ingest_triple(
        source_type: str,
        *,
        user_confirmed: bool = False,
    ) -> tuple[str, str, str]:
        normalized = source_type.strip().lower()
        if normalized == "tool":
            return ("tool_output", "tool_passed", "auto_accepted")
        if normalized == "external":
            return ("external_web", "web_passed", "auto_accepted")
        if user_confirmed:
            return ("user_confirmed", "command", "user_confirmed")
        return ("user_direct", "command", "user_asserted")

    @staticmethod
    def _with_memory_reject_hint(response: dict[str, Any]) -> dict[str, Any]:
        if response.get("kind") != "reject":
            return response
        reason = str(response.get("reason", "")).strip()
        detail, hint = _MEMORY_WRITE_REJECT_HINTS.get(reason, ("", ""))
        if detail and not response.get("reason_detail"):
            response["reason_detail"] = detail
        if hint and not response.get("hint"):
            response["hint"] = hint
        return response

    @staticmethod
    def _required_owner_scope_from_params(params: Mapping[str, Any]) -> dict[str, Any]:
        user_id, workspace_id = MemoryImplMixin._required_owner_tuple_from_params(params)
        return {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "include_unowned": bool(params.get("include_unowned", False)),
        }

    @staticmethod
    def _thread_value_text(value: object, key: str) -> str:
        if isinstance(value, Mapping):
            raw = value.get(key)
            if isinstance(raw, str):
                return " ".join(raw.strip().split())
        if key == "summary" and isinstance(value, str):
            return " ".join(value.strip().split())
        return ""

    @staticmethod
    def _thread_value_list(value: object, key: str) -> list[str]:
        if not isinstance(value, Mapping):
            return []
        raw = value.get(key)
        if isinstance(raw, str):
            item = " ".join(raw.strip().split())
            return [item] if item else []
        if not isinstance(raw, list):
            return []
        items: list[str] = []
        for item in raw:
            text = " ".join(str(item).strip().split())
            if text:
                items.append(text)
        return items

    @staticmethod
    def _thread_title(entry: MemoryEntry) -> str:
        title = MemoryImplMixin._thread_value_text(entry.value, "title")
        if title:
            return title
        normalized_key = entry.key.replace("thread:", "", 1).replace("-", " ").replace("_", " ")
        return " ".join(normalized_key.split())

    @staticmethod
    def _thread_last_relevant_timestamp(entry: MemoryEntry) -> str:
        timestamp = (
            entry.last_cited_at
            or entry.last_verified_at
            or entry.valid_from
            or entry.created_at
        )
        return timestamp.isoformat()

    @staticmethod
    def _thread_packet_payload(entry: MemoryEntry) -> dict[str, Any]:
        packet = build_thread_packet(entry)
        return MemoryImplMixin._thread_packet_payload_from_packet(packet)

    @staticmethod
    def _thread_packet_payload_from_packet(packet: Any) -> dict[str, Any]:
        return {
            "entry_id": packet.entry_id,
            "title": packet.title,
            "summary": packet.summary,
            "unresolved_state": packet.unresolved_state,
            "evidence_refs": list(packet.evidence_refs),
            "evidence_snippets": list(packet.evidence_snippets),
            "caveats": list(packet.caveats),
            "source_taints": list(packet.source_taints),
            "sufficiency": dict(packet.sufficiency),
            "token_cost": packet.token_cost,
            "max_tokens": packet.max_tokens,
            "staleness": dict(packet.staleness),
            "verification_gap": packet.verification_gap,
        }

    @staticmethod
    def _thread_summary_payload(entry: MemoryEntry) -> dict[str, Any]:
        channel_binding = MemoryImplMixin._thread_value_text(entry.value, "channel_id")
        return {
            "id": entry.id,
            "key": entry.key,
            "title": MemoryImplMixin._thread_title(entry),
            "workflow_state": entry.workflow_state or "",
            "status": entry.status,
            "scope": entry.scope,
            "owner": {
                "user_id": entry.user_id or "",
                "workspace_id": entry.workspace_id or "",
            },
            "user_id": entry.user_id or "",
            "workspace_id": entry.workspace_id or "",
            "channel_binding": channel_binding,
            "channel_trust": entry.channel_trust,
            "source_origin": entry.source_origin,
            "confidence": entry.confidence,
            "missing_evidence": MemoryImplMixin._thread_packet_payload(entry)["sufficiency"][
                "missing_evidence"
            ],
            "last_relevant_at": MemoryImplMixin._thread_last_relevant_timestamp(entry),
            "created_at": entry.created_at.isoformat(),
        }

    @staticmethod
    def _thread_selection_payload(pack: Any) -> dict[str, Any]:
        metadata: Mapping[str, Any] = {}
        metadata_method = getattr(pack, "metadata", None)
        if callable(metadata_method):
            raw_metadata = metadata_method()
            if isinstance(raw_metadata, Mapping):
                metadata = raw_metadata
        raw_metrics = metadata.get("metrics", {})
        metrics = dict(raw_metrics) if isinstance(raw_metrics, Mapping) else {}
        return {
            "status": str(getattr(pack, "status", "")),
            "selected_id": (
                pack.selected.entry.id if getattr(pack, "selected", None) is not None else ""
            ),
            "candidate_ids": list(getattr(pack, "candidate_ids", [])),
            "confidence": float(getattr(pack, "confidence", 0.0)),
            "rationale": list(getattr(pack, "rationale", [])),
            "missing_evidence": list(getattr(pack, "missing_evidence", [])),
            "query_terms": list(getattr(pack, "query_terms", [])),
            "packet_token_cost": (
                pack.packet.token_cost if getattr(pack, "packet", None) is not None else 0
            ),
            "max_tokens": int(getattr(pack, "max_tokens", 0)),
            "metrics": metrics,
        }

    @staticmethod
    def _thread_state_filter(raw_state: Any) -> tuple[str, set[str] | None]:
        state = str(raw_state or "open").strip().lower() or "open"
        if state not in _THREAD_LIST_STATES:
            raise ValueError("invalid_thread_state_filter")
        if state == "all":
            return state, None
        if state == "open":
            return state, set(_THREAD_OPEN_STATES)
        return state, {state}

    @staticmethod
    def _optional_string_param(params: Mapping[str, Any], key: str) -> str | None:
        value = params.get(key)
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized or None

    @staticmethod
    def _string_set_param(params: Mapping[str, Any], key: str) -> set[str] | None:
        raw = params.get(key)
        if raw is None:
            return None
        if not isinstance(raw, list):
            return set()
        return {str(item).strip() for item in raw if str(item).strip()}

    def _thread_context_filters_from_params(
        self,
        params: Mapping[str, Any],
    ) -> tuple[set[str] | None, set[str] | None, str | None, str | None]:
        channel_binding = self._optional_string_param(params, "channel_binding")
        allowed_channel_trusts = self._string_set_param(params, "allowed_channel_trusts")
        if channel_binding is None and allowed_channel_trusts is None:
            allowed_channel_trusts = {"command", "owner_observed"}
        scope_filter = self._scope_filter_from_params(
            params,
            default=_THREAD_CONTEXT_DEFAULT_SCOPE_FILTER,
        )
        session_scope_id = self._optional_string_param(params, "session_scope_id")
        return scope_filter, allowed_channel_trusts, channel_binding, session_scope_id

    def _filter_thread_entries_by_context(
        self,
        entries: list[MemoryEntry],
        *,
        scope_filter: set[str] | None,
        allowed_channel_trusts: set[str] | None,
        channel_binding: str | None,
        session_scope_id: str | None,
    ) -> list[MemoryEntry]:
        session_visible = self._memory_manager._filter_session_scoped_entries(
            entries,
            session_scope_id=session_scope_id,
        )
        return [
            entry
            for entry in session_visible
            if entry_passes_context_filters(
                entry=entry,
                scope_filter=scope_filter,
                allowed_channel_trusts=allowed_channel_trusts,
                channel_binding=channel_binding,
            )
        ]

    def _get_visible_thread(
        self,
        *,
        thread_id: str,
        user_id: str,
        workspace_id: str,
        include_unowned: bool,
    ) -> MemoryEntry | None:
        entry = self._memory_manager.get_entry(
            thread_id,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        if entry is None or entry.entry_type != "open_thread":
            return None
        return cast(MemoryEntry, entry)

    def _index_note_write_for_recall(
        self,
        result: dict[str, Any],
        *,
        user_id: str | None = None,
        workspace_id: str | None = None,
    ) -> None:
        if result.get("kind") != "allow":
            return
        ingestion = getattr(self, "_ingestion", None)
        if ingestion is None:
            return
        entry = result.get("entry")
        if not isinstance(entry, Mapping):
            return
        value = str(entry.get("value", "")).strip()
        if not value:
            return
        key = str(entry.get("key", "")).strip()
        content = f"{key}: {value}" if key else value
        source_origin = str(entry.get("source_origin", "user_direct")).strip() or "user_direct"
        # Prefer explicit user_id/workspace_id from the caller (threaded from
        # the invoking session context). Fall back to any values on the
        # persisted entry — these are present once the schema rework has
        # propagated through ingress/write paths end-to-end.
        effective_user_id = user_id or (
            str(entry.get("user_id")) if entry.get("user_id") is not None else None
        )
        effective_workspace_id = workspace_id or (
            str(entry.get("workspace_id")) if entry.get("workspace_id") is not None else None
        )
        try:
            ingestion.ingest(
                source_id=str(entry.get("id", "") or entry.get("source_id", "") or "note"),
                source_type=self._retrieval_source_type_for_ingress(source_origin),
                content=content,
                source_origin=source_origin,
                channel_trust=str(entry.get("channel_trust", "command")).strip() or "command",
                confirmation_status=str(entry.get("confirmation_status", "user_asserted")).strip()
                or "user_asserted",
                scope=str(entry.get("scope", "user")).strip() or "user",
                user_id=effective_user_id,
                workspace_id=effective_workspace_id,
            )
        except Exception:
            logger.warning("Failed to index note.create result for recall", exc_info=True)

    def _write_control_api_authenticated_entry(
        self,
        params: Mapping[str, Any],
        *,
        entry_type: str,
        key: str,
        value: Any,
        confidence: float,
    ) -> dict[str, Any]:
        user_confirmed = bool(params.get("user_confirmed", False))
        source_origin = "user_confirmed" if user_confirmed else "user_direct"
        confirmation_status = "user_confirmed" if user_confirmed else "user_asserted"
        context = self._memory_ingress_registry.mint(
            source_origin=source_origin,
            channel_trust="command",
            confirmation_status=confirmation_status,
            scope="user",
            source_id=self._source_id_for_control_write(params),
            content=self._canonical_ingress_content(value),
            taint_labels=self._firewall_taint_labels(params),
        )
        handle_params = dict(params)
        handle_params["ingress_context"] = context.handle_id
        if not isinstance(value, (str, bytes)):
            handle_params["content_digest"] = digest_memory_value(value)
        return self._write_handle_bound_entry(
            handle_params,
            entry_type=entry_type,
            key=key,
            value=value,
            confidence=confidence,
        )

    def _write_handle_bound_entry(
        self,
        params: Mapping[str, Any],
        *,
        entry_type: str,
        key: str,
        value: Any,
        confidence: float,
    ) -> dict[str, Any]:
        handle_id = str(params.get("ingress_context", ""))
        context = self._memory_ingress_registry.resolve(handle_id)
        derivation_path = DerivationPath(str(params.get("derivation_path", "direct")))
        content_digest = str(params.get("content_digest", "")).strip() or None
        if content_digest is None and not isinstance(value, (str, bytes)):
            content_digest = digest_memory_value(value)
        resolved_digest = self._memory_ingress_registry.validate_binding(
            handle_id,
            content=value if isinstance(value, (str, bytes)) else None,
            content_digest=content_digest,
            derivation_path=derivation_path,
            parent_digest=str(params.get("parent_digest", "")).strip() or None,
        )
        source = MemorySource(
            origin=legacy_source_view_origin(context.source_origin),
            source_id=context.source_id,
            extraction_method=f"ingress.{derivation_path.value}",
        )
        confirmation_satisfied = self._legacy_confirmation_satisfied(params, context)
        supersedes = str(params.get("supersedes", "")).strip() or None
        user_id, workspace_id = self._owner_tuple_from_params(params)
        if supersedes is not None:
            user_id, workspace_id = self._required_owner_tuple_from_params(params)
        decision = self._memory_manager.write_with_provenance(
            entry_type=entry_type,
            key=key,
            value=value,
            predicate=str(params.get("predicate", "")).strip() or None,
            strength=str(params.get("strength", "moderate")).strip() or "moderate",
            source=source,
            source_origin=context.source_origin,
            channel_trust=context.channel_trust,
            confirmation_status=context.confirmation_status,
            source_id=context.source_id,
            scope=context.scope,
            confidence=confidence,
            confirmation_satisfied=confirmation_satisfied,
            taint_labels=context.taint_labels,
            ingress_handle_id=context.handle_id,
            content_digest=resolved_digest,
            workflow_state=params.get("workflow_state"),
            invocation_eligible=bool(params.get("invocation_eligible", False)),
            supersedes=supersedes,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=bool(params.get("include_unowned", False)),
        )
        return self._with_memory_reject_hint(cast(dict[str, Any], decision.model_dump(mode="json")))

    def _resolve_skill_promotion_ingress(
        self,
        params: Mapping[str, Any],
        *,
        candidate_value: Any,
    ) -> tuple[IngressContext, str]:
        handle_id = str(params.get("ingress_context", "")).strip()
        context = self._memory_ingress_registry.resolve(handle_id)
        content_digest = str(params.get("content_digest", "")).strip() or None
        if content_digest is None and not isinstance(candidate_value, (str, bytes)):
            content_digest = digest_memory_value(candidate_value)
        resolved_digest = self._memory_ingress_registry.validate_binding(
            handle_id,
            content=candidate_value if isinstance(candidate_value, (str, bytes)) else None,
            content_digest=content_digest,
        )
        if (
            bool(params.get(_CONTROL_API_AUTHENTICATED_WRITE, False))
            and context.source_origin == "tool_output"
            and context.channel_trust == "tool_passed"
            and context.confirmation_status == "auto_accepted"
        ):
            install_context = self._memory_ingress_registry.mint(
                source_origin="tool_output",
                channel_trust="tool_passed",
                confirmation_status="pep_approved",
                scope="user",
                source_id=context.source_id,
                content=self._canonical_ingress_content(candidate_value),
                taint_labels=context.taint_labels,
            )
            return install_context, install_context.content_digest
        return context, resolved_digest

    async def do_memory_mint_ingress_context(self, params: Mapping[str, Any]) -> dict[str, Any]:
        is_internal_ingress = self._is_internal_ingress_request(params)
        source_type = str(params.get("source_type", "user")).strip().lower() or "user"
        user_confirmed = bool(params.get("user_confirmed", False))
        if not is_internal_ingress:
            source_type = "user"
        if user_confirmed and source_type != "user":
            raise ValueError("user_confirmed requires source_type=user")

        if source_type == "user":
            source_origin = "user_confirmed" if user_confirmed else "user_direct"
            channel_trust = "command"
            confirmation_status = "user_confirmed" if user_confirmed else "user_asserted"
        else:
            source_origin, channel_trust, confirmation_status = self._control_ingest_triple(
                source_type,
                user_confirmed=False,
            )

        content = self._canonical_ingress_content(params.get("content"))
        source_id = self._source_id_for_control_write(params) if is_internal_ingress else "cli"
        context = self._memory_ingress_registry.mint(
            source_origin=source_origin,
            channel_trust=channel_trust,
            confirmation_status=confirmation_status,
            scope="user",
            source_id=source_id,
            content=content,
            taint_labels=self._firewall_taint_labels(params),
        )
        return {
            "ingress_context": context.handle_id,
            "content_digest": context.content_digest,
            "source_origin": context.source_origin,
            "channel_trust": context.channel_trust,
            "confirmation_status": context.confirmation_status,
            "scope": context.scope,
            "source_id": context.source_id,
        }

    async def do_memory_ingest(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if params.get("ingress_context"):
            handle_id = str(params.get("ingress_context", ""))
            content = str(params.get("content", ""))
            context = self._memory_ingress_registry.resolve(handle_id)
            derivation_path = DerivationPath(str(params.get("derivation_path", "direct")))
            content_digest = str(params.get("content_digest", "")).strip() or None
            self._memory_ingress_registry.validate_binding(
                handle_id,
                content=content,
                content_digest=content_digest,
                derivation_path=derivation_path,
                parent_digest=str(params.get("parent_digest", "")).strip() or None,
            )
            collection = params.get("collection")
            source_origin: str | None = context.source_origin
            channel_trust: str | None = context.channel_trust
            confirmation_status: str | None = context.confirmation_status
            if (
                collection in {"project_docs", "external_web", "tool_outputs"}
                and context.source_origin == "user_direct"
                and context.confirmation_status == "user_asserted"
            ):
                source_origin = None
                channel_trust = None
                confirmation_status = None
            result = self._ingestion.ingest(
                source_id=context.source_id,
                source_type=self._retrieval_source_type_for_ingress(context.source_origin),
                content=content,
                collection=collection,
                source_origin=source_origin,
                channel_trust=channel_trust,
                confirmation_status=confirmation_status,
                scope=context.scope,
                user_id=(str(params.get("user_id")) if params.get("user_id") is not None else None),
                workspace_id=(
                    str(params.get("workspace_id"))
                    if params.get("workspace_id") is not None
                    else None
                ),
            )
            return cast(dict[str, Any], result.model_dump(mode="json"))
        if params.get(_CONTROL_API_AUTHENTICATED_WRITE):
            content = str(params.get("content", ""))
            source_origin, channel_trust, confirmation_status = self._control_ingest_triple(
                str(params.get("source_type", "user")),
                user_confirmed=bool(params.get("user_confirmed", False)),
            )
            context = self._memory_ingress_registry.mint(
                source_origin=source_origin,
                channel_trust=channel_trust,
                confirmation_status=confirmation_status,
                scope="user",
                source_id=self._source_id_for_control_write(params),
                content=content,
                taint_labels=self._firewall_taint_labels(params),
            )
            return await self.do_memory_ingest(
                {
                    "ingress_context": context.handle_id,
                    "content": content,
                    "collection": params.get("collection"),
                    "user_id": params.get("user_id"),
                    "workspace_id": params.get("workspace_id"),
                }
            )
        raise ValueError("ingress_context is required for memory.ingest")

    async def do_memory_retrieve(self, params: Mapping[str, Any]) -> dict[str, Any]:
        query = params.get("query", "")
        limit = int(params.get("limit", 5))
        capabilities = {Capability(cap) for cap in params.get("capabilities", [])}
        as_of_raw = params.get("as_of")
        as_of: datetime | None = None
        if isinstance(as_of_raw, datetime):
            as_of = as_of_raw
        elif str(as_of_raw or "").strip():
            as_of = datetime.fromisoformat(str(as_of_raw))
        scope_filter = (
            {str(item).strip() for item in params.get("scope_filter", []) if str(item).strip()}
            if params.get("scope_filter") is not None
            else None
        )
        pack = self._ingestion.compile_recall(
            query,
            task=(str(params.get("task", "")).strip() if params.get("task") is not None else None),
            limit=limit,
            capabilities=capabilities,
            require_corroboration=bool(params.get("require_corroboration", False)),
            verify_sufficiency=bool(params.get("verify_sufficiency", False)),
            expand_on_insufficient=bool(params.get("expand_on_insufficient", False)),
            min_sufficiency_results=int(params.get("min_sufficiency_results", 1)),
            min_sufficiency_coverage=float(params.get("min_sufficiency_coverage", 0.8)),
            max_tokens=(
                int(params["max_tokens"]) if params.get("max_tokens") is not None else None
            ),
            as_of=as_of,
            include_archived=bool(params.get("include_archived", False)),
            scope_filter=scope_filter,
            user_id=(str(params.get("user_id")) if params.get("user_id") is not None else None),
            workspace_id=(
                str(params.get("workspace_id")) if params.get("workspace_id") is not None else None
            ),
            # Normal memory.retrieve must not expose maintenance-only unowned
            # private recall. Low-level maintenance callers can invoke
            # compile_recall directly with include_unowned=True.
            include_unowned=False,
        )
        payload = cast(dict[str, Any], pack.legacy_payload())
        self._ingestion.record_citations([item.chunk_id for item in pack.results])
        return payload

    async def do_memory_write(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if params.get("ingress_context"):
            return self._write_handle_bound_entry(
                params,
                entry_type=str(params.get("entry_type", "fact")),
                key=str(params.get("key", "")),
                value=params.get("value"),
                confidence=float(params.get("confidence", 0.5)),
            )
        if params.get(_CONTROL_API_AUTHENTICATED_WRITE):
            return self._write_control_api_authenticated_entry(
                params,
                entry_type=str(params.get("entry_type", "fact")),
                key=str(params.get("key", "")),
                value=params.get("value"),
                confidence=float(params.get("confidence", 0.5)),
            )
        raise ValueError("ingress_context is required for memory.write")

    async def do_memory_supersede(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if not params.get("ingress_context") and not params.get(_CONTROL_API_AUTHENTICATED_WRITE):
            raise ValueError("ingress_context is required for memory.supersede")
        return await self.do_memory_write(params)

    async def do_memory_promote_identity_candidate(
        self,
        params: Mapping[str, Any],
    ) -> dict[str, Any]:
        handle_id = str(params.get("ingress_context", "")).strip()
        if not handle_id:
            raise ValueError("ingress_context is required for memory.promote_identity_candidate")
        candidate_id = str(params.get("candidate_id", "")).strip()
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        include_unowned = bool(params.get("include_unowned", False))
        context = self._memory_ingress_registry.resolve(handle_id)
        promoted_value = params.get("value")
        if promoted_value is None:
            candidate = self._memory_manager.get_entry(
                candidate_id,
                include_pending_review=True,
                user_id=user_id,
                workspace_id=workspace_id,
                include_unowned=include_unowned,
            )
            promoted_value = candidate.value if candidate is not None else None
        if promoted_value is None:
            return {
                "kind": "reject",
                "reason": "candidate_not_found",
                "entry": None,
            }
        content_digest = str(params.get("content_digest", "")).strip() or None
        if content_digest is None and not isinstance(promoted_value, (str, bytes)):
            content_digest = digest_memory_value(promoted_value)
        resolved_digest = self._memory_ingress_registry.validate_binding(
            handle_id,
            content=promoted_value if isinstance(promoted_value, (str, bytes)) else None,
            content_digest=content_digest,
        )
        decision = self._memory_manager.promote_identity_candidate(
            candidate_id=candidate_id,
            value=promoted_value,
            source=MemorySource(
                origin=legacy_source_view_origin(context.source_origin),
                source_id=context.source_id,
                extraction_method="identity.review.promote",
            ),
            source_origin=context.source_origin,
            channel_trust=context.channel_trust,
            confirmation_status=context.confirmation_status,
            source_id=context.source_id,
            scope=context.scope,
            ingress_handle_id=context.handle_id,
            content_digest=resolved_digest,
            taint_labels=context.taint_labels,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        return cast(dict[str, Any], decision.model_dump(mode="json"))

    async def do_memory_reject_identity_candidate(
        self,
        params: Mapping[str, Any],
    ) -> dict[str, Any]:
        handle_id = str(params.get("ingress_context", "")).strip()
        if not handle_id:
            raise ValueError("ingress_context is required for memory.reject_identity_candidate")
        self._memory_ingress_registry.resolve(handle_id)
        candidate_id = str(params.get("candidate_id", "")).strip()
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        changed, reason = self._memory_manager.reject_identity_candidate(
            candidate_id,
            ingress_handle_id=handle_id,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=bool(params.get("include_unowned", False)),
        )
        return {
            "changed": changed,
            "candidate_id": candidate_id,
            "reason": reason,
        }

    async def do_memory_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if params.get("include_quarantined") and not params.get("confirmed"):
            raise ValueError("confirmed is required when include_quarantined is true")
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        rows = self._memory_manager.list_entries(
            limit=int(params.get("limit", 100)),
            include_deleted=bool(params.get("include_deleted", False)),
            include_quarantined=bool(params.get("include_quarantined", False)),
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=bool(params.get("include_unowned", False)),
        )
        return {"entries": [entry.model_dump(mode="json") for entry in rows], "count": len(rows)}

    async def do_memory_list_review_queue(self, params: Mapping[str, Any]) -> dict[str, Any]:
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        include_unowned = bool(params.get("include_unowned", False))
        rows = self._memory_manager.list_review_queue(
            limit=int(params.get("limit", 100)),
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        return {
            "entries": [
                self._review_queue_entry_payload(
                    entry,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    include_unowned=include_unowned,
                )
                for entry in rows
            ],
            "count": len(rows),
        }

    def _review_queue_entry_payload(
        self,
        entry: MemoryEntry,
        *,
        user_id: str | None,
        workspace_id: str | None,
        include_unowned: bool,
    ) -> dict[str, Any]:
        if str(entry.entry_type) != "procedure_experience":
            return entry.model_dump(mode="json")
        payload: dict[str, Any] = {
            "id": entry.id,
            "entry_type": str(entry.entry_type),
            "key": entry.key,
            "status": entry.status,
            "confirmation_status": entry.confirmation_status,
            "scope": entry.scope,
            "user_id": entry.user_id,
            "workspace_id": entry.workspace_id,
            "source_id": entry.source_id,
            "source_origin": entry.source_origin,
            "channel_trust": entry.channel_trust,
            "created_at": entry.created_at.isoformat(),
        }
        review = self._memory_manager.describe_procedure_candidate(
            entry.id,
            backfill_legacy=False,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        candidate = review.get("candidate") if isinstance(review, Mapping) else None
        if not isinstance(candidate, Mapping):
            payload["review_blocked_reason"] = str(review.get("reason", "")).strip()
            return payload
        scanner = candidate.get("scanner")
        payload.update(
            {
                "target_entry_type": str(candidate.get("target_entry_type", "")).strip(),
                "target_key": str(candidate.get("target_key", "")).strip(),
                "trace_pool_hash_verified": bool(
                    candidate.get("trace_pool_hash_verified", False)
                ),
                "scanner": dict(scanner) if isinstance(scanner, Mapping) else {},
                "review_packet_ready": True,
            }
        )
        return payload

    async def do_memory_invoke_skill(self, params: Mapping[str, Any]) -> dict[str, Any]:
        skill_id = str(params.get("skill_id", "")).strip()
        caller_context: dict[str, Any] = {"method": "memory.invoke_skill"}
        rpc_peer = params.get("_rpc_peer")
        if isinstance(rpc_peer, Mapping):
            caller_context["rpc_peer"] = dict(rpc_peer)
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        include_unowned = bool(params.get("include_unowned", False))
        result = self._memory_manager.invoke_skill(
            skill_id,
            audit_context=caller_context,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        artifact = None
        if result.artifact is not None:
            artifact = {
                "id": result.artifact.id,
                "entry_type": result.artifact.entry_type,
                "key": result.artifact.key,
                "name": result.artifact.name,
                "description": result.artifact.description,
                "content": result.artifact.content,
                "trust_band": result.artifact.trust_band,
                "source_origin": result.artifact.source_origin,
                "channel_trust": result.artifact.channel_trust,
                "confirmation_status": result.artifact.confirmation_status,
                "last_used_at": result.artifact.last_used_at.isoformat()
                if result.artifact.last_used_at is not None
                else None,
                "size_bytes": result.artifact.size_bytes,
                "invocation_eligible": result.artifact.invocation_eligible,
                "prior_entry_id": result.artifact.prior_entry_id,
                "diff_preview": result.artifact.diff_preview,
            }
        return {
            "skill_id": result.skill_id,
            "found": result.found,
            "invoked": result.invoked,
            "reason": result.reason,
            "artifact": artifact,
        }

    async def do_memory_ingest_procedure_candidate(
        self,
        params: Mapping[str, Any],
    ) -> dict[str, Any]:
        handle_id = str(params.get("ingress_context", "")).strip()
        if not handle_id:
            raise ValueError("ingress_context is required for memory.ingest_procedure_candidate")
        context = self._memory_ingress_registry.resolve(handle_id)
        artifact = params.get("artifact")
        content_digest = (
            None if isinstance(artifact, (str, bytes)) else digest_memory_value(artifact)
        )
        resolved_digest = self._memory_ingress_registry.validate_binding(
            handle_id,
            content=artifact if isinstance(artifact, (str, bytes)) else None,
            content_digest=content_digest,
        )
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        decision = self._memory_manager.ingest_procedure_candidate(
            key=str(params.get("key", "")).strip(),
            artifact=artifact,
            target_entry_type=str(params.get("target_entry_type", "")).strip(),
            target_key=str(params.get("target_key", "")).strip(),
            trace_ids=[
                str(item).strip()
                for item in params.get("trace_ids", [])
                if str(item).strip()
            ],
            trace_pool_hash=str(params.get("trace_pool_hash", "")).strip(),
            scanner_verdict=(
                str(params.get("scanner_verdict", "")).strip() or None
                if params.get("scanner_verdict") is not None
                else None
            ),
            scanner_findings=[
                str(item).strip()
                for item in params.get("scanner_findings", [])
                if str(item).strip()
            ],
            diff_preview=(
                str(params.get("diff_preview", ""))
                if params.get("diff_preview") is not None
                else None
            ),
            source=MemorySource(
                origin=legacy_source_view_origin(context.source_origin),
                source_id=context.source_id,
                extraction_method="procedure.candidate.ingest",
            ),
            source_origin=context.source_origin,
            channel_trust=context.channel_trust,
            confirmation_status=context.confirmation_status,
            source_id=context.source_id,
            scope=context.scope,
            ingress_handle_id=context.handle_id,
            content_digest=resolved_digest,
            taint_labels=context.taint_labels,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=bool(params.get("include_unowned", False)),
        )
        return cast(dict[str, Any], decision.model_dump(mode="json"))

    async def do_memory_review_procedure_candidate(
        self,
        params: Mapping[str, Any],
    ) -> dict[str, Any]:
        handle_id = str(params.get("ingress_context", "")).strip()
        if not handle_id:
            raise ValueError("ingress_context is required for memory.review_procedure_candidate")
        context = self._memory_ingress_registry.resolve(handle_id)
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        return cast(
            dict[str, Any],
            self._memory_manager.describe_procedure_candidate(
                str(params.get("candidate_id", "")).strip(),
                ingress_handle_id=context.handle_id,
                user_id=user_id,
                workspace_id=workspace_id,
                include_unowned=bool(params.get("include_unowned", False)),
            ),
        )

    async def do_memory_reject_procedure_candidate(
        self,
        params: Mapping[str, Any],
    ) -> dict[str, Any]:
        handle_id = str(params.get("ingress_context", "")).strip()
        if not handle_id:
            raise ValueError("ingress_context is required for memory.reject_procedure_candidate")
        context = self._memory_ingress_registry.resolve(handle_id)
        candidate_id = str(params.get("candidate_id", "")).strip()
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        changed, reason = self._memory_manager.reject_procedure_candidate(
            candidate_id,
            ingress_handle_id=context.handle_id,
            reviewer=(
                str(params.get("reviewer", "")).strip()
                if params.get("reviewer") is not None
                else None
            ),
            reason=(
                str(params.get("reason", "")).strip()
                if params.get("reason") is not None
                else None
            ),
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=bool(params.get("include_unowned", False)),
        )
        return {
            "changed": changed,
            "candidate_id": candidate_id,
            "reason": reason,
        }

    async def do_memory_promote_procedure_candidate(
        self,
        params: Mapping[str, Any],
    ) -> dict[str, Any]:
        handle_id = str(params.get("ingress_context", "")).strip()
        if not handle_id:
            raise ValueError("ingress_context is required for memory.promote_procedure_candidate")
        candidate_id = str(params.get("candidate_id", "")).strip()
        context = self._memory_ingress_registry.resolve(handle_id)
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        include_unowned = bool(params.get("include_unowned", False))
        candidate = self._memory_manager.get_entry(
            candidate_id,
            include_pending_review=True,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        if (
            candidate is None
            or str(candidate.entry_type) != "procedure_experience"
            or not isinstance(candidate.value, dict)
        ):
            return {
                "kind": "reject",
                "reason": "procedure_candidate_not_found",
                "entry": None,
            }
        review = self._memory_manager.describe_procedure_candidate(
            candidate_id,
            ingress_handle_id=context.handle_id,
            backfill_legacy=False,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        review_candidate = review.get("candidate") or {}
        approval_payload = str(review_candidate.get("approval_payload", "")).strip()
        if not approval_payload:
            return {
                "kind": "reject",
                "reason": "procedure_candidate_review_packet_required",
                "entry": None,
            }
        artifact_digest = digest_memory_value(review_candidate.get("artifact"))
        self._memory_ingress_registry.validate_binding(
            handle_id,
            content=approval_payload,
        )
        decision = self._memory_manager.promote_procedure_candidate(
            candidate_id=candidate_id,
            source=MemorySource(
                origin=legacy_source_view_origin(context.source_origin),
                source_id=context.source_id,
                extraction_method="procedure.candidate.promote",
            ),
            source_origin=context.source_origin,
            channel_trust=context.channel_trust,
            confirmation_status=context.confirmation_status,
            source_id=context.source_id,
            scope=context.scope,
            ingress_handle_id=context.handle_id,
            content_digest=artifact_digest,
            reviewer=(
                str(params.get("reviewer", "")).strip()
                if params.get("reviewer") is not None
                else None
            ),
            taint_labels=context.taint_labels,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        return cast(dict[str, Any], decision.model_dump(mode="json"))

    async def do_memory_promote_skill(
        self,
        params: Mapping[str, Any],
    ) -> dict[str, Any]:
        handle_id = str(params.get("ingress_context", "")).strip()
        if not handle_id:
            raise ValueError("ingress_context is required for memory.promote_to_skill")
        entry_id = str(params.get("entry_id", "")).strip()
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        include_unowned = bool(params.get("include_unowned", False))
        candidate = self._memory_manager.get_entry(
            entry_id,
            include_pending_review=True,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        if candidate is None:
            return {
                "kind": "reject",
                "reason": "skill_not_found",
                "entry": None,
            }
        context, resolved_digest = self._resolve_skill_promotion_ingress(
            params,
            candidate_value=candidate.value,
        )
        decision = self._memory_manager.promote_to_skill(
            entry_id=entry_id,
            source=MemorySource(
                origin=legacy_source_view_origin(context.source_origin),
                source_id=context.source_id,
                extraction_method="skill.review.promote",
            ),
            source_origin=context.source_origin,
            channel_trust=context.channel_trust,
            confirmation_status=context.confirmation_status,
            source_id=context.source_id,
            scope=context.scope,
            ingress_handle_id=context.handle_id,
            content_digest=resolved_digest,
            taint_labels=context.taint_labels,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        return cast(dict[str, Any], decision.model_dump(mode="json"))

    async def do_memory_read_original(self, params: Mapping[str, Any]) -> dict[str, Any]:
        chunk_id = str(params.get("chunk_id", "")).strip()
        caller_context: dict[str, Any] = {"method": "memory.read_original"}
        rpc_peer = params.get("_rpc_peer")
        if isinstance(rpc_peer, Mapping):
            caller_context["rpc_peer"] = dict(rpc_peer)
        content = self._ingestion.read_original(chunk_id, audit_context=caller_context)
        return {
            "chunk_id": chunk_id,
            "found": content is not None,
            "content": content,
        }

    async def do_graph_query(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entity = str(params.get("entity", "")).strip()
        depth = max(1, min(3, int(params.get("depth", 1))))
        limit = max(1, min(100, int(params.get("limit", 20))))
        scope_filter = self._scope_filter_from_params(params)
        user_id, workspace_id = self._owner_tuple_from_params(params)
        entries = self._list_memory_entries_for_scope(
            scope_filter=scope_filter,
            user_id=user_id,
            workspace_id=workspace_id,
            include_quarantined=False,
        )
        graph = build_knowledge_graph(entries)
        result = graph.query(entity, depth=depth, limit=limit)
        return {
            "root_entity_id": result.root_entity_id,
            "derived": result.derived,
            "schema_version": result.schema_version,
            "build_version": result.build_version,
            "nodes": [node.to_dict() for node in result.nodes],
            "edges": [edge.to_dict() for edge in result.edges],
        }

    async def do_graph_export(self, params: Mapping[str, Any]) -> dict[str, Any]:
        fmt = str(params.get("format", "json")).strip().lower() or "json"
        scope_filter = self._scope_filter_from_params(params)
        user_id, workspace_id = self._owner_tuple_from_params(params)
        entries = self._list_memory_entries_for_scope(
            scope_filter=scope_filter,
            user_id=user_id,
            workspace_id=workspace_id,
            include_quarantined=False,
        )
        graph = build_knowledge_graph(entries)
        return {"format": fmt, "data": graph.export(format=fmt)}

    async def do_thread_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        include_unowned = bool(params.get("include_unowned", False))
        state, allowed_states = self._thread_state_filter(params.get("state"))
        limit = max(1, int(params.get("limit", 20)))
        scope_filter, allowed_channel_trusts, channel_binding, session_scope_id = (
            self._thread_context_filters_from_params(params)
        )
        entries = self._memory_manager.list_entries(
            entry_type="open_thread",
            limit=max(limit, len(getattr(self._memory_manager, "_entries", {})), 1),
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        entries = self._filter_thread_entries_by_context(
            entries,
            scope_filter=scope_filter,
            allowed_channel_trusts=allowed_channel_trusts,
            channel_binding=channel_binding,
            session_scope_id=session_scope_id,
        )
        if allowed_states is not None:
            entries = [entry for entry in entries if str(entry.workflow_state) in allowed_states]
        selected = entries[:limit]
        return {
            "threads": [self._thread_summary_payload(entry) for entry in selected],
            "count": len(selected),
            "filters": {
                "state": state,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "include_unowned": include_unowned,
                "scope_filter": sorted(scope_filter) if scope_filter is not None else None,
                "allowed_channel_trusts": sorted(allowed_channel_trusts)
                if allowed_channel_trusts is not None
                else None,
                "channel_binding": channel_binding,
                "session_scope_id": session_scope_id,
            },
        }

    async def do_thread_inspect(self, params: Mapping[str, Any]) -> dict[str, Any]:
        thread_id = str(params.get("thread_id", "") or params.get("entry_id", "")).strip()
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        include_unowned = bool(params.get("include_unowned", False))
        entry = self._get_visible_thread(
            thread_id=thread_id,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        if entry is not None:
            scope_filter, allowed_channel_trusts, channel_binding, session_scope_id = (
                self._thread_context_filters_from_params(params)
            )
            visible_entries = self._filter_thread_entries_by_context(
                [entry],
                scope_filter=scope_filter,
                allowed_channel_trusts=allowed_channel_trusts,
                channel_binding=channel_binding,
                session_scope_id=session_scope_id,
            )
            entry = visible_entries[0] if visible_entries else None
        if entry is None:
            return {
                "found": False,
                "thread": None,
                "packet": None,
                "selection": {
                    "status": "not_found",
                    "selected_id": "",
                    "candidate_ids": [],
                    "confidence": 0.0,
                    "rationale": [],
                    "missing_evidence": ["thread_not_found"],
                    "metrics": thread_selection_metrics(
                        status="not_found",
                        confidence=0.0,
                        alternatives=(),
                        packet=None,
                        missing_evidence=["thread_not_found"],
                    ),
                },
            }
        packet_obj = build_thread_packet(entry)
        packet = self._thread_packet_payload_from_packet(packet_obj)
        missing_evidence = packet["sufficiency"]["missing_evidence"]
        return {
            "found": True,
            "thread": self._thread_summary_payload(entry),
            "packet": packet,
            "selection": {
                "status": "inspect_only",
                "selected_id": "",
                "candidate_ids": [entry.id],
                "confidence": entry.confidence,
                "rationale": ["explicit_thread_inspect"],
                "missing_evidence": missing_evidence,
                "metrics": thread_selection_metrics(
                    status="inspect_only",
                    confidence=entry.confidence,
                    alternatives=(),
                    packet=packet_obj,
                    missing_evidence=missing_evidence,
                ),
            },
        }

    async def _do_thread_set_state(
        self,
        params: Mapping[str, Any],
        *,
        workflow_state: str,
        default_reason: str,
    ) -> dict[str, Any]:
        thread_id = str(params.get("thread_id", "") or params.get("entry_id", "")).strip()
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        include_unowned = bool(params.get("include_unowned", False))
        reason = str(params.get("reason", "")).strip() or default_reason
        entry = self._get_visible_thread(
            thread_id=thread_id,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        if entry is not None:
            scope_filter, allowed_channel_trusts, channel_binding, session_scope_id = (
                self._thread_context_filters_from_params(params)
            )
            visible_entries = self._filter_thread_entries_by_context(
                [entry],
                scope_filter=scope_filter,
                allowed_channel_trusts=allowed_channel_trusts,
                channel_binding=channel_binding,
                session_scope_id=session_scope_id,
            )
            entry = visible_entries[0] if visible_entries else None
        if entry is None:
            return {
                "changed": False,
                "thread_id": thread_id,
                "thread": None,
                "reason": "thread_not_found",
            }
        try:
            changed = self._memory_manager.set_workflow_state(
                thread_id,
                workflow_state,
                user_id=user_id,
                workspace_id=workspace_id,
                include_unowned=include_unowned,
                reason=reason,
                allow_closed_reopen=workflow_state == "active",
            )
        except ValueError as exc:
            return {
                "changed": False,
                "thread_id": thread_id,
                "thread": self._thread_summary_payload(entry),
                "reason": str(exc).split(":", 1)[0].strip() or "invalid_workflow_transition",
            }
        updated = self._get_visible_thread(
            thread_id=thread_id,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        return {
            "changed": changed,
            "thread_id": thread_id,
            "thread": self._thread_summary_payload(updated or entry),
            "reason": "changed" if changed else "thread_not_found",
        }

    async def do_thread_resume(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._do_thread_set_state(
            params,
            workflow_state="active",
            default_reason="explicit_thread_resume",
        )

    async def do_thread_close(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self._do_thread_set_state(
            params,
            workflow_state="closed",
            default_reason="explicit_thread_close",
        )

    async def do_thread_why(self, params: Mapping[str, Any]) -> dict[str, Any]:
        query = str(params.get("query", "")).strip()
        if not query:
            raise ValueError("query is required")
        thread_id = str(params.get("thread_id", "") or params.get("entry_id", "")).strip()
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        include_unowned = bool(params.get("include_unowned", False))
        scope_filter, allowed_channel_trusts, channel_binding, session_scope_id = (
            self._thread_context_filters_from_params(params)
        )
        visible_thread = (
            self._get_visible_thread(
                thread_id=thread_id,
                user_id=user_id,
                workspace_id=workspace_id,
                include_unowned=include_unowned,
            )
            if thread_id
            else None
        )
        if visible_thread is not None:
            visible_entries = self._filter_thread_entries_by_context(
                [visible_thread],
                scope_filter=scope_filter,
                allowed_channel_trusts=allowed_channel_trusts,
                channel_binding=channel_binding,
                session_scope_id=session_scope_id,
            )
            visible_thread = visible_entries[0] if visible_entries else None
        pack = self._memory_manager.compile_thread_resume(
            query,
            max_tokens=max(1, int(params.get("max_tokens", 700))),
            scope_filter=scope_filter,
            allowed_channel_trusts=allowed_channel_trusts,
            channel_binding=channel_binding,
            session_scope_id=session_scope_id,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=include_unowned,
        )
        selection = self._thread_selection_payload(pack)
        selected_id = str(selection.get("selected_id", ""))
        selected = bool(selected_id) and (not thread_id or selected_id == thread_id)
        packet = None
        packet_obj = getattr(pack, "packet", None)
        if packet_obj is not None:
            packet = self._thread_packet_payload_from_packet(packet_obj)
        return {
            "selected": selected,
            "thread": self._thread_summary_payload(visible_thread) if visible_thread else None,
            "selection": selection,
            "packet": packet,
        }

    async def do_memory_consolidate(self, params: Mapping[str, Any]) -> dict[str, Any]:
        scope_filter = self._scope_filter_from_params(params)
        user_id, workspace_id = self._owner_tuple_from_params(params)
        worker = ConsolidationWorker(
            self._memory_manager,
            scope_filter=scope_filter,
            user_id=user_id,
            workspace_id=workspace_id,
            require_owner_scope=True,
        )
        result = None
        if (
            bool(params.get("recompute_scores", True))
            and bool(params.get("apply_confidence_updates", True))
            and bool(params.get("propose_strong_invalidations", True))
            and bool(params.get("accumulate_identity_candidates", True))
        ):
            result = worker.run_once()
        else:
            result = ConsolidationRunResult()
            if bool(params.get("recompute_scores", True)):
                decay = worker.recompute_decay_scores()
                result.updated_entry_ids.extend(decay.updated_entry_ids)
            if bool(params.get("apply_confidence_updates", True)):
                confidence = worker.apply_confidence_updates()
                result.updated_entry_ids.extend(confidence.updated_entry_ids)
                result.corroborating_entry_ids.extend(confidence.corroborating_entry_ids)
                result.contradicted_entry_ids.extend(confidence.contradicted_entry_ids)
            dedup = worker.deduplicate_entries()
            retention = worker.enforce_retention()
            result.merged_entry_ids.extend(dedup.merged_entry_ids)
            result.archive_candidate_ids.extend(retention.archive_candidate_ids)
            result.quarantined_entry_ids.extend(retention.quarantined_entry_ids)
            if bool(params.get("propose_strong_invalidations", True)):
                result.strong_invalidations.extend(worker.propose_strong_invalidations())
            if bool(params.get("accumulate_identity_candidates", True)):
                result.identity_candidates.extend(worker.accumulate_identity_candidates())
        return {
            "updated_entry_ids": sorted(set(result.updated_entry_ids)),
            "corroborating_entry_ids": sorted(set(result.corroborating_entry_ids)),
            "contradicted_entry_ids": sorted(set(result.contradicted_entry_ids)),
            "merged_entry_ids": sorted(set(result.merged_entry_ids)),
            "archive_candidate_ids": sorted(set(result.archive_candidate_ids)),
            "quarantined_entry_ids": sorted(set(result.quarantined_entry_ids)),
            "strong_invalidation_count": len(result.strong_invalidations),
            "identity_candidate_count": len(result.identity_candidates),
            "strong_invalidations": [
                {
                    "target_entry_id": item.target_entry_id,
                    "signal_entry_id": item.signal_entry_id,
                    "pattern": item.pattern,
                    "message": item.message,
                }
                for item in result.strong_invalidations
            ],
            "identity_candidate_ids": [entry.id for entry in result.identity_candidates],
            "capability_scope": {
                "network": worker.capability_scope.network,
                "tool_recursion": worker.capability_scope.tool_recursion,
                "self_invocation": worker.capability_scope.self_invocation,
                "write_scope": worker.capability_scope.write_scope,
            },
        }

    async def do_memory_get(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if params.get("include_quarantined") and not params.get("confirmed"):
            raise ValueError("confirmed is required when include_quarantined is true")
        entry_id = str(params.get("entry_id", ""))
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        entry = self._memory_manager.get_entry(
            entry_id,
            include_deleted=bool(params.get("include_deleted", False)),
            include_quarantined=bool(params.get("include_quarantined", False)),
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=bool(params.get("include_unowned", False)),
        )
        return {"entry": entry.model_dump(mode="json") if entry is not None else None}

    async def do_memory_delete(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        deleted = self._memory_manager.delete(
            entry_id,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=bool(params.get("include_unowned", False)),
        )
        return {"deleted": deleted, "entry_id": entry_id}

    async def do_memory_quarantine(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        reason = str(params.get("reason", "")).strip()
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        changed = self._memory_manager.quarantine(
            entry_id,
            reason=reason,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=bool(params.get("include_unowned", False)),
        )
        return {"changed": changed, "entry_id": entry_id, "reason": reason}

    async def do_memory_unquarantine(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        reason = str(params.get("reason", "")).strip()
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        changed = self._memory_manager.unquarantine(
            entry_id,
            reason=reason,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=bool(params.get("include_unowned", False)),
        )
        return {"changed": changed, "entry_id": entry_id, "reason": reason}

    async def do_memory_set_workflow_state(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        workflow_state = str(params.get("workflow_state", "")).strip()
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        try:
            changed = self._memory_manager.set_workflow_state(
                entry_id,
                workflow_state,
                user_id=user_id,
                workspace_id=workspace_id,
                include_unowned=bool(params.get("include_unowned", False)),
            )
        except ValueError as exc:
            reason = str(exc).split(":", 1)[0].strip() or "invalid_workflow_transition"
            return {
                "changed": False,
                "entry_id": entry_id,
                "workflow_state": workflow_state,
                "reason": reason,
            }
        return {
            "changed": changed,
            "entry_id": entry_id,
            "workflow_state": workflow_state,
            "reason": "changed" if changed else "entry_not_found",
        }

    async def do_memory_export(self, params: Mapping[str, Any]) -> dict[str, Any]:
        fmt = str(params.get("format", "json"))
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        return {
            "format": fmt,
            "data": self._memory_manager.export(
                fmt=fmt,
                user_id=user_id,
                workspace_id=workspace_id,
                include_unowned=bool(params.get("include_unowned", False)),
            ),
        }

    async def do_memory_verify(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        user_id, workspace_id = self._required_owner_tuple_from_params(params)
        verified = self._memory_manager.verify(
            entry_id,
            user_id=user_id,
            workspace_id=workspace_id,
            include_unowned=bool(params.get("include_unowned", False)),
        )
        return {"verified": verified, "entry_id": entry_id}

    async def do_memory_rotate_key(self, params: Mapping[str, Any]) -> dict[str, Any]:
        reencrypt_existing = bool(params.get("reencrypt_existing", True))
        key_id = self._ingestion.rotate_data_key(reencrypt_existing=reencrypt_existing)
        return {
            "rotated": True,
            "active_key_id": key_id,
            "reencrypt_existing": reencrypt_existing,
        }

    async def do_note_create(self, params: Mapping[str, Any]) -> dict[str, Any]:
        caller_user_id, caller_workspace_id = self._required_owner_tuple_from_params(params)
        if params.get("ingress_context"):
            result = self._write_handle_bound_entry(
                params,
                entry_type="note",
                key=str(params.get("key", "")),
                value=str(params.get("content", "")),
                confidence=float(params.get("confidence", 0.8)),
            )
            self._index_note_write_for_recall(
                result, user_id=caller_user_id, workspace_id=caller_workspace_id
            )
            return result
        if params.get(_CONTROL_API_AUTHENTICATED_WRITE):
            result = self._write_control_api_authenticated_entry(
                params,
                entry_type="note",
                key=str(params.get("key", "")),
                value=str(params.get("content", "")),
                confidence=float(params.get("confidence", 0.8)),
            )
            self._index_note_write_for_recall(
                result, user_id=caller_user_id, workspace_id=caller_workspace_id
            )
            return result
        source = MemorySource(
            origin=str(params.get("origin", "user")),
            source_id=self._coerce_source_id(params.get("source_id")) or "cli",
            extraction_method="note.create",
        )
        context = self._mint_legacy_compat_ingress(
            params,
            source=source,
            value=str(params.get("content", "")),
        )
        result = self._write_handle_bound_entry(
            {
                **dict(params),
                "ingress_context": context.handle_id,
                "_confirmation_satisfied_override": bool(params.get("user_confirmed", False)),
            },
            entry_type="note",
            key=str(params.get("key", "")),
            value=str(params.get("content", "")),
            confidence=float(params.get("confidence", 0.8)),
        )
        self._index_note_write_for_recall(
            result, user_id=caller_user_id, workspace_id=caller_workspace_id
        )
        return result

    async def do_note_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        limit = max(1, int(params.get("limit", 100)))
        owner_scope = self._required_owner_scope_from_params(params)
        rows = self._memory_manager.list_entries(
            entry_type="note",
            limit=limit,
            **owner_scope,
        )
        notes = [entry.model_dump(mode="json") for entry in rows]
        return {"entries": notes, "count": len(notes)}

    async def do_note_search(self, params: Mapping[str, Any]) -> dict[str, Any]:
        query = str(params.get("query", "")).strip()
        limit = max(1, int(params.get("limit", 20)))
        lowered_terms = [term for term in query.lower().split() if term]
        owner_scope = self._required_owner_scope_from_params(params)
        rows = self._memory_manager.list_entries(
            entry_type="note",
            limit=200,
            **owner_scope,
        )
        matches: list[dict[str, Any]] = []
        for entry in rows:
            haystack = " ".join(
                [
                    str(entry.key),
                    str(entry.value),
                    str(getattr(entry.source, "source_id", "")),
                ]
            ).lower()
            if lowered_terms and not all(term in haystack for term in lowered_terms):
                continue
            matches.append(entry.model_dump(mode="json"))
            if len(matches) >= limit:
                break
        return {"query": query, "entries": matches, "count": len(matches)}

    async def do_note_get(self, params: Mapping[str, Any]) -> dict[str, Any]:
        owner_scope = self._required_owner_scope_from_params(params)
        entry = self._memory_manager.get_entry(
            str(params.get("entry_id", "")),
            **owner_scope,
        )
        if entry is None or str(entry.entry_type) != "note":
            return {"entry": None}
        return {"entry": entry.model_dump(mode="json")}

    async def do_note_delete(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        owner_scope = self._required_owner_scope_from_params(params)
        entry = self._memory_manager.get_entry(
            entry_id,
            **owner_scope,
        )
        if entry is None or str(entry.entry_type) != "note":
            return {"deleted": False, "entry_id": entry_id}
        deleted = self._memory_manager.delete(entry_id, **owner_scope)
        return {"deleted": deleted, "entry_id": entry_id}

    async def do_note_verify(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        owner_scope = self._required_owner_scope_from_params(params)
        entry = self._memory_manager.get_entry(
            entry_id,
            **owner_scope,
        )
        if entry is None or str(entry.entry_type) != "note":
            return {"verified": False, "entry_id": entry_id}
        verified = self._memory_manager.verify(entry_id, **owner_scope)
        return {"verified": verified, "entry_id": entry_id}

    async def do_note_export(self, params: Mapping[str, Any]) -> dict[str, Any]:
        fmt = str(params.get("format", "json"))
        owner_scope = self._required_owner_scope_from_params(params)
        rows = self._memory_manager.list_entries(
            entry_type="note",
            include_deleted=True,
            limit=2000,
            **owner_scope,
        )
        notes = [entry.model_dump(mode="json") for entry in rows if str(entry.entry_type) == "note"]
        if fmt == "json":
            return {"format": "json", "data": json.dumps(notes, indent=2)}
        if fmt == "csv":
            header = "id,key,value,created_at,user_verified,deleted_at"
            body = [
                render_csv_row(
                    [
                        item.get("id", ""),
                        item.get("key", ""),
                        item.get("value", ""),
                        item.get("created_at", ""),
                        item.get("user_verified", ""),
                        item.get("deleted_at", ""),
                    ]
                )
                for item in notes
            ]
            return {"format": "csv", "data": "\n".join([header, *body])}
        raise ValueError(f"Unsupported export format: {fmt}")

    async def do_todo_create(self, params: Mapping[str, Any]) -> dict[str, Any]:
        self._required_owner_tuple_from_params(params)
        payload = {
            "title": str(params.get("title", "")).strip(),
            "details": str(params.get("details", "")).strip(),
            "status": str(params.get("status", "open")).strip() or "open",
            "due_date": str(params.get("due_date", "")).strip(),
        }
        if payload["status"] not in {"open", "in_progress", "done"}:
            raise ValueError("status must be one of: open, in_progress, done")
        if params.get("ingress_context"):
            return self._write_handle_bound_entry(
                params,
                entry_type="todo",
                key=f"todo:{payload['title'][:64]}",
                value=payload,
                confidence=float(params.get("confidence", 0.8)),
            )
        if params.get(_CONTROL_API_AUTHENTICATED_WRITE):
            return self._write_control_api_authenticated_entry(
                params,
                entry_type="todo",
                key=f"todo:{payload['title'][:64]}",
                value=payload,
                confidence=float(params.get("confidence", 0.8)),
            )
        source = MemorySource(
            origin=str(params.get("origin", "user")),
            source_id=self._coerce_source_id(params.get("source_id")) or "cli",
            extraction_method="todo.create",
        )
        context = self._mint_legacy_compat_ingress(
            params,
            source=source,
            value=payload,
        )
        return self._write_handle_bound_entry(
            {
                **dict(params),
                "ingress_context": context.handle_id,
                "content_digest": digest_memory_value(payload),
                "_confirmation_satisfied_override": bool(params.get("user_confirmed", False)),
            },
            entry_type="todo",
            key=f"todo:{payload['title'][:64]}",
            value=payload,
            confidence=float(params.get("confidence", 0.8)),
        )

    async def do_todo_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        limit = max(1, int(params.get("limit", 100)))
        owner_scope = self._required_owner_scope_from_params(params)
        rows = self._memory_manager.list_entries(
            entry_type="todo",
            limit=limit,
            **owner_scope,
        )
        todos = [entry.model_dump(mode="json") for entry in rows]
        return {"entries": todos, "count": len(todos)}

    def _resolve_todo_matches(
        self,
        selector: str,
        *,
        user_id: str | None = None,
        workspace_id: str | None = None,
        include_unowned: bool = False,
    ) -> list[Any]:
        normalized = selector.strip().lower()
        if not normalized:
            return []
        owner_scope = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "include_unowned": include_unowned,
        }
        direct = self._memory_manager.get_entry(selector, **owner_scope)
        if direct is not None and str(direct.entry_type) == "todo":
            return [direct]
        exact: list[Any] = []
        partial: list[Any] = []
        for entry in self._memory_manager.list_entries(
            entry_type="todo",
            limit=200,
            **owner_scope,
        ):
            value = entry.value if isinstance(entry.value, dict) else {}
            title = str(value.get("title", "")).strip()
            if normalized == entry.id.lower() or (title and normalized == title.lower()):
                exact.append(entry)
                continue
            haystacks = [entry.id.lower(), str(entry.key).lower(), title.lower()]
            if any(normalized in item for item in haystacks if item):
                partial.append(entry)
        return exact or partial

    async def do_todo_complete(self, params: Mapping[str, Any]) -> dict[str, Any]:
        selector = str(params.get("selector", "")).strip()
        owner_scope = self._required_owner_scope_from_params(params)
        matches = self._resolve_todo_matches(
            selector,
            **owner_scope,
        )
        if not matches:
            return {
                "completed": False,
                "entry_id": "",
                "entry": None,
                "reason": "todo_not_found",
                "matches": [],
            }
        if len(matches) > 1:
            preview = [entry.model_dump(mode="json") for entry in matches[:10]]
            return {
                "completed": False,
                "entry_id": "",
                "entry": None,
                "reason": "todo_selector_ambiguous",
                "matches": preview,
            }
        entry = matches[0]
        value = entry.value if isinstance(entry.value, dict) else {}
        updated_value = dict(value)
        updated_value["status"] = "done"
        updated_value["completed_at"] = datetime.now(UTC).isoformat()
        entry.value = updated_value
        entry.user_verified = True
        entry.last_verified_at = datetime.now(UTC)
        self._memory_manager._persist_entry(entry)
        self._memory_manager._audit(
            "memory.todo_complete",
            {
                "entry_id": entry.id,
                "selector": selector,
            },
        )
        return {
            "completed": True,
            "entry_id": entry.id,
            "entry": entry.model_dump(mode="json"),
            "reason": "",
            "matches": [],
        }

    async def do_todo_get(self, params: Mapping[str, Any]) -> dict[str, Any]:
        owner_scope = self._required_owner_scope_from_params(params)
        entry = self._memory_manager.get_entry(
            str(params.get("entry_id", "")),
            **owner_scope,
        )
        if entry is None or str(entry.entry_type) != "todo":
            return {"entry": None}
        return {"entry": entry.model_dump(mode="json")}

    async def do_todo_delete(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        owner_scope = self._required_owner_scope_from_params(params)
        entry = self._memory_manager.get_entry(
            entry_id,
            **owner_scope,
        )
        if entry is None or str(entry.entry_type) != "todo":
            return {"deleted": False, "entry_id": entry_id}
        deleted = self._memory_manager.delete(entry_id, **owner_scope)
        return {"deleted": deleted, "entry_id": entry_id}

    async def do_todo_verify(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        owner_scope = self._required_owner_scope_from_params(params)
        entry = self._memory_manager.get_entry(
            entry_id,
            **owner_scope,
        )
        if entry is None or str(entry.entry_type) != "todo":
            return {"verified": False, "entry_id": entry_id}
        verified = self._memory_manager.verify(entry_id, **owner_scope)
        return {"verified": verified, "entry_id": entry_id}

    async def do_todo_export(self, params: Mapping[str, Any]) -> dict[str, Any]:
        fmt = str(params.get("format", "json"))
        owner_scope = self._required_owner_scope_from_params(params)
        rows = self._memory_manager.list_entries(
            entry_type="todo",
            include_deleted=True,
            limit=2000,
            **owner_scope,
        )
        todos = [entry.model_dump(mode="json") for entry in rows if str(entry.entry_type) == "todo"]
        if fmt == "json":
            return {"format": "json", "data": json.dumps(todos, indent=2)}
        if fmt == "csv":
            header = "id,title,status,due_date,created_at,user_verified,deleted_at"
            body = []
            for item in todos:
                value = item.get("value", {})
                if not isinstance(value, dict):
                    value = {}
                body.append(
                    render_csv_row(
                        [
                            item.get("id", ""),
                            value.get("title", ""),
                            value.get("status", ""),
                            value.get("due_date", ""),
                            item.get("created_at", ""),
                            item.get("user_verified", ""),
                            item.get("deleted_at", ""),
                        ]
                    )
                )
            return {"format": "csv", "data": "\n".join([header, *body])}
        raise ValueError(f"Unsupported export format: {fmt}")
