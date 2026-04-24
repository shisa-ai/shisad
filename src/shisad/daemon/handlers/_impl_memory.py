"""Memory/note/todo handler implementations."""

from __future__ import annotations

import json
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
from shisad.memory.schema import MemorySource
from shisad.memory.trust import backfill_legacy_triple

_CONTROL_API_AUTHENTICATED_WRITE = "_control_api_authenticated_write"
_DEFAULT_MEMORY_GRAPH_SCOPES = frozenset({"user"})


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

    def _list_memory_entries_for_scope(
        self,
        *,
        scope_filter: set[str] | None,
        include_quarantined: bool = False,
        include_pending_review: bool = False,
    ) -> list[Any]:
        entries = cast(
            list[Any],
            self._memory_manager.list_entries(
                limit=max(1, len(getattr(self._memory_manager, "_entries", {}))),
                include_quarantined=include_quarantined,
                include_pending_review=include_pending_review,
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
            supersedes=str(params.get("supersedes", "")).strip() or None,
        )
        return cast(dict[str, Any], decision.model_dump(mode="json"))

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
            result = self._ingestion.ingest(
                source_id=context.source_id,
                source_type=self._retrieval_source_type_for_ingress(context.source_origin),
                content=content,
                collection=params.get("collection"),
                source_origin=context.source_origin,
                channel_trust=context.channel_trust,
                confirmation_status=context.confirmation_status,
                scope=context.scope,
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
            limit=limit,
            capabilities=capabilities,
            require_corroboration=bool(params.get("require_corroboration", False)),
            max_tokens=(
                int(params["max_tokens"]) if params.get("max_tokens") is not None else None
            ),
            as_of=as_of,
            include_archived=bool(params.get("include_archived", False)),
            scope_filter=scope_filter,
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
        context = self._memory_ingress_registry.resolve(handle_id)
        promoted_value = params.get("value")
        if promoted_value is None:
            candidate = self._memory_manager.get_entry(
                candidate_id,
                include_pending_review=True,
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
        changed, reason = self._memory_manager.reject_identity_candidate(
            candidate_id,
            ingress_handle_id=handle_id,
        )
        return {
            "changed": changed,
            "candidate_id": candidate_id,
            "reason": reason,
        }

    async def do_memory_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if params.get("include_quarantined") and not params.get("confirmed"):
            raise ValueError("confirmed is required when include_quarantined is true")
        rows = self._memory_manager.list_entries(
            limit=int(params.get("limit", 100)),
            include_deleted=bool(params.get("include_deleted", False)),
            include_quarantined=bool(params.get("include_quarantined", False)),
        )
        return {"entries": [entry.model_dump(mode="json") for entry in rows], "count": len(rows)}

    async def do_memory_list_review_queue(self, params: Mapping[str, Any]) -> dict[str, Any]:
        rows = self._memory_manager.list_review_queue(limit=int(params.get("limit", 100)))
        return {"entries": [entry.model_dump(mode="json") for entry in rows], "count": len(rows)}

    async def do_memory_invoke_skill(self, params: Mapping[str, Any]) -> dict[str, Any]:
        skill_id = str(params.get("skill_id", "")).strip()
        caller_context: dict[str, Any] = {"method": "memory.invoke_skill"}
        rpc_peer = params.get("_rpc_peer")
        if isinstance(rpc_peer, Mapping):
            caller_context["rpc_peer"] = dict(rpc_peer)
        result = self._memory_manager.invoke_skill(skill_id, audit_context=caller_context)
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

    async def do_memory_promote_skill(
        self,
        params: Mapping[str, Any],
    ) -> dict[str, Any]:
        handle_id = str(params.get("ingress_context", "")).strip()
        if not handle_id:
            raise ValueError("ingress_context is required for memory.promote_to_skill")
        entry_id = str(params.get("entry_id", "")).strip()
        candidate = self._memory_manager.get_entry(
            entry_id,
            include_pending_review=True,
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
        entries = self._list_memory_entries_for_scope(
            scope_filter=scope_filter,
            include_quarantined=False,
        )
        graph = build_knowledge_graph(entries)
        result = graph.query(entity, depth=depth, limit=limit)
        return {
            "root_entity_id": result.root_entity_id,
            "nodes": [node.to_dict() for node in result.nodes],
            "edges": [edge.to_dict() for edge in result.edges],
        }

    async def do_graph_export(self, params: Mapping[str, Any]) -> dict[str, Any]:
        fmt = str(params.get("format", "json")).strip().lower() or "json"
        scope_filter = self._scope_filter_from_params(params)
        entries = self._list_memory_entries_for_scope(
            scope_filter=scope_filter,
            include_quarantined=False,
        )
        graph = build_knowledge_graph(entries)
        return {"format": fmt, "data": graph.export(format=fmt)}

    async def do_memory_consolidate(self, params: Mapping[str, Any]) -> dict[str, Any]:
        scope_filter = self._scope_filter_from_params(params)
        worker = ConsolidationWorker(self._memory_manager, scope_filter=scope_filter)
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
        entry = self._memory_manager.get_entry(
            entry_id,
            include_deleted=bool(params.get("include_deleted", False)),
            include_quarantined=bool(params.get("include_quarantined", False)),
        )
        return {"entry": entry.model_dump(mode="json") if entry is not None else None}

    async def do_memory_delete(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        deleted = self._memory_manager.delete(entry_id)
        return {"deleted": deleted, "entry_id": entry_id}

    async def do_memory_quarantine(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        reason = str(params.get("reason", "")).strip()
        changed = self._memory_manager.quarantine(entry_id, reason=reason)
        return {"changed": changed, "entry_id": entry_id, "reason": reason}

    async def do_memory_unquarantine(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        reason = str(params.get("reason", "")).strip()
        changed = self._memory_manager.unquarantine(entry_id, reason=reason)
        return {"changed": changed, "entry_id": entry_id, "reason": reason}

    async def do_memory_set_workflow_state(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        workflow_state = str(params.get("workflow_state", "")).strip()
        changed = self._memory_manager.set_workflow_state(entry_id, workflow_state)
        return {
            "changed": changed,
            "entry_id": entry_id,
            "workflow_state": workflow_state,
        }

    async def do_memory_export(self, params: Mapping[str, Any]) -> dict[str, Any]:
        fmt = str(params.get("format", "json"))
        return {"format": fmt, "data": self._memory_manager.export(fmt=fmt)}

    async def do_memory_verify(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        verified = self._memory_manager.verify(entry_id)
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
        if params.get("ingress_context"):
            return self._write_handle_bound_entry(
                params,
                entry_type="note",
                key=str(params.get("key", "")),
                value=str(params.get("content", "")),
                confidence=float(params.get("confidence", 0.8)),
            )
        if params.get(_CONTROL_API_AUTHENTICATED_WRITE):
            return self._write_control_api_authenticated_entry(
                params,
                entry_type="note",
                key=str(params.get("key", "")),
                value=str(params.get("content", "")),
                confidence=float(params.get("confidence", 0.8)),
            )
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
        return self._write_handle_bound_entry(
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

    async def do_note_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        limit = max(1, int(params.get("limit", 100)))
        rows = self._memory_manager.list_entries(entry_type="note", limit=limit)
        notes = [entry.model_dump(mode="json") for entry in rows]
        return {"entries": notes, "count": len(notes)}

    async def do_note_search(self, params: Mapping[str, Any]) -> dict[str, Any]:
        query = str(params.get("query", "")).strip()
        limit = max(1, int(params.get("limit", 20)))
        lowered_terms = [term for term in query.lower().split() if term]
        rows = self._memory_manager.list_entries(entry_type="note", limit=200)
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
        entry = self._memory_manager.get_entry(str(params.get("entry_id", "")))
        if entry is None or str(entry.entry_type) != "note":
            return {"entry": None}
        return {"entry": entry.model_dump(mode="json")}

    async def do_note_delete(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        entry = self._memory_manager.get_entry(entry_id)
        if entry is None or str(entry.entry_type) != "note":
            return {"deleted": False, "entry_id": entry_id}
        deleted = self._memory_manager.delete(entry_id)
        return {"deleted": deleted, "entry_id": entry_id}

    async def do_note_verify(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        entry = self._memory_manager.get_entry(entry_id)
        if entry is None or str(entry.entry_type) != "note":
            return {"verified": False, "entry_id": entry_id}
        verified = self._memory_manager.verify(entry_id)
        return {"verified": verified, "entry_id": entry_id}

    async def do_note_export(self, params: Mapping[str, Any]) -> dict[str, Any]:
        fmt = str(params.get("format", "json"))
        rows = self._memory_manager.list_entries(
            entry_type="note",
            include_deleted=True,
            limit=2000,
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
        rows = self._memory_manager.list_entries(entry_type="todo", limit=limit)
        todos = [entry.model_dump(mode="json") for entry in rows]
        return {"entries": todos, "count": len(todos)}

    def _resolve_todo_matches(self, selector: str) -> list[Any]:
        normalized = selector.strip().lower()
        if not normalized:
            return []
        direct = self._memory_manager.get_entry(selector)
        if direct is not None and str(direct.entry_type) == "todo":
            return [direct]
        exact: list[Any] = []
        partial: list[Any] = []
        for entry in self._memory_manager.list_entries(entry_type="todo", limit=200):
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
        matches = self._resolve_todo_matches(selector)
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
        entry = self._memory_manager.get_entry(str(params.get("entry_id", "")))
        if entry is None or str(entry.entry_type) != "todo":
            return {"entry": None}
        return {"entry": entry.model_dump(mode="json")}

    async def do_todo_delete(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        entry = self._memory_manager.get_entry(entry_id)
        if entry is None or str(entry.entry_type) != "todo":
            return {"deleted": False, "entry_id": entry_id}
        deleted = self._memory_manager.delete(entry_id)
        return {"deleted": deleted, "entry_id": entry_id}

    async def do_todo_verify(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        entry = self._memory_manager.get_entry(entry_id)
        if entry is None or str(entry.entry_type) != "todo":
            return {"verified": False, "entry_id": entry_id}
        verified = self._memory_manager.verify(entry_id)
        return {"verified": verified, "entry_id": entry_id}

    async def do_todo_export(self, params: Mapping[str, Any]) -> dict[str, Any]:
        fmt = str(params.get("format", "json"))
        rows = self._memory_manager.list_entries(
            entry_type="todo",
            include_deleted=True,
            limit=2000,
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
