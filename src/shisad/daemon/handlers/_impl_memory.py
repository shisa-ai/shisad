"""Memory/note/todo handler implementations."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast

from shisad.core.types import Capability
from shisad.daemon.handlers._csv import render_csv_row
from shisad.daemon.handlers._mixin_typing import HandlerMixinBase
from shisad.memory.ingress import DerivationPath
from shisad.memory.remap import digest_memory_value, legacy_source_view_origin
from shisad.memory.schema import MemorySource

_CONTROL_API_AUTHENTICATED_WRITE = "_control_api_authenticated_write"


class MemoryImplMixin(HandlerMixinBase):
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
            source_id = str(source.get("source_id", "")).strip()
            if source_id:
                return source_id
        source_id = str(params.get("source_id", "")).strip()
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
        decision = self._memory_manager.write_with_provenance(
            entry_type=entry_type,
            key=key,
            value=value,
            source=source,
            source_origin=context.source_origin,
            channel_trust=context.channel_trust,
            confirmation_status=context.confirmation_status,
            source_id=context.source_id,
            scope=context.scope,
            confidence=confidence,
            confirmation_satisfied=context.confirmation_status
            in {"user_asserted", "user_confirmed", "user_corrected", "pep_approved"},
            taint_labels=context.taint_labels,
            ingress_handle_id=context.handle_id,
            content_digest=resolved_digest,
            workflow_state=params.get("workflow_state"),
            invocation_eligible=bool(params.get("invocation_eligible", False)),
            supersedes=str(params.get("supersedes", "")).strip() or None,
        )
        return cast(dict[str, Any], decision.model_dump(mode="json"))

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
        result = self._ingestion.ingest(
            source_id=params.get("source_id", ""),
            source_type=params.get("source_type", "user"),
            content=params.get("content", ""),
            collection=params.get("collection"),
        )
        return cast(dict[str, Any], result.model_dump(mode="json"))

    async def do_memory_retrieve(self, params: Mapping[str, Any]) -> dict[str, Any]:
        query = params.get("query", "")
        limit = int(params.get("limit", 5))
        capabilities = {Capability(cap) for cap in params.get("capabilities", [])}
        results = self._ingestion.retrieve(
            query,
            limit=limit,
            capabilities=capabilities,
            require_corroboration=bool(params.get("require_corroboration", False)),
        )
        return {
            "results": [item.model_dump(mode="json") for item in results],
            "count": len(results),
        }

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
        source = MemorySource.model_validate(params.get("source", {}))
        decision = self._memory_manager.write(
            entry_type=params.get("entry_type", "fact"),
            key=params.get("key", ""),
            value=params.get("value"),
            source=source,
            confidence=float(params.get("confidence", 0.5)),
            workflow_state=params.get("workflow_state"),
            invocation_eligible=bool(params.get("invocation_eligible", False)),
            supersedes=str(params.get("supersedes", "")).strip() or None,
            user_confirmed=bool(params.get("user_confirmed", False)),
        )
        return cast(dict[str, Any], decision.model_dump(mode="json"))

    async def do_memory_supersede(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return await self.do_memory_write(params)

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
            source_id=str(params.get("source_id", "cli")),
            extraction_method="note.create",
        )
        decision = self._memory_manager.write(
            entry_type="note",
            key=str(params.get("key", "")),
            value=str(params.get("content", "")),
            source=source,
            confidence=float(params.get("confidence", 0.8)),
            user_confirmed=bool(params.get("user_confirmed", False)),
        )
        return cast(dict[str, Any], decision.model_dump(mode="json"))

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
            source_id=str(params.get("source_id", "cli")),
            extraction_method="todo.create",
        )
        decision = self._memory_manager.write(
            entry_type="todo",
            key=f"todo:{payload['title'][:64]}",
            value=payload,
            source=source,
            confidence=float(params.get("confidence", 0.8)),
            user_confirmed=bool(params.get("user_confirmed", False)),
        )
        return cast(dict[str, Any], decision.model_dump(mode="json"))

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
