"""Memory/note/todo handler implementations."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast

from shisad.core.types import Capability
from shisad.daemon.handlers._csv import render_csv_row
from shisad.daemon.handlers._mixin_typing import HandlerMixinBase
from shisad.memory.schema import MemorySource


class MemoryImplMixin(HandlerMixinBase):
    async def do_memory_ingest(self, params: Mapping[str, Any]) -> dict[str, Any]:
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
        source = MemorySource.model_validate(params.get("source", {}))
        decision = self._memory_manager.write(
            entry_type=params.get("entry_type", "fact"),
            key=params.get("key", ""),
            value=params.get("value"),
            source=source,
            confidence=float(params.get("confidence", 0.5)),
            user_confirmed=bool(params.get("user_confirmed", False)),
        )
        return cast(dict[str, Any], decision.model_dump(mode="json"))

    async def do_memory_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        rows = self._memory_manager.list_entries(limit=int(params.get("limit", 100)))
        return {"entries": [entry.model_dump(mode="json") for entry in rows], "count": len(rows)}

    async def do_memory_get(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        entry = self._memory_manager.get_entry(entry_id)
        return {"entry": entry.model_dump(mode="json") if entry is not None else None}

    async def do_memory_delete(self, params: Mapping[str, Any]) -> dict[str, Any]:
        entry_id = str(params.get("entry_id", ""))
        deleted = self._memory_manager.delete(entry_id)
        return {"deleted": deleted, "entry_id": entry_id}

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
        rows = self._memory_manager.list_entries(include_deleted=True, limit=2000)
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
        source = MemorySource(
            origin=str(params.get("origin", "user")),
            source_id=str(params.get("source_id", "cli")),
            extraction_method="todo.create",
        )
        payload = {
            "title": str(params.get("title", "")).strip(),
            "details": str(params.get("details", "")).strip(),
            "status": str(params.get("status", "open")).strip() or "open",
            "due_date": str(params.get("due_date", "")).strip(),
        }
        if payload["status"] not in {"open", "in_progress", "done"}:
            raise ValueError("status must be one of: open, in_progress, done")
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
        rows = self._memory_manager.list_entries(include_deleted=True, limit=2000)
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
