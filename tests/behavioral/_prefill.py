"""Reusable behavioral prefill helpers.

The helpers intentionally separate public trusted-user writes from test-only
non-user provenance seeding. Public RPCs cannot forge tool/external trust
labels; tests that need accumulated non-user state use the explicit internal
helper and should assert the provenance they seeded.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

from shisad.core.api.transport import ControlClient
from shisad.core.config import DaemonConfig
from shisad.memory.ingestion import IngestionPipeline

DEFAULT_ACCUMULATED_TOOL_OUTPUT = (
    "Prior tool output mentioned latest world news, README.md, favorite color, "
    "and related projects. This accumulated state should not make a later "
    "trusted first-principles request require confirmation."
)


def load_prefill_profile(path: Path) -> dict[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise AssertionError(f"Prefill profile must be a mapping: {path}")
    return dict(loaded)


async def prefill_memory(
    client: ControlClient,
    *,
    user_id: str,
    entries: Iterable[Mapping[str, Any]],
) -> list[str]:
    """Write trusted user/CLI memory through the public ingress + write path."""

    entry_ids: list[str] = []
    for index, raw_entry in enumerate(entries):
        value = raw_entry.get("value", raw_entry.get("content", ""))
        ingress = await client.call(
            "memory.mint_ingress_context",
            {
                "content": value,
                "source_type": "user",
                "source_id": f"user:{user_id}",
            },
        )
        payload: dict[str, Any] = {
            "ingress_context": ingress["ingress_context"],
            "entry_type": str(raw_entry.get("type", raw_entry.get("entry_type", "fact"))),
            "key": str(raw_entry.get("key", f"prefill:{index}")),
            "value": value,
        }
        for optional in ("predicate", "strength", "confidence", "supersedes"):
            if optional in raw_entry:
                payload[optional] = raw_entry[optional]
        result = await client.call("memory.write", payload)
        if result.get("kind") not in {"allow", "write"}:
            raise AssertionError(f"prefill memory write was not accepted: {result}")
        entry = result.get("entry")
        if isinstance(entry, dict):
            entry_id = str(entry.get("id") or entry.get("entry_id") or "").strip()
            if entry_id:
                entry_ids.append(entry_id)
    return entry_ids


async def prefill_transcript(
    client: ControlClient,
    *,
    user_id: str,
    turns: Iterable[Mapping[str, Any] | str],
    workspace_id: str = "prefill",
) -> str:
    """Replay user turns through `session.message` so transcript/audit state is real."""

    created = await client.call(
        "session.create",
        {"channel": "cli", "user_id": user_id, "workspace_id": workspace_id},
    )
    session_id = str(created["session_id"])
    for raw_turn in turns:
        if isinstance(raw_turn, str):
            content = raw_turn
        else:
            role = str(raw_turn.get("role", "user"))
            if role != "user":
                raise AssertionError(f"prefill transcript only supports user turns: {raw_turn}")
            content = str(raw_turn.get("content", ""))
        await client.call("session.message", {"session_id": session_id, "content": content})
    return session_id


async def prefill_pending_actions(
    client: ControlClient,
    *,
    session_id: str,
    queued: Iterable[Mapping[str, Any] | str],
) -> list[str]:
    """Replay prompts expected to leave pending confirmations and return their ids."""

    pending_ids: list[str] = []
    for raw_item in queued:
        content = raw_item if isinstance(raw_item, str) else str(raw_item.get("content", ""))
        reply = await client.call("session.message", {"session_id": session_id, "content": content})
        ids = reply.get("pending_confirmation_ids")
        if isinstance(ids, list):
            pending_ids.extend(str(item) for item in ids if str(item).strip())
    return pending_ids


def prefill_accumulated_tool_output(
    config: DaemonConfig,
    *,
    source_id: str = "prior-tool-output",
    content: str = DEFAULT_ACCUMULATED_TOOL_OUTPUT,
) -> None:
    """Seed non-user recall before daemon startup without public trust forgery."""

    recall = IngestionPipeline(config.data_dir / "memory_entries").ingest(
        source_id=source_id,
        source_type="tool",
        collection="tool_outputs",
        content=content,
        source_origin="tool_output",
        channel_trust="tool_passed",
        confirmation_status="auto_accepted",
        scope="user",
    )
    assert recall.chunk_id
