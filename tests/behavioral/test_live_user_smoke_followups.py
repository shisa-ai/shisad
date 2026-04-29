"""Behavioral regressions surfaced by live-user-smoke review."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from shisad.core.config import DaemonConfig
from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.memory.ingestion import IngestionPipeline
from tests.behavioral.test_behavioral_contract import (
    _contract_harness_context,
    _create_session,
    _extract_tool_outputs,
    _stub_complete,
    _tool_call,
)


def _seed_accumulated_tool_recall(config: DaemonConfig, *, content: str) -> None:
    retrieval = IngestionPipeline(config.data_dir / "memory_entries").ingest(
        source_id="prior-tool-output",
        source_type="tool",
        collection="tool_outputs",
        content=content,
        source_origin="tool_output",
        channel_trust="tool_passed",
        confirmation_status="auto_accepted",
        scope="user",
    )
    assert retrieval.chunk_id


@pytest.mark.asyncio
async def test_lus_multi_tool_todo_create_uses_trusted_current_turn_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _seed(config: DaemonConfig) -> None:
        _seed_accumulated_tool_recall(
            config,
            content=(
                "Prior tool output mentioned scan-complete and file listing. "
                "This accumulated recall should not make an explicit trusted todo write "
                "require confirmation."
            ),
        )

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:

        async def _multi_tool_complete(
            self: LocalPlannerProvider,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            planner_input = messages[-1].content if messages else ""
            lowered = planner_input.lower()
            if "list the files" in lowered and "create a todo called scan-complete" in lowered:
                return ProviderResponse(
                    message=Message(
                        role="assistant",
                        content="Working on both.",
                        tool_calls=[
                            _tool_call("fs.list", {}, call_id="t-lus-list"),
                            _tool_call(
                                "todo.create",
                                {"title": "scan-complete"},
                                call_id="t-lus-todo",
                            ),
                        ],
                    ),
                    model="behavioral-stub",
                    finish_reason="tool_calls",
                    usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                )
            return await _stub_complete(self, messages, tools)

        monkeypatch.setattr(LocalPlannerProvider, "complete", _multi_tool_complete, raising=True)
        sid = await _create_session(harness.client)
        reply = await harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "list the files in the folder and create a todo called scan-complete",
            },
        )

    assert reply.get("lockdown_level") == "normal"
    assert int(reply.get("blocked_actions", 0)) == 0
    assert int(reply.get("confirmation_required_actions", 0)) == 0
    assert reply.get("pending_confirmation_ids") == []
    assert int(reply.get("executed_actions", 0)) == 2
    outputs = _extract_tool_outputs(reply)
    assert "fs.list" in outputs
    assert "todo.create" in outputs


@pytest.mark.asyncio
async def test_lus_go_ahead_confirms_single_pending_action_in_tainted_recovery_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _seed(config: DaemonConfig) -> None:
        _seed_accumulated_tool_recall(
            config,
            content=(
                "Prior tool output mentioned TODO.LOG, INSTALL.LOG, and similar filename "
                "recovery. This accumulated recall makes the session tainted but should not "
                "break single pending confirmation shorthand."
            ),
        )

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        (harness.workspace_root / "todo.log").write_text(
            "OPEN: verify live user smoke recovery\n",
            encoding="utf-8",
        )
        sid = await _create_session(harness.client)
        first = await harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "review TODO.LOG and list only open items",
            },
        )
        assert int(first.get("blocked_actions", 0)) == 0
        assert _extract_tool_outputs(first)["fs.read"][0].get("error") == "path_not_found"

        proposed = await harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": (
                    "can you look for the file? filename should be similar if it's not exact"
                ),
            },
        )
        assert int(proposed.get("confirmation_required_actions", 0)) >= 1
        assert proposed.get("pending_confirmation_ids")

        confirmed = await harness.client.call(
            "session.message",
            {"session_id": sid, "content": "go ahead"},
        )

    assert confirmed.get("lockdown_level") == "normal"
    assert int(confirmed.get("blocked_actions", 0)) == 0
    assert int(confirmed.get("confirmation_required_actions", 0)) == 0
    assert confirmed.get("pending_confirmation_ids") == []
    assert int(confirmed.get("executed_actions", 0)) == 1
    assert "Pending action resolution:" in str(confirmed.get("response", ""))
    assert "Tool results summary:" in str(confirmed.get("response", ""))
    assert "Confirmed action result:" not in str(confirmed.get("response", ""))
    assert "fs.list" in _extract_tool_outputs(confirmed)


@pytest.mark.asyncio
async def test_lus_shell_file_discovery_routes_to_confirmation_without_lockdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _seed(config: DaemonConfig) -> None:
        _seed_accumulated_tool_recall(
            config,
            content=(
                "Prior tool output mentioned TODO.LOG, INSTALL.LOG, and similar filename "
                "recovery. The current user can still ask for local filesystem discovery."
            ),
        )

    async with _contract_harness_context(tmp_path, monkeypatch, prestart=_seed) as harness:
        (harness.workspace_root / "todo.log").write_text(
            "OPEN: verify shell recovery is confirmable\n",
            encoding="utf-8",
        )

        async def _shell_recovery_complete(
            self: LocalPlannerProvider,
            messages: list[Message],
            tools: list[dict[str, Any]] | None = None,
        ) -> ProviderResponse:
            planner_input = messages[-1].content if messages else ""
            lowered = planner_input.lower()
            if "look for the file" in lowered and "filename should be similar" in lowered:
                return ProviderResponse(
                    message=Message(
                        role="assistant",
                        content="I'll search for similarly named files.",
                        tool_calls=[
                            _tool_call(
                                "shell.exec",
                                {
                                    "command": [
                                        "find",
                                        ".",
                                        "-maxdepth",
                                        "2",
                                        "-iname",
                                        "*todo*log*",
                                    ],
                                    "read_paths": ["."],
                                },
                                call_id="t-lus-shell-find",
                            )
                        ],
                    ),
                    model="behavioral-stub",
                    finish_reason="tool_calls",
                    usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                )
            return await _stub_complete(self, messages, tools)

        monkeypatch.setattr(
            LocalPlannerProvider,
            "complete",
            _shell_recovery_complete,
            raising=True,
        )
        sid = await _create_session(harness.client)
        first = await harness.client.call(
            "session.message",
            {
                "session_id": sid,
                "content": "review TODO.LOG and list only open items",
            },
        )
        assert first.get("lockdown_level") == "normal"
        assert int(first.get("blocked_actions", 0)) == 0
        assert _extract_tool_outputs(first)["fs.read"][0].get("error") == "path_not_found"

        proposed: dict[str, Any] = {}
        for _ in range(3):
            proposed = await harness.client.call(
                "session.message",
                {
                    "session_id": sid,
                    "content": (
                        "can you look for the file? filename should be similar if it's not exact"
                    ),
                },
            )
            assert proposed.get("lockdown_level") == "normal"
            assert int(proposed.get("blocked_actions", 0)) == 0
            assert int(proposed.get("confirmation_required_actions", 0)) >= 1
            assert proposed.get("pending_confirmation_ids")

    assert "LOCKDOWN NOTICE" not in str(proposed.get("response", ""))
