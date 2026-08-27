"""Behavioral coverage for the themed chat TUI entry path."""

from __future__ import annotations

from pathlib import Path

import pytest
from textual.widgets import Markdown, Static, TextArea

from shisad.core.planner import (
    ActionProposal,
    EvaluatedProposal,
    Planner,
    PlannerOutput,
    PlannerResult,
)
from shisad.core.types import ToolName
from shisad.ui.chat import ChatApp
from tests.helpers.daemon import clear_remote_provider_env, daemon_harness

pytestmark = pytest.mark.asyncio


async def _wait_for_pending_panel(
    app: ChatApp,
    pilot: object,
    expected: str,
) -> str:
    for _ in range(150):
        await pilot.pause(0.01)  # type: ignore[attr-defined]
        rendered = str(app.query_one("#chat-pending", Static).renderable)
        if expected in rendered:
            return rendered
    raise AssertionError(f"pending panel did not render {expected!r}")


async def _queue_write_confirmation(harness: object, session_id: str, path: str) -> str:
    reply = await harness.client.call(  # type: ignore[attr-defined]
        "session.message",
        {"session_id": session_id, "content": f"write {path}"},
    )
    pending_ids = reply.get("pending_confirmation_ids", [])
    assert isinstance(pending_ids, list)
    assert pending_ids, repr(sorted(reply.items()))
    return str(pending_ids[-1])


async def test_u2_chat_tui_happy_path_uses_real_control_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)

    async with daemon_harness(
        tmp_path,
        policy_text='version: "1"\ndefault_require_confirmation: false\n',
    ) as harness:
        app = ChatApp(
            socket_path=harness.config.socket_path,
            user_id="alice",
            workspace_id="ws1",
            reuse_bound_session=False,
        )

        async with app.run_test() as pilot:
            await pilot.pause()
            input_widget = app.query_one("#chat-input", TextArea)
            input_widget.focus()
            input_widget.load_text("hello")
            await app.action_submit_prompt()
            await pilot.pause()

            status_bar = app.query_one("#chat-status", Static)
            user_messages = [
                str(widget.renderable)
                for widget in app.query(".user-message")
                if hasattr(widget, "renderable")
            ]
            assistant_messages = [widget._markdown for widget in app.query(Markdown)]

    assert "connection=connected" in str(status_bar.renderable)
    assert "session=unbound" not in str(status_bar.renderable)
    assert "channel=cli" in str(status_bar.renderable)
    assert "lockdown=normal" in str(status_bar.renderable)
    assert user_messages[-1] == "you: hello"
    assert assistant_messages[-1].strip()


async def test_o3c_chat_pending_panel_tracks_only_current_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_remote_provider_env(monkeypatch)
    monkeypatch.setattr(ChatApp, "PENDING_POLL_SECONDS", 0.01, raising=False)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "README.md").write_text("current session\n", encoding="utf-8")
    (workspace / "pyproject.toml").write_text("[project]\n", encoding="utf-8")

    async def _forced_workspace_write(
        self: Planner,
        user_content: str,
        context: object,
        *,
        tools: list[dict[str, object]] | None = None,
        persona_tone_override: str | None = None,
    ) -> PlannerResult:
        _ = tools, persona_tone_override
        path = "pyproject.toml" if "pyproject.toml" in user_content else "README.md"
        proposal = ActionProposal(
            action_id=f"o3c-write-{path}",
            tool_name=ToolName("fs.write"),
            arguments={"path": path, "content": "not written before confirmation"},
            reasoning="exercise the persistent pending panel",
            data_sources=[],
        )
        decision = self._pep.evaluate(proposal.tool_name, proposal.arguments, context)
        return PlannerResult(
            output=PlannerOutput(actions=[proposal], assistant_response="workspace read pending"),
            evaluated=[EvaluatedProposal(proposal=proposal, decision=decision)],
            attempts=1,
            provider_response=None,
            messages_sent=(),
        )

    monkeypatch.setattr(Planner, "propose", _forced_workspace_write)
    policy = """\
version: "1"
default_deny: false
default_require_confirmation: true
default_capabilities:
  - file.write
session_tool_allowlist:
  - fs.write
tools:
  fs.write:
    capabilities_required:
      - file.write
    confirmation:
      level: software
"""

    async with daemon_harness(
        tmp_path,
        policy_text=policy,
        config_kwargs={"assistant_fs_roots": [workspace]},
    ) as harness:
        current = await harness.client.call(
            "session.create",
            {"channel": "cli", "user_id": "alice", "workspace_id": "ws1"},
        )
        other = await harness.client.call(
            "session.create",
            {"channel": "cli", "user_id": "bob", "workspace_id": "ws2"},
        )
        current_id = str(current["session_id"])
        other_id = str(other["session_id"])
        current_confirmation = await _queue_write_confirmation(harness, current_id, "README.md")
        other_confirmation = await _queue_write_confirmation(harness, other_id, "README.md")

        app = ChatApp(
            socket_path=harness.config.socket_path,
            data_dir=harness.config.data_dir,
            user_id="alice",
            workspace_id="ws1",
            session_id=current_id,
            reuse_bound_session=False,
        )
        async with app.run_test() as pilot:
            rendered = await _wait_for_pending_panel(app, pilot, current_confirmation)
            assert other_confirmation not in rendered

            pending = await harness.client.call(
                "action.pending",
                {"confirmation_id": current_confirmation, "status": "pending", "limit": 1},
            )
            decision_nonce = str(pending["actions"][0]["decision_nonce"])
            rejected = await harness.client.call(
                "action.reject",
                {
                    "confirmation_id": current_confirmation,
                    "decision_nonce": decision_nonce,
                },
            )
            assert rejected["rejected"] is True
            rendered = await _wait_for_pending_panel(app, pilot, "No pending confirmations")
            assert current_confirmation not in rendered
            assert other_confirmation not in rendered

            next_confirmation = await _queue_write_confirmation(
                harness, current_id, "pyproject.toml"
            )
            await _wait_for_pending_panel(app, pilot, next_confirmation)
            await app.action_new_session()
            await pilot.pause()
            rendered = str(app.query_one("#chat-pending", Static).renderable)

            assert app._session_id not in {current_id, other_id}
            assert next_confirmation not in rendered
            assert other_confirmation not in rendered
