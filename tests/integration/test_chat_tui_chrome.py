"""Integration coverage for the themed chat TUI entry path."""

from __future__ import annotations

from pathlib import Path

import pytest
from textual.widgets import Markdown, Static, TextArea

from shisad.ui.chat import ChatApp
from tests.helpers.daemon import clear_remote_provider_env, daemon_harness

pytestmark = pytest.mark.asyncio


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
