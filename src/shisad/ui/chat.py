"""Interactive chat TUI for shisad.

CLI-side Textual app that talks to the daemon over the Unix socket
using session.create + session.message RPC calls. This is NOT a
daemon-side channel — it runs as a separate CLI process.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header, Input, TextArea


def format_user_message(content: str) -> str:
    """Format a user message for display in the chat log."""
    text = content.strip()
    return f"you: {text}"


def format_assistant_message(content: str) -> str:
    """Format an assistant message for display in the chat log."""
    text = content.strip()
    if not text:
        return "(no response)"
    return f"shisad: {text}"


def _format_error(content: str) -> str:
    """Format an error message for display in the chat log."""
    return f"error: {content}"


def _rpc_error_code(message: str) -> int | None:
    match = re.match(r"^\s*RPC error\s+(-?\d+):", message, flags=re.IGNORECASE)
    if match is None:
        return None
    with contextlib.suppress(ValueError):
        return int(match.group(1))
    return None


def _is_unknown_session_error(exc: Exception) -> bool:
    message = str(exc).strip()
    code = getattr(exc, "code", None)
    rpc_code = code if isinstance(code, int) else _rpc_error_code(message)
    if rpc_code != -32602:
        return False
    lowered = message.lower()
    return any(
        marker in lowered
        for marker in (
            "unknown session",
            "session no longer exists",
            "session not found",
            "invalid session",
        )
    )


class ChatApp(App[None]):
    """Interactive chat with the shisad daemon."""

    TITLE = "shisad chat"

    CSS = """
    Screen {
        layout: vertical;
    }
    #chat-log {
        height: 1fr;
        border: solid $panel;
        padding: 0 1;
    }
    #chat-input {
        height: 3;
        margin: 0 0;
        border: solid $panel;
        padding: 0 1;
    }
    #chat-log:focus {
        border: heavy $accent;
    }
    #chat-input:focus {
        border: heavy $accent;
    }
    """

    BINDINGS = [  # noqa: RUF012
        Binding("ctrl+c", "quit", "Quit", show=True),
        Binding("ctrl+d", "quit", "Quit", show=False),
        Binding("ctrl+n", "new_session", "New Session", show=True),
        Binding("tab", "focus_next_pane", show=False),
        Binding("shift+tab", "focus_prev_pane", show=False),
    ]

    def __init__(
        self,
        *,
        socket_path: Path,
        user_id: str = "ops",
        workspace_id: str = "default",
        session_id: str | None = None,
        reuse_bound_session: bool = True,
    ) -> None:
        super().__init__()
        self._socket_path = socket_path
        self._user_id = user_id
        self._workspace_id = workspace_id
        self._session_id = session_id
        self._reuse_bound_session = reuse_bound_session
        self._reconnected = False
        self._prompt_history: list[str] = []
        self._prompt_history_cursor: int | None = None
        self._prompt_draft = ""

    def compose(self) -> ComposeResult:
        yield Header()
        yield TextArea(id="chat-log", read_only=True, soft_wrap=True)
        yield Input(id="chat-input", placeholder="Type a message...")
        yield Footer()

    async def on_mount(self) -> None:
        self._append_history("Connecting to daemon...")
        try:
            client = await self._connect()
            try:
                await self._ensure_session(client)
            finally:
                await client.close()
            self._append_history("Connected.")
            self._append_history(
                "Type a message and press Enter. "
                "Up/Down recalls prompts. "
                "Ctrl-N starts a new session. "
                "Ctrl-C to quit."
            )
            self._append_history("")
            self.sub_title = "connected"
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            self._append_history(_format_error(f"Could not connect to daemon: {exc}"))
            self._append_history("Is the daemon running? Try: shisad start --foreground")
        self.query_one("#chat-input", Input).focus()

    def on_key(self, event: events.Key) -> None:
        """Support readline-like history navigation on the input widget."""
        if event.key == "up" and self._is_input_focused():
            self.action_history_prev()
            event.stop()
            return
        if event.key == "down" and self._is_input_focused():
            self.action_history_next()
            event.stop()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        content = event.value.strip()
        if not content:
            return

        self._record_prompt_history(content)
        input_widget = self.query_one("#chat-input", Input)
        input_widget.value = ""

        self._append_history(format_user_message(content))

        try:
            client = await self._connect()
            try:
                prev_reconnected = self._reconnected
                response = await self._send_message(client, content)
                if self._reconnected and not prev_reconnected:
                    self._append_history(
                        _format_error(
                            "Daemon restarted - started a new conversation."
                        )
                    )
            finally:
                await client.close()
            self._append_history(format_assistant_message(response))
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            self._append_history(_format_error(str(exc)))
        self._append_history("")

    async def _connect(self) -> Any:
        """Connect to the daemon control socket."""
        from shisad.core.api.transport import ControlClient

        client = ControlClient(self._socket_path)
        await client.connect()
        return client

    async def _ensure_session(self, client: Any) -> None:
        """Create a session if one wasn't provided."""
        if self._session_id:
            return
        if self._reuse_bound_session:
            existing_session_id, lockdown_level = await self._find_bound_session(client)
            if existing_session_id:
                self._session_id = existing_session_id
                normalized_lockdown = lockdown_level.strip().lower()
                if normalized_lockdown and normalized_lockdown != "normal":
                    self._append_history(
                        "info: reusing existing session in lockdown "
                        f"state ({normalized_lockdown})."
                    )
                return
        await self._create_new_session(client)

    async def _create_new_session(self, client: Any) -> None:
        """Create a fresh session for the current user/workspace."""
        result = await client.call(
            "session.create",
            params={"user_id": self._user_id, "workspace_id": self._workspace_id},
        )
        if not isinstance(result, Mapping):
            raise RuntimeError(
                f"session.create returned invalid response type: {type(result).__name__}"
            )
        sid = str(result.get("session_id", "")).strip()
        if not sid:
            raise RuntimeError("session.create returned invalid session_id")
        self._session_id = sid

    async def _find_bound_session(self, client: Any) -> tuple[str, str]:
        """Resolve an existing active CLI session by user/workspace binding."""
        try:
            result = await client.call("session.list", params={})
        except Exception:
            return "", ""
        if not isinstance(result, Mapping):
            return "", ""
        sessions = result.get("sessions", [])
        if not isinstance(sessions, list):
            return "", ""
        for item in sessions:
            if not isinstance(item, Mapping):
                continue
            if str(item.get("state", "")).strip().lower() != "active":
                continue
            if str(item.get("channel", "")).strip().lower() != "cli":
                continue
            if str(item.get("user_id", "")) != self._user_id:
                continue
            if str(item.get("workspace_id", "")) != self._workspace_id:
                continue
            sid = str(item.get("id", "")).strip()
            if sid:
                lockdown_level = str(item.get("lockdown_level", "")).strip()
                return sid, lockdown_level
        return "", ""

    async def _send_message(self, client: Any, content: str) -> str:
        """Send a message and return the assistant response.

        If the session is unknown (daemon restarted), automatically creates
        a new session and retries once.
        """
        try:
            result = await self._do_session_message(client, content)
        except Exception as exc:
            if not _is_unknown_session_error(exc):
                raise
            # Session is stale — daemon likely restarted. Recover.
            old_session_id = self._session_id
            self._session_id = None
            await self._ensure_session(client)
            if not self._session_id or self._session_id == old_session_id:
                raise RuntimeError("Failed to recover session after unknown session error") from exc
            self._reconnected = True
            try:
                result = await self._do_session_message(client, content)
            except Exception as retry_exc:
                raise RuntimeError(str(retry_exc)) from retry_exc

        return self._extract_response(result)

    async def _do_session_message(
        self, client: Any, content: str
    ) -> dict[str, Any]:
        """Call session.message RPC and return the raw result dict."""
        result = await client.call(
            "session.message",
            params={"session_id": self._session_id, "content": content},
        )
        if not isinstance(result, Mapping):
            raise RuntimeError(
                f"Invalid session.message response type: {type(result).__name__}"
            )
        return dict(result)

    @staticmethod
    def _extract_response(result: dict[str, Any]) -> str:
        """Extract the response text from a session.message result."""
        response = result.get("response", "")
        if isinstance(response, str) and response.strip():
            return response.strip()
        raise RuntimeError(
            "session.message returned no response text"
        )

    def _append_history(self, line: str) -> None:
        """Append a single line to the history pane."""
        history = self.query_one("#chat-log", TextArea)
        history.move_cursor(history.document.end)
        if history.text:
            history.insert("\n")
        history.insert(line)
        history.move_cursor(history.document.end)
        history.scroll_end(animate=False)

    def action_focus_next_pane(self) -> None:
        """Move focus between history and input panes."""
        focused = self.focused
        if focused is not None and focused.id == "chat-input":
            self.query_one("#chat-log", TextArea).focus()
            return
        self.query_one("#chat-input", Input).focus()

    def action_focus_prev_pane(self) -> None:
        """Move focus between history and input panes."""
        self.action_focus_next_pane()

    def action_history_prev(self) -> None:
        """Recall the previous submitted prompt."""
        if not self._is_input_focused():
            return
        input_widget = self.query_one("#chat-input", Input)
        input_widget.value = self._recall_prompt_history(
            direction=-1,
            current_value=input_widget.value,
        )

    def action_history_next(self) -> None:
        """Recall the next submitted prompt."""
        if not self._is_input_focused():
            return
        input_widget = self.query_one("#chat-input", Input)
        input_widget.value = self._recall_prompt_history(
            direction=1,
            current_value=input_widget.value,
        )

    async def action_new_session(self) -> None:
        """Create and switch to a new session without restarting chat."""
        old_session_id = self._session_id
        self._session_id = None
        self._reconnected = False
        try:
            client = await self._connect()
            try:
                await self._create_new_session(client)
            finally:
                await client.close()
            self._append_history("info: started a new session.")
            self._append_history("")
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            self._session_id = old_session_id
            self._append_history(_format_error(f"Could not start new session: {exc}"))
            self._append_history("")
        self.query_one("#chat-input", Input).focus()

    def _is_input_focused(self) -> bool:
        focused = self.focused
        return focused is not None and focused.id == "chat-input"

    def _record_prompt_history(self, content: str) -> None:
        """Store a submitted prompt for Up/Down recall."""
        text = content.strip()
        if not text:
            return
        self._prompt_history.append(text)
        self._prompt_history_cursor = None
        self._prompt_draft = ""

    def _recall_prompt_history(self, *, direction: int, current_value: str) -> str:
        """Step through prompt history, restoring draft text when exiting."""
        if not self._prompt_history:
            return current_value
        if direction not in (-1, 1):
            return current_value
        if self._prompt_history_cursor is None:
            if direction == 1:
                return current_value
            self._prompt_draft = current_value
            self._prompt_history_cursor = len(self._prompt_history) - 1
            return self._prompt_history[self._prompt_history_cursor]

        next_index = self._prompt_history_cursor + direction
        if next_index < 0:
            self._prompt_history_cursor = 0
            return self._prompt_history[0]
        if next_index >= len(self._prompt_history):
            self._prompt_history_cursor = None
            draft = self._prompt_draft
            self._prompt_draft = ""
            return draft
        self._prompt_history_cursor = next_index
        return self._prompt_history[next_index]
