"""Interactive chat TUI for shisad.

CLI-side Textual app that talks to the daemon over the Unix socket
using session.create + session.message RPC calls. This is NOT a
daemon-side channel — it runs as a separate CLI process.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

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
    ) -> None:
        super().__init__()
        self._socket_path = socket_path
        self._user_id = user_id
        self._workspace_id = workspace_id
        self._session_id = session_id
        self._reconnected = False

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
            self._append_history("Type a message and press Enter. Ctrl-C to quit.")
            self._append_history("")
            self.sub_title = "connected"
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            self._append_history(_format_error(f"Could not connect to daemon: {exc}"))
            self._append_history("Is the daemon running? Try: shisad start --foreground")
        self.query_one("#chat-input", Input).focus()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        content = event.value.strip()
        if not content:
            return

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

    async def _send_message(self, client: Any, content: str) -> str:
        """Send a message and return the assistant response.

        If the session is unknown (daemon restarted), automatically creates
        a new session and retries once.
        """
        try:
            result = await self._do_session_message(client, content)
        except Exception as exc:
            if "unknown session" not in str(exc).lower():
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
