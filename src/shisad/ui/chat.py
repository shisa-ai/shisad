"""Interactive chat TUI for shisad.

CLI-side Textual app that talks to the daemon over the Unix socket
using session.create + session.message RPC calls. This is NOT a
daemon-side channel — it runs as a separate CLI process.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header, Input, RichLog


def format_user_message(content: str) -> str:
    """Format a user message for display in the chat log."""
    text = content.strip()
    return f"[bold dodger_blue1]you:[/bold dodger_blue1] {text}"


def format_assistant_message(content: str) -> str:
    """Format an assistant message for display in the chat log."""
    text = content.strip()
    if not text:
        return "[dim](no response)[/dim]"
    return f"[bold chartreuse3]shisad:[/bold chartreuse3] {text}"


def _format_error(content: str) -> str:
    """Format an error message for display in the chat log."""
    return f"[bold dark_orange]notice:[/bold dark_orange] {content}"


class ChatApp(App[None]):
    """Interactive chat with the shisad daemon."""

    TITLE = "shisad chat"

    CSS = """
    Screen {
        layout: vertical;
    }
    #chat-log {
        height: 1fr;
        border: round $accent;
        padding: 0 1;
        scrollbar-size: 1 1;
    }
    #chat-input {
        height: 3;
        margin: 0 0;
    }
    """

    BINDINGS = [  # noqa: RUF012
        Binding("ctrl+c", "quit", "Quit", show=True),
        Binding("ctrl+d", "quit", "Quit", show=False),
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

    def compose(self) -> ComposeResult:
        yield Header()
        yield RichLog(id="chat-log", wrap=True, highlight=True, markup=True)
        yield Input(id="chat-input", placeholder="Type a message...")
        yield Footer()

    async def on_mount(self) -> None:
        log = self.query_one("#chat-log", RichLog)
        log.write("[dim]Connecting to daemon...[/dim]")
        try:
            client = await self._connect()
            try:
                await self._ensure_session(client)
            finally:
                await client.close()
            log.write(f"[dim]Session: {self._session_id}[/dim]")
            log.write("[dim]Type a message and press Enter. Ctrl-C to quit.[/dim]")
            log.write("")
            self.sub_title = f"session {self._session_id}"
        except (OSError, RuntimeError) as exc:
            log.write(_format_error(f"Could not connect to daemon: {exc}"))
            log.write("[dim]Is the daemon running? Try: shisad start --foreground[/dim]")
        self.query_one("#chat-input", Input).focus()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        content = event.value.strip()
        if not content:
            return

        input_widget = self.query_one("#chat-input", Input)
        input_widget.value = ""

        log = self.query_one("#chat-log", RichLog)
        log.write(format_user_message(content))

        try:
            client = await self._connect()
            try:
                response = await self._send_message(client, content)
            finally:
                await client.close()
            log.write(format_assistant_message(response))
        except (OSError, RuntimeError) as exc:
            log.write(_format_error(str(exc)))
        log.write("")

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
        self._session_id = str(result.get("session_id", ""))

    async def _send_message(self, client: Any, content: str) -> str:
        """Send a message and return the assistant response."""
        try:
            result = await client.call(
                "session.message",
                params={"session_id": self._session_id, "content": content},
            )
        except Exception as exc:
            return f"Error: {exc}"

        if isinstance(result, dict):
            response = result.get("response", "")
            if isinstance(response, str) and response.strip():
                return response.strip()
            return json.dumps(result, indent=2)
        return str(result)
