"""Interactive chat TUI for shisad.

CLI-side Textual app that talks to the daemon over the Unix socket
using session.create + session.message RPC calls. This is NOT a
daemon-side channel — it runs as a separate CLI process.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Footer, Header, Markdown, Static, TextArea

from shisad.core.transcript import derive_legacy_transcript_entry_id
from shisad.ui.evidence import render_evidence_refs_for_terminal

_INLINE_LIST_LEAD_RE = re.compile(r":\s+(?P<marker>[-*+]|\d+[.)])\s+(?=\S)")
_INLINE_LIST_BULLET_CONT_RE = re.compile(r"(?<!\d)\s+(?P<marker>[-*+])\s+(?=\S)")
_INLINE_LIST_ORDERED_CONT_RE = re.compile(r"\s+(?P<marker>[1-9]\d?[.)])\s+(?=\S)")
_UNICODE_BULLET_MARKERS = ("\u25cf", "\u2022")
_UNICODE_LIST_LEAD_RE = re.compile(r":\s+[\u25cf\u2022]\s+(?=\S)")
_UNICODE_LIST_LINE_RE = re.compile(r"^(?P<indent> {0,3})[\u25cf\u2022]\s+(?=\S)")
_UNICODE_LIST_CONT_RE = re.compile(r"\s+[\u25cf\u2022]\s+(?=\S)")
_INLINE_LIST_SUBHEADING_RE = re.compile(
    r"(?P<item_prefix>\n(?:[-*+]|\d+[.)]) [^\n]*?[.!?])\s+"
    r"(?P<heading>[A-Z][^\n:]{1,120}:\n\n?(?:[-*+]|\d+[.)])\s)"
)
_MARKDOWN_LIST_ITEM_RE = re.compile(r"^ {0,3}(?:[-*+]|\d+[.)])\s+\S")
_MARKDOWN_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_MARKDOWN_ATX_HEADING_RE = re.compile(r"^ {0,3}#{1,6}\s+\S")
_PENDING_BLOCK_START_RE = re.compile(r"^\[PENDING CONFIRMATIONS\]$", re.MULTILINE)


def format_user_message(content: str) -> str:
    """Format a user message for display in the chat log."""
    text = content.strip()
    return f"you: {text}"


def format_assistant_message(
    content: str,
    *,
    preserve_pending_preview_escapes: bool = False,
) -> str:
    """Format an assistant message for display in the chat log."""
    rendered = _render_assistant_text(
        content,
        preserve_pending_preview_escapes=preserve_pending_preview_escapes,
    )
    return f"shisad: {rendered}"


def _render_assistant_text(
    content: str,
    *,
    preserve_pending_preview_escapes: bool = False,
) -> str:
    """Render assistant content before display in terminal/TUI surfaces."""
    text = content.strip()
    if not text:
        return "(no response)"
    rendered = render_evidence_refs_for_terminal(
        text,
        preserve_pending_preview_escapes=preserve_pending_preview_escapes,
    )
    if preserve_pending_preview_escapes and _PENDING_BLOCK_START_RE.search(rendered):
        return rendered
    rendered = _normalize_markdown_heading_blocks(rendered)
    rendered = _normalize_unicode_markdown_lists(rendered)
    return _normalize_inline_markdown_lists(rendered)


def _normalize_markdown_heading_blocks(text: str) -> str:
    """Ensure ATX headings have a blank-line boundary before Textual renders them."""
    if not text or "#" not in text:
        return text

    trailing_newline = text.endswith("\n")
    normalized_lines: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if _MARKDOWN_FENCE_RE.match(line):
            in_fence = not in_fence
            normalized_lines.append(line)
            continue
        if (
            not in_fence
            and _MARKDOWN_ATX_HEADING_RE.match(line)
            and normalized_lines
            and normalized_lines[-1].strip()
        ):
            normalized_lines.append("")
        normalized_lines.append(line)

    normalized = "\n".join(normalized_lines)
    if trailing_newline:
        normalized += "\n"
    return normalized


def _normalize_inline_markdown_lists(text: str) -> str:
    """Promote common single-line markdown-ish lists to real Markdown lists.

    Some provider responses arrive as one wrapped paragraph like
    ``Things I can do: - read files - search the web``. Textual's Markdown
    renderer treats that as a paragraph, not a list. Keep the transformation
    narrow: only rewrite lines whose list starts immediately after a colon,
    and leave fenced code blocks untouched.
    """
    if not text or ":" not in text:
        return text

    trailing_newline = text.endswith("\n")
    normalized_lines: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if _MARKDOWN_FENCE_RE.match(line):
            in_fence = not in_fence
            normalized_lines.append(line)
            continue
        if in_fence:
            normalized_lines.append(line)
            continue
        normalized_lines.append(_normalize_inline_markdown_list_line(line))

    normalized = "\n".join(normalized_lines)
    if trailing_newline:
        normalized += "\n"
    return normalized


def _normalize_unicode_markdown_lists(text: str) -> str:
    """Promote common Unicode bullet responses to real Markdown lists."""
    if not text or not any(marker in text for marker in _UNICODE_BULLET_MARKERS):
        return text

    trailing_newline = text.endswith("\n")
    normalized_lines: list[str] = []
    in_fence = False
    previous_unicode_list_item = False
    for line in text.splitlines():
        if _MARKDOWN_FENCE_RE.match(line):
            in_fence = not in_fence
            normalized_lines.append(line)
            previous_unicode_list_item = False
            continue
        if in_fence:
            normalized_lines.append(line)
            continue

        starts_unicode_item = _UNICODE_LIST_LINE_RE.match(line) is not None
        if starts_unicode_item:
            previous_line = normalized_lines[-1] if normalized_lines else ""
            if previous_line.strip() and _MARKDOWN_LIST_ITEM_RE.match(previous_line) is None:
                normalized_lines.append("")
        elif previous_unicode_list_item and line.strip() and not line.startswith((" ", "\t")):
            normalized_lines.append("")

        normalized = _normalize_unicode_markdown_list_line(line)
        normalized_parts = normalized.split("\n")
        normalized_lines.extend(normalized_parts)
        previous_unicode_list_item = (
            _unicode_markdown_list_line_changed(line, normalized)
            and _MARKDOWN_LIST_ITEM_RE.match(normalized_parts[-1]) is not None
        )

    normalized = "\n".join(normalized_lines)
    if trailing_newline:
        normalized += "\n"
    return normalized


def _normalize_unicode_markdown_list_line(line: str) -> str:
    first_marker = _UNICODE_LIST_LEAD_RE.search(line)
    if first_marker is not None:
        prefix = line[: first_marker.start() + 1].rstrip()
        tail = line[first_marker.start() + 1 :].lstrip()
        tail = _UNICODE_LIST_LINE_RE.sub("- ", tail, count=1)
        tail = _UNICODE_LIST_CONT_RE.sub("\n- ", tail)
        return f"{prefix}\n\n{tail}"

    line_marker = _UNICODE_LIST_LINE_RE.match(line)
    if line_marker is None:
        return line

    tail = line[line_marker.end() :]
    tail = _UNICODE_LIST_CONT_RE.sub("\n- ", tail)
    return f"{line_marker.group('indent')}- {tail}"


def _unicode_markdown_list_line_changed(original: str, normalized: str) -> bool:
    return original != normalized and any(marker in original for marker in _UNICODE_BULLET_MARKERS)


def _normalize_inline_markdown_list_line(line: str) -> str:
    first_marker = _INLINE_LIST_LEAD_RE.search(line)
    if first_marker is None:
        return line

    marker = first_marker.group("marker")
    is_ordered = marker[0].isdigit()

    prefix = line[: first_marker.start() + 1].rstrip()
    tail = line[first_marker.start() + 1 :]

    cont_re = _INLINE_LIST_ORDERED_CONT_RE if is_ordered else _INLINE_LIST_BULLET_CONT_RE
    tail = cont_re.sub(
        lambda match: f"\n{match.group('marker')} ",
        tail,
    ).lstrip()

    if "\n" not in tail:
        return line

    normalized = f"{prefix}\n\n{tail}"
    return _INLINE_LIST_SUBHEADING_RE.sub(_split_inline_list_subheading, normalized)


def _split_inline_list_subheading(match: re.Match[str]) -> str:
    heading = match.group("heading").replace(":\n", ":\n\n", 1)
    return f"{match.group('item_prefix')}\n\n{heading}"


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
    if _is_session_id_validation_error(lowered):
        return True
    return any(
        marker in lowered
        for marker in (
            "unknown session",
            "session no longer exists",
            "session not found",
            "invalid session",
        )
    )


def _is_session_id_validation_error(lowered_message: str) -> bool:
    """Match the daemon's bounded schema error for invalid session.message ids."""
    if "sessionmessageparams" not in lowered_message or "session_id" not in lowered_message:
        return False
    return (
        "input should be a valid string" in lowered_message or "field required" in lowered_message
    )


class ChatApp(App[None]):
    """Interactive chat with the shisad daemon."""

    TITLE = "shisad chat"
    PROMPT_INPUT_MIN_HEIGHT = 3
    PROMPT_INPUT_MAX_HEIGHT = 8
    PROMPT_INPUT_CHROME_ROWS = 2
    PROMPT_INPUT_HORIZONTAL_CHROME = 4
    TRANSCRIPT_REPLAY_LIMIT = 50

    CSS = """
    Screen {
        layout: vertical;
    }
    #chat-log {
        height: 1fr;
        border: solid $panel;
        padding: 0 1;
    }
    .chat-turn {
        height: auto;
        margin: 0 0 1 0;
    }
    .speaker {
        text-style: bold;
    }
    .assistant-message {
        height: auto;
    }
    #chat-input {
        height: 3;
        max-height: 8;
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
        Binding("enter", "submit_prompt", show=False, priority=True),
        Binding("tab", "focus_next_pane", show=False),
        Binding("shift+tab", "focus_prev_pane", show=False),
    ]

    def __init__(
        self,
        *,
        socket_path: Path,
        data_dir: Path | None = None,
        user_id: str = "ops",
        workspace_id: str = "default",
        session_id: str | None = None,
        reuse_bound_session: bool = True,
    ) -> None:
        super().__init__()
        self._socket_path = socket_path
        self._transcript_root = None if data_dir is None else data_dir / "sessions"
        self._user_id = user_id
        self._workspace_id = workspace_id
        self._session_id = self._normalize_session_id(session_id)
        self._reuse_bound_session = reuse_bound_session
        self._reconnected = False
        self._prompt_history: list[str] = []
        self._prompt_history_cursor: int | None = None
        self._prompt_draft = ""
        self._displayed_transcript_entry_ids: set[str] = set()
        self._transcript_poll_task: asyncio.Task[None] | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield VerticalScroll(id="chat-log", can_focus=True)
        prompt = TextArea(
            id="chat-input",
            soft_wrap=True,
            tab_behavior="focus",
            show_line_numbers=False,
        )
        prompt.border_title = "Message"
        prompt.border_subtitle = "Enter sends"
        yield prompt
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
            self._append_current_session_status()
            self._replay_recent_transcript_history_best_effort()
            self._start_transcript_polling()
            self._append_history(
                "Type a message and press Enter. "
                "Up/Down recalls prompts. "
                "Ctrl-N starts a new session. "
                "Ctrl-C to quit."
            )
            self._append_history("")
            self._poll_transcript_for_async_messages_best_effort()
            self.sub_title = "connected"
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            self._append_history(_format_error(f"Could not connect to daemon: {exc}"))
            self._append_history("Is the daemon running? Try: shisad start --foreground")
        self.query_one("#chat-input", TextArea).focus()

    async def on_unmount(self) -> None:
        if self._transcript_poll_task is not None:
            self._transcript_poll_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._transcript_poll_task
            self._transcript_poll_task = None

    async def on_key(self, event: events.Key) -> None:
        """Support readline-like history navigation on the input widget."""
        if event.key == "enter" and self._is_input_focused():
            event.prevent_default()
            event.stop()
            await self.action_submit_prompt()
            return
        if event.key == "up" and self._is_input_focused():
            self.action_history_prev()
            event.stop()
            return
        if event.key == "down" and self._is_input_focused():
            self.action_history_next()
            event.stop()

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        """Resize the prompt box as drafted text wraps."""
        if event.text_area.id == "chat-input":
            self._resize_prompt_input(event.text_area)

    async def action_submit_prompt(self) -> None:
        """Submit the current prompt when Enter is pressed in the prompt box."""
        if not self._is_input_focused():
            return
        await self._submit_prompt()

    async def _submit_prompt(self) -> None:
        input_widget = self.query_one("#chat-input", TextArea)
        content = input_widget.text.strip()
        if not content:
            return

        self._record_prompt_history(content)
        input_widget.load_text("")
        self._resize_prompt_input(input_widget)

        self._append_user_message(content)

        try:
            client = await self._connect()
            try:
                prev_reconnected = self._reconnected
                result = await self._send_message(client, content)
                if self._reconnected and not prev_reconnected:
                    self._append_history(
                        _format_error("Daemon restarted - started a new conversation.")
                    )
            finally:
                await client.close()
            self._poll_transcript_for_async_messages_best_effort()
            self._append_assistant_message(
                self._extract_response(result),
                preserve_pending_preview_escapes=self._preserve_pending_preview_escapes(result),
            )
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
        if self._active_session_id():
            return
        self._session_id = None
        if self._reuse_bound_session:
            existing_session_id, lockdown_level = await self._find_bound_session(client)
            if existing_session_id:
                self._session_id = existing_session_id
                normalized_lockdown = lockdown_level.strip().lower()
                if normalized_lockdown and normalized_lockdown != "normal":
                    self._append_history(
                        f"info: reusing existing session in lockdown state ({normalized_lockdown})."
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

    async def _send_message(self, client: Any, content: str) -> dict[str, Any]:
        """Send a message and return the raw session.message result.

        If the session is unknown (daemon restarted), automatically creates
        a new session and retries once.
        """
        if not self._active_session_id():
            self._session_id = None
            await self._ensure_session(client)
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
            self._prime_transcript_display_state_best_effort()
            try:
                result = await self._do_session_message(client, content)
            except Exception as retry_exc:
                raise RuntimeError(str(retry_exc)) from retry_exc

        self._extract_response(result)
        return result

    async def _do_session_message(self, client: Any, content: str) -> dict[str, Any]:
        """Call session.message RPC and return the raw result dict."""
        session_id = self._active_session_id()
        if not session_id:
            raise RuntimeError("No active session; could not send message")
        result = await client.call(
            "session.message",
            params={"session_id": session_id, "content": content},
        )
        if not isinstance(result, Mapping):
            raise RuntimeError(f"Invalid session.message response type: {type(result).__name__}")
        return dict(result)

    @staticmethod
    def _normalize_session_id(session_id: str | None) -> str | None:
        sid = str(session_id or "").strip()
        return sid or None

    def _active_session_id(self) -> str:
        return str(self._session_id or "").strip()

    @staticmethod
    def _extract_response(result: dict[str, Any]) -> str:
        """Extract the response text from a session.message result."""
        response = result.get("response", "")
        if isinstance(response, str) and response.strip():
            return response.strip()
        raise RuntimeError("session.message returned no response text")

    @staticmethod
    def _preserve_pending_preview_escapes(result: dict[str, Any]) -> bool:
        pending_ids = result.get("pending_confirmation_ids")
        return isinstance(pending_ids, list) and any(
            isinstance(item, str) and item.strip() for item in pending_ids
        )

    def _append_history(self, line: str) -> None:
        """Append a plain status/error line to the history pane."""
        self._append_turn(
            Static(line, markup=False, classes="status-message"), classes="status-turn"
        )

    def _append_user_message(self, content: str) -> None:
        """Append a user message as literal text."""
        self._append_turn(
            Static(format_user_message(content), markup=False, classes="user-message"),
            classes="user-turn",
        )

    def _append_assistant_message(
        self,
        content: str,
        *,
        preserve_pending_preview_escapes: bool = False,
    ) -> None:
        """Append an assistant message as Markdown content."""
        rendered = _render_assistant_text(
            content,
            preserve_pending_preview_escapes=preserve_pending_preview_escapes,
        )
        self._append_turn(
            Static("shisad:", markup=False, classes="speaker assistant-speaker"),
            Markdown(rendered, classes="assistant-message"),
            classes="assistant-turn",
        )

    def _append_current_session_status(self) -> None:
        session_id = self._active_session_id()
        if not session_id:
            return
        self._append_history(
            f"info: current session {session_id} "
            f"user={self._user_id} workspace={self._workspace_id}"
        )

    def _start_transcript_polling(self) -> None:
        if self._transcript_root is None or self._transcript_poll_task is not None:
            return
        self._transcript_poll_task = asyncio.create_task(self._transcript_poll_loop())

    async def _transcript_poll_loop(self) -> None:
        while True:
            await asyncio.sleep(0.5)
            self._poll_transcript_for_async_messages_best_effort()

    def _poll_transcript_for_async_messages_best_effort(self) -> None:
        try:
            self._poll_transcript_for_async_messages()
        except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
            return

    def _prime_transcript_display_state_best_effort(self) -> None:
        try:
            self._prime_transcript_display_state()
        except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
            return

    def _replay_recent_transcript_history_best_effort(self) -> None:
        try:
            self._replay_recent_transcript_history()
        except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
            return

    def _prime_transcript_display_state(self) -> None:
        for entry in self._read_transcript_entries():
            entry_id = str(entry.get("entry_id", "")).strip()
            if entry_id and not self._is_async_assistant_delivery(entry):
                self._displayed_transcript_entry_ids.add(entry_id)

    def _replay_recent_transcript_history(self) -> None:
        visible_entries: list[tuple[Mapping[str, Any], str]] = []
        hidden_entry_ids: set[str] = set()
        for entry in self._read_transcript_entries():
            entry_id = str(entry.get("entry_id", "")).strip()
            role = str(entry.get("role", "")).strip().lower()
            if role not in {"user", "assistant"} or (
                self._transcript_entry_is_ephemeral_evidence_read(entry)
            ):
                if entry_id:
                    hidden_entry_ids.add(entry_id)
                continue
            visible_entries.append((entry, role))

        for entry_id in hidden_entry_ids:
            self._displayed_transcript_entry_ids.add(entry_id)

        render_entries: list[tuple[Mapping[str, Any], str, str]] = []
        oldest_render_index = len(visible_entries)
        for index in range(len(visible_entries) - 1, -1, -1):
            entry, role = visible_entries[index]
            entry_id = str(entry.get("entry_id", "")).strip()
            content = self._transcript_entry_content(entry).strip()
            if not content:
                if entry_id and not self._is_async_assistant_delivery(entry):
                    self._displayed_transcript_entry_ids.add(entry_id)
                continue
            if entry_id:
                self._displayed_transcript_entry_ids.add(entry_id)
            render_entries.append((entry, role, content))
            oldest_render_index = index
            if len(render_entries) >= self.TRANSCRIPT_REPLAY_LIMIT:
                break
        for entry, _role in visible_entries[:oldest_render_index]:
            entry_id = str(entry.get("entry_id", "")).strip()
            if not entry_id:
                continue
            if self._is_async_assistant_delivery(entry) and (
                not self._transcript_entry_content_available(entry)
            ):
                continue
            self._displayed_transcript_entry_ids.add(entry_id)
        render_entries.reverse()
        if render_entries:
            self._append_history(f"info: loaded {len(render_entries)} previous messages.")
        for entry, role, content in render_entries:
            if role == "user":
                self._append_user_message(content)
                continue
            self._append_assistant_message(
                content,
                preserve_pending_preview_escapes=(
                    self._transcript_entry_preserve_pending_preview_escapes(entry)
                ),
            )

    def _poll_transcript_for_async_messages(self) -> None:
        for entry in self._read_transcript_entries():
            entry_id = str(entry.get("entry_id", "")).strip()
            if not entry_id or entry_id in self._displayed_transcript_entry_ids:
                continue
            if self._transcript_entry_is_ephemeral_evidence_read(entry):
                self._displayed_transcript_entry_ids.add(entry_id)
                continue
            if not self._is_async_assistant_delivery(entry):
                self._displayed_transcript_entry_ids.add(entry_id)
                continue
            content = self._transcript_entry_content(entry).strip()
            if not content:
                continue
            self._displayed_transcript_entry_ids.add(entry_id)
            self._append_assistant_message(
                content,
                preserve_pending_preview_escapes=(
                    self._transcript_entry_preserve_pending_preview_escapes(entry)
                ),
            )
            self._append_history("")

    def _read_transcript_entries(self) -> list[Mapping[str, Any]]:
        path = self._transcript_path()
        if path is None or not path.exists():
            return []
        session_id = self._active_session_id()
        entries: list[Mapping[str, Any]] = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, Mapping):
                entry = dict(payload)
                if not str(entry.get("entry_id", "")).strip():
                    entry["entry_id"] = derive_legacy_transcript_entry_id(
                        session_id=session_id,
                        line_number=line_number,
                        payload=entry,
                    )
                entries.append(entry)
        return entries

    def _transcript_path(self) -> Path | None:
        session_id = self._active_session_id()
        if self._transcript_root is None or not session_id:
            return None
        return self._transcript_root / "transcripts" / f"{session_id}.jsonl"

    def _is_async_assistant_delivery(self, entry: Mapping[str, Any]) -> bool:
        if str(entry.get("role", "")).strip() != "assistant":
            return False
        metadata = entry.get("metadata", {})
        if not isinstance(metadata, Mapping):
            return False
        delivery_target = metadata.get("delivery_target", {})
        if not isinstance(delivery_target, Mapping):
            delivery_target = {}
        recipient = str(delivery_target.get("recipient", "")).strip()
        if recipient and recipient != self._active_session_id():
            return False
        delivered_by = str(metadata.get("delivered_by", "")).strip()
        channel = str(metadata.get("channel", "")).strip()
        return bool(delivered_by) or channel == "session"

    @staticmethod
    def _transcript_entry_metadata(entry: Mapping[str, Any]) -> Mapping[str, Any]:
        metadata = entry.get("metadata", {})
        if isinstance(metadata, Mapping):
            return metadata
        return {}

    @classmethod
    def _transcript_entry_is_ephemeral_evidence_read(cls, entry: Mapping[str, Any]) -> bool:
        return bool(cls._transcript_entry_metadata(entry).get("ephemeral_evidence_read"))

    @classmethod
    def _transcript_entry_preserve_pending_preview_escapes(
        cls,
        entry: Mapping[str, Any],
    ) -> bool:
        metadata = cls._transcript_entry_metadata(entry)
        if bool(metadata.get("system_generated_pending_confirmations")) or bool(
            metadata.get("pending_confirmation_bridge")
        ):
            return True
        pending_ids = metadata.get("pending_confirmation_ids")
        return isinstance(pending_ids, list) and any(
            isinstance(item, str) and item.strip() for item in pending_ids
        )

    def _transcript_entry_content(self, entry: Mapping[str, Any]) -> str:
        blob_path = self._transcript_entry_blob_path(entry)
        if blob_path is not None:
            if not blob_path.exists():
                return ""
            return blob_path.read_text(encoding="utf-8")
        return str(entry.get("content_preview", "") or "")

    def _transcript_entry_content_available(self, entry: Mapping[str, Any]) -> bool:
        blob_path = self._transcript_entry_blob_path(entry)
        if blob_path is not None:
            return blob_path.exists()
        return bool(str(entry.get("content_preview", "") or "").strip())

    def _transcript_entry_blob_path(self, entry: Mapping[str, Any]) -> Path | None:
        blob_ref = str(entry.get("blob_ref", "") or "").strip()
        if not blob_ref or self._transcript_root is None:
            return None
        return self._transcript_root / "blobs" / f"{blob_ref}.txt"

    def _append_turn(self, *widgets: Static | Markdown, classes: str) -> None:
        history = self.query_one("#chat-log", VerticalScroll)
        history.mount(Vertical(*widgets, classes=f"chat-turn {classes}"))
        history.scroll_end(animate=False)

    def action_focus_next_pane(self) -> None:
        """Move focus between history and input panes."""
        focused = self.focused
        if focused is not None and focused.id == "chat-input":
            self.query_one("#chat-log", VerticalScroll).focus()
            return
        self.query_one("#chat-input", TextArea).focus()

    def action_focus_prev_pane(self) -> None:
        """Move focus between history and input panes."""
        self.action_focus_next_pane()

    def action_history_prev(self) -> None:
        """Recall the previous submitted prompt."""
        if not self._is_input_focused():
            return
        input_widget = self.query_one("#chat-input", TextArea)
        self._set_prompt_text(
            self._recall_prompt_history(
                direction=-1,
                current_value=input_widget.text,
            )
        )

    def action_history_next(self) -> None:
        """Recall the next submitted prompt."""
        if not self._is_input_focused():
            return
        input_widget = self.query_one("#chat-input", TextArea)
        self._set_prompt_text(
            self._recall_prompt_history(
                direction=1,
                current_value=input_widget.text,
            )
        )

    def _set_prompt_text(self, text: str) -> None:
        input_widget = self.query_one("#chat-input", TextArea)
        input_widget.load_text(text)
        input_widget.move_cursor(input_widget.document.end)
        self._resize_prompt_input(input_widget)

    def _resize_prompt_input(self, input_widget: TextArea) -> None:
        """Grow the prompt box for wrapped drafts, then cap it to keep history visible."""
        width = max(int(input_widget.size.width or self.size.width or 80), 1)
        available_width = max(width - self.PROMPT_INPUT_HORIZONTAL_CHROME, 20)
        visual_lines = self._estimate_visual_line_count(input_widget.text, available_width)
        height = min(
            self.PROMPT_INPUT_MAX_HEIGHT,
            max(self.PROMPT_INPUT_MIN_HEIGHT, visual_lines + self.PROMPT_INPUT_CHROME_ROWS),
        )
        input_widget.styles.height = height
        input_widget.refresh(layout=True)

    @staticmethod
    def _estimate_visual_line_count(text: str, width: int) -> int:
        lines = text.splitlines() or [""]
        total = 0
        for line in lines:
            length = len(line.expandtabs(4))
            total += max(1, (length + max(width, 1) - 1) // max(width, 1))
        return total

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
            self._displayed_transcript_entry_ids.clear()
            self._prime_transcript_display_state_best_effort()
            self._append_history("info: started a new session.")
            self._append_history("")
            self._poll_transcript_for_async_messages_best_effort()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            self._session_id = old_session_id
            self._append_history(_format_error(f"Could not start new session: {exc}"))
            self._append_history("")
        self.query_one("#chat-input", TextArea).focus()

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
