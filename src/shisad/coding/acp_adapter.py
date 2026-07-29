"""ACP-backed coding-agent adapter implementation."""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import re
import shutil
import signal
import sys
import time
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

from acp import (
    PROTOCOL_VERSION,
    RequestError,
    spawn_agent_process,
    text_block,
)
from acp.contrib import SessionAccumulator
from acp.contrib.session_state import SessionNotificationMismatchError
from acp.core import DEFAULT_STDIO_BUFFER_LIMIT_BYTES
from acp.interfaces import Agent, Client
from acp.schema import (
    AllowedOutcome,
    ConfigOptionUpdate,
    CurrentModeUpdate,
    DeniedOutcome,
    Implementation,
    RequestPermissionResponse,
    SessionConfigOption,
    SessionNotification,
)

from shisad.core.process_environment import (
    ChildEnvironmentProfile,
    build_child_environment,
)

from .adapter import CodingAgentAdapter
from .models import CodingAgentConfig, CodingAgentResult, CodingAgentRunOutput
from .registry import AgentCommandSpec

logger = logging.getLogger(__name__)

_CODING_AGENT_SUMMARY_MAX_CHARS = 4000
_PROCESS_STDERR_TAIL_MAX_BYTES = 8192
_PROCESS_STDERR_TRUNCATED_MESSAGE = (
    "[stderr truncated before redaction; retained output suppressed]"
)
_PROCESS_TREE_SHUTDOWN_GRACE_SEC = 0.2
_PROCESS_GROUP_WRAPPER_CODE = (
    "import os, sys\n"
    "argv = sys.argv[1:]\n"
    "try:\n"
    "    os.setsid()\n"
    "except (AttributeError, OSError):\n"
    "    pass\n"
    "os.execvp(argv[0], argv)\n"
)
_TRANSPORT_ERROR_STRING_MAX_CHARS = 2000
_TRANSPORT_ERROR_ESCAPED_CONTAINER_STATE_LIMIT = 4096
_SESSION_NOTIFICATION_DRAIN_SEC = 0.1
_TRANSPORT_ERROR_HUMAN_SECRET_LABEL = (
    r"(?:(?!(?:tokens?|secrets?|passwords?|credentials?|keys?)\b)"
    r"[A-Za-z0-9]+[ _]+){0,4}"
    r"(?:api[ _-]?keys?|auth[ _-]?tokens?|tokens?|secrets?|passwords?|credentials?)"
)
_TRANSPORT_ERROR_HUMAN_KEY_MATERIAL_LABEL = (
    r"(?:(?!(?:secret|access|private|keys?)\b)[A-Za-z0-9]+[ _]+){0,4}"
    r"(?:secret[ _-]+access[ _-]+keys?|secret[ _-]+keys?|private[ _-]+keys?)"
)
_TRANSPORT_ERROR_KEY_MATERIAL_LABEL = (
    rf"(?:{_TRANSPORT_ERROR_HUMAN_KEY_MATERIAL_LABEL}|"
    r"[A-Za-z0-9_-]*(?:secret[_-]?access[_-]?keys?|secret[_-]?keys?|private[_-]?keys?))"
)
_TRANSPORT_ERROR_SECRET_IDENTIFIER_LABEL = (
    r"(?:"
    r"[A-Za-z0-9_-]*(?:api[_-]?keys?|auth[_-]?tokens?)[A-Za-z0-9_-]*"
    r"|[A-Za-z0-9_-]+[_-](?:tokens?|secrets?|passwords?|credentials?)"
    r"|(?-i:[A-Za-z0-9]+(?:Tokens?|Secrets?|Passwords?|Credentials?))"
    r"|(?:tokens?|secrets?|passwords?|credentials?)"
    r")"
)
_TRANSPORT_ERROR_SECRET_LABEL = (
    rf"(?:x-api-keys?|authorization|cookie|set-cookie|"
    rf"{_TRANSPORT_ERROR_KEY_MATERIAL_LABEL}|"
    rf"{_TRANSPORT_ERROR_HUMAN_SECRET_LABEL}|"
    rf"{_TRANSPORT_ERROR_SECRET_IDENTIFIER_LABEL})"
)
_TRANSPORT_ERROR_SECRET_LABEL_SUFFIX = r"(?:\s+(?:provided|supplied|passed|received|returned))?"
_TRANSPORT_ERROR_SECRET_LABEL_WITH_SUFFIX = (
    rf"(?:{_TRANSPORT_ERROR_SECRET_LABEL}s?){_TRANSPORT_ERROR_SECRET_LABEL_SUFFIX}"
)
_TRANSPORT_ERROR_SECRET_KEY_RE = re.compile(
    rf"{_TRANSPORT_ERROR_SECRET_LABEL_WITH_SUFFIX}",
    flags=re.IGNORECASE,
)
_TRANSPORT_ERROR_QUOTED_SECRET_RE = re.compile(
    rf"(?P<label_quote>['\"])(?P<label>{_TRANSPORT_ERROR_SECRET_LABEL_WITH_SUFFIX})"
    rf"(?P=label_quote)(?P<sep>\s*[:=]\s*)"
    rf"(?P<value_quote>['\"])(?P<value>(?:\\.|(?!(?P=value_quote)).)*)"
    rf"(?P=value_quote)",
    flags=re.IGNORECASE,
)
_TRANSPORT_ERROR_ESCAPED_QUOTED_SECRET_RE = re.compile(
    rf"(?P<label_quote>\\['\"])(?P<label>{_TRANSPORT_ERROR_SECRET_LABEL_WITH_SUFFIX})"
    rf"(?P=label_quote)(?P<sep>\s*[:=]\s*)"
    rf"(?P<value_quote>\\['\"])(?P<value>(?:\\\\.|(?!(?P=value_quote)).)*)"
    rf"(?P=value_quote)",
    flags=re.IGNORECASE,
)
_TRANSPORT_ERROR_ESCAPED_SECRET_CONTAINER_PREFIX_RE = re.compile(
    rf"(?P<label_quote>\\['\"])(?P<label>{_TRANSPORT_ERROR_SECRET_LABEL_WITH_SUFFIX})"
    rf"(?P=label_quote)(?P<sep>\s*[:=]\s*)",
    flags=re.IGNORECASE,
)
_TRANSPORT_ERROR_SECRET_CONTAINER_PREFIX_RE = re.compile(
    rf"(?P<label_expr>(?:(?P<label_quote>['\"])(?P<quoted_label>"
    rf"{_TRANSPORT_ERROR_SECRET_LABEL_WITH_SUFFIX})(?P=label_quote)|"
    rf"\b(?P<plain_label>{_TRANSPORT_ERROR_SECRET_LABEL_WITH_SUFFIX})\b))"
    r"(?P<sep>\s*[:=]\s*)",
    flags=re.IGNORECASE,
)
_TRANSPORT_ERROR_SECRET_HEADER_RE = re.compile(
    r"(?P<label>\b(?:authorization|cookie|set-cookie)\b)(?P<sep>\s*[:=]\s*)"
    r"[^\r\n]+",
    flags=re.IGNORECASE,
)
_TRANSPORT_ERROR_SECRET_ASSIGNMENT_PREFIX_RE = re.compile(
    rf"(?P<label>(?<!-)\b{_TRANSPORT_ERROR_SECRET_LABEL_WITH_SUFFIX}\b)"
    r"(?P<sep>\s*[:=]\s*)",
    flags=re.IGNORECASE,
)


def _coding_agent_environment() -> dict[str, str]:
    """Preserve the minimal env needed for real coding-agent auth and transport."""

    return build_child_environment(ChildEnvironmentProfile.CODING_AGENT)


def _command_executable_exists(command: tuple[str, ...]) -> bool:
    executable = command[0]
    if Path(executable).is_absolute():
        return Path(executable).exists()
    return shutil.which(executable) is not None


def _agent_process_command(command: tuple[str, ...]) -> tuple[str, ...]:
    if not _command_executable_exists(command):
        return command
    if os.name != "posix" or not hasattr(os, "setsid"):
        return command
    # Isolate adapter CLIs so cleanup can terminate descendants the CLI leaves behind.
    return (sys.executable, "-c", _PROCESS_GROUP_WRAPPER_CODE, *command)


def _uses_process_group_wrapper(command: tuple[str, ...]) -> bool:
    return (
        len(command) >= 3
        and command[0] == sys.executable
        and command[1] == "-c"
        and command[2] == _PROCESS_GROUP_WRAPPER_CODE
    )


def _bounded_summary(text: str, *, max_chars: int = _CODING_AGENT_SUMMARY_MAX_CHARS) -> str:
    normalized = text.strip()
    if len(normalized) <= max_chars:
        return normalized
    if max_chars <= 16:
        return normalized[:max_chars]
    return f"{normalized[: max_chars - 15].rstrip()}... [truncated]"


def _is_secret_transport_key(key: object) -> bool:
    normalized = str(key).strip()
    return bool(normalized and _TRANSPORT_ERROR_SECRET_KEY_RE.fullmatch(normalized))


def _is_multiline_key_material_transport_key(key: object) -> bool:
    compact = re.sub(r"[^a-z0-9]+", "", str(key).casefold())
    return "privatekey" in compact or "secretaccesskey" in compact or "secretkey" in compact


def _json_safe_transport_error_data(value: object, *, key: object = "") -> object:
    if _is_secret_transport_key(key):
        return "[redacted]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return _redact_transport_error_message(value)
    if isinstance(value, Mapping):
        return {
            str(item_key): _json_safe_transport_error_data(item_value, key=item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list | tuple):
        if len(value) == 2 and isinstance(value[0], str) and _is_secret_transport_key(value[0]):
            return [
                _json_safe_transport_error_data(value[0]),
                _json_safe_transport_error_data(value[1], key=value[0]),
            ]
        return [_json_safe_transport_error_data(item) for item in value]
    return _bounded_summary(repr(value), max_chars=_TRANSPORT_ERROR_STRING_MAX_CHARS)


def _transport_error_container_end(text: str, start: int) -> int | None:
    opener = text[start]
    closer_for = {"[": "]", "{": "}"}
    if opener not in closer_for:
        return None

    expected_closers = [closer_for[opener]]
    quote: str | None = None
    escaped = False
    for index in range(start + 1, len(text)):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in closer_for:
            expected_closers.append(closer_for[char])
            continue
        if char in {"]", "}"}:
            if not expected_closers or char != expected_closers[-1]:
                return None
            expected_closers.pop()
            if not expected_closers:
                return index + 1
    return None


def _escaped_json_quote_backslash_count(text: str, index: int) -> int:
    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes


def _transport_error_escaped_container_end(text: str, start: int) -> int | None:
    opener = text[start]
    closer_for = {"[": "]", "{": "}"}
    if opener not in closer_for:
        return None

    pending: list[tuple[int, tuple[str, ...], str | None]] = [
        (start + 1, (closer_for[opener],), None)
    ]
    states_seen = 0
    while pending:
        index, expected_closers, quote = pending.pop()
        states_seen += 1
        if states_seen > _TRANSPORT_ERROR_ESCAPED_CONTAINER_STATE_LIMIT:
            # We are already inside a secret-labeled value; fail closed.
            return len(text)

        closers = list(expected_closers)
        while index < len(text):
            char = text[index]
            if quote is not None:
                if char == quote:
                    backslashes = _escaped_json_quote_backslash_count(text, index)
                    if backslashes == 1:
                        quote = None
                    elif backslashes > 1 and backslashes % 2 == 1:
                        if len(pending) >= _TRANSPORT_ERROR_ESCAPED_CONTAINER_STATE_LIMIT:
                            # We are already inside a secret-labeled value; fail closed.
                            return len(text)
                        pending.append((index + 1, tuple(closers), None))
                index += 1
                continue

            if char in {"'", '"'} and _escaped_json_quote_backslash_count(text, index) == 1:
                quote = char
                index += 1
                continue
            if char in closer_for:
                closers.append(closer_for[char])
            elif char in {"]", "}"}:
                if not closers or char != closers[-1]:
                    break
                closers.pop()
                if not closers:
                    return index + 1
            index += 1

    return None


def _transport_error_malformed_container_end(text: str, _start: int) -> int:
    return len(text)


def _redact_transport_error_secret_containers(message: str) -> str:
    parts: list[str] = []
    cursor = 0
    search_pos = 0
    while match := _TRANSPORT_ERROR_SECRET_CONTAINER_PREFIX_RE.search(message, search_pos):
        value_start = match.end()
        if value_start >= len(message) or message[value_start] not in {"[", "{"}:
            search_pos = match.end()
            continue
        value_end = _transport_error_container_end(message, value_start)
        if value_end is None:
            value_end = _transport_error_malformed_container_end(message, value_start)

        parts.append(message[cursor:value_start])
        value_quote = match.group("label_quote")
        if value_quote is None:
            parts.append("[redacted]")
        else:
            parts.append(f"{value_quote}[redacted]{value_quote}")
        cursor = value_end
        search_pos = value_end

    if not parts:
        return message
    parts.append(message[cursor:])
    return "".join(parts)


def _redact_transport_error_escaped_secret_containers(message: str) -> str:
    parts: list[str] = []
    cursor = 0
    search_pos = 0
    while match := _TRANSPORT_ERROR_ESCAPED_SECRET_CONTAINER_PREFIX_RE.search(message, search_pos):
        value_start = match.end()
        if value_start >= len(message) or message[value_start] not in {"[", "{"}:
            search_pos = match.end()
            continue
        value_end = _transport_error_escaped_container_end(message, value_start)
        if value_end is None:
            value_end = _transport_error_malformed_container_end(message, value_start)

        parts.append(message[cursor:value_start])
        value_quote = match.group("label_quote")
        parts.append(f"{value_quote}[redacted]{value_quote}")
        cursor = value_end
        search_pos = value_end

    if not parts:
        return message
    parts.append(message[cursor:])
    return "".join(parts)


def _redact_transport_error_secret_assignments(message: str) -> str:
    parts: list[str] = []
    cursor = 0
    search_pos = 0
    while match := _TRANSPORT_ERROR_SECRET_ASSIGNMENT_PREFIX_RE.search(message, search_pos):
        value_start = match.end()
        multiline_key_material = _is_multiline_key_material_transport_key(match.group("label"))
        if value_start >= len(message) or (
            message[value_start] in {"\r", "\n"} and not multiline_key_material
        ):
            search_pos = match.end()
            continue

        line_end = len(message)
        for line_break in ("\r", "\n"):
            index = message.find(line_break, value_start)
            if index != -1:
                line_end = min(line_end, index)

        if multiline_key_material and line_end < len(message):
            value_end = len(message)
        else:
            next_match = _TRANSPORT_ERROR_SECRET_ASSIGNMENT_PREFIX_RE.search(
                message,
                value_start,
                line_end,
            )
            value_end = next_match.start() if next_match else line_end
        while value_end > value_start and message[value_end - 1].isspace():
            value_end -= 1
        if value_end <= value_start:
            search_pos = match.end()
            continue

        parts.append(message[cursor:value_start])
        parts.append("[redacted]")
        cursor = value_end
        search_pos = value_end

    if not parts:
        return message
    parts.append(message[cursor:])
    return "".join(parts)


def _redact_transport_error_message(message: str) -> str:
    redacted = _redact_transport_error_secret_containers(message)
    redacted = _redact_transport_error_escaped_secret_containers(redacted)
    redacted = _TRANSPORT_ERROR_ESCAPED_QUOTED_SECRET_RE.sub(
        lambda match: (
            f"{match.group('label_quote')}{match.group('label')}"
            f"{match.group('label_quote')}{match.group('sep')}"
            f"{match.group('value_quote')}[redacted]{match.group('value_quote')}"
        ),
        redacted,
    )
    redacted = _TRANSPORT_ERROR_QUOTED_SECRET_RE.sub(
        lambda match: (
            f"{match.group('label_quote')}{match.group('label')}"
            f"{match.group('label_quote')}{match.group('sep')}"
            f"{match.group('value_quote')}[redacted]{match.group('value_quote')}"
        ),
        redacted,
    )
    redacted = _TRANSPORT_ERROR_SECRET_HEADER_RE.sub(
        lambda match: f"{match.group('label')}{match.group('sep')}[redacted]",
        redacted,
    )
    redacted = _redact_transport_error_secret_assignments(redacted)
    return _bounded_summary(redacted, max_chars=_TRANSPORT_ERROR_STRING_MAX_CHARS)


def _request_error_payload(exc: RequestError) -> dict[str, Any]:
    message = _redact_transport_error_message(str(exc).strip() or exc.__class__.__name__)
    payload: dict[str, Any] = {
        "kind": "request_error",
        "message": message,
    }
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        payload["code"] = code
    data = getattr(exc, "data", None)
    if data is not None:
        payload["data"] = _json_safe_transport_error_data(data)
    return payload


class _ProcessStderrTail:
    def __init__(self, *, max_bytes: int = _PROCESS_STDERR_TAIL_MAX_BYTES) -> None:
        self._max_bytes = max(1, max_bytes)
        self._buffer = bytearray()
        self._truncated = False

    def append(self, chunk: bytes) -> None:
        if not chunk:
            return
        self._buffer.extend(chunk)
        if len(self._buffer) > self._max_bytes:
            self._truncated = True
            del self._buffer[: len(self._buffer) - self._max_bytes]

    def text(self) -> str:
        if not self._buffer:
            return ""
        if self._truncated:
            return _PROCESS_STDERR_TRUNCATED_MESSAGE
        decoded = self._buffer.decode("utf-8", errors="replace").strip()
        return _redact_transport_error_message(decoded)

    def mark_incomplete(self) -> None:
        self._truncated = True


class _AcpProcessExited(RuntimeError):
    def __init__(self, *, phase: str, returncode: int | None, stderr: str) -> None:
        super().__init__(f"ACP process exited during {phase}")
        self.phase = phase
        self.returncode = returncode
        self.stderr = stderr

    def payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": "process_exit",
            "phase": self.phase,
            "returncode": self.returncode,
            "stderr": self.stderr,
        }
        return payload


async def _drain_process_stderr(process: Any, stderr_tail: _ProcessStderrTail) -> None:
    stderr = getattr(process, "stderr", None)
    if stderr is None:
        return
    while True:
        chunk = await stderr.read(1024)
        if not chunk:
            return
        stderr_tail.append(chunk)


async def _wait_for_stderr_flush(
    stderr_task: asyncio.Task[None] | None,
    stderr_tail: _ProcessStderrTail,
) -> None:
    if stderr_task is None:
        await asyncio.sleep(0)
        return
    try:
        await asyncio.wait_for(asyncio.shield(stderr_task), timeout=0.1)
    except TimeoutError:
        stderr_tail.mark_incomplete()


async def _await_acp_step(
    awaitable: Awaitable[Any],
    *,
    process: Any,
    stderr_tail: _ProcessStderrTail,
    stderr_task: asyncio.Task[None] | None,
    phase: str,
) -> Any:
    operation_task: asyncio.Future[Any] = asyncio.ensure_future(awaitable)
    process_wait_task: asyncio.Task[Any] = asyncio.create_task(process.wait())
    try:
        done, _pending = await asyncio.wait(
            {operation_task, process_wait_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if process_wait_task in done:
            operation_exception: BaseException | None = None
            operation_failed = operation_task not in done
            if operation_task.done():
                with suppress(asyncio.CancelledError):
                    operation_exception = operation_task.exception()
                    operation_failed = operation_exception is not None
            if isinstance(operation_exception, RequestError):
                await _wait_for_stderr_flush(stderr_task, stderr_tail)
                process_wait_task.cancel()
                with suppress(asyncio.CancelledError):
                    await process_wait_task
                return await operation_task
            if operation_failed:
                returncode = await process_wait_task
                operation_task.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await operation_task
                await _wait_for_stderr_flush(stderr_task, stderr_tail)
                raise _AcpProcessExited(
                    phase=phase,
                    returncode=returncode,
                    stderr=stderr_tail.text(),
                )
        if operation_task in done:
            process_wait_task.cancel()
            with suppress(asyncio.CancelledError):
                await process_wait_task
            return await operation_task

        returncode = await process_wait_task
        operation_task.cancel()
        with suppress(asyncio.CancelledError, Exception):
            await operation_task
        await _wait_for_stderr_flush(stderr_task, stderr_tail)
        raise _AcpProcessExited(
            phase=phase,
            returncode=returncode,
            stderr=stderr_tail.text(),
        )
    finally:
        if not operation_task.done():
            operation_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await operation_task
        if not process_wait_task.done():
            process_wait_task.cancel()
            with suppress(asyncio.CancelledError):
                await process_wait_task


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _process_group_has_running_members(
    process_group_id: int | None,
    *,
    proc_root: Path | None = None,
) -> bool | None:
    if process_group_id is None:
        return False
    proc_root = proc_root or Path("/proc")
    if not proc_root.exists():
        return None
    # Poll the live group instead of caching child PIDs that may later be reused.
    for stat_file in proc_root.glob("[0-9]*/stat"):
        try:
            stat = stat_file.read_text(encoding="utf-8")
            fields = stat.rsplit(")", 1)[1].strip().split()
            state = fields[0]
            group_id = int(fields[2])
        except (OSError, IndexError, ValueError):
            continue
        if group_id == process_group_id and state != "Z":
            return True
    return False


async def _wait_for_process_group_exit(
    process_group_id: int | None,
    *,
    timeout: float,
) -> bool | None:
    if process_group_id is None:
        return True
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        running = _process_group_has_running_members(process_group_id)
        if running is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            await asyncio.sleep(min(0.02, remaining))
            continue
        if not running:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(0.02, remaining))
    running = _process_group_has_running_members(process_group_id)
    return None if running is None else not running


def _descendant_pids(pid: int) -> tuple[int, ...]:
    descendants: list[int] = []
    seen: set[int] = set()
    pending = [pid]
    while pending:
        current = pending.pop()
        children_file = Path("/proc") / str(current) / "task" / str(current) / "children"
        try:
            raw_children = children_file.read_text(encoding="utf-8")
        except OSError:
            continue
        for raw_child in raw_children.split():
            try:
                child_pid = int(raw_child)
            except ValueError:
                continue
            if child_pid in seen:
                continue
            seen.add(child_pid)
            descendants.append(child_pid)
            pending.append(child_pid)
    return tuple(descendants)


def _signal_processes(pids: tuple[int, ...], sig: signal.Signals) -> None:
    for pid in pids:
        with suppress(ProcessLookupError, PermissionError):
            os.kill(pid, sig)


def _process_group_id(process: Any) -> int | None:
    pid = getattr(process, "pid", None)
    if not isinstance(pid, int) or pid <= 0:
        return None
    getpgid = getattr(os, "getpgid", None)
    getpgrp = getattr(os, "getpgrp", None)
    if not callable(getpgid) or not callable(getpgrp):
        return None
    try:
        pgid_value = getpgid(pid)
        current_pgrp_value = getpgrp()
    except (OSError, ProcessLookupError, PermissionError):
        return None
    if not isinstance(pgid_value, int) or not isinstance(current_pgrp_value, int):
        return None
    pgid = pgid_value
    current_pgrp = current_pgrp_value
    if pgid <= 0 or pgid == current_pgrp:
        return None
    return pgid


def _signal_process_group_id(process_group_id: int | None, sig: signal.Signals) -> None:
    if process_group_id is None:
        return
    killpg = getattr(os, "killpg", None)
    if not callable(killpg):
        return
    with suppress(ProcessLookupError, PermissionError):
        killpg(process_group_id, sig)


def _process_kill_signal() -> signal.Signals | None:
    sigkill = getattr(signal, "SIGKILL", None)
    return sigkill if isinstance(sigkill, signal.Signals) else None


async def _terminate_process_tree(
    process: Any,
    *,
    process_group_id: int | None = None,
) -> None:
    pid = getattr(process, "pid", None)
    if not isinstance(pid, int) or pid <= 0:
        _signal_process_group_id(process_group_id, signal.SIGTERM)
        kill_signal = _process_kill_signal()
        if kill_signal is not None:
            _signal_process_group_id(process_group_id, kill_signal)
        return

    descendants = _descendant_pids(pid)
    targets = (*reversed(descendants), pid)
    _signal_process_group_id(process_group_id, signal.SIGTERM)
    _signal_processes(targets, signal.SIGTERM)
    with suppress(asyncio.TimeoutError, ProcessLookupError):
        await asyncio.wait_for(process.wait(), timeout=_PROCESS_TREE_SHUTDOWN_GRACE_SEC)
    group_exited = await _wait_for_process_group_exit(
        process_group_id,
        timeout=_PROCESS_TREE_SHUTDOWN_GRACE_SEC,
    )

    remaining = tuple(target for target in targets if _process_exists(target))
    if not remaining and group_exited is True:
        return
    kill_signal = _process_kill_signal()
    if kill_signal is None:
        return
    _signal_process_group_id(process_group_id, kill_signal)
    _signal_processes(remaining, kill_signal)
    with suppress(asyncio.TimeoutError, ProcessLookupError):
        await asyncio.wait_for(process.wait(), timeout=_PROCESS_TREE_SHUTDOWN_GRACE_SEC)
    await _wait_for_process_group_exit(
        process_group_id,
        timeout=_PROCESS_TREE_SHUTDOWN_GRACE_SEC,
    )


def _extract_summary(notifications: tuple[dict[str, Any], ...]) -> str:
    messages: list[str] = []
    for notification in notifications:
        update = notification.get("update")
        if not isinstance(update, dict):
            continue
        session_update = (
            str(update.get("session_update", "")).strip()
            or str(update.get("sessionUpdate", "")).strip()
        )
        if session_update != "agent_message_chunk":
            continue
        content = update.get("content")
        if not isinstance(content, dict):
            continue
        text = str(content.get("text", ""))
        if text.strip():
            messages.append(text)
    return "".join(messages).strip() if messages else ""


def _extract_files_changed(notifications: tuple[dict[str, Any], ...]) -> tuple[str, ...]:
    files: list[str] = []
    for notification in notifications:
        update = notification.get("update")
        if not isinstance(update, dict):
            continue
        session_update = (
            str(update.get("session_update", "")).strip()
            or str(update.get("sessionUpdate", "")).strip()
        )
        if session_update not in {"tool_call", "tool_call_update"}:
            continue
        content_list = update.get("content")
        if not isinstance(content_list, list):
            continue
        for content in content_list:
            if not isinstance(content, dict):
                continue
            if str(content.get("type", "")).strip() != "diff":
                continue
            path = str(content.get("path", "")).strip()
            if path and path not in files:
                files.append(path)
    return tuple(files)


def _extract_cost_usd(payload: object) -> float | None:
    if not isinstance(payload, dict):
        return None
    raw_cost = payload.get("cost")
    if not isinstance(raw_cost, dict):
        return None
    currency = str(raw_cost.get("currency", "")).strip().upper()
    if currency != "USD":
        return None
    amount = raw_cost.get("amount")
    if amount is None or isinstance(amount, bool):
        return None
    if isinstance(amount, str):
        amount = amount.strip()
        if not amount:
            return None
    try:
        return float(amount)
    except (TypeError, ValueError):
        return None


def _extract_config_options(
    config_options: list[SessionConfigOption] | None,
) -> dict[str, tuple[str, frozenset[str]]]:
    extracted: dict[str, tuple[str, frozenset[str]]] = {}
    for option in config_options or []:
        normalized_option = getattr(option, "root", option)
        option_id = str(getattr(normalized_option, "id", "")).strip()
        if not option_id:
            continue
        values: set[str] = set()
        for candidate in getattr(normalized_option, "options", []):
            value = str(getattr(candidate, "value", "")).strip()
            if value:
                values.add(value)
                continue
            for grouped_candidate in getattr(candidate, "options", []):
                grouped_value = str(getattr(grouped_candidate, "value", "")).strip()
                if grouped_value:
                    values.add(grouped_value)
        current_value = str(getattr(normalized_option, "current_value", "")).strip()
        extracted[option_id] = (current_value, frozenset(values))
    return extracted


def _extract_mode_ids(modes: Any) -> set[str]:
    if modes is None:
        return set()
    return {
        str(getattr(mode, "id", "")).strip()
        for mode in getattr(modes, "available_modes", [])
        if str(getattr(mode, "id", "")).strip()
    }


class _AcpRecordingClient(Client):
    def __init__(self) -> None:
        self._accumulator = SessionAccumulator()
        self.notifications: list[dict[str, Any]] = []
        self.current_mode: str | None = None
        self.applied_config: dict[str, str] = {}
        self.cost_usd: float | None = None
        self._conn: Agent | None = None

    def on_connect(self, conn: Agent) -> None:
        self._conn = conn

    async def request_permission(
        self,
        options: list[Any],
        session_id: str,
        tool_call: Any,
        **kwargs: Any,
    ) -> RequestPermissionResponse:
        _ = (session_id, tool_call, kwargs)
        for option in options:
            kind = str(getattr(option, "kind", "")).strip().lower()
            option_id = str(getattr(option, "option_id", "")).strip()
            if kind.startswith("allow") and option_id:
                logger.debug(
                    "ACP permission auto-approved session_id=%s tool_call_id=%s title=%s "
                    "option_id=%s",
                    session_id,
                    str(getattr(tool_call, "tool_call_id", "")).strip(),
                    str(getattr(tool_call, "title", "")).strip(),
                    option_id,
                )
                return RequestPermissionResponse(
                    outcome=AllowedOutcome(option_id=option_id, outcome="selected")
                )
        return RequestPermissionResponse(outcome=DeniedOutcome(outcome="cancelled"))

    async def session_update(
        self,
        session_id: str,
        update: Any,
        **kwargs: Any,
    ) -> None:
        _ = kwargs
        notification = SessionNotification(session_id=session_id, update=update)
        payload = notification.model_dump(mode="json")
        self.notifications.append(payload)
        payload_cost = _extract_cost_usd(payload.get("update"))
        if payload_cost is not None:
            self.cost_usd = payload_cost
        with suppress(SessionNotificationMismatchError):
            self._accumulator.apply(notification)
        if isinstance(update, CurrentModeUpdate):
            self.current_mode = str(update.current_mode_id).strip() or None
        elif isinstance(update, ConfigOptionUpdate):
            for option in update.config_options:
                option_id = str(getattr(option, "id", "")).strip()
                current_value = str(getattr(option, "current_value", "")).strip()
                if option_id and current_value:
                    self.applied_config[option_id] = current_value

    async def write_text_file(
        self,
        content: str,
        path: str,
        session_id: str,
        **kwargs: Any,
    ) -> Any:
        _ = (content, path, session_id, kwargs)
        raise RequestError.method_not_found("fs/write_text_file")

    async def read_text_file(
        self,
        path: str,
        session_id: str,
        limit: int | None = None,
        line: int | None = None,
        **kwargs: Any,
    ) -> Any:
        _ = (path, session_id, limit, line, kwargs)
        raise RequestError.method_not_found("fs/read_text_file")

    async def create_terminal(
        self,
        command: str,
        session_id: str,
        args: list[str] | None = None,
        cwd: str | None = None,
        env: list[Any] | None = None,
        output_byte_limit: int | None = None,
        **kwargs: Any,
    ) -> Any:
        _ = (command, session_id, args, cwd, env, output_byte_limit, kwargs)
        raise RequestError.method_not_found("terminal/create")

    async def terminal_output(self, session_id: str, terminal_id: str, **kwargs: Any) -> Any:
        _ = (session_id, terminal_id, kwargs)
        raise RequestError.method_not_found("terminal/output")

    async def release_terminal(
        self,
        session_id: str,
        terminal_id: str,
        **kwargs: Any,
    ) -> Any:
        _ = (session_id, terminal_id, kwargs)
        raise RequestError.method_not_found("terminal/release")

    async def wait_for_terminal_exit(
        self,
        session_id: str,
        terminal_id: str,
        **kwargs: Any,
    ) -> Any:
        _ = (session_id, terminal_id, kwargs)
        raise RequestError.method_not_found("terminal/wait_for_exit")

    async def kill_terminal(self, session_id: str, terminal_id: str, **kwargs: Any) -> Any:
        _ = (session_id, terminal_id, kwargs)
        raise RequestError.method_not_found("terminal/kill")

    async def ext_method(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        _ = (method, params)
        return {}

    async def ext_notification(self, method: str, params: dict[str, Any]) -> None:
        _ = (method, params)


class AcpAdapter(CodingAgentAdapter):
    """Default ACP transport implementation for coding-agent tasks."""

    def __init__(self, *, spec: AgentCommandSpec) -> None:
        self._spec = spec

    async def run(
        self,
        *,
        prompt_text: str,
        workdir: Path,
        config: CodingAgentConfig,
        on_session_started: Callable[[str], Awaitable[None] | None] | None = None,
    ) -> CodingAgentRunOutput:
        start = time.monotonic()
        recorder = _AcpRecordingClient()
        env = _coding_agent_environment()
        session_id = ""
        selected_mode: str | None = None
        applied_config: dict[str, str] = {}
        conn: Any | None = None
        process: Any | None = None
        process_group_id: int | None = None
        stderr_tail = _ProcessStderrTail()
        launch_command = _agent_process_command(self._spec.command)
        launch_uses_process_group_wrapper = _uses_process_group_wrapper(launch_command)

        async def _run_session() -> CodingAgentRunOutput:
            nonlocal applied_config, conn, process, process_group_id, selected_mode, session_id
            async with spawn_agent_process(
                recorder,
                *launch_command,
                env=env,
                cwd=str(workdir),
                transport_kwargs={"limit": DEFAULT_STDIO_BUFFER_LIMIT_BYTES},
            ) as (inner_conn, inner_process):
                conn = inner_conn
                process = inner_process
                process_group_id = _process_group_id(process)
                if process_group_id is None and launch_uses_process_group_wrapper:
                    # The wrapper may not have switched groups when we inspect immediately.
                    pid = getattr(process, "pid", None)
                    if isinstance(pid, int) and pid > 0:
                        process_group_id = pid
                stderr_task = asyncio.create_task(_drain_process_stderr(process, stderr_tail))

                async def _step(awaitable: Awaitable[Any], phase: str) -> Any:
                    return await _await_acp_step(
                        awaitable,
                        process=process,
                        stderr_tail=stderr_tail,
                        stderr_task=stderr_task,
                        phase=phase,
                    )

                try:
                    await _step(
                        conn.initialize(
                            PROTOCOL_VERSION,
                            client_info=Implementation(name="shisad", version="0.4.0"),
                        ),
                        "initialize",
                    )
                    new_session = await _step(conn.new_session(cwd=str(workdir)), "new_session")
                    session_id = str(new_session.session_id)
                    if on_session_started is not None:
                        try:
                            callback_result = on_session_started(session_id)
                            if inspect.isawaitable(callback_result):
                                await callback_result
                        except Exception:
                            logger.warning(
                                "ACP session-start callback failed for agent=%s session_id=%s",
                                self._spec.name,
                                session_id,
                                exc_info=True,
                            )

                    available_modes = _extract_mode_ids(getattr(new_session, "modes", None))
                    current_mode = (
                        str(
                            getattr(
                                getattr(new_session, "modes", None),
                                "current_mode_id",
                                "",
                            )
                        ).strip()
                        or None
                    )
                    selected_mode = await self._apply_mode(
                        conn=conn,
                        session_id=session_id,
                        current_mode=current_mode,
                        available_modes=available_modes,
                        config=config,
                        request_step=_step,
                    )

                    available_config = _extract_config_options(
                        getattr(new_session, "config_options", None)
                    )
                    applied_config = await self._apply_config(
                        conn=conn,
                        session_id=session_id,
                        available_config=available_config,
                        selected_mode=selected_mode,
                        config=config,
                        request_step=_step,
                    )

                    prompt_response = await _step(
                        conn.prompt(
                            [text_block(prompt_text)],
                            session_id=session_id,
                        ),
                        "prompt",
                    )
                    await asyncio.sleep(_SESSION_NOTIFICATION_DRAIN_SEC)
                    duration_ms = int((time.monotonic() - start) * 1000)
                    raw_updates = tuple(recorder.notifications)
                    if not _extract_summary(raw_updates):
                        await asyncio.sleep(0.05)
                        raw_updates = tuple(recorder.notifications)
                    cost_usd = recorder.cost_usd
                    if cost_usd is None:
                        cost_usd = _extract_cost_usd(getattr(prompt_response, "field_meta", None))
                    return CodingAgentRunOutput(
                        result=CodingAgentResult(
                            agent=self._spec.name,
                            task=prompt_text,
                            success=True,
                            summary=_bounded_summary(
                                _extract_summary(raw_updates) or "Coding agent completed."
                            ),
                            cost=cost_usd,
                            duration_ms=duration_ms,
                            files_changed=_extract_files_changed(raw_updates),
                        ),
                        stop_reason=str(getattr(prompt_response, "stop_reason", "")).strip(),
                        session_id=session_id,
                        raw_updates=raw_updates,
                        selected_mode=recorder.current_mode or selected_mode,
                        applied_config={**applied_config, **recorder.applied_config},
                    )
                finally:
                    await _terminate_process_tree(
                        process,
                        process_group_id=process_group_id,
                    )
                    stderr_task.cancel()
                    with suppress(asyncio.CancelledError, Exception):
                        await stderr_task

        try:
            if config.timeout_sec is not None:
                async with asyncio.timeout(config.timeout_sec):
                    return await _run_session()
            return await _run_session()
        except TimeoutError:
            with suppress(Exception):
                if conn is not None and session_id:
                    await conn.cancel(session_id=session_id)
            with suppress(Exception):
                if process is not None:
                    await _terminate_process_tree(process, process_group_id=process_group_id)
            duration_ms = int((time.monotonic() - start) * 1000)
            return CodingAgentRunOutput(
                result=CodingAgentResult(
                    agent=self._spec.name,
                    task=prompt_text,
                    success=False,
                    summary="Coding agent timed out before completion.",
                    cost=recorder.cost_usd,
                    duration_ms=duration_ms,
                    files_changed=_extract_files_changed(tuple(recorder.notifications)),
                ),
                error_code="timeout",
                session_id=session_id,
                raw_updates=tuple(recorder.notifications),
                selected_mode=recorder.current_mode or selected_mode,
                applied_config={**applied_config, **recorder.applied_config},
            )
        except _AcpProcessExited as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            summary = (
                f"Coding agent '{self._spec.name}' exited during ACP {exc.phase} "
                f"(exit code {exc.returncode})."
            )
            if exc.stderr:
                summary = f"{summary} stderr: {exc.stderr}"
            return CodingAgentRunOutput(
                result=CodingAgentResult(
                    agent=self._spec.name,
                    task=prompt_text,
                    success=False,
                    summary=_bounded_summary(summary),
                    cost=recorder.cost_usd,
                    duration_ms=duration_ms,
                    files_changed=_extract_files_changed(tuple(recorder.notifications)),
                ),
                error_code="protocol_error",
                transport_error=exc.payload(),
                session_id=session_id,
                raw_updates=tuple(recorder.notifications),
                selected_mode=recorder.current_mode or selected_mode,
                applied_config={**applied_config, **recorder.applied_config},
            )
        except FileNotFoundError:
            duration_ms = int((time.monotonic() - start) * 1000)
            return CodingAgentRunOutput(
                result=CodingAgentResult(
                    agent=self._spec.name,
                    task=prompt_text,
                    success=False,
                    summary=(
                        f"Coding agent '{self._spec.name}' is not available: "
                        f"unable to launch '{self._spec.command[0]}'."
                    ),
                    duration_ms=duration_ms,
                ),
                error_code="agent_unavailable",
                session_id=session_id,
                selected_mode=selected_mode,
                applied_config=applied_config,
            )
        except RequestError as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            transport_error = _request_error_payload(exc)
            stderr = stderr_tail.text()
            if stderr:
                transport_error["stderr"] = stderr
            error_message = str(transport_error.get("message", "")).strip() or str(exc)
            summary = (
                f"Coding agent '{self._spec.name}' failed during ACP negotiation: {error_message}"
            )
            code = transport_error.get("code")
            if isinstance(code, int):
                summary = f"{summary} (code {code})"
            if stderr:
                summary = f"{summary}; stderr: {stderr}"
            return CodingAgentRunOutput(
                result=CodingAgentResult(
                    agent=self._spec.name,
                    task=prompt_text,
                    success=False,
                    summary=f"{summary}.",
                    duration_ms=duration_ms,
                ),
                error_code="protocol_error",
                transport_error=transport_error,
                session_id=session_id,
                raw_updates=tuple(recorder.notifications),
                selected_mode=recorder.current_mode or selected_mode,
                applied_config={**applied_config, **recorder.applied_config},
            )
        except Exception as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            detail = _redact_transport_error_message(str(exc).strip())
            summary = f"Coding agent '{self._spec.name}' failed during ACP transport."
            if detail:
                summary = f"{summary} {detail}"
            transport_error = {
                "kind": "transport_exception",
                "message": _redact_transport_error_message(detail or exc.__class__.__name__),
            }
            stderr = stderr_tail.text()
            if stderr:
                transport_error["stderr"] = stderr
                summary = f"{summary} stderr: {stderr}"
            return CodingAgentRunOutput(
                result=CodingAgentResult(
                    agent=self._spec.name,
                    task=prompt_text,
                    success=False,
                    summary=_bounded_summary(summary),
                    duration_ms=duration_ms,
                ),
                error_code="protocol_error",
                transport_error=transport_error,
                session_id=session_id,
                raw_updates=tuple(recorder.notifications),
                selected_mode=recorder.current_mode or selected_mode,
                applied_config={**applied_config, **recorder.applied_config},
            )

    async def _apply_mode(
        self,
        *,
        conn: Any,
        session_id: str,
        current_mode: str | None,
        available_modes: set[str],
        config: CodingAgentConfig,
        request_step: Callable[[Awaitable[Any], str], Awaitable[Any]] | None = None,
    ) -> str | None:
        desired_modes = self._spec.read_only_modes if config.read_only else self._spec.write_modes

        async def _request(awaitable: Awaitable[Any], phase: str) -> Any:
            if request_step is None:
                return await awaitable
            return await request_step(awaitable, phase)

        for candidate in desired_modes:
            if candidate not in available_modes:
                continue
            if candidate == current_mode:
                return current_mode
            try:
                await _request(
                    conn.set_session_mode(candidate, session_id=session_id),
                    "set_session_mode",
                )
                return candidate
            except RequestError:
                continue
        return current_mode

    async def _apply_config(
        self,
        *,
        conn: Any,
        session_id: str,
        available_config: Mapping[str, tuple[str, frozenset[str]]],
        selected_mode: str | None,
        config: CodingAgentConfig,
        request_step: Callable[[Awaitable[Any], str], Awaitable[Any]] | None = None,
    ) -> dict[str, str]:
        config_state = dict(available_config)
        initial_config_ids = frozenset(config_state)
        permissive_legacy_config = not config_state and self._spec.name != "claude"
        claude_empty_surface = not config_state and self._spec.name == "claude"
        applied: dict[str, str] = {}

        async def _request(awaitable: Awaitable[Any], phase: str) -> Any:
            if request_step is None:
                return await awaitable
            return await request_step(awaitable, phase)

        async def _apply_option(
            config_id: str,
            value: str,
            *,
            require_exact_acknowledgement: bool = False,
        ) -> None:
            nonlocal config_state
            response = await _request(
                conn.set_config_option(config_id, session_id=session_id, value=value),
                "set_config_option",
            )
            response_options = getattr(response, "config_options", None)
            response_state = _extract_config_options(response_options)
            acknowledged_config = response_state.get(config_id)
            if require_exact_acknowledgement and acknowledged_config is None:
                raise RequestError(
                    -32602,
                    (
                        f"ACP config option '{config_id}' did not acknowledge "
                        f"requested value '{value}'"
                    ),
                    {
                        "config_id": config_id,
                        "requested_value": value,
                    },
                )
            if (
                require_exact_acknowledgement
                and acknowledged_config is not None
                and acknowledged_config[0] != value
            ):
                acknowledged_value = acknowledged_config[0]
                raise RequestError(
                    -32602,
                    (
                        f"ACP config option '{config_id}' acknowledged "
                        f"'{acknowledged_value}' instead of requested '{value}'"
                    ),
                    {
                        "config_id": config_id,
                        "requested_value": value,
                        "acknowledged_value": acknowledged_value,
                    },
                )
            if acknowledged_config is not None:
                applied[config_id] = acknowledged_config[0]
            if response_options is not None:
                config_state = response_state

        if config.model:
            await _apply_option("model", config.model)

        if config.reasoning_effort:
            effort_config_id = next(
                (
                    candidate
                    for candidate in ("reasoning_effort", "effort")
                    if candidate in config_state
                ),
                None,
            )
            if effort_config_id is None:
                raise RequestError(
                    -32602,
                    (
                        f"ACP agent '{self._spec.name}' does not advertise "
                        "a reasoning-effort config option"
                    ),
                    {
                        "semantic_config": "reasoning_effort",
                        "requested_value": config.reasoning_effort,
                        "advertised_config_ids": sorted(config_state),
                    },
                )
            _, advertised_effort_values = config_state[effort_config_id]
            if config.reasoning_effort not in advertised_effort_values:
                raise RequestError(
                    -32602,
                    (
                        f"ACP config option '{effort_config_id}' does not advertise "
                        f"requested value '{config.reasoning_effort}'"
                    ),
                    {
                        "config_id": effort_config_id,
                        "requested_value": config.reasoning_effort,
                        "advertised_values": sorted(advertised_effort_values),
                    },
                )
            await _apply_option(
                effort_config_id,
                config.reasoning_effort,
                require_exact_acknowledgement=True,
            )

        def _available_for_optional_config(config_id: str) -> bool:
            if claude_empty_surface:
                return False
            if permissive_legacy_config:
                return True
            return config_id in initial_config_ids and config_id in config_state

        if config.max_turns is not None and _available_for_optional_config("max_turns"):
            await _apply_option("max_turns", str(config.max_turns))
        if config.permission_mode and _available_for_optional_config("permission_mode"):
            await _apply_option("permission_mode", config.permission_mode)
        if _available_for_optional_config("allowed_tools"):
            if config.allowed_tools:
                await _apply_option("allowed_tools", ",".join(config.allowed_tools))
            elif config.read_only:
                await _apply_option("allowed_tools", "read-only")
        if selected_mode is None:
            await _apply_option("mode", "plan" if config.read_only else "build")
        return applied
