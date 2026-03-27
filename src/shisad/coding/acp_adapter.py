"""ACP-backed coding-agent adapter implementation."""

from __future__ import annotations

import asyncio
import logging
import os
import time
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
from acp.transports import default_environment

from .adapter import CodingAgentAdapter
from .models import CodingAgentConfig, CodingAgentResult, CodingAgentRunOutput
from .registry import AgentCommandSpec

logger = logging.getLogger(__name__)

_CODING_AGENT_ENV_KEYS = frozenset(
    {
        "CLOUD_ML_REGION",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "NODE_OPTIONS",
        "NPM_CONFIG_USERCONFIG",
        "NPM_TOKEN",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)
_CODING_AGENT_ENV_PREFIXES = (
    "ANTHROPIC_",
    "AWS_",
    "AZURE_",
    "CLAUDE_CODE_",
    "GEMINI_",
    "GOOGLE_",
    "OPENAI_",
    "OPENROUTER_",
)
_CODING_AGENT_SUMMARY_MAX_CHARS = 4000


def _coding_agent_environment() -> dict[str, str]:
    """Preserve the minimal env needed for real coding-agent auth and transport."""

    env = default_environment()
    for key, value in os.environ.items():
        if not value or value.startswith("()"):
            continue
        if key in _CODING_AGENT_ENV_KEYS or any(
            key.startswith(prefix) for prefix in _CODING_AGENT_ENV_PREFIXES
        ):
            env[key] = value
    return env


def _bounded_summary(text: str, *, max_chars: int = _CODING_AGENT_SUMMARY_MAX_CHARS) -> str:
    normalized = text.strip()
    if len(normalized) <= max_chars:
        return normalized
    if max_chars <= 16:
        return normalized[:max_chars]
    return f"{normalized[: max_chars - 15].rstrip()}... [truncated]"


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


def _extract_config_ids(config_options: list[SessionConfigOption] | None) -> set[str]:
    ids: set[str] = set()
    for option in config_options or []:
        option_id = str(getattr(option, "id", "")).strip()
        if option_id:
            ids.add(option_id)
    return ids


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
    ) -> CodingAgentRunOutput:
        start = time.monotonic()
        recorder = _AcpRecordingClient()
        env = _coding_agent_environment()
        session_id = ""
        selected_mode: str | None = None
        applied_config: dict[str, str] = {}
        conn: Any | None = None
        process: Any | None = None

        async def _run_session() -> CodingAgentRunOutput:
            nonlocal applied_config, conn, process, selected_mode, session_id
            async with spawn_agent_process(
                recorder,
                *self._spec.command,
                env=env,
                cwd=str(workdir),
                transport_kwargs={"limit": DEFAULT_STDIO_BUFFER_LIMIT_BYTES},
            ) as (inner_conn, inner_process):
                conn = inner_conn
                process = inner_process
                await conn.initialize(
                    PROTOCOL_VERSION,
                    client_info=Implementation(name="shisad", version="0.4.0"),
                )
                new_session = await conn.new_session(cwd=str(workdir))
                session_id = str(new_session.session_id)

                available_modes = _extract_mode_ids(getattr(new_session, "modes", None))
                current_mode = str(
                    getattr(getattr(new_session, "modes", None), "current_mode_id", "")
                ).strip() or None
                selected_mode = await self._apply_mode(
                    conn=conn,
                    session_id=session_id,
                    current_mode=current_mode,
                    available_modes=available_modes,
                    config=config,
                )

                available_config = _extract_config_ids(getattr(new_session, "config_options", None))
                applied_config = await self._apply_config(
                    conn=conn,
                    session_id=session_id,
                    available_config=available_config,
                    selected_mode=selected_mode,
                    config=config,
                )

                prompt_response = await conn.prompt(
                    [text_block(prompt_text)],
                    session_id=session_id,
                )
                await asyncio.sleep(0)
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

        try:
            if config.timeout_sec is not None:
                async with asyncio.timeout(config.timeout_sec):
                    return await _run_session()
            return await _run_session()
        except TimeoutError:
            with suppress(Exception):
                if conn is not None and session_id:
                    await conn.cancel(session_id=session_id)
            with suppress(ProcessLookupError):
                if process is not None:
                    process.kill()
            with suppress(Exception):
                if process is not None:
                    await process.wait()
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
            return CodingAgentRunOutput(
                result=CodingAgentResult(
                    agent=self._spec.name,
                    task=prompt_text,
                    success=False,
                    summary=(
                        f"Coding agent '{self._spec.name}' failed during ACP negotiation: {exc}."
                    ),
                    duration_ms=duration_ms,
                ),
                error_code="protocol_error",
                session_id=session_id,
                selected_mode=selected_mode,
                applied_config=applied_config,
            )
        except Exception as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            detail = str(exc).strip()
            summary = f"Coding agent '{self._spec.name}' failed during ACP transport."
            if detail:
                summary = f"{summary} {detail}"
            return CodingAgentRunOutput(
                result=CodingAgentResult(
                    agent=self._spec.name,
                    task=prompt_text,
                    success=False,
                    summary=_bounded_summary(summary),
                    duration_ms=duration_ms,
                ),
                error_code="protocol_error",
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
    ) -> str | None:
        desired_modes = self._spec.read_only_modes if config.read_only else self._spec.write_modes
        for candidate in desired_modes:
            if candidate not in available_modes:
                continue
            if candidate == current_mode:
                return current_mode
            try:
                await conn.set_session_mode(candidate, session_id=session_id)
                return candidate
            except RequestError:
                continue
        return current_mode

    async def _apply_config(
        self,
        *,
        conn: Any,
        session_id: str,
        available_config: set[str],
        selected_mode: str | None,
        config: CodingAgentConfig,
    ) -> dict[str, str]:
        desired: dict[str, str] = {}
        if config.model:
            desired["model"] = config.model
        if config.reasoning_effort:
            desired["reasoning_effort"] = config.reasoning_effort
        if config.max_turns is not None:
            desired["max_turns"] = str(config.max_turns)
        if config.permission_mode:
            desired["permission_mode"] = config.permission_mode
        if "allowed_tools" in available_config or not available_config:
            if config.allowed_tools:
                desired["allowed_tools"] = ",".join(config.allowed_tools)
            elif config.read_only:
                desired["allowed_tools"] = "read-only"
        if selected_mode is None:
            desired_mode = "plan" if config.read_only else "build"
            desired["mode"] = desired_mode

        applied: dict[str, str] = {}
        for config_id, value in desired.items():
            try:
                await conn.set_config_option(config_id, session_id=session_id, value=value)
            except RequestError:
                continue
            applied[config_id] = value
        return applied
