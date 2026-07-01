from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from acp import (
    PROTOCOL_VERSION,
    InitializeResponse,
    LoadSessionResponse,
    NewSessionResponse,
    PromptResponse,
    RequestError,
    SetSessionConfigOptionResponse,
    SetSessionModeResponse,
    default_environment,
    run_agent,
)
from acp.helpers import (
    start_tool_call,
    tool_diff_content,
    update_agent_message_text,
    update_current_mode,
    update_tool_call,
)
from acp.interfaces import Agent, Client
from acp.schema import (
    AgentCapabilities,
    Implementation,
    SessionConfigOptionSelect,
    SessionConfigSelectOption,
    SessionMode,
    SessionModeState,
)


def _extract_prompt_text(prompt: list[Any]) -> str:
    parts: list[str] = []
    for block in prompt:
        text = getattr(block, "text", None)
        if isinstance(text, str) and text:
            parts.append(text)
    return "\n".join(parts)


def _extract_file_refs(prompt_text: str) -> list[str]:
    refs: list[str] = []
    capture = False
    for raw_line in prompt_text.splitlines():
        line = raw_line.rstrip()
        if line == "FILES:":
            capture = True
            continue
        if capture and line.startswith("- "):
            candidate = line[2:].strip()
            if candidate:
                refs.append(candidate)
            continue
        if capture and line:
            break
    return refs


def _extract_sleep_seconds(prompt_text: str) -> float:
    marker = "SLEEP:"
    for line in prompt_text.splitlines():
        if not line.startswith(marker):
            continue
        raw = line.partition(marker)[2].strip()
        try:
            return max(0.0, float(raw))
        except ValueError:
            return 0.0
    return 0.0


class FakeAcpAgent(Agent):
    def __init__(
        self,
        *,
        agent_name: str,
        default_mode: str = "auto",
        read_only_modes: tuple[str, ...] = ("plan", "read-only"),
        initialize_sleep: float = 0.0,
        new_session_sleep: float = 0.0,
        fail_initialize: bool = False,
        large_single_line_summary_bytes: int = 0,
        required_env_keys: tuple[str, ...] = (),
        child_pid_file: str | None = None,
        child_sleep: float = 60.0,
        exit_on_set_session_mode: bool = False,
        exit_on_set_config_option: bool = False,
        exit_stderr: str = "",
        exit_code: int = 1,
        omit_config_options: bool = False,
    ) -> None:
        self._agent_name = agent_name
        self._default_mode = default_mode
        self._read_only_modes = set(read_only_modes)
        self._initialize_sleep = initialize_sleep
        self._new_session_sleep = new_session_sleep
        self._fail_initialize = fail_initialize
        self._large_single_line_summary_bytes = max(0, large_single_line_summary_bytes)
        self._required_env_keys = tuple(required_env_keys)
        self._child_pid_file = child_pid_file
        self._child_sleep = max(0.0, child_sleep)
        self._child_process: subprocess.Popen[bytes] | None = None
        self._exit_on_set_session_mode = exit_on_set_session_mode
        self._exit_on_set_config_option = exit_on_set_config_option
        self._exit_stderr = exit_stderr
        self._exit_code = exit_code
        self._omit_config_options = omit_config_options
        self._background_tasks: set[asyncio.Task[None]] = set()
        self._client: Client | None = None
        self._sessions: dict[str, dict[str, Any]] = {}

    def on_connect(self, conn: Client) -> None:
        self._client = conn

    async def initialize(
        self,
        protocol_version: int,
        client_capabilities: Any | None = None,
        client_info: Implementation | None = None,
        **kwargs: Any,
    ) -> InitializeResponse:
        _ = (client_capabilities, client_info, kwargs)
        self._spawn_child_if_configured()
        if self._initialize_sleep > 0:
            await asyncio.sleep(self._initialize_sleep)
        if self._fail_initialize:
            raise RequestError.invalid_request("configured initialize failure")
        missing_env = [key for key in self._required_env_keys if not os.getenv(key, "").strip()]
        if missing_env:
            raise RequestError.auth_required({"missing_env": missing_env})
        return InitializeResponse(
            protocol_version=min(protocol_version, PROTOCOL_VERSION),
            agent_info=Implementation(name=f"fake-{self._agent_name}", version="0.1.0"),
            agent_capabilities=AgentCapabilities(),
        )

    def _spawn_child_if_configured(self) -> None:
        if not self._child_pid_file or self._child_process is not None:
            return
        self._child_process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                f"import time; time.sleep({self._child_sleep!r})",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        Path(self._child_pid_file).write_text(
            str(self._child_process.pid),
            encoding="utf-8",
        )

    def _exit_process_if_configured(self, should_exit: bool) -> None:
        if not should_exit:
            return
        if self._exit_stderr:
            print(self._exit_stderr, file=sys.stderr)
            sys.stderr.flush()
        os._exit(self._exit_code)

    async def new_session(
        self,
        cwd: str,
        mcp_servers: list[Any] | None = None,
        **kwargs: Any,
    ) -> NewSessionResponse:
        _ = (mcp_servers, kwargs)
        if self._new_session_sleep > 0:
            await asyncio.sleep(self._new_session_sleep)
        session_id = f"{self._agent_name}-{uuid.uuid4().hex}"
        config = {
            "mode": self._default_mode,
            "model": "fake-model",
            "reasoning_effort": "medium",
            "max_turns": "4",
            "allowed_tools": "all",
            "permission_mode": "approve-all",
        }
        self._sessions[session_id] = {
            "cwd": cwd,
            "config": config,
        }
        return NewSessionResponse(
            session_id=session_id,
            modes=SessionModeState(
                current_mode_id=self._default_mode,
                available_modes=[
                    SessionMode(id="auto", name="Auto"),
                    SessionMode(id="build", name="Build"),
                    SessionMode(id="plan", name="Plan"),
                    SessionMode(id="read-only", name="Read Only"),
                ],
            ),
            config_options=[] if self._omit_config_options else self._config_options(config),
        )

    async def load_session(
        self,
        cwd: str,
        session_id: str,
        mcp_servers: list[Any] | None = None,
        **kwargs: Any,
    ) -> LoadSessionResponse | None:
        _ = (cwd, mcp_servers, kwargs)
        state = self._sessions.get(session_id)
        if state is None:
            return None
        config = dict(state["config"])
        return LoadSessionResponse(
            modes=SessionModeState(
                current_mode_id=str(config["mode"]),
                available_modes=[
                    SessionMode(id="auto", name="Auto"),
                    SessionMode(id="build", name="Build"),
                    SessionMode(id="plan", name="Plan"),
                    SessionMode(id="read-only", name="Read Only"),
                ],
            ),
            config_options=[] if self._omit_config_options else self._config_options(config),
        )

    async def list_sessions(
        self,
        cursor: str | None = None,
        cwd: str | None = None,
        **kwargs: Any,
    ) -> Any:
        _ = (cursor, cwd, kwargs)
        raise NotImplementedError

    async def set_session_mode(
        self,
        mode_id: str,
        session_id: str,
        **kwargs: Any,
    ) -> SetSessionModeResponse | None:
        _ = kwargs
        self._exit_process_if_configured(self._exit_on_set_session_mode)
        state = self._sessions[session_id]
        state["config"]["mode"] = mode_id
        if self._client is not None:
            await self._client.session_update(
                session_id=session_id,
                update=update_current_mode(mode_id),
            )
        return SetSessionModeResponse()

    async def set_session_model(
        self,
        model_id: str,
        session_id: str,
        **kwargs: Any,
    ) -> Any:
        _ = kwargs
        state = self._sessions[session_id]
        state["config"]["model"] = model_id
        return None

    async def set_config_option(
        self,
        config_id: str,
        session_id: str,
        value: str,
        **kwargs: Any,
    ) -> SetSessionConfigOptionResponse | None:
        _ = kwargs
        self._exit_process_if_configured(self._exit_on_set_config_option)
        state = self._sessions[session_id]
        state["config"][config_id] = value
        return SetSessionConfigOptionResponse(config_options=self._config_options(state["config"]))

    async def authenticate(self, method_id: str, **kwargs: Any) -> Any:
        _ = (method_id, kwargs)
        return None

    async def prompt(
        self,
        prompt: list[Any],
        session_id: str,
        **kwargs: Any,
    ) -> PromptResponse:
        _ = kwargs
        state = self._sessions[session_id]
        prompt_text = _extract_prompt_text(prompt)
        sleep_seconds = _extract_sleep_seconds(prompt_text)
        if sleep_seconds > 0:
            await asyncio.sleep(sleep_seconds)

        workdir = Path(str(state["cwd"]))
        config = dict(state["config"])
        mode = str(config.get("mode", self._default_mode))
        read_only = mode in self._read_only_modes
        opportunistic_edit = "OPPORTUNISTIC_EDIT" in prompt_text
        file_refs = _extract_file_refs(prompt_text)
        target_file = workdir / (file_refs[0] if file_refs else "README.md")
        target_file.parent.mkdir(parents=True, exist_ok=True)

        do_edit = not read_only or opportunistic_edit
        old_text = target_file.read_text(encoding="utf-8") if target_file.exists() else ""
        new_text = old_text
        if do_edit:
            patch_line = (
                f"\nFake ACP edit from {self._agent_name} mode={mode} "
                f"reasoning={config.get('reasoning_effort', '')}\n"
            )
            new_text = f"{old_text}{patch_line}"
            target_file.write_text(new_text, encoding="utf-8")

        if self._client is not None:
            summary = (
                f"{self._agent_name} completed mode={mode} "
                f"model={config.get('model', '')} "
                f"permission_mode={config.get('permission_mode', '')}"
            )
            if "POST_RETURN_SUMMARY" in prompt_text:
                await self._client.session_update(
                    session_id=session_id,
                    update=update_agent_message_text("Task"),
                )

                async def _send_late_summary() -> None:
                    await asyncio.sleep(0.05)
                    if self._client is not None:
                        await self._client.session_update(
                            session_id=session_id,
                            update=update_agent_message_text(" ACP_CANARY_OK"),
                        )

                task = asyncio.create_task(_send_late_summary())
                self._background_tasks.add(task)
                task.add_done_callback(self._background_tasks.discard)
            elif self._large_single_line_summary_bytes > 0:
                payload = f"{self._agent_name} large-response mode={mode} " + (
                    "x" * self._large_single_line_summary_bytes
                )
                await self._client.session_update(
                    session_id=session_id,
                    update=update_agent_message_text(payload),
                )
            elif "MULTI_CHUNK_SUMMARY" in prompt_text:
                await self._client.session_update(
                    session_id=session_id,
                    update=update_agent_message_text(f"{self._agent_name} completed mode={mode} "),
                )
                await self._client.session_update(
                    session_id=session_id,
                    update=update_agent_message_text(
                        f"model={config.get('model', '')} "
                        f"permission_mode={config.get('permission_mode', '')}"
                    ),
                )
            else:
                await self._client.session_update(
                    session_id=session_id,
                    update=update_agent_message_text(summary),
                )
            if do_edit:
                tool_call_id = f"edit-{uuid.uuid4().hex}"
                await self._client.session_update(
                    session_id=session_id,
                    update=start_tool_call(
                        tool_call_id=tool_call_id,
                        title=f"Edit {target_file.name}",
                        kind="edit",
                        status="in_progress",
                    ),
                )
                await self._client.session_update(
                    session_id=session_id,
                    update=update_tool_call(
                        tool_call_id=tool_call_id,
                        status="completed",
                        content=[
                            tool_diff_content(
                                path=str(target_file.relative_to(workdir)),
                                old_text=old_text or None,
                                new_text=new_text,
                            )
                        ],
                    ),
                )
        return PromptResponse(
            stop_reason="end_turn",
            field_meta={"cost": {"amount": 0.42, "currency": "USD"}},
        )

    async def fork_session(
        self,
        cwd: str,
        session_id: str,
        mcp_servers: list[Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        _ = (cwd, session_id, mcp_servers, kwargs)
        raise NotImplementedError

    async def resume_session(
        self,
        cwd: str,
        session_id: str,
        mcp_servers: list[Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        _ = (cwd, session_id, mcp_servers, kwargs)
        raise NotImplementedError

    async def cancel(self, session_id: str, **kwargs: Any) -> None:
        _ = (session_id, kwargs)

    async def ext_method(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        _ = (method, params)
        return {}

    async def ext_notification(self, method: str, params: dict[str, Any]) -> None:
        _ = (method, params)

    @staticmethod
    def _config_options(config: dict[str, str]) -> list[SessionConfigOptionSelect]:
        return [
            SessionConfigOptionSelect(
                id="mode",
                name="Mode",
                type="select",
                current_value=str(config["mode"]),
                options=[
                    SessionConfigSelectOption(name="Auto", value="auto"),
                    SessionConfigSelectOption(name="Build", value="build"),
                    SessionConfigSelectOption(name="Plan", value="plan"),
                    SessionConfigSelectOption(name="Read Only", value="read-only"),
                ],
            ),
            SessionConfigOptionSelect(
                id="model",
                name="Model",
                type="select",
                current_value=str(config["model"]),
                options=[
                    SessionConfigSelectOption(name="Fake Model", value="fake-model"),
                    SessionConfigSelectOption(name="Fast Model", value="fast-model"),
                ],
            ),
            SessionConfigOptionSelect(
                id="reasoning_effort",
                name="Reasoning Effort",
                type="select",
                current_value=str(config["reasoning_effort"]),
                options=[
                    SessionConfigSelectOption(name="Low", value="low"),
                    SessionConfigSelectOption(name="Medium", value="medium"),
                    SessionConfigSelectOption(name="High", value="high"),
                ],
            ),
            SessionConfigOptionSelect(
                id="max_turns",
                name="Max Turns",
                type="select",
                current_value=str(config["max_turns"]),
                options=[
                    SessionConfigSelectOption(name="2", value="2"),
                    SessionConfigSelectOption(name="4", value="4"),
                    SessionConfigSelectOption(name="8", value="8"),
                ],
            ),
            SessionConfigOptionSelect(
                id="allowed_tools",
                name="Allowed Tools",
                type="select",
                current_value=str(config["allowed_tools"]),
                options=[
                    SessionConfigSelectOption(name="All", value="all"),
                    SessionConfigSelectOption(name="Read Only", value="read-only"),
                ],
            ),
            SessionConfigOptionSelect(
                id="permission_mode",
                name="Permission Mode",
                type="select",
                current_value=str(config["permission_mode"]),
                options=[
                    SessionConfigSelectOption(name="Approve All", value="approve-all"),
                    SessionConfigSelectOption(name="Deny All", value="deny-all"),
                ],
            ),
        ]


async def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-name", default="codex")
    parser.add_argument("--default-mode", default="auto")
    parser.add_argument("--initialize-sleep", type=float, default=0.0)
    parser.add_argument("--new-session-sleep", type=float, default=0.0)
    parser.add_argument("--fail-initialize", action="store_true")
    parser.add_argument("--exit-before-initialize", action="store_true")
    parser.add_argument("--exit-code", type=int, default=1)
    parser.add_argument("--stderr", default="")
    parser.add_argument("--large-single-line-summary-bytes", type=int, default=0)
    parser.add_argument("--require-env", action="append", default=[])
    parser.add_argument("--child-pid-file")
    parser.add_argument("--child-sleep", type=float, default=60.0)
    parser.add_argument("--exit-on-set-session-mode", action="store_true")
    parser.add_argument("--exit-on-set-config-option", action="store_true")
    parser.add_argument("--omit-config-options", action="store_true")
    args = parser.parse_args()
    _ = default_environment()
    if args.exit_before_initialize:
        if args.stderr:
            print(args.stderr, file=sys.stderr)
        raise SystemExit(args.exit_code)
    await run_agent(
        FakeAcpAgent(
            agent_name=args.agent_name,
            default_mode=args.default_mode,
            initialize_sleep=args.initialize_sleep,
            new_session_sleep=args.new_session_sleep,
            fail_initialize=args.fail_initialize,
            large_single_line_summary_bytes=args.large_single_line_summary_bytes,
            required_env_keys=tuple(str(item) for item in args.require_env),
            child_pid_file=args.child_pid_file,
            child_sleep=args.child_sleep,
            exit_on_set_session_mode=args.exit_on_set_session_mode,
            exit_on_set_config_option=args.exit_on_set_config_option,
            exit_stderr=args.stderr,
            exit_code=args.exit_code,
            omit_config_options=args.omit_config_options,
        )
    )


if __name__ == "__main__":
    asyncio.run(_main())
