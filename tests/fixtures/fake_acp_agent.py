from __future__ import annotations

import argparse
import asyncio
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
    ) -> None:
        self._agent_name = agent_name
        self._default_mode = default_mode
        self._read_only_modes = set(read_only_modes)
        self._initialize_sleep = initialize_sleep
        self._new_session_sleep = new_session_sleep
        self._fail_initialize = fail_initialize
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
        if self._initialize_sleep > 0:
            await asyncio.sleep(self._initialize_sleep)
        if self._fail_initialize:
            raise RequestError.invalid_request("configured initialize failure")
        return InitializeResponse(
            protocol_version=min(protocol_version, PROTOCOL_VERSION),
            agent_info=Implementation(name=f"fake-{self._agent_name}", version="0.1.0"),
            agent_capabilities=AgentCapabilities(),
        )

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
            config_options=self._config_options(config),
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
            config_options=self._config_options(config),
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
            if "MULTI_CHUNK_SUMMARY" in prompt_text:
                await self._client.session_update(
                    session_id=session_id,
                    update=update_agent_message_text(
                        f"{self._agent_name} completed mode={mode} "
                    ),
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
    parser.add_argument("--initialize-sleep", type=float, default=0.0)
    parser.add_argument("--new-session-sleep", type=float, default=0.0)
    parser.add_argument("--fail-initialize", action="store_true")
    args = parser.parse_args()
    _ = default_environment()
    await run_agent(
        FakeAcpAgent(
            agent_name=args.agent_name,
            initialize_sleep=args.initialize_sleep,
            new_session_sleep=args.new_session_sleep,
            fail_initialize=args.fail_initialize,
        )
    )


if __name__ == "__main__":
    asyncio.run(_main())
