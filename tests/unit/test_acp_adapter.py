from __future__ import annotations

import sys
from pathlib import Path

import pytest
from acp import RequestError

from shisad.coding.acp_adapter import AcpAdapter, _request_error_payload
from shisad.coding.models import CodingAgentConfig
from shisad.coding.registry import AgentCommandSpec


def _fake_agent_spec(agent_name: str, *extra_args: str) -> AgentCommandSpec:
    script = Path(__file__).resolve().parents[1] / "fixtures" / "fake_acp_agent.py"
    return AgentCommandSpec(
        name=agent_name,
        command=(sys.executable, str(script), "--agent-name", agent_name, *extra_args),
        read_only_modes=("plan", "read-only"),
        write_modes=("build", "auto"),
    )


@pytest.mark.asyncio
async def test_m3_acp_adapter_collects_summary_mode_cost_and_raw_updates(
    tmp_path: Path,
) -> None:
    adapter = AcpAdapter(spec=_fake_agent_spec("codex"))

    result = await adapter.run(
        prompt_text="TASK KIND: implement\nFILES:\n- README.md\nMULTI_CHUNK_SUMMARY\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="codex",
            read_only=False,
            model="fast-model",
            reasoning_effort="high",
            max_turns=8,
        ),
    )

    assert result.result.success is True
    assert result.result.agent == "codex"
    assert "mode=build" in result.result.summary
    assert "model=fast-model" in result.result.summary
    assert result.result.files_changed == ("README.md",)
    assert result.result.cost == pytest.approx(0.42)
    assert result.selected_mode == "build"
    assert result.applied_config["model"] == "fast-model"
    assert result.applied_config["reasoning_effort"] == "high"
    assert result.applied_config["max_turns"] == "8"
    assert result.applied_config["permission_mode"] == "approve-all"
    assert result.raw_updates
    assert result.stop_reason == "end_turn"


@pytest.mark.asyncio
async def test_m3_acp_adapter_emits_session_id_when_session_starts(
    tmp_path: Path,
) -> None:
    adapter = AcpAdapter(spec=_fake_agent_spec("codex"))
    seen_session_ids: list[str] = []

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="codex",
            read_only=True,
        ),
        on_session_started=seen_session_ids.append,
    )

    assert result.result.success is True
    assert seen_session_ids == [result.session_id]


@pytest.mark.asyncio
async def test_m3_acp_adapter_review_mode_uses_read_only_session_mode(
    tmp_path: Path,
) -> None:
    adapter = AcpAdapter(spec=_fake_agent_spec("claude"))

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\nOPPORTUNISTIC_EDIT\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="claude",
            read_only=True,
        ),
    )

    assert result.result.success is True
    assert result.selected_mode == "plan"
    assert "mode=plan" in result.result.summary


@pytest.mark.asyncio
async def test_m3_acp_adapter_keeps_existing_preferred_mode(tmp_path: Path) -> None:
    adapter = AcpAdapter(spec=_fake_agent_spec("codex", "--default-mode", "build"))

    result = await adapter.run(
        prompt_text="TASK KIND: implement\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="codex",
            read_only=False,
        ),
    )

    assert result.result.success is True
    assert result.selected_mode == "build"
    assert "mode=build" in result.result.summary


@pytest.mark.asyncio
async def test_m3_acp_adapter_timeout_maps_to_clean_failure(tmp_path: Path) -> None:
    adapter = AcpAdapter(spec=_fake_agent_spec("opencode"))

    result = await adapter.run(
        prompt_text="TASK KIND: implement\nSLEEP: 0.25\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="opencode",
            timeout_sec=0.05,
        ),
    )

    assert result.result.success is False
    assert result.error_code == "timeout"
    assert "timed out" in result.result.summary.lower()


@pytest.mark.asyncio
async def test_m3_acp_adapter_timeout_covers_initialize_handshake(tmp_path: Path) -> None:
    adapter = AcpAdapter(spec=_fake_agent_spec("claude", "--initialize-sleep", "0.25"))

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="claude",
            timeout_sec=0.05,
            read_only=True,
        ),
    )

    assert result.result.success is False
    assert result.error_code == "timeout"
    assert "timed out" in result.result.summary.lower()


@pytest.mark.asyncio
async def test_m3_acp_adapter_handles_large_single_line_updates(tmp_path: Path) -> None:
    adapter = AcpAdapter(
        spec=_fake_agent_spec(
            "codex",
            "--large-single-line-summary-bytes",
            "70000",
        )
    )

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="codex",
            read_only=True,
        ),
    )

    assert result.result.success is True
    assert result.error_code == ""
    assert result.result.summary.startswith("codex large-response mode=plan ")
    assert len(result.result.summary) <= 4000
    assert result.result.summary.endswith("[truncated]")


@pytest.mark.asyncio
async def test_m3_acp_adapter_preserves_agent_auth_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    adapter = AcpAdapter(spec=_fake_agent_spec("claude", "--require-env", "ANTHROPIC_API_KEY"))

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="claude",
            read_only=True,
        ),
    )

    assert result.result.success is True
    assert result.error_code == ""
    assert "mode=plan" in result.result.summary


@pytest.mark.asyncio
async def test_m3_acp_adapter_initialize_failure_maps_to_protocol_error(
    tmp_path: Path,
) -> None:
    adapter = AcpAdapter(spec=_fake_agent_spec("claude", "--fail-initialize"))

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="claude",
            read_only=True,
        ),
    )

    assert result.result.success is False
    assert result.error_code == "protocol_error"
    assert "failed during acp negotiation" in result.result.summary.lower()
    assert "invalid request" in result.result.summary.lower()


@pytest.mark.asyncio
async def test_m9_acp_adapter_preserves_request_error_transport_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_env = "SHISAD_TEST_MISSING_ACP_AUTH"
    monkeypatch.delenv(missing_env, raising=False)
    adapter = AcpAdapter(spec=_fake_agent_spec("claude", "--require-env", missing_env))

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="claude",
            read_only=True,
        ),
    )

    assert result.result.success is False
    assert result.error_code == "protocol_error"
    assert result.transport_error == {
        "kind": "request_error",
        "code": -32000,
        "message": "Authentication required",
        "data": {"missing_env": [missing_env]},
    }
    assert "code -32000" in result.result.summary
    assert "Authentication required" in result.result.summary


def test_m9_acp_adapter_redacts_transport_error_secrets() -> None:
    payload = _request_error_payload(
        RequestError(
            -32000,
            (
                "Authentication failed: api_key=sk-test-secret "
                "Invalid API key: sk-space-secret Auth token: auth-space-secret "
                "Access token: access-space-secret OpenAI API key: sk-openai-space-secret "
                "API token: api-token-space-secret "
                "Authorization: Bearer token-value OPENAI_API_KEY=sk-env-secret"
            ),
            {
                "api_key": "sk-test-secret",
                "x-api-key": "header-secret",
                "API key": "sk-mapping-space-secret",
                "auth token": "auth-mapping-space-secret",
                "cookie": "session=secret",
                "nested": {"authorization": "Bearer token-value"},
                "detail": "Authorization: Basic dXNlcjpwYXNz",
                "space_detail": "API key: sk-detail-space-secret",
                "space_list_detail": "API keys: sk-list-a, sk-list-b",
                "detail_auth_list": "Auth token: tok-a tok-b",
                "human_detail": "Access token: access-detail-secret",
                "space_token_list": "Auth token: tok-a tok-b",
                "body": "api_key=sk-body-secret",
                "headers": "Cookie: sid=secret; csrf=secret2",
                "json": (
                    '{"api_key":"sk-json","API key":"sk-json-space",'
                    '"Authorization":"Bearer json-token"}'
                ),
                "json_plural": (
                    '{"API keys":["sk-json-a","sk-json-b"],'
                    '"Auth tokens":["tok-json-a","tok-json-b"],"safe":"ok"}'
                ),
                "json_human": (
                    '{"OpenAI API key":"sk-openai-json",'
                    '"API token":"api-token-json",'
                    '"access token":["tok-human-a","tok-human-b"],"safe":"ok"}'
                ),
                "json_escaped": '{"api_key":"sk-part1\\"part2","safe":"ok"}',
                "json_list": '{"api_key":["sk-a","sk-b"],"safe":"ok"}',
                "pythonish": "{'authorization': 'Bearer py-token'}",
                "pythonish_list": "{'authorization': ['Bearer py-a', 'Bearer py-b'], 'safe': 'ok'}",
                "env_detail": "OPENAI_API_KEY=sk-env ANTHROPIC_AUTH_TOKEN=auth-token",
                "header_pairs": [["Authorization", "Bearer pair-token"], ["safe", "ok"]],
                "env_pairs": [["OPENAI_API_KEY", "sk-pair-secret"]],
                "missing_env": ["OPENAI_API_KEY"],
            },
        )
    )

    assert payload["message"] == (
        "Authentication failed: api_key=[redacted] Invalid API key: [redacted] "
        "Auth token: [redacted] Access token: [redacted] OpenAI API key: "
        "[redacted] API token: [redacted] Authorization: [redacted]"
    )
    assert payload["data"] == {
        "api_key": "[redacted]",
        "x-api-key": "[redacted]",
        "API key": "[redacted]",
        "auth token": "[redacted]",
        "cookie": "[redacted]",
        "nested": {"authorization": "[redacted]"},
        "detail": "Authorization: [redacted]",
        "space_detail": "API key: [redacted]",
        "space_list_detail": "API keys: [redacted]",
        "detail_auth_list": "Auth token: [redacted]",
        "human_detail": "Access token: [redacted]",
        "space_token_list": "[redacted]",
        "body": "api_key=[redacted]",
        "headers": "Cookie: [redacted]",
        "json": (
            '{"api_key":"[redacted]","API key":"[redacted]",'
            '"Authorization":"[redacted]"}'
        ),
        "json_plural": (
            '{"API keys":"[redacted]",'
            '"Auth tokens":"[redacted]","safe":"ok"}'
        ),
        "json_human": (
            '{"OpenAI API key":"[redacted]",'
            '"API token":"[redacted]",'
            '"access token":"[redacted]","safe":"ok"}'
        ),
        "json_escaped": '{"api_key":"[redacted]","safe":"ok"}',
        "json_list": '{"api_key":"[redacted]","safe":"ok"}',
        "pythonish": "{'authorization': '[redacted]'}",
        "pythonish_list": "{'authorization': '[redacted]', 'safe': 'ok'}",
        "env_detail": "OPENAI_API_KEY=[redacted] ANTHROPIC_AUTH_TOKEN=[redacted]",
        "header_pairs": [["Authorization", "[redacted]"], ["safe", "ok"]],
        "env_pairs": [["OPENAI_API_KEY", "[redacted]"]],
        "missing_env": ["OPENAI_API_KEY"],
    }
    assert "part2" not in repr(payload)
    assert "sk-b" not in repr(payload)
    assert "Bearer py-b" not in repr(payload)
    assert "Bearer pair-token" not in repr(payload)
    assert "sk-pair-secret" not in repr(payload)
    assert "sk-space-secret" not in repr(payload)
    assert "auth-space-secret" not in repr(payload)
    assert "sk-detail-space-secret" not in repr(payload)
    assert "sk-list-b" not in repr(payload)
    assert "tok-b" not in repr(payload)
    assert "sk-json-b" not in repr(payload)
    assert "tok-json-b" not in repr(payload)
    assert "access-space-secret" not in repr(payload)
    assert "sk-openai-space-secret" not in repr(payload)
    assert "api-token-space-secret" not in repr(payload)
    assert "access-detail-secret" not in repr(payload)
    assert "sk-openai-json" not in repr(payload)
    assert "api-token-json" not in repr(payload)
    assert "tok-human-b" not in repr(payload)


@pytest.mark.asyncio
async def test_m3_acp_adapter_spawn_failure_is_actionable_unavailable(tmp_path: Path) -> None:
    adapter = AcpAdapter(
        spec=AgentCommandSpec(
            name="codex",
            command=("definitely-missing-acp-adapter",),
        )
    )

    result = await adapter.run(
        prompt_text="TASK KIND: implement\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(preferred_agent="codex"),
    )

    assert result.result.success is False
    assert result.error_code == "agent_unavailable"
    assert "not available" in result.result.summary.lower()
