from __future__ import annotations

import asyncio
import os
import signal
import sys
from contextlib import suppress
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


async def _wait_for_pid_file(path: Path) -> int:
    for _ in range(100):
        if path.exists():
            return int(path.read_text(encoding="utf-8").strip())
        await asyncio.sleep(0.02)
    raise AssertionError(f"timed out waiting for child pid file {path}")


def _process_is_running(pid: int) -> bool:
    proc_stat = Path("/proc") / str(pid) / "stat"
    if proc_stat.exists():
        try:
            fields = proc_stat.read_text(encoding="utf-8").split()
        except OSError:
            return False
        if len(fields) > 2 and fields[2] == "Z":
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


async def _wait_until_process_exits(pid: int) -> bool:
    for _ in range(50):
        if not _process_is_running(pid):
            return True
        await asyncio.sleep(0.02)
    return False


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
async def test_m3_acp_adapter_timeout_cleans_up_descendant_processes(tmp_path: Path) -> None:
    child_pid_file = tmp_path / "child.pid"
    adapter = AcpAdapter(
        spec=_fake_agent_spec(
            "claude",
            "--initialize-sleep",
            "5.0",
            "--child-pid-file",
            str(child_pid_file),
            "--child-sleep",
            "60.0",
        )
    )

    run_task = asyncio.create_task(
        adapter.run(
            prompt_text="TASK KIND: review\nFILES:\n- README.md\n",
            workdir=tmp_path,
            config=CodingAgentConfig(
                preferred_agent="claude",
                timeout_sec=1.0,
                read_only=True,
            ),
        )
    )
    child_pid = await _wait_for_pid_file(child_pid_file)
    result = await run_task

    child_exited = await _wait_until_process_exits(child_pid)
    if not child_exited:
        with suppress(ProcessLookupError):
            os.kill(child_pid, signal.SIGKILL)

    assert result.result.success is False
    assert result.error_code == "timeout"
    assert child_exited


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
async def test_m3_acp_adapter_startup_exit_surfaces_stderr(tmp_path: Path) -> None:
    diagnostic = (
        "error loading config: /home/ubuntu/.codex/config.toml:4:16: "
        "unknown variant 'default', expected 'fast' or 'flex'"
    )
    adapter = AcpAdapter(
        spec=_fake_agent_spec(
            "codex",
            "--exit-before-initialize",
            "--stderr",
            diagnostic,
        )
    )

    result = await adapter.run(
        prompt_text="TASK KIND: review\nFILES:\n- README.md\n",
        workdir=tmp_path,
        config=CodingAgentConfig(
            preferred_agent="codex",
            timeout_sec=1.0,
            read_only=True,
        ),
    )

    assert result.result.success is False
    assert result.error_code == "protocol_error"
    assert result.transport_error == {
        "kind": "process_exit",
        "phase": "initialize",
        "returncode": 1,
        "stderr": diagnostic,
    }
    assert "exited during acp initialize" in result.result.summary.lower()
    assert "unknown variant 'default'" in result.result.summary


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
                "Authentication failed: tokenizer: gpt2 token_count: 8192 "
                'Escaped JSON: {\\"api_key\\":\\"sk-escaped-message\\",'
                '\\"AWS Secret Access Key\\":\\"aws-escaped-message\\",'
                '\\"tokenizer\\":\\"gpt2\\"} '
                'Escaped containers: {\\"api_key\\":[\\"sk-escaped-list-a\\",'
                '\\"sk-escaped-list-b\\"],\\"tokenizer\\":\\"gpt2\\"} '
                'Escaped quoted containers: {\\"api_key\\":[\\"sk-escaped-quote\\\\",tail\\"]} '
                'Escaped odd quoted containers: {\\"api_key\\":'
                '[\\"sk-escaped-odd-quote\\\\\\"tail\\"]} '
                'Escaped backslash containers: {\\"api_key\\":[\\"sk-escaped-backslash\\\\\\"]} '
                "api_key=sk-test-secret "
                "SECRET_KEY=secret-key-env-secret Secret Key: secret-key-space-secret "
                "serviceSecretKey=service-secret-key-camel "
                "accessToken=access-camel-secret apiCredential=api-credential-camel-secret "
                "AWS_SECRET_ACCESS_KEY=aws-secret-access-key "
                "Secret Access Key: aws-space-secret secretAccessKey=aws-camel-secret "
                "privateKey=private-camel-secret "
                "AWS Secret Access Key: aws-qualified-space-secret "
                "SSH Private Key: ssh-qualified-space-secret "
                "Invalid API key: sk-space-secret Auth token: auth-space-secret "
                "Access token: access-space-secret OpenAI API key: sk-openai-space-secret "
                "API token: api-token-space-secret "
                "API credential: api-credential-space-secret "
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
                    '"API credential":"api-credential-json",'
                    '"access token":["tok-human-a","tok-human-b"],"safe":"ok"}'
                ),
                "diagnostic": "tokenizer: gpt2 token_count: 8192",
                "tokenizer": "gpt2",
                "token_count": 8192,
                "model_token_limit": 128000,
                "json_diagnostic": '{"tokenizer":"gpt2","token_count":8192,"safe":"ok"}',
                "diagnostic_pairs": [["token_count", 8192], ["tokenizer", "gpt2"]],
                "apiKey": "sk-camel-key",
                "authToken": "auth-camel-token",
                "accessToken": "access-camel-token",
                "apiToken": "api-camel-token",
                "apiCredential": "api-camel-credential",
                "sessionToken": "session-camel-token",
                "clientSecret": "client-camel-secret",
                "json_camel": (
                    '{"accessToken":"access-json-camel",'
                    '"apiCredential":"api-credential-json-camel",'
                    '"clientSecret":"client-secret-json-camel","tokenizer":"gpt2"}'
                ),
                "camel_pairs": [["clientSecret", "client-pair-secret"]],
                "AWS_SECRET_ACCESS_KEY": "aws-structured-secret",
                "Secret Access Key": "aws-space-structured-secret",
                "secretAccessKey": "aws-camel-structured-secret",
                "privateKey": "private-camel-structured-secret",
                "SSH_PRIVATE_KEY": "ssh-private-structured-secret",
                "json_key_material": (
                    '{"AWS_SECRET_ACCESS_KEY":"aws-json-secret",'
                    '"secretAccessKey":"aws-json-camel-secret",'
                    '"privateKey":"private-json-secret","tokenizer":"gpt2"}'
                ),
                "key_material_pairs": [["AWS_SECRET_ACCESS_KEY", "aws-pair-secret"]],
                "AWS Secret Access Key": "aws-qualified-structured-secret",
                "SSH Private Key": "ssh-qualified-structured-secret",
                "Service Account Private Key": "service-private-structured-secret",
                "json_qualified_key_material": (
                    '{"AWS Secret Access Key":"aws-qualified-json-secret",'
                    '"SSH Private Key":"ssh-qualified-json-secret",'
                    '"Service Account Private Key":"service-private-json-secret",'
                    '"tokenizer":"gpt2"}'
                ),
                "qualified_key_material_pairs": [
                    ["Service Account Private Key", "service-private-pair-secret"]
                ],
                "json_escaped_delimiters": (
                    '{\\"api_key\\":\\"sk-escaped-json\\",'
                    '\\"AWS Secret Access Key\\":\\"aws-qualified-escaped-json\\",'
                    '\\"tokenizer\\":\\"gpt2\\"}'
                ),
                "json_escaped_key_payload": (
                    '{\\"secret_key\\":\\"secret-key-escaped-json\\",\\"tokenizer\\":\\"gpt2\\"}'
                ),
                "json_escaped_delimiter_list": (
                    '{\\"api_key\\":[\\"sk-escaped-list-a\\",'
                    '\\"sk-escaped-list-b\\"],\\"tokenizer\\":\\"gpt2\\"}'
                ),
                "json_escaped_delimiter_list_quote": (
                    '{\\"api_key\\":[\\"sk-escaped-quote\\\\",tail\\"],\\"tokenizer\\":\\"gpt2\\"}'
                ),
                "json_escaped_delimiter_list_odd_quote": (
                    '{\\"api_key\\":[\\"sk-escaped-odd-quote\\\\\\"tail\\"],'
                    '\\"tokenizer\\":\\"gpt2\\"}'
                ),
                "json_escaped_delimiter_list_backslash": (
                    '{\\"api_key\\":[\\"sk-escaped-backslash\\\\\\"],\\"tokenizer\\":\\"gpt2\\"}'
                ),
                "json_escaped_delimiter_object": (
                    '{\\"AWS Secret Access Key\\":{\\"value\\":\\"aws-escaped-object\\"},'
                    '\\"tokenizer\\":\\"gpt2\\"}'
                ),
                "json_escaped": '{"api_key":"sk-part1\\"part2","safe":"ok"}',
                "json_list": '{"api_key":["sk-a","sk-b"],"safe":"ok"}',
                "secret_key": "secret-key-structured-secret",
                "SECRET_KEY": "secret-key-uppercase-secret",
                "JWT_SECRET_KEY": "secret-key-jwt-secret",
                "Secret Key": "secret-key-space-structured-secret",
                "serviceSecretKey": "service-secret-key-structured-secret",
                "json_key_payload": (
                    '{"secret_key":"secret-key-json",'
                    '"Secret Key":"secret-key-space-json",'
                    '"JWT_SECRET_KEY":"secret-key-jwt-json","tokenizer":"gpt2"}'
                ),
                "secret_key_pairs": [["JWT_SECRET_KEY", "secret-key-pair-secret"]],
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
        "Authentication failed: tokenizer: gpt2 token_count: 8192 "
        'Escaped JSON: {\\"api_key\\":\\"[redacted]\\",'
        '\\"AWS Secret Access Key\\":\\"[redacted]\\",'
        '\\"tokenizer\\":\\"gpt2\\"} '
        'Escaped containers: {\\"api_key\\":\\"[redacted]\\",'
        '\\"tokenizer\\":\\"gpt2\\"} '
        'Escaped quoted containers: {\\"api_key\\":\\"[redacted]\\"} '
        'Escaped odd quoted containers: {\\"api_key\\":\\"[redacted]\\"} '
        'Escaped backslash containers: {\\"api_key\\":\\"[redacted]\\"} '
        "api_key=[redacted] SECRET_KEY=[redacted] Secret Key: [redacted] "
        "serviceSecretKey=[redacted] accessToken=[redacted] apiCredential=[redacted] "
        "AWS_SECRET_ACCESS_KEY=[redacted] Secret Access Key: [redacted] "
        "secretAccessKey=[redacted] privateKey=[redacted] "
        "AWS Secret Access Key: [redacted] SSH Private Key: [redacted] "
        "Invalid API key: [redacted] Auth token: [redacted] Access token: "
        "[redacted] OpenAI API key: [redacted] API token: [redacted] "
        "API credential: [redacted] Authorization: [redacted]"
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
        "space_token_list": "Auth token: [redacted]",
        "body": "api_key=[redacted]",
        "headers": "Cookie: [redacted]",
        "json": ('{"api_key":"[redacted]","API key":"[redacted]","Authorization":"[redacted]"}'),
        "json_plural": ('{"API keys":"[redacted]","Auth tokens":"[redacted]","safe":"ok"}'),
        "json_human": (
            '{"OpenAI API key":"[redacted]",'
            '"API token":"[redacted]",'
            '"API credential":"[redacted]",'
            '"access token":"[redacted]","safe":"ok"}'
        ),
        "diagnostic": "tokenizer: gpt2 token_count: 8192",
        "tokenizer": "gpt2",
        "token_count": 8192,
        "model_token_limit": 128000,
        "json_diagnostic": '{"tokenizer":"gpt2","token_count":8192,"safe":"ok"}',
        "diagnostic_pairs": [["token_count", 8192], ["tokenizer", "gpt2"]],
        "apiKey": "[redacted]",
        "authToken": "[redacted]",
        "accessToken": "[redacted]",
        "apiToken": "[redacted]",
        "apiCredential": "[redacted]",
        "sessionToken": "[redacted]",
        "clientSecret": "[redacted]",
        "json_camel": (
            '{"accessToken":"[redacted]",'
            '"apiCredential":"[redacted]",'
            '"clientSecret":"[redacted]","tokenizer":"gpt2"}'
        ),
        "camel_pairs": [["clientSecret", "[redacted]"]],
        "AWS_SECRET_ACCESS_KEY": "[redacted]",
        "Secret Access Key": "[redacted]",
        "secretAccessKey": "[redacted]",
        "privateKey": "[redacted]",
        "SSH_PRIVATE_KEY": "[redacted]",
        "json_key_material": (
            '{"AWS_SECRET_ACCESS_KEY":"[redacted]",'
            '"secretAccessKey":"[redacted]",'
            '"privateKey":"[redacted]","tokenizer":"gpt2"}'
        ),
        "key_material_pairs": [["AWS_SECRET_ACCESS_KEY", "[redacted]"]],
        "AWS Secret Access Key": "[redacted]",
        "SSH Private Key": "[redacted]",
        "Service Account Private Key": "[redacted]",
        "json_qualified_key_material": (
            '{"AWS Secret Access Key":"[redacted]",'
            '"SSH Private Key":"[redacted]",'
            '"Service Account Private Key":"[redacted]",'
            '"tokenizer":"gpt2"}'
        ),
        "qualified_key_material_pairs": [["Service Account Private Key", "[redacted]"]],
        "json_escaped_delimiters": (
            '{\\"api_key\\":\\"[redacted]\\",'
            '\\"AWS Secret Access Key\\":\\"[redacted]\\",'
            '\\"tokenizer\\":\\"gpt2\\"}'
        ),
        "json_escaped_key_payload": (
            '{\\"secret_key\\":\\"[redacted]\\",\\"tokenizer\\":\\"gpt2\\"}'
        ),
        "json_escaped_delimiter_list": (
            '{\\"api_key\\":\\"[redacted]\\",\\"tokenizer\\":\\"gpt2\\"}'
        ),
        "json_escaped_delimiter_list_quote": (
            '{\\"api_key\\":\\"[redacted]\\",\\"tokenizer\\":\\"gpt2\\"}'
        ),
        "json_escaped_delimiter_list_odd_quote": (
            '{\\"api_key\\":\\"[redacted]\\",\\"tokenizer\\":\\"gpt2\\"}'
        ),
        "json_escaped_delimiter_list_backslash": (
            '{\\"api_key\\":\\"[redacted]\\",\\"tokenizer\\":\\"gpt2\\"}'
        ),
        "json_escaped_delimiter_object": (
            '{\\"AWS Secret Access Key\\":\\"[redacted]\\",\\"tokenizer\\":\\"gpt2\\"}'
        ),
        "json_escaped": '{"api_key":"[redacted]","safe":"ok"}',
        "json_list": '{"api_key":"[redacted]","safe":"ok"}',
        "secret_key": "[redacted]",
        "SECRET_KEY": "[redacted]",
        "JWT_SECRET_KEY": "[redacted]",
        "Secret Key": "[redacted]",
        "serviceSecretKey": "[redacted]",
        "json_key_payload": (
            '{"secret_key":"[redacted]",'
            '"Secret Key":"[redacted]",'
            '"JWT_SECRET_KEY":"[redacted]","tokenizer":"gpt2"}'
        ),
        "secret_key_pairs": [["JWT_SECRET_KEY", "[redacted]"]],
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
    assert "api-credential-space-secret" not in repr(payload)
    assert "access-detail-secret" not in repr(payload)
    assert "sk-openai-json" not in repr(payload)
    assert "api-token-json" not in repr(payload)
    assert "api-credential-json" not in repr(payload)
    assert "tok-human-b" not in repr(payload)


def test_m9_acp_adapter_redacts_pathological_escaped_container_without_recursion() -> None:
    ambiguous_value = 'secret-piece\\\\\\"tail' * 1200
    payload = _request_error_payload(
        RequestError(
            -32000,
            (
                'Pathological escaped container: {\\"api_key\\":[\\"'
                f"{ambiguous_value}"
                '\\"],\\"safe_after\\":\\"ok\\"} done'
            ),
        )
    )

    assert payload["message"] == (
        'Pathological escaped container: {\\"api_key\\":\\"[redacted]\\",'
        '\\"safe_after\\":\\"ok\\"} done'
    )
    assert "secret-piece" not in repr(payload)


def test_m9_acp_adapter_redacts_escaped_container_after_branch_mismatch() -> None:
    payload = _request_error_payload(
        RequestError(
            -32000,
            (
                'Branch mismatch escaped container: {\\"api_key\\":'
                '[\\"secret-branch\\\\\\"]\\"},\\"tokenizer\\":\\"gpt2\\"}'
            ),
        )
    )

    assert payload["message"] == (
        'Branch mismatch escaped container: {\\"api_key\\":\\"[redacted]\\"\\"},'
        '\\"tokenizer\\":\\"gpt2\\"}'
    )
    assert "secret-branch" not in repr(payload)


def test_m9_acp_adapter_redacts_malformed_secret_containers_fail_closed() -> None:
    plain_payload = _request_error_payload(
        RequestError(
            -32000,
            ('Plain malformed: api_key=[\n"plain-secret"\nsafe diagnostic: tokenizer gpt2'),
        )
    )
    escaped_payload = _request_error_payload(
        RequestError(
            -32000,
            (
                'Escaped malformed: {\\"api_key\\":[\n'
                '\\"escaped-secret\\"\n'
                "safe diagnostic: tokenizer gpt2"
            ),
        )
    )

    assert plain_payload["message"] == "Plain malformed: api_key=[redacted]"
    assert escaped_payload["message"] == ('Escaped malformed: {\\"api_key\\":\\"[redacted]\\"')
    assert "plain-secret" not in repr(plain_payload)
    assert "escaped-secret" not in repr(escaped_payload)
    assert "safe diagnostic" not in repr(plain_payload)
    assert "safe diagnostic" not in repr(escaped_payload)


def test_m9_acp_adapter_redacts_multiline_key_material_assignments() -> None:
    for label in (
        "SSH Private Key",
        "privateKey",
        "SSHPrivateKey",
        "secretAccessKey",
        "AWSSecretAccessKey",
        "Secret Key",
        "secretKey",
        "JWT_SECRET_KEY",
    ):
        payload = _request_error_payload(
            RequestError(
                -32000,
                (
                    f"{label}:\n"
                    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                    "private-key-body\n"
                    "-----END OPENSSH PRIVATE KEY-----\n"
                    "safe diagnostic: tokenizer gpt2"
                ),
            )
        )

        assert payload["message"] == f"{label}:\n[redacted]"
        assert "private-key-body" not in repr(payload)
        assert "safe diagnostic" not in repr(payload)


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
