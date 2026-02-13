"""Unit tests for the training-ready trace recorder."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from pydantic import ValidationError

from shisad.core.trace import TraceMessage, TraceRecorder, TraceToolCall, TraceTurn


@pytest.fixture()
def traces_dir(tmp_path: Path) -> Path:
    d = tmp_path / "traces"
    d.mkdir()
    return d


@pytest.fixture()
def recorder(traces_dir: Path) -> TraceRecorder:
    return TraceRecorder(traces_dir)


def _make_turn(
    session_id: str = "sess-1",
    user_content: str = "hello",
    llm_response: str = "world",
    assistant_response: str = "done",
) -> TraceTurn:
    return TraceTurn(
        session_id=session_id,
        user_content=user_content,
        messages_sent=[
            TraceMessage(role="system", content="sys prompt"),
            TraceMessage(role="user", content=user_content),
        ],
        llm_response=llm_response,
        usage={"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        finish_reason="stop",
        tool_calls=[
            TraceToolCall(
                tool_name="echo",
                arguments={"text": "hi"},
                pep_decision="allow",
                monitor_decision="allow",
                control_plane_decision="allow",
                final_decision="allow",
                executed=True,
                execution_success=True,
            ),
        ],
        assistant_response=assistant_response,
        model_id="test-model",
        risk_score=0.1,
        trust_level="trusted",
        taint_labels=["user_input"],
        duration_ms=42.5,
    )


class TestTraceRecorderRoundtrip:
    def test_record_and_read(self, recorder: TraceRecorder) -> None:
        turn = _make_turn()
        recorder.record(turn)
        turns = recorder.read_turns("sess-1")
        assert len(turns) == 1
        assert turns[0].session_id == "sess-1"
        assert turns[0].user_content == "hello"
        assert turns[0].usage == {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        assert turns[0].finish_reason == "stop"
        assert len(turns[0].tool_calls) == 1
        assert turns[0].tool_calls[0].tool_name == "echo"
        assert turns[0].tool_calls[0].executed is True
        assert turns[0].model_id == "test-model"

    def test_multi_turn_append(self, recorder: TraceRecorder) -> None:
        recorder.record(_make_turn(user_content="first"))
        recorder.record(_make_turn(user_content="second"))
        turns = recorder.read_turns("sess-1")
        assert len(turns) == 2
        assert turns[0].user_content == "first"
        assert turns[1].user_content == "second"

    def test_per_session_isolation(self, recorder: TraceRecorder) -> None:
        recorder.record(_make_turn(session_id="a"))
        recorder.record(_make_turn(session_id="b"))
        assert len(recorder.read_turns("a")) == 1
        assert len(recorder.read_turns("b")) == 1
        assert len(recorder.read_turns("c")) == 0

    def test_read_empty_session(self, recorder: TraceRecorder) -> None:
        assert recorder.read_turns("nonexistent") == []


class TestTraceSecretRedaction:
    def test_openai_key_redacted(self, recorder: TraceRecorder) -> None:
        turn = _make_turn(user_content="key is sk-abc1234567890abcdef")
        recorder.record(turn)
        turns = recorder.read_turns("sess-1")
        assert "sk-abc1234567890abcdef" not in turns[0].user_content
        assert "[REDACTED:openai_key]" in turns[0].user_content

    def test_github_token_redacted(self, recorder: TraceRecorder) -> None:
        turn = _make_turn(llm_response="token ghp_abcdefghijklmnopqrst1234")
        recorder.record(turn)
        turns = recorder.read_turns("sess-1")
        assert "ghp_" not in turns[0].llm_response
        assert "[REDACTED:github_token]" in turns[0].llm_response

    def test_aws_key_redacted(self, recorder: TraceRecorder) -> None:
        turn = _make_turn(assistant_response="AKIAIOSFODNN7EXAMPLE")
        recorder.record(turn)
        turns = recorder.read_turns("sess-1")
        assert "AKIAIOSFODNN7EXAMPLE" not in turns[0].assistant_response
        assert "[REDACTED:aws_access_key]" in turns[0].assistant_response

    def test_jwt_redacted(self, recorder: TraceRecorder) -> None:
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        turn = _make_turn(user_content=f"my jwt: {jwt}")
        recorder.record(turn)
        turns = recorder.read_turns("sess-1")
        assert jwt not in turns[0].user_content
        assert "[REDACTED:jwt]" in turns[0].user_content


class TestTracePIIRedaction:
    def test_ssn_redacted(self, recorder: TraceRecorder) -> None:
        turn = _make_turn(user_content="ssn 123-45-6789")
        recorder.record(turn)
        turns = recorder.read_turns("sess-1")
        assert "123-45-6789" not in turns[0].user_content
        assert "[REDACTED:ssn]" in turns[0].user_content

    def test_email_redacted(self, recorder: TraceRecorder) -> None:
        turn = _make_turn(llm_response="contact user@example.com")
        recorder.record(turn)
        turns = recorder.read_turns("sess-1")
        assert "user@example.com" not in turns[0].llm_response
        assert "[REDACTED:email]" in turns[0].llm_response

    def test_phone_redacted(self, recorder: TraceRecorder) -> None:
        turn = _make_turn(assistant_response="call 555-123-4567")
        recorder.record(turn)
        turns = recorder.read_turns("sess-1")
        assert "555-123-4567" not in turns[0].assistant_response
        assert "[REDACTED:phone]" in turns[0].assistant_response


class TestTraceMessageRedaction:
    def test_messages_sent_content_redacted(self, recorder: TraceRecorder) -> None:
        turn = TraceTurn(
            session_id="sess-1",
            user_content="clean",
            messages_sent=[
                TraceMessage(role="user", content="key sk-secret1234567890abc"),
            ],
            llm_response="ok",
            assistant_response="done",
        )
        recorder.record(turn)
        turns = recorder.read_turns("sess-1")
        msg = turns[0].messages_sent[0]
        assert "sk-secret1234567890abc" not in msg.content
        assert "[REDACTED:openai_key]" in msg.content

    def test_messages_sent_tool_calls_redacted(self, recorder: TraceRecorder) -> None:
        turn = TraceTurn(
            session_id="sess-1",
            user_content="clean",
            messages_sent=[
                TraceMessage(
                    role="assistant",
                    content="",
                    tool_calls=[{"function": {"arguments": "sk-toolcall_secret12345678"}}],
                ),
            ],
            llm_response="ok",
            assistant_response="done",
        )
        recorder.record(turn)
        turns = recorder.read_turns("sess-1")
        tc = turns[0].messages_sent[0].tool_calls[0]
        assert "sk-toolcall_secret12345678" not in json.dumps(tc)
        assert "[REDACTED:openai_key]" in json.dumps(tc)


class TestTraceToolCallArgumentsRedaction:
    def test_secret_in_arguments_redacted(self, recorder: TraceRecorder) -> None:
        turn = TraceTurn(
            session_id="sess-1",
            user_content="clean",
            llm_response="ok",
            assistant_response="done",
            tool_calls=[
                TraceToolCall(
                    tool_name="http_request",
                    arguments={
                        "url": "https://api.example.com",
                        "token": "sk-argkey_1234567890abc",
                    },
                    final_decision="allow",
                    executed=True,
                ),
            ],
        )
        recorder.record(turn)
        turns = recorder.read_turns("sess-1")
        args = turns[0].tool_calls[0].arguments
        assert "sk-argkey_1234567890abc" not in json.dumps(args)
        assert "[REDACTED:openai_key]" in json.dumps(args)

    def test_pii_in_arguments_redacted(self, recorder: TraceRecorder) -> None:
        turn = TraceTurn(
            session_id="sess-1",
            user_content="clean",
            llm_response="ok",
            assistant_response="done",
            tool_calls=[
                TraceToolCall(
                    tool_name="send_email",
                    arguments={"to": "victim@example.com", "body": "SSN: 123-45-6789"},
                    final_decision="reject",
                ),
            ],
        )
        recorder.record(turn)
        turns = recorder.read_turns("sess-1")
        args = turns[0].tool_calls[0].arguments
        assert "victim@example.com" not in json.dumps(args)
        assert "123-45-6789" not in json.dumps(args)
        assert "[REDACTED:email]" in json.dumps(args)
        assert "[REDACTED:ssn]" in json.dumps(args)

    def test_nested_arguments_redacted(self, recorder: TraceRecorder) -> None:
        turn = TraceTurn(
            session_id="sess-1",
            user_content="clean",
            llm_response="ok",
            assistant_response="done",
            tool_calls=[
                TraceToolCall(
                    tool_name="complex_tool",
                    arguments={
                        "config": {"api_key": "sk-nested_secret1234567890"},
                        "items": ["sk-list_secret_1234567890ab"],
                    },
                    final_decision="allow",
                    executed=True,
                ),
            ],
        )
        recorder.record(turn)
        turns = recorder.read_turns("sess-1")
        args = turns[0].tool_calls[0].arguments
        serialized = json.dumps(args)
        assert "sk-nested_secret1234567890" not in serialized
        assert "sk-list_secret_1234567890ab" not in serialized


class TestTraceFilePermissions:
    def test_file_created_with_restricted_permissions(
        self, recorder: TraceRecorder, traces_dir: Path
    ) -> None:
        recorder.record(_make_turn())
        trace_file = traces_dir / "sess-1.jsonl"
        assert trace_file.exists()
        mode = stat.S_IMODE(os.stat(trace_file).st_mode)
        assert mode == 0o600


class TestTraceSchemaRoundtrip:
    def test_json_roundtrip(self) -> None:
        turn = _make_turn()
        json_str = turn.model_dump_json()
        parsed = TraceTurn.model_validate_json(json_str)
        assert parsed.session_id == turn.session_id
        assert parsed.user_content == turn.user_content
        assert parsed.usage == turn.usage
        assert len(parsed.tool_calls) == 1
        assert parsed.tool_calls[0].tool_name == "echo"

    def test_dict_roundtrip(self) -> None:
        turn = _make_turn()
        d = turn.model_dump(mode="json")
        parsed = TraceTurn.model_validate(d)
        assert parsed.finish_reason == turn.finish_reason
        assert parsed.model_id == turn.model_id

    def test_frozen_models(self) -> None:
        msg = TraceMessage(role="user", content="hello")
        with pytest.raises(ValidationError):
            msg.content = "modified"  # type: ignore[misc]

        tc = TraceToolCall(tool_name="echo", executed=True)
        with pytest.raises(ValidationError):
            tc.executed = False  # type: ignore[misc]


class TestTraceToolCallDefaults:
    def test_defaults(self) -> None:
        tc = TraceToolCall(tool_name="test")
        assert tc.arguments == {}
        assert tc.pep_decision == ""
        assert tc.executed is False
        assert tc.execution_success is None


class TestTraceTurnDefaults:
    def test_defaults(self) -> None:
        turn = TraceTurn()
        assert turn.session_id == ""
        assert turn.messages_sent == []
        assert turn.tool_calls == []
        assert turn.risk_score == 0.0
        assert turn.duration_ms == 0.0
        assert turn.turn_id  # should be a non-empty uuid hex


class TestTraceRecorderCreatesDir:
    def test_creates_dir_if_missing(self, tmp_path: Path) -> None:
        new_dir = tmp_path / "deep" / "nested" / "traces"
        recorder = TraceRecorder(new_dir)
        recorder.record(_make_turn())
        assert (new_dir / "sess-1.jsonl").exists()
