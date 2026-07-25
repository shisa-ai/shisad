"""F13B removal and bounded structural-authority contract tests."""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from typing import Any

import pytest

import shisad.daemon.handlers._impl_session as impl_session
from shisad.core.action_state import CURRENT_TURN_REMINDER_CREATE_INTENT
from shisad.core.planner import ActionProposal
from shisad.core.types import SessionId, SessionMode, ToolName, UserId, WorkspaceId
from shisad.daemon.handlers._impl_session import SessionMessageValidationResult
from shisad.security.firewall import FirewallResult

_CURRENT_TURN_TOOL_CALL_SOURCE = "planner:current_turn_tool_call"
_STRUCTURED_SIMILAR_FILE_RECOVERY_SOURCE = "planner:structured_similar_file_recovery"
_REMOVED_ENGINE_SYMBOLS = (
    "_build_explicit_memory_intent_proposal",
    "_build_explicit_multi_intent_proposals",
    "_rewrite_explicit_memory_intent_planner_result",
    "_rewrite_explicit_filesystem_intent_planner_failure",
)
_REMOVED_LINGUISTIC_SOURCES = (
    "user_text:explicit_memory_intent",
    "user_text:explicit_file_intent",
    "user_text:explicit_reminder_intent",
    "user_text:explicit_similar_file_recovery_intent",
    "user_text:explicit_similar_file_read_intent",
)


def _validated_turn(
    text: str,
    *,
    trusted_input: bool = True,
    operator_owned_cli_input: bool = True,
) -> SessionMessageValidationResult:
    return SessionMessageValidationResult(
        sid=SessionId("sess-f13b"),
        params={"content": text},
        content=text,
        session=SimpleNamespace(channel="cli"),
        session_mode=SessionMode.DEFAULT,
        channel="cli",
        user_id=UserId("user-f13b"),
        workspace_id=WorkspaceId("workspace-f13b"),
        trust_level="trusted",
        trusted_input=trusted_input,
        firewall_result=FirewallResult(
            sanitized_text=text,
            original_hash="0" * 64,
        ),
        incoming_taint_labels=set(),
        is_internal_ingress=False,
        operator_owned_cli_input=operator_owned_cli_input,
    )


def _proposal(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    sources: list[str],
) -> ActionProposal:
    return ActionProposal(
        action_id=f"f13b-{tool_name}",
        tool_name=ToolName(tool_name),
        arguments=arguments,
        reasoning="Exercise the typed structural contract.",
        data_sources=sources,
    )


def test_f13b_compatibility_engine_and_linguistic_sources_are_absent() -> None:
    source = inspect.getsource(impl_session)

    assert all(not hasattr(impl_session, name) for name in _REMOVED_ENGINE_SYMBOLS)
    assert all(label not in source for label in _REMOVED_LINGUISTIC_SOURCES)


@pytest.mark.parametrize(
    ("tool_name", "arguments", "turn_text", "expected"),
    [
        (
            "note.create",
            {"content": "buy groceries"},
            "add a note: buy groceries",
            True,
        ),
        (
            "note.create",
            {"content": "buy groceries", "key": "groceries"},
            "add a groceries note: buy groceries",
            True,
        ),
        (
            "note.create",
            {"content": "buy groceries", "key": "private-label"},
            "add a note: buy groceries",
            False,
        ),
        (
            "todo.create",
            {
                "title": "review pull request",
                "details": "check security comments",
                "due_date": "Friday",
            },
            "add todo review pull request, check security comments by Friday",
            True,
        ),
        (
            "todo.create",
            {"title": "review pull request", "details": "invented detail"},
            "add todo: review pull request",
            False,
        ),
        (
            "todo.create",
            {"title": "review pull request", "due_date": "2099-01-01"},
            "add todo: review pull request",
            False,
        ),
    ],
    ids=(
        "note-required-only",
        "note-anchored-key",
        "note-unanchored-key",
        "todo-all-anchored",
        "todo-unanchored-details",
        "todo-unanchored-due-date",
    ),
)
def test_f13b_memory_authority_requires_all_supplied_stored_fields(
    tool_name: str,
    arguments: dict[str, Any],
    turn_text: str,
    expected: bool,
) -> None:
    proposal = _proposal(
        tool_name,
        arguments,
        sources=[_CURRENT_TURN_TOOL_CALL_SOURCE],
    )

    assert (
        impl_session._proposal_has_current_turn_memory_write_authority(
            proposal=proposal,
            validated=_validated_turn(turn_text),
        )
        is expected
    )


def test_f13b_legacy_memory_source_cannot_grant_authority() -> None:
    proposal = _proposal(
        "note.create",
        {"content": "invented content"},
        sources=["user_text:explicit_memory_intent"],
    )

    assert (
        impl_session._proposal_has_current_turn_memory_write_authority(
            proposal=proposal,
            validated=_validated_turn(
                "ordinary untrusted speech",
                trusted_input=False,
                operator_owned_cli_input=False,
            ),
        )
        is False
    )


def test_f13b_legacy_file_source_cannot_grant_authority() -> None:
    proposal = _proposal(
        "fs.read",
        {"path": "README.md"},
        sources=["user_text:explicit_file_intent"],
    )

    helper = impl_session._has_current_turn_local_filesystem_read_intent

    assert "proposal" not in inspect.signature(helper).parameters
    assert (
        helper(
            tool_name=proposal.tool_name,
            arguments=proposal.arguments,
            validated=_validated_turn("ordinary trusted speech"),
        )
        is False
    )


def test_f13b_legacy_reminder_source_cannot_grant_authority() -> None:
    proposal = _proposal(
        "reminder.create",
        {
            "message": "invented reminder",
            "when": "in 5 seconds",
            "reminder_intent": CURRENT_TURN_REMINDER_CREATE_INTENT,
        },
        sources=["user_text:explicit_reminder_intent"],
    )

    helper = impl_session._has_current_turn_reminder_create_intent

    assert "proposal" not in inspect.signature(helper).parameters
    assert (
        helper(
            tool_name=proposal.tool_name,
            arguments=proposal.arguments,
            validated=_validated_turn("ordinary trusted speech"),
        )
        is False
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (_STRUCTURED_SIMILAR_FILE_RECOVERY_SOURCE, True),
        ("user_text:explicit_similar_file_recovery_intent", False),
        ("user_text:explicit_similar_file_read_intent", False),
    ],
)
def test_f13b_similar_file_recovery_accepts_only_structural_source(
    source: str,
    expected: bool,
) -> None:
    proposal = _proposal(
        "fs.list",
        {"path": ".", "filesystem_intent": "current_turn_local_read"},
        sources=[source],
    )

    assert impl_session._proposal_has_similar_file_recovery(proposal) is expected


class _TranscriptStore:
    def __init__(self, entries: list[SimpleNamespace]) -> None:
        self._entries = entries

    def list_entries(self, _sid: SessionId) -> list[SimpleNamespace]:
        return list(self._entries)


def test_f13b_machine_failed_read_summary_retains_unredacted_path() -> None:
    store = _TranscriptStore(
        [
            SimpleNamespace(
                role="assistant",
                content_preview="- fs.read read README.md failed: path_not_found.",
            )
        ]
    )

    assert (
        impl_session._recent_failed_fs_read_path_from_transcript(
            store,  # type: ignore[arg-type]
            SessionId("sess-f13b"),
        )
        == "README.md"
    )


def test_f13b_redacted_failed_read_does_not_reconstruct_path_from_user_prose() -> None:
    store = _TranscriptStore(
        [
            SimpleNamespace(role="user", content_preview="read private-notes.txt"),
            SimpleNamespace(
                role="assistant",
                content_preview=(
                    "- fs.read read [REDACTED:workspace_path] failed: path_not_found."
                ),
            ),
        ]
    )

    assert (
        impl_session._recent_failed_fs_read_path_from_transcript(
            store,  # type: ignore[arg-type]
            SessionId("sess-f13b"),
        )
        == ""
    )


def test_f13b_redacted_failed_read_uses_matching_machine_action_state() -> None:
    store = _TranscriptStore(
        [
            SimpleNamespace(
                entry_id="turn-failed-read",
                role="user",
                content_preview="read content that must not be reparsed",
            ),
            SimpleNamespace(
                entry_id="turn-failed-summary",
                role="assistant",
                content_preview=(
                    "I tried to read [REDACTED:workspace_path], but it failed: path_not_found."
                ),
            ),
            SimpleNamespace(
                entry_id="turn-recovery",
                role="user",
                content_preview="unrelated conversational text",
            ),
        ]
    )
    failed_action = SimpleNamespace(
        session_id=SessionId("sess-f13b"),
        origin_turn_id="turn-failed-read",
        status="failed",
        tool_name=ToolName("fs.read"),
        arguments={"path": "README.md"},
    )

    assert (
        impl_session._recent_failed_fs_read_path_from_action_state(
            store,  # type: ignore[arg-type]
            SessionId("sess-f13b"),
            pending_actions={"failed-read": failed_action},
            current_turn_entry_id="turn-recovery",
        )
        == "README.md"
    )


@pytest.mark.parametrize(
    ("changed_field", "changed_value"),
    [
        ("session_id", SessionId("another-session")),
        ("origin_turn_id", "another-turn"),
        ("status", "succeeded"),
        ("tool_name", ToolName("fs.write")),
    ],
)
def test_f13b_failed_read_action_state_must_match_immediately_preceding_failure(
    changed_field: str,
    changed_value: Any,
) -> None:
    store = _TranscriptStore(
        [
            SimpleNamespace(
                entry_id="turn-failed-read",
                role="user",
                content_preview="do not parse this text",
            ),
            SimpleNamespace(
                entry_id="turn-failed-summary",
                role="assistant",
                content_preview="The action failed: path_not_found.",
            ),
            SimpleNamespace(
                entry_id="turn-recovery",
                role="user",
                content_preview="do not parse this text either",
            ),
        ]
    )
    action_fields = {
        "session_id": SessionId("sess-f13b"),
        "origin_turn_id": "turn-failed-read",
        "status": "failed",
        "tool_name": ToolName("fs.read"),
        "arguments": {"path": "README.md"},
    }
    action_fields[changed_field] = changed_value

    assert (
        impl_session._recent_failed_fs_read_path_from_action_state(
            store,  # type: ignore[arg-type]
            SessionId("sess-f13b"),
            pending_actions={"candidate": SimpleNamespace(**action_fields)},
            current_turn_entry_id="turn-recovery",
        )
        == ""
    )


def test_f13b_failed_read_action_state_rejects_ambiguous_matches() -> None:
    store = _TranscriptStore(
        [
            SimpleNamespace(
                entry_id="turn-failed-read",
                role="user",
                content_preview="do not parse this text",
            ),
            SimpleNamespace(
                entry_id="turn-failed-summary",
                role="assistant",
                content_preview="The action failed: path_not_found.",
            ),
            SimpleNamespace(
                entry_id="turn-recovery",
                role="user",
                content_preview="do not parse this text either",
            ),
        ]
    )
    failed_action = SimpleNamespace(
        session_id=SessionId("sess-f13b"),
        origin_turn_id="turn-failed-read",
        status="failed",
        tool_name=ToolName("fs.read"),
        arguments={"path": "README.md"},
    )

    assert (
        impl_session._recent_failed_fs_read_path_from_action_state(
            store,  # type: ignore[arg-type]
            SessionId("sess-f13b"),
            pending_actions={"first": failed_action, "second": failed_action},
            current_turn_entry_id="turn-recovery",
        )
        == ""
    )


@pytest.mark.parametrize(
    ("success", "entries", "expected", "absent"),
    [
        (True, [], "No file contents were read.", "reply with its filename"),
        (
            False,
            [{"name": "README.md", "path": "README.md"}],
            "Completed action result:",
            "This listing contains names only",
        ),
    ],
    ids=("empty-list", "failed-list"),
)
def test_f13b_fs_list_guidance_does_not_overclaim(
    success: bool,
    entries: list[dict[str, str]],
    expected: str,
    absent: str,
) -> None:
    response = impl_session._direct_tool_output_response_without_synthesis(
        [
            {
                "tool_name": "fs.list",
                "success": success,
                "payload": {
                    "ok": success,
                    "path": ".",
                    "entries": entries,
                    "count": len(entries),
                },
            }
        ]
    )

    assert expected in response
    assert absent not in response
