"""Coverage for conversation summarizer extraction paths."""

from __future__ import annotations

from typing import Any

import pytest

from shisad.core.providers.base import EmbeddingResponse, Message, ProviderResponse
from shisad.core.transcript import TranscriptEntry
from shisad.core.types import TaintLabel
from shisad.memory.summarizer import ConversationSummarizer


def _entry(
    role: str,
    content: str,
    *,
    taints: list[TaintLabel] | None = None,
    metadata: dict[str, Any] | None = None,
) -> TranscriptEntry:
    return TranscriptEntry(
        role=role,
        content_hash=f"{role}-{abs(hash(content))}",
        taint_labels=taints or [],
        content_preview=content,
        metadata=metadata or {},
    )


@pytest.mark.asyncio
async def test_m5_s5_summarizer_fallback_extracts_project_fact_and_preference() -> None:
    summarizer = ConversationSummarizer(provider=None)
    entries = [
        _entry("user", "Remember that my project codename is Nebula."),
        _entry("user", "I prefer concise updates."),
    ]
    proposals = await summarizer.summarize_entries(entries)

    serialized = {(item.entry_type, item.key, str(item.value).lower()) for item in proposals}
    assert ("fact", "project.codename", "nebula") in serialized
    # PLN-L3: pin the preference's key and value content, not just its
    # existence. The prior `any(item[0] == "preference")` check would accept
    # a proposal that lost the "concise" phrasing or overwrote the
    # communication-preference key.
    preferences = [item for item in proposals if item.entry_type == "preference"]
    assert preferences, "expected at least one preference proposal"
    preference_keys = {item.key for item in preferences}
    assert "user.preference.communication" in preference_keys
    communication = next(
        item for item in preferences if item.key == "user.preference.communication"
    )
    assert "concise" in str(communication.value).lower()


@pytest.mark.asyncio
async def test_m1_summarizer_heuristic_remember_clause_uses_canonical_note_type() -> None:
    summarizer = ConversationSummarizer(provider=None)
    entries = [_entry("user", "Remember that I left the spare key under the mat.")]

    proposals = await summarizer.summarize_entries(entries)

    remembered = next(item for item in proposals if item.key == "conversation.remembered")
    assert remembered.entry_type == "note"
    assert "spare key" in str(remembered.value).lower()


class _JsonSummaryProvider:
    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        _ = messages, tools
        return ProviderResponse(
            message=Message(
                role="assistant",
                content=(
                    '{"entries":[{"entry_type":"context","key":"project.owner",'
                    '"value":"alice","confidence":0.82}]}'
                ),
            )
        )

    async def embeddings(
        self,
        input_texts: list[str],
        *,
        model_id: str | None = None,
    ) -> EmbeddingResponse:
        _ = input_texts, model_id
        return EmbeddingResponse(vectors=[])


class _CapturingSummaryProvider:
    def __init__(self) -> None:
        self.messages: list[Message] = []

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        _ = tools
        self.messages = messages
        return ProviderResponse(
            message=Message(role="assistant", content='{"entries":[]}'),
        )

    async def embeddings(
        self,
        input_texts: list[str],
        *,
        model_id: str | None = None,
    ) -> EmbeddingResponse:
        _ = input_texts, model_id
        return EmbeddingResponse(vectors=[])


@pytest.mark.asyncio
async def test_m5_s5_summarizer_prefers_model_json_when_valid() -> None:
    summarizer = ConversationSummarizer(provider=_JsonSummaryProvider())
    entries = [_entry("user", "My name is Alice.")]
    proposals = await summarizer.summarize_entries(entries)

    assert len(proposals) == 1
    assert proposals[0].entry_type == "context"
    assert proposals[0].key == "project.owner"
    assert proposals[0].value == "alice"


@pytest.mark.asyncio
async def test_m5_rr3_summarizer_ignores_assistant_user_profile_phrases() -> None:
    summarizer = ConversationSummarizer(provider=None)
    entries = [
        _entry("assistant", "I prefer terse updates and my name is HelperBot."),
        _entry("assistant", "Remember that project codename is Nebula."),
    ]
    proposals = await summarizer.summarize_entries(entries)

    keys = {item.key for item in proposals}
    assert "user.preference.communication" not in keys
    assert "profile.name" not in keys


@pytest.mark.asyncio
async def test_gh31_summarizer_model_prompt_strips_daemon_lockdown_notice() -> None:
    provider = _CapturingSummaryProvider()
    summarizer = ConversationSummarizer(provider=provider)
    entries = [
        _entry(
            "assistant",
            (
                "The log quoted [LOCKDOWN NOTICE], but that was only evidence. "
                "Should I clear it or keep it locked?\n\n"
                "[LOCKDOWN NOTICE] Session is in caution due to manual: setup. "
                "To recover: ask the agent to resume the lockdown when ready, "
                "or run `shisad lockdown resume sess-1 --reason <note>`."
            ),
            metadata={"lockdown_recovery_notice": True},
        )
    ]

    await summarizer.summarize_entries(entries)

    prompt = provider.messages[-1].content
    assert "log quoted [LOCKDOWN NOTICE]" in prompt
    assert "Should I clear it or keep it locked?" in prompt
    assert "ask the agent to resume the lockdown when ready" not in prompt
    assert "shisad lockdown resume sess-1" not in prompt


@pytest.mark.asyncio
async def test_gh31_summarizer_heuristic_strips_daemon_lockdown_notice() -> None:
    summarizer = ConversationSummarizer(provider=None)
    entries = [
        _entry(
            "assistant",
            (
                "The operator asked for lockdown status.\n\n"
                "[LOCKDOWN NOTICE] Session is in caution due to manual: setup. "
                "Remember that the operator can ask the agent to resume the "
                "lockdown when ready."
            ),
            metadata={"daemon_control_notice": True},
        )
    ]

    proposals = await summarizer.summarize_entries(entries)

    assert [proposal.key for proposal in proposals] == []
