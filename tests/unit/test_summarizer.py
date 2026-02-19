"""Coverage for conversation summarizer extraction paths."""

from __future__ import annotations

from typing import Any

import pytest

from shisad.core.providers.base import EmbeddingResponse, Message, ProviderResponse
from shisad.core.transcript import TranscriptEntry
from shisad.core.types import TaintLabel
from shisad.memory.summarizer import ConversationSummarizer


def _entry(role: str, content: str, *, taints: list[TaintLabel] | None = None) -> TranscriptEntry:
    return TranscriptEntry(
        role=role,
        content_hash=f"{role}-{abs(hash(content))}",
        taint_labels=taints or [],
        content_preview=content,
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
    assert any(item[0] == "preference" for item in serialized)


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
