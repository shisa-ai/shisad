"""Assistant reply layout survives egress and transcript persistence."""

from typing import Any

import pytest

from shisad.core.providers.base import Message, ProviderResponse
from shisad.core.providers.local_planner import LocalPlannerProvider
from shisad.core.transcript import TranscriptStore
from shisad.core.types import SessionId
from tests.helpers.contract import ContractHarness, _create_session


@pytest.mark.asyncio
async def test_multiline_reply_is_delivered_and_stored(
    clean_harness: ContractHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = "Steps:\n\n1. Build\n2. Test\n\n```python\nif ready:\n    run()\n```"

    async def complete(
        self: LocalPlannerProvider,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        return ProviderResponse(
            message=Message(role="assistant", content=expected),
            model="behavioral-stub",
            finish_reason="stop",
            usage={},
            trusted_origin="local-fallback",
        )

    monkeypatch.setattr(LocalPlannerProvider, "complete", complete)
    sid = await _create_session(clean_harness.client)
    reply = await clean_harness.client.call(
        "session.message", {"session_id": sid, "content": "Show the steps and sample code"}
    )
    assert reply["response"] == expected
    store = TranscriptStore(clean_harness.config.data_dir / "sessions")
    entries = store.list_entries(SessionId(sid))
    assistant = [entry for entry in entries if entry.role == "assistant"][-1]
    assert store.entry_content(assistant) == expected
