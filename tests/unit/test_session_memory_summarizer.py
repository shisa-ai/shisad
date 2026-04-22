from __future__ import annotations

import pytest

from shisad.core.config import DaemonConfig
from shisad.core.types import Capability, SessionMode, TaintLabel, UserId, WorkspaceId
from shisad.daemon.handlers._impl import HandlerImplementation
from shisad.daemon.services import DaemonServices
from shisad.memory.summarizer import MemorySummaryProposal


def _clear_remote_provider_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for env_var in (
        "SHISA_API_KEY",
        "SHISAD_MODEL_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "OPENROUTER_API_KEY",
        "ANTHROPIC_API_KEY",
        "SHISAD_MODEL_PLANNER_PROVIDER_PRESET",
        "SHISAD_MODEL_PLANNER_BASE_URL",
        "SHISAD_MODEL_PLANNER_REMOTE_ENABLED",
        "SHISAD_MODEL_PLANNER_API_KEY",
        "SHISAD_MODEL_PLANNER_AUTH_MODE",
        "SHISAD_MODEL_EMBEDDINGS_PROVIDER_PRESET",
        "SHISAD_MODEL_EMBEDDINGS_BASE_URL",
        "SHISAD_MODEL_EMBEDDINGS_REMOTE_ENABLED",
        "SHISAD_MODEL_EMBEDDINGS_API_KEY",
        "SHISAD_MODEL_EMBEDDINGS_AUTH_MODE",
        "SHISAD_MODEL_MONITOR_PROVIDER_PRESET",
        "SHISAD_MODEL_MONITOR_BASE_URL",
        "SHISAD_MODEL_MONITOR_REMOTE_ENABLED",
        "SHISAD_MODEL_MONITOR_API_KEY",
        "SHISAD_MODEL_MONITOR_AUTH_MODE",
    ):
        monkeypatch.delenv(env_var, raising=False)
    monkeypatch.setenv("SHISAD_MODEL_REMOTE_ENABLED", "false")
    monkeypatch.setenv("SHISAD_MODEL_MONITOR_REMOTE_ENABLED", "false")


@pytest.mark.asyncio
async def test_m1_conversation_summarizer_mints_handles_for_memory_and_ingest(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        summarize_interval=1,
    )
    services = await DaemonServices.build(config)
    impl = HandlerImplementation(services=services)
    try:
        session = services.session_manager.create(
            channel="cli",
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
        )
        services.transcript_store.append(
            session.id,
            role="user",
            content="Remember that I prefer short replies.",
            taint_labels={TaintLabel.UNTRUSTED},
        )

        async def _summarize(_entries):
            return [
                MemorySummaryProposal(
                    entry_type="note",
                    key="conversation.preference.communication",
                    value="short replies",
                    confidence=0.7,
                )
            ]

        monkeypatch.setattr(impl._conversation_summarizer, "summarize_entries", _summarize)

        await impl._maybe_run_conversation_summarizer(
            sid=session.id,
            session=session,
            session_mode=SessionMode.DEFAULT,
            capabilities={Capability.MEMORY_WRITE},
        )

        entries = services.memory_manager.list_entries(limit=10)
        assert len(entries) == 1
        entry = entries[0]
        assert entry.key == "conversation.preference.communication"
        assert entry.source_origin == "consolidation_derived"
        assert entry.channel_trust == "consolidation"
        assert entry.ingress_handle_id
        assert entry.source_id.startswith("transcript-summary:")
        assert entry.taint_labels == [TaintLabel.UNTRUSTED]

        summary_records = [
            record
            for record in services.ingestion.list_records(limit=20)
            if record.source_id == entry.source_id
        ]
        assert len(summary_records) == 1
        assert summary_records[0].source_type == "tool"
        assert summary_records[0].collection == "tool_outputs"
        assert (
            summary_records[0].content_sanitized
            == "conversation.preference.communication: short replies"
        )
    finally:
        await services.shutdown()
