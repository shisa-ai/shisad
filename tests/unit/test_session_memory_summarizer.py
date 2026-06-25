from __future__ import annotations

from types import SimpleNamespace

import pytest

from shisad.channels.base import DeliveryTarget
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


def test_gh19_memory_auto_extraction_config_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHISAD_MEMORY_AUTO_EXTRACTION_ENABLED", "false")
    monkeypatch.setenv("SHISAD_MEMORY_AUTO_EXTRACTION_CONFIDENCE_THRESHOLD", "0.85")

    config = DaemonConfig()

    assert config.memory_auto_extraction_enabled is False
    assert config.memory_auto_extraction_confidence_threshold == pytest.approx(0.85)


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
        assert entry.user_id == "alice"
        assert entry.workspace_id == "ws1"

        summary_records = [
            record
            for record in services.ingestion.list_records(limit=20)
            if record.source_id == entry.source_id
        ]
        assert len(summary_records) == 1
        assert summary_records[0].source_type == "tool"
        assert summary_records[0].collection == "tool_outputs"
        assert summary_records[0].user_id == "alice"
        assert summary_records[0].workspace_id == "ws1"
        assert (
            summary_records[0].content_sanitized
            == "conversation.preference.communication: short replies"
        )

        alice_recall = services.ingestion.compile_recall(
            "short replies",
            limit=10,
            capabilities={Capability.MEMORY_READ},
            user_id="alice",
            workspace_id="ws1",
        )
        bob_recall = services.ingestion.compile_recall(
            "short replies",
            limit=10,
            capabilities={Capability.MEMORY_READ},
            user_id="bob",
            workspace_id="ws2",
        )
        assert any(
            record.chunk_id == summary_records[0].chunk_id for record in alice_recall.results
        )
        assert all(record.chunk_id != summary_records[0].chunk_id for record in bob_recall.results)
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_conversation_summarizer_filters_internal_ingress_by_delivery_target(
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
        target_a = DeliveryTarget(channel="discord", recipient="chan-a")
        target_b = DeliveryTarget(channel="discord", recipient="chan-b")
        session = services.session_manager.create(
            channel="discord",
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
        )
        services.transcript_store.append(
            session.id,
            role="user",
            content="Target A preference should stay isolated.",
            metadata={"delivery_target": target_a.model_dump(mode="json")},
        )
        services.transcript_store.append(
            session.id,
            role="user",
            content="Target B preference is visible.",
            metadata={"delivery_target": target_b.model_dump(mode="json")},
        )
        summarized_batches: list[list[str]] = []

        async def _summarize(entries):
            batch = [entry.content_preview for entry in entries]
            summarized_batches.append(batch)
            value = batch[0]
            return [
                MemorySummaryProposal(
                    entry_type="note",
                    key=f"conversation.target.{len(summarized_batches)}",
                    value=value,
                    confidence=0.7,
                )
            ]

        monkeypatch.setattr(impl._conversation_summarizer, "summarize_entries", _summarize)

        await impl._maybe_run_conversation_summarizer(
            sid=session.id,
            session=session,
            session_mode=SessionMode.DEFAULT,
            capabilities={Capability.MEMORY_WRITE},
            validated=SimpleNamespace(
                is_internal_ingress=True,
                delivery_target=target_b,
                session=session,
            ),
        )
        await impl._maybe_run_conversation_summarizer(
            sid=session.id,
            session=session,
            session_mode=SessionMode.DEFAULT,
            capabilities={Capability.MEMORY_WRITE},
            validated=SimpleNamespace(
                is_internal_ingress=True,
                delivery_target=target_a,
                session=session,
            ),
        )

        assert summarized_batches == [
            ["Target B preference is visible."],
            ["Target A preference should stay isolated."],
        ]
        memory_values = {
            str(entry.value) for entry in services.memory_manager.list_entries(limit=10)
        }
        assert memory_values == {
            "Target A preference should stay isolated.",
            "Target B preference is visible.",
        }
        count_keys = [
            key for key in session.metadata if str(key).startswith("summarized_entry_count:")
        ]
        assert len(count_keys) == 2
        assert "summarized_entry_count" not in session.metadata
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_conversation_summarizer_target_cursor_seeds_from_legacy_count(
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
        target_a = DeliveryTarget(channel="discord", recipient="chan-a")
        target_b = DeliveryTarget(channel="discord", recipient="chan-b")
        session = services.session_manager.create(
            channel="discord",
            user_id=UserId("alice"),
            workspace_id=WorkspaceId("ws1"),
            metadata={"summarized_entry_count": 2},
        )
        services.transcript_store.append(
            session.id,
            role="user",
            content="Target A was summarized before upgrade.",
            metadata={"delivery_target": target_a.model_dump(mode="json")},
        )
        services.transcript_store.append(
            session.id,
            role="user",
            content="Target B was summarized before upgrade.",
            metadata={"delivery_target": target_b.model_dump(mode="json")},
        )

        async def _summarize(_entries):
            raise AssertionError("legacy cursor should suppress already summarized target rows")

        monkeypatch.setattr(impl._conversation_summarizer, "summarize_entries", _summarize)

        await impl._maybe_run_conversation_summarizer(
            sid=session.id,
            session=session,
            session_mode=SessionMode.DEFAULT,
            capabilities={Capability.MEMORY_WRITE},
            validated=SimpleNamespace(
                is_internal_ingress=True,
                delivery_target=target_b,
                session=session,
            ),
        )

        assert services.memory_manager.list_entries(limit=10) == []
        target_count_items = {
            key: value
            for key, value in session.metadata.items()
            if str(key).startswith("summarized_entry_count:")
        }
        assert list(target_count_items.values()) == [1]
        assert session.metadata["summarized_entry_count"] == 2
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_gh19_conversation_summarizer_respects_auto_extraction_disabled(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        summarize_interval=1,
        memory_auto_extraction_enabled=False,
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
            content="Hello, just checking the demo workspace.",
            taint_labels={TaintLabel.UNTRUSTED},
        )

        async def _summarize(_entries):
            raise AssertionError("auto-extraction disabled should not call the summarizer")

        monkeypatch.setattr(impl._conversation_summarizer, "summarize_entries", _summarize)

        await impl._maybe_run_conversation_summarizer(
            sid=session.id,
            session=session,
            session_mode=SessionMode.DEFAULT,
            capabilities={Capability.MEMORY_WRITE},
        )

        assert services.memory_manager.list_entries(limit=10) == []
        assert services.ingestion.list_records(limit=20) == []
        assert session.metadata["summarized_entry_count"] == 1
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_gh19_auto_extraction_disabled_subinterval_turns_are_not_backfilled(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        summarize_interval=3,
        memory_auto_extraction_enabled=False,
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
            content="This opted-out demo turn must not be summarized later.",
            taint_labels={TaintLabel.UNTRUSTED},
        )

        async def _disabled_summarize(_entries):
            raise AssertionError("disabled sub-interval turns should not call summarizer")

        monkeypatch.setattr(
            impl._conversation_summarizer,
            "summarize_entries",
            _disabled_summarize,
        )

        await impl._maybe_run_conversation_summarizer(
            sid=session.id,
            session=session,
            session_mode=SessionMode.DEFAULT,
            capabilities={Capability.MEMORY_WRITE},
        )
        assert session.metadata["summarized_entry_count"] == 1
        assert services.memory_manager.list_entries(limit=10) == []

        impl._config.memory_auto_extraction_enabled = True
        for content in (
            "After re-enable turn one.",
            "After re-enable turn two.",
            "After re-enable turn three.",
        ):
            services.transcript_store.append(
                session.id,
                role="user",
                content=content,
                taint_labels={TaintLabel.UNTRUSTED},
            )

        async def _reenabled_summarize(entries):
            assert len(entries) == 3
            assert all("opted-out demo" not in entry.content_preview for entry in entries)
            return [
                MemorySummaryProposal(
                    entry_type="note",
                    key="conversation.after_reenable",
                    value="post opt-out turns only",
                    confidence=0.9,
                )
            ]

        monkeypatch.setattr(
            impl._conversation_summarizer,
            "summarize_entries",
            _reenabled_summarize,
        )

        await impl._maybe_run_conversation_summarizer(
            sid=session.id,
            session=session,
            session_mode=SessionMode.DEFAULT,
            capabilities={Capability.MEMORY_WRITE},
        )

        entries = services.memory_manager.list_entries(limit=10)
        assert [entry.key for entry in entries] == ["conversation.after_reenable"]
    finally:
        await services.shutdown()


@pytest.mark.asyncio
async def test_gh19_conversation_summarizer_skips_below_confidence_threshold(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_remote_provider_env(monkeypatch)
    config = DaemonConfig(
        data_dir=tmp_path / "data",
        socket_path=tmp_path / "control.sock",
        policy_path=tmp_path / "policy.yaml",
        summarize_interval=1,
        memory_auto_extraction_confidence_threshold=0.8,
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
            content="Remember that I prefer concise daily updates.",
            taint_labels={TaintLabel.UNTRUSTED},
        )

        async def _summarize(_entries):
            return [
                MemorySummaryProposal(
                    entry_type="note",
                    key="conversation.low_confidence_guess",
                    value="possibly likes demos",
                    confidence=0.5,
                ),
                MemorySummaryProposal(
                    entry_type="note",
                    key="conversation.preference.updates",
                    value="concise daily updates",
                    confidence=0.95,
                ),
            ]

        monkeypatch.setattr(impl._conversation_summarizer, "summarize_entries", _summarize)

        await impl._maybe_run_conversation_summarizer(
            sid=session.id,
            session=session,
            session_mode=SessionMode.DEFAULT,
            capabilities={Capability.MEMORY_WRITE},
        )

        entries = services.memory_manager.list_entries(limit=10)
        assert [entry.key for entry in entries] == ["conversation.preference.updates"]
        assert entries[0].confidence == pytest.approx(0.95)

        summary_records = [
            record
            for record in services.ingestion.list_records(limit=20)
            if record.source_id == entries[0].source_id
        ]
        assert len(summary_records) == 1
        assert (
            summary_records[0].content_sanitized
            == "conversation.preference.updates: concise daily updates"
        )
    finally:
        await services.shutdown()
