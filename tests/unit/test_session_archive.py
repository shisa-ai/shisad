"""M2 session archive roundtrip and integrity coverage."""

from __future__ import annotations

import hashlib
import json
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from shisad.core.session import CheckpointStore, Session, SessionManager
from shisad.core.session_archive import SessionArchiveError, SessionArchiveManager
from shisad.core.transcript import TranscriptStore
from shisad.core.types import Capability, SessionMode, UserId, WorkspaceId
from shisad.security.lockdown import LockdownLevel, LockdownManager


def _lockdown_hooks(
    lockdown: LockdownManager,
) -> tuple[
    Callable[[Session], dict[str, Any]],
    Callable[[Session, dict[str, Any], str], None],
]:
    def _provider(session: Session) -> dict[str, Any]:
        return {"lockdown": lockdown.snapshot(session.id)}

    def _restorer(session: Session, record: dict[str, Any], _source: str) -> None:
        lockdown.rehydrate(session.id, record.get("lockdown"))

    return _provider, _restorer


def _build_archive_stack(
    tmp_path: Path,
) -> tuple[
    SessionManager,
    TranscriptStore,
    CheckpointStore,
    LockdownManager,
    SessionArchiveManager,
]:
    lockdown = LockdownManager()
    provider, restorer = _lockdown_hooks(lockdown)
    session_manager = SessionManager(
        state_dir=tmp_path / "sessions" / "state",
        supplemental_state_provider=provider,
        supplemental_state_restorer=restorer,
    )
    transcript_store = TranscriptStore(tmp_path / "sessions")
    checkpoint_store = CheckpointStore(
        tmp_path / "checkpoints",
        supplemental_state_provider=provider,
    )
    archive_manager = SessionArchiveManager(
        session_manager=session_manager,
        transcript_store=transcript_store,
        checkpoint_store=checkpoint_store,
        lockdown_manager=lockdown,
        archive_dir=tmp_path / "archives",
    )
    return session_manager, transcript_store, checkpoint_store, lockdown, archive_manager


def test_m2_session_archive_roundtrip_preserves_scope_and_lockdown(tmp_path: Path) -> None:
    (
        session_manager,
        transcript_store,
        checkpoint_store,
        lockdown,
        archive_manager,
    ) = _build_archive_stack(tmp_path)
    session = session_manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities={Capability.FILE_READ},
        metadata={"trust_level": "trusted"},
    )
    session_manager.set_mode(session.id, SessionMode.ADMIN_CLEANROOM)
    lockdown.set_level(
        session.id,
        level=LockdownLevel.CAUTION,
        reason="archive-test",
        trigger="manual",
    )
    transcript_store.append(
        session.id,
        role="assistant",
        content="hello from transcript archive",
        timestamp=datetime(2026, 4, 2, tzinfo=UTC),
    )
    checkpoint = checkpoint_store.create(session)

    exported = archive_manager.export_session(session.id)
    imported = archive_manager.import_archive(exported.archive_path)

    assert imported.session.id != session.id
    assert imported.session.user_id == session.user_id
    assert imported.session.workspace_id == session.workspace_id
    assert imported.session.mode == SessionMode.ADMIN_CLEANROOM
    assert lockdown.state_for(imported.session.id).level == LockdownLevel.CAUTION
    imported_entries = transcript_store.list_entries(imported.session.id)
    assert len(imported_entries) == 1
    assert imported_entries[0].content_preview == "hello from transcript archive"
    assert imported.checkpoint_ids
    imported_checkpoint = checkpoint_store.restore(imported.checkpoint_ids[0])
    assert imported_checkpoint is not None
    assert imported_checkpoint.state["session"]["id"] == str(imported.session.id)
    assert imported_checkpoint.state["lockdown"]["level"] == LockdownLevel.CAUTION.value
    assert checkpoint_store.restore(checkpoint.checkpoint_id) is not None


def test_m2_session_archive_rejects_checksum_tamper(tmp_path: Path) -> None:
    session_manager, _, checkpoint_store, lockdown, archive_manager = _build_archive_stack(tmp_path)
    session = session_manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    lockdown.set_level(session.id, level=LockdownLevel.CAUTION, reason="archive", trigger="manual")
    checkpoint_store.create(session)
    exported = archive_manager.export_session(session.id)
    tampered = tmp_path / "tampered.shisad-session.zip"

    with zipfile.ZipFile(exported.archive_path, "r") as original, zipfile.ZipFile(
        tampered,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as rewritten:
        for info in original.infolist():
            payload = original.read(info.filename)
            if info.filename == "session.json":
                session_payload = json.loads(payload.decode("utf-8"))
                session_payload["session"]["workspace_id"] = "ws2"
                payload = json.dumps(
                    session_payload,
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                ).encode("utf-8")
            rewritten.writestr(info.filename, payload)

    with pytest.raises(SessionArchiveError, match="archive_checksum_mismatch"):
        archive_manager.import_archive(tampered)


def test_m2_session_archive_rejects_path_traversal_members(tmp_path: Path) -> None:
    _, _, _, _, archive_manager = _build_archive_stack(tmp_path)
    traversal = tmp_path / "traversal.shisad-session.zip"
    manifest = {
        "format": "shisad_session_archive",
        "version": 1,
        "original_session_id": "s1",
        "channel": "cli",
        "user_id": "alice",
        "workspace_id": "ws1",
        "role": "orchestrator",
        "mode": "default",
        "lockdown_level": "",
        "transcript_entries": 0,
        "checkpoint_count": 0,
        "includes": ["session", "lockdown", "transcript", "checkpoints"],
        "excludes": ["evidence_store", "memory", "scheduler_global_state"],
        "entries": {"../session.json": "deadbeef"},
    }
    with zipfile.ZipFile(traversal, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=True, indent=2))
        archive.writestr("../session.json", "{}")

    with pytest.raises(SessionArchiveError, match="invalid_archive_member"):
        archive_manager.import_archive(traversal)


def test_m2_session_archive_rejects_cross_workspace_scope_mismatch(tmp_path: Path) -> None:
    session_manager, _, _, lockdown, archive_manager = _build_archive_stack(tmp_path)
    session = session_manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    lockdown.set_level(session.id, level=LockdownLevel.NORMAL, reason="archive", trigger="manual")
    exported = archive_manager.export_session(session.id)
    mismatched = tmp_path / "mismatched.shisad-session.zip"

    with zipfile.ZipFile(exported.archive_path, "r") as original:
        session_payload = json.loads(original.read("session.json").decode("utf-8"))
        transcript_payload = original.read("transcript.json")
        manifest = json.loads(original.read("manifest.json").decode("utf-8"))

    manifest["workspace_id"] = "ws2"
    manifest["entries"]["session.json"] = hashlib.sha256(
        json.dumps(session_payload, ensure_ascii=True, indent=2, sort_keys=True).encode("utf-8")
    ).hexdigest()
    manifest["entries"]["transcript.json"] = hashlib.sha256(transcript_payload).hexdigest()

    with zipfile.ZipFile(mismatched, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "session.json",
            json.dumps(session_payload, ensure_ascii=True, indent=2, sort_keys=True),
        )
        archive.writestr("transcript.json", transcript_payload)
        archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=True, indent=2))

    with pytest.raises(SessionArchiveError, match="archive_workspace_id_mismatch"):
        archive_manager.import_archive(mismatched)
