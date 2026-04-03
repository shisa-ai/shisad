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

import shisad.core.session_archive as session_archive_module
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


def _read_archive_members(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path, "r") as archive:
        return {info.filename: archive.read(info.filename) for info in archive.infolist()}


def _write_archive_members(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in sorted(members.items()):
            archive.writestr(name, payload)


def _with_rehashed_manifest(members: dict[str, bytes]) -> dict[str, bytes]:
    manifest = json.loads(members["manifest.json"].decode("utf-8"))
    manifest["entries"] = {
        name: hashlib.sha256(payload).hexdigest()
        for name, payload in members.items()
        if name != "manifest.json"
    }
    rewritten = dict(members)
    rewritten["manifest.json"] = json.dumps(
        manifest,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    return rewritten


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

    with (
        zipfile.ZipFile(exported.archive_path, "r") as original,
        zipfile.ZipFile(
            tampered,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as rewritten,
    ):
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


def test_m2_session_archive_import_rejects_invalid_zip_files(tmp_path: Path) -> None:
    _, _, _, _, archive_manager = _build_archive_stack(tmp_path)
    invalid = tmp_path / "not-a-zip.shisad-session.zip"
    invalid.write_text("not really a zip archive", encoding="utf-8")

    with pytest.raises(SessionArchiveError, match="invalid_archive"):
        archive_manager.import_archive(invalid)


def test_m2_session_archive_import_rejects_encrypted_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_manager, _, _, _, archive_manager = _build_archive_stack(tmp_path)
    session = session_manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    exported = archive_manager.export_session(session.id)

    original_infolist = zipfile.ZipFile.infolist

    def _encrypted_infolist(self: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
        infos = original_infolist(self)
        for info in infos:
            info.flag_bits |= 0x1
        return infos

    def _unexpected_read(
        _archive: zipfile.ZipFile,
        _info: zipfile.ZipInfo,
    ) -> bytes:
        raise AssertionError("encrypted archive should be rejected before member read")

    monkeypatch.setattr(
        zipfile.ZipFile,
        "infolist",
        _encrypted_infolist,
    )
    monkeypatch.setattr(
        SessionArchiveManager,
        "_read_archive_member",
        staticmethod(_unexpected_read),
    )

    with pytest.raises(SessionArchiveError, match="encrypted_archive"):
        archive_manager.import_archive(exported.archive_path)


def test_m2_session_archive_import_rejects_oversized_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_manager, _, _, _, archive_manager = _build_archive_stack(tmp_path)
    session = session_manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    exported = archive_manager.export_session(session.id)
    oversized = tmp_path / "oversized.shisad-session.zip"
    members = _read_archive_members(exported.archive_path)
    members["transcript.json"] = b"x" * 128
    members = _with_rehashed_manifest(members)
    _write_archive_members(oversized, members)
    monkeypatch.setattr(session_archive_module, "_ARCHIVE_MAX_MEMBER_BYTES", 32)

    with pytest.raises(SessionArchiveError, match="archive_member_too_large"):
        archive_manager.import_archive(oversized)


def test_m2_session_archive_import_rejects_excessive_member_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_manager, _, _, _, archive_manager = _build_archive_stack(tmp_path)
    session = session_manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    exported = archive_manager.export_session(session.id)
    too_many = tmp_path / "too-many.shisad-session.zip"
    members = _read_archive_members(exported.archive_path)
    members["checkpoints/extra-1.json"] = b"{}"
    members["checkpoints/extra-2.json"] = b"{}"
    members = _with_rehashed_manifest(members)
    manifest = json.loads(members["manifest.json"].decode("utf-8"))
    manifest["checkpoint_count"] = 2
    members["manifest.json"] = json.dumps(
        manifest,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    monkeypatch.setattr(session_archive_module, "_ARCHIVE_MAX_MEMBER_COUNT", 4)
    _write_archive_members(too_many, members)

    with pytest.raises(SessionArchiveError, match="archive_too_many_members"):
        archive_manager.import_archive(too_many)


def test_m2_session_archive_import_rejects_excessive_total_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_manager, _, _, _, archive_manager = _build_archive_stack(tmp_path)
    session = session_manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    exported = archive_manager.export_session(session.id)
    too_large = tmp_path / "too-large.shisad-session.zip"
    members = _read_archive_members(exported.archive_path)
    members["transcript.json"] = b"a" * 40
    members["checkpoints/extra-1.json"] = b"b" * 40
    members = _with_rehashed_manifest(members)
    _write_archive_members(too_large, members)
    monkeypatch.setattr(session_archive_module, "_ARCHIVE_MAX_TOTAL_BYTES", 60)

    with pytest.raises(SessionArchiveError, match="archive_too_large"):
        archive_manager.import_archive(too_large)


def test_m2_session_archive_roundtrip_preserves_checkpoint_lockdown_history(
    tmp_path: Path,
) -> None:
    session_manager, _, checkpoint_store, lockdown, archive_manager = _build_archive_stack(tmp_path)
    session = session_manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    lockdown.set_level(
        session.id,
        level=LockdownLevel.FULL_LOCKDOWN,
        reason="strict",
        trigger="manual",
    )
    checkpoint_store.create(session)
    lockdown.resume(session.id, reason="recovered")
    checkpoint_store.create(session)

    exported = archive_manager.export_session(session.id)
    imported = archive_manager.import_archive(exported.archive_path)

    imported_levels = {
        checkpoint_store.restore(checkpoint_id).state["lockdown"]["level"]  # type: ignore[union-attr]
        for checkpoint_id in imported.checkpoint_ids
    }
    assert imported_levels == {
        LockdownLevel.FULL_LOCKDOWN.value,
        LockdownLevel.NORMAL.value,
    }


def test_m2_session_archive_import_rejects_transcript_hash_mismatch(tmp_path: Path) -> None:
    session_manager, transcript_store, _, _, archive_manager = _build_archive_stack(tmp_path)
    session = session_manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    transcript_store.append(
        session.id,
        role="assistant",
        content="original content",
        timestamp=datetime(2026, 4, 2, tzinfo=UTC),
    )
    exported = archive_manager.export_session(session.id)
    tampered = tmp_path / "tampered-transcript.shisad-session.zip"
    members = _read_archive_members(exported.archive_path)
    transcript_rows = json.loads(members["transcript.json"].decode("utf-8"))
    transcript_rows[0]["content"] = "tampered content"
    members["transcript.json"] = json.dumps(
        transcript_rows,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    members = _with_rehashed_manifest(members)
    _write_archive_members(tampered, members)

    with pytest.raises(SessionArchiveError, match="transcript_hash_mismatch"):
        archive_manager.import_archive(tampered)


def test_m2_session_archive_import_rejects_capability_manifest_mismatch(tmp_path: Path) -> None:
    session_manager, _, _, _, archive_manager = _build_archive_stack(tmp_path)
    session = session_manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
        capabilities={Capability.FILE_READ},
    )
    exported = archive_manager.export_session(session.id)
    tampered = tmp_path / "tampered-capabilities.shisad-session.zip"
    members = _read_archive_members(exported.archive_path)
    session_payload = json.loads(members["session.json"].decode("utf-8"))
    session_payload["session"]["capabilities"] = [Capability.HTTP_REQUEST.value]
    members["session.json"] = json.dumps(
        session_payload,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    members = _with_rehashed_manifest(members)
    _write_archive_members(tampered, members)

    with pytest.raises(SessionArchiveError, match="archive_capability_mismatch"):
        archive_manager.import_archive(tampered)


def test_m2_session_archive_import_rewrites_only_session_payload_dicts(tmp_path: Path) -> None:
    session_manager, _, checkpoint_store, _, archive_manager = _build_archive_stack(tmp_path)
    session = session_manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    checkpoint = checkpoint_store.create(
        session,
        state={
            "session": session.model_dump(mode="json"),
            "routing_hint": {
                "id": str(session.id),
                "channel": session.channel,
                "user_id": str(session.user_id),
                "workspace_id": str(session.workspace_id),
            },
        },
    )

    exported = archive_manager.export_session(session.id)
    imported = archive_manager.import_archive(exported.archive_path)
    imported_checkpoint = next(
        checkpoint_store.restore(checkpoint_id)
        for checkpoint_id in imported.checkpoint_ids
        if checkpoint_store.restore(checkpoint_id) is not None
    )

    assert imported_checkpoint is not None
    assert imported_checkpoint.state["session"]["id"] == str(imported.session.id)
    assert imported_checkpoint.state["routing_hint"]["id"] == str(session.id)
    assert checkpoint_store.restore(checkpoint.checkpoint_id) is not None


def test_m2_session_archive_export_wraps_write_failures(tmp_path: Path) -> None:
    session_manager, _, _, _, archive_manager = _build_archive_stack(tmp_path)
    session = session_manager.create(
        channel="cli",
        user_id=UserId("alice"),
        workspace_id=WorkspaceId("ws1"),
    )
    destination = tmp_path / "archive-dir"
    destination.mkdir()

    with pytest.raises(SessionArchiveError, match="archive_write_failed"):
        archive_manager.export_session(session.id, destination=destination)
