"""F3B evidence-domain durability and retained-corruption regressions."""

from __future__ import annotations

import json
import os
import time
from hashlib import sha256
from pathlib import Path
from stat import S_IMODE
from threading import Event, Thread
from uuid import uuid4

import pytest
from pydantic import ValidationError

from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteStage,
    StateLoadStatus,
    StatePersistenceDegradedError,
    encode_versioned_json_snapshot,
)
from shisad.core.evidence import (
    ArtifactBlobCodecError,
    ArtifactEndorsementState,
    ArtifactLedger,
    EvidenceRef,
)
from shisad.core.types import SessionId, TaintLabel


def _store(
    ledger: ArtifactLedger,
    *,
    sid: str = "sess-a",
    content: str = "evidence",
) -> EvidenceRef:
    return ledger.store(
        SessionId(sid),
        content,
        taint_labels={TaintLabel.UNTRUSTED},
        source="web.fetch:example.com",
        summary=content,
    )


def _index_payload(index_path: Path) -> dict[str, object]:
    raw = json.loads(index_path.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and set(raw) == {"version", "checksum", "payload"}:
        payload = raw["payload"]
        assert isinstance(payload, dict)
        return payload
    assert isinstance(raw, dict)
    return raw


def _assert_degraded(ledger: ArtifactLedger, *, reason: str) -> None:
    result = ledger.state_load_result()
    assert result.status is StateLoadStatus.CORRUPT
    assert result.reason == reason
    assert ledger.state_degraded is True
    status = ledger.state_status()
    assert status["status"] == "degraded"
    assert status["fail_closed"] is True
    assert status["cleanup_allowed"] is False
    assert reason in status["problems"]


def test_f3_evidence_domain_new_root_is_durable_versioned_and_owner_only(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"

    ledger = ArtifactLedger(evidence_root, salt=b"a" * 32)

    assert ledger.state_load_result().status is StateLoadStatus.OK
    assert ledger.state_load_result().reason == "new_domain"
    index = json.loads((evidence_root / "refs_index.json").read_text(encoding="utf-8"))
    assert set(index) == {"version", "checksum", "payload"}
    assert index["version"] == 1
    assert index["payload"] == {}
    assert (evidence_root / "evidence_salt").read_bytes() == b"a" * 32
    assert S_IMODE(evidence_root.stat().st_mode) == 0o700
    assert S_IMODE((evidence_root / "blobs").stat().st_mode) == 0o700
    assert S_IMODE((evidence_root / "quarantine").stat().st_mode) == 0o700
    assert S_IMODE((evidence_root / "evidence_salt").stat().st_mode) == 0o600
    assert S_IMODE((evidence_root / "refs_index.json").stat().st_mode) == 0o600


def test_f3_evidence_domain_first_create_fsyncs_root_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fsynced: list[Path] = []
    original = ArtifactLedger._fsync_directory

    def _record(path: Path) -> None:
        fsynced.append(path)
        original(path)

    monkeypatch.setattr(ArtifactLedger, "_fsync_directory", staticmethod(_record))

    ledger = ArtifactLedger(tmp_path / "evidence", salt=b"a" * 32)

    assert ledger.state_degraded is False
    assert tmp_path in fsynced


def test_f3_evidence_domain_first_create_parent_fsync_failure_degrades(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = ArtifactLedger._fsync_directory

    def _fault(path: Path) -> None:
        if path == tmp_path:
            raise OSError("parent fsync failed")
        original(path)

    monkeypatch.setattr(ArtifactLedger, "_fsync_directory", staticmethod(_fault))

    ledger = ArtifactLedger(tmp_path / "evidence", salt=b"a" * 32)

    _assert_degraded(ledger, reason="new_domain_publication_failed")
    with pytest.raises(StatePersistenceDegradedError):
        _store(ledger)


@pytest.mark.parametrize("child_name", ["blobs", "quarantine"])
def test_f3_evidence_domain_file_child_degrades_without_startup_exception(
    tmp_path: Path,
    child_name: str,
) -> None:
    evidence_root = tmp_path / "evidence"
    ArtifactLedger(evidence_root, salt=b"a" * 32)
    child = evidence_root / child_name
    child.rmdir()
    child.write_bytes(b"retained invalid child")

    restarted = ArtifactLedger(evidence_root)

    _assert_degraded(restarted, reason=f"invalid_{child_name}_directory")
    assert child.read_bytes() == b"retained invalid child"


@pytest.mark.parametrize("child_name", ["blobs", "quarantine"])
def test_f3_evidence_domain_symlink_child_never_touches_external_directory(
    tmp_path: Path,
    child_name: str,
) -> None:
    evidence_root = tmp_path / "evidence"
    ArtifactLedger(evidence_root, salt=b"a" * 32)
    child = evidence_root / child_name
    child.rmdir()
    external = tmp_path / f"external-{child_name}"
    external.mkdir()
    external_file = external / "opaque.txt"
    external_file.write_bytes(b"must remain external")
    child.symlink_to(external, target_is_directory=True)

    restarted = ArtifactLedger(evidence_root)

    _assert_degraded(restarted, reason=f"invalid_{child_name}_directory")
    assert child.is_symlink() is True
    assert external_file.read_bytes() == b"must remain external"


def test_f3_evidence_domain_missing_salt_retains_index_and_blob_without_rotation(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    first = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(first)
    index_path = evidence_root / "refs_index.json"
    blob_path = evidence_root / "blobs" / f"{ref.content_hash}.txt"
    index_bytes = index_path.read_bytes()
    blob_bytes = blob_path.read_bytes()
    (evidence_root / "evidence_salt").unlink()

    restarted = ArtifactLedger(evidence_root)

    _assert_degraded(restarted, reason="missing_salt_existing_domain")
    assert (evidence_root / "evidence_salt").exists() is False
    assert index_path.read_bytes() == index_bytes
    assert blob_path.read_bytes() == blob_bytes
    assert restarted.get_ref_metadata(SessionId("sess-a"), ref.ref_id) is None


@pytest.mark.parametrize(
    ("salt_bytes", "reason"),
    [
        pytest.param(b"short", "invalid_salt", id="truncated"),
        pytest.param(b"b" * 32, "salt_mismatch", id="configured-mismatch"),
    ],
)
def test_f3_evidence_domain_invalid_salt_retains_complete_domain(
    tmp_path: Path,
    salt_bytes: bytes,
    reason: str,
) -> None:
    evidence_root = tmp_path / "evidence"
    first = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(first)
    blob_path = evidence_root / "blobs" / f"{ref.content_hash}.txt"
    blob_bytes = blob_path.read_bytes()
    salt_path = evidence_root / "evidence_salt"
    if reason == "invalid_salt":
        salt_path.write_bytes(salt_bytes)

    restarted = ArtifactLedger(
        evidence_root,
        salt=(salt_bytes if reason == "salt_mismatch" else None),
    )

    _assert_degraded(restarted, reason=reason)
    assert salt_path.read_bytes() == (b"a" * 32 if reason == "salt_mismatch" else salt_bytes)
    assert blob_path.read_bytes() == blob_bytes


def test_f3_evidence_domain_missing_index_with_blob_retains_every_byte(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    first = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(first)
    salt_bytes = (evidence_root / "evidence_salt").read_bytes()
    blob_path = evidence_root / "blobs" / f"{ref.content_hash}.txt"
    blob_bytes = blob_path.read_bytes()
    (evidence_root / "refs_index.json").unlink()

    restarted = ArtifactLedger(evidence_root)

    _assert_degraded(restarted, reason="missing_index_existing_domain")
    assert (evidence_root / "refs_index.json").exists() is False
    assert (evidence_root / "evidence_salt").read_bytes() == salt_bytes
    assert blob_path.read_bytes() == blob_bytes
    assert list((evidence_root / "quarantine").iterdir()) == []


@pytest.mark.parametrize(
    ("index_bytes", "reason"),
    [
        pytest.param(b"{not-json", "invalid_json", id="invalid-json"),
        pytest.param(
            encode_versioned_json_snapshot({}, version=2),
            "unsupported_schema",
            id="newer-schema",
        ),
    ],
)
def test_f3_evidence_domain_bad_index_retains_orphan_and_blocks_cleanup(
    tmp_path: Path,
    index_bytes: bytes,
    reason: str,
) -> None:
    evidence_root = tmp_path / "evidence"
    first = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(first)
    referenced_blob = evidence_root / "blobs" / f"{ref.content_hash}.txt"
    orphan_blob = evidence_root / "blobs" / f"{'d' * 64}.txt"
    orphan_blob.write_bytes(b"retained orphan")
    index_path = evidence_root / "refs_index.json"
    index_path.write_bytes(index_bytes)

    restarted = ArtifactLedger(evidence_root)

    result = restarted.state_load_result()
    expected_status = (
        StateLoadStatus.UNSUPPORTED_SCHEMA
        if reason == "unsupported_schema"
        else StateLoadStatus.CORRUPT
    )
    assert result.status is expected_status
    assert result.reason == reason
    assert restarted.state_degraded is True
    assert index_path.read_bytes() == index_bytes
    assert referenced_blob.exists() is True
    assert orphan_blob.read_bytes() == b"retained orphan"
    assert list((evidence_root / "quarantine").iterdir()) == []


@pytest.mark.parametrize("failure", ["missing", "hash_mismatch"])
def test_f3_evidence_domain_blob_companion_failure_retains_index_and_degrades(
    tmp_path: Path,
    failure: str,
) -> None:
    evidence_root = tmp_path / "evidence"
    first = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(first)
    index_path = evidence_root / "refs_index.json"
    index_bytes = index_path.read_bytes()
    blob_path = evidence_root / "blobs" / f"{ref.content_hash}.txt"
    if failure == "missing":
        blob_path.unlink()
    else:
        blob_path.write_bytes(b"tampered-but-retained")

    restarted = ArtifactLedger(evidence_root)

    _assert_degraded(restarted, reason=f"blob_{failure}")
    assert restarted.read(SessionId("sess-a"), ref.ref_id) is None
    assert restarted.get_ref(SessionId("sess-a"), ref.ref_id) is None
    assert restarted.resolve_ref_content(SessionId("sess-a"), ref.ref_id) == (None, None)
    assert index_path.read_bytes() == index_bytes
    if failure == "missing":
        assert blob_path.exists() is False
    else:
        assert blob_path.read_bytes() == b"tampered-but-retained"


def test_f3_evidence_domain_valid_legacy_index_migrates_only_after_full_validation(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    first = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(first)
    index_path = evidence_root / "refs_index.json"
    legacy_payload = _index_payload(index_path)
    index_path.write_text(
        json.dumps(legacy_payload, ensure_ascii=True, sort_keys=True),
        encoding="utf-8",
    )

    restarted = ArtifactLedger(evidence_root)

    result = restarted.state_load_result()
    assert result.status is StateLoadStatus.OK
    assert result.legacy is True
    assert restarted.read(SessionId("sess-a"), ref.ref_id) == "evidence"
    migrated = json.loads(index_path.read_text(encoding="utf-8"))
    assert set(migrated) == {"version", "checksum", "payload"}
    assert migrated["version"] == 1
    assert migrated["payload"] == legacy_payload


def test_f3_evidence_domain_rejects_content_hash_path_before_blob_access(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    first = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(first)
    payload = _index_payload(evidence_root / "refs_index.json")
    session_payload = payload["sess-a"]
    assert isinstance(session_payload, dict)
    raw_ref = session_payload[ref.ref_id]
    assert isinstance(raw_ref, dict)
    escaped = EvidenceRef.model_validate(
        {**raw_ref, "content_hash": str(tmp_path / "outside")}
    )
    escaped = escaped.model_copy(
        update={"metadata_mac": first._make_metadata_mac("sess-a", escaped)}
    )
    session_payload[ref.ref_id] = escaped.model_dump(mode="json")
    (evidence_root / "refs_index.json").write_bytes(
        encode_versioned_json_snapshot(payload, version=1)
    )
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"must not be read")

    restarted = ArtifactLedger(evidence_root)

    _assert_degraded(restarted, reason="invalid_content_hash")
    assert outside.read_bytes() == b"must not be read"


def test_f3_evidence_domain_rejects_authenticated_but_forged_ref_id(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    first = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(first)
    forged_id = "ev-forged"
    forged = ref.model_copy(update={"ref_id": forged_id, "metadata_mac": ""})
    forged = forged.model_copy(
        update={"metadata_mac": first._make_metadata_mac("sess-a", forged)}
    )
    payload = {"sess-a": {forged_id: forged.model_dump(mode="json")}}
    (evidence_root / "refs_index.json").write_bytes(
        encode_versioned_json_snapshot(payload, version=1)
    )

    restarted = ArtifactLedger(evidence_root)

    _assert_degraded(restarted, reason="ref_id_auth_mismatch")


@pytest.mark.parametrize("stage", list(AtomicWriteStage))
def test_f3_evidence_blob_publication_fault_never_publishes_dangling_ref(
    tmp_path: Path,
    stage: AtomicWriteStage,
) -> None:
    ledger = ArtifactLedger(tmp_path / "evidence", salt=b"a" * 32)

    def _fault(observed: AtomicWriteStage) -> None:
        if observed is stage:
            raise OSError(f"fault at {stage.value}")

    ledger._atomic_fault_injector = _fault

    with pytest.raises(AtomicWriteError):
        _store(ledger)

    assert ledger.committed_ref_count() == 0
    assert ledger.get_ref_metadata(SessionId("sess-a"), "ev-any") is None
    assert ledger.state_degraded is True
    assert ledger.cleanup_allowed is False


@pytest.mark.parametrize("stage", list(AtomicWriteStage))
def test_f3_evidence_index_publication_fault_keeps_prior_committed_view(
    tmp_path: Path,
    stage: AtomicWriteStage,
) -> None:
    ledger = ArtifactLedger(tmp_path / "evidence", salt=b"a" * 32)
    original = _store(ledger, sid="sess-a", content="shared")
    committed_index = (tmp_path / "evidence" / "refs_index.json").read_bytes()

    def _fault(observed: AtomicWriteStage) -> None:
        if observed is stage:
            raise OSError(f"fault at {stage.value}")

    ledger._atomic_fault_injector = _fault

    with pytest.raises(AtomicWriteError):
        _store(ledger, sid="sess-b", content="shared")

    assert ledger.get_ref_metadata(SessionId("sess-a"), original.ref_id) is None
    assert ledger._committed_view.refs["sess-a"][original.ref_id] == original
    assert ledger.committed_ref_count() == 1
    assert ledger.state_degraded is True
    assert ledger.cleanup_allowed is False
    if stage is not AtomicWriteStage.PARENT_FSYNC:
        assert (tmp_path / "evidence" / "refs_index.json").read_bytes() == committed_index


@pytest.mark.parametrize("stage", list(AtomicWriteStage))
def test_f3_evidence_endorsement_index_fault_keeps_prior_ref(
    tmp_path: Path,
    stage: AtomicWriteStage,
) -> None:
    evidence_root = tmp_path / "evidence"
    ledger = ArtifactLedger(evidence_root, salt=b"a" * 32)
    original = _store(ledger)
    committed_index = (evidence_root / "refs_index.json").read_bytes()

    def _fault(observed: AtomicWriteStage) -> None:
        if observed is stage:
            raise OSError(f"fault at {stage.value}")

    ledger._atomic_fault_injector = _fault

    with pytest.raises(AtomicWriteError):
        ledger.endorse(
            SessionId("sess-a"),
            original.ref_id,
            endorsement_state=ArtifactEndorsementState.USER_ENDORSED,
            actor="human",
        )

    assert ledger.get_ref_metadata(SessionId("sess-a"), original.ref_id) is None
    assert ledger._committed_view.refs["sess-a"][original.ref_id] == original
    assert ledger._refs["sess-a"][original.ref_id] == original
    assert ledger.state_degraded is True
    assert ledger.cleanup_allowed is False
    if stage is not AtomicWriteStage.PARENT_FSYNC:
        assert (evidence_root / "refs_index.json").read_bytes() == committed_index


@pytest.mark.parametrize("stage", list(AtomicWriteStage))
def test_f3_evidence_eviction_index_fault_restores_ref_marker_and_blob(
    tmp_path: Path,
    stage: AtomicWriteStage,
) -> None:
    evidence_root = tmp_path / "evidence"
    ledger = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(ledger)
    ledger._refs["sess-a"][ref.ref_id] = ref.model_copy(
        update={"created_at": ref.created_at.replace(year=2000)}
    )
    ledger._mark_temporarily_unreadable("sess-a", ref.ref_id, "kms_unavailable")
    blob_path = evidence_root / "blobs" / f"{ref.content_hash}.txt"
    blob_bytes = blob_path.read_bytes()
    committed_index = (evidence_root / "refs_index.json").read_bytes()

    def _fault(observed: AtomicWriteStage) -> None:
        if observed is stage:
            raise OSError(f"fault at {stage.value}")

    ledger._atomic_fault_injector = _fault

    with pytest.raises(AtomicWriteError):
        ledger.evict_expired(SessionId("sess-a"), max_age_seconds=60)

    assert ledger.get_ref_metadata(SessionId("sess-a"), ref.ref_id) is None
    assert ledger._committed_view.refs["sess-a"][ref.ref_id] == ref
    assert ref.ref_id in ledger._refs["sess-a"]
    assert ledger._is_temporarily_unreadable("sess-a", ref.ref_id) is True
    assert blob_path.read_bytes() == blob_bytes
    assert ledger.state_degraded is True
    assert ledger.cleanup_allowed is False
    if stage is not AtomicWriteStage.PARENT_FSYNC:
        assert (evidence_root / "refs_index.json").read_bytes() == committed_index


@pytest.mark.parametrize("stage", list(AtomicWriteStage))
def test_f3_evidence_lazy_drop_index_fault_restores_ref_and_marker(
    tmp_path: Path,
    stage: AtomicWriteStage,
) -> None:
    evidence_root = tmp_path / "evidence"
    ledger = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(ledger)
    (evidence_root / "blobs" / f"{ref.content_hash}.txt").unlink()
    ledger._mark_temporarily_unreadable("sess-a", ref.ref_id, "prior_marker")
    committed_index = (evidence_root / "refs_index.json").read_bytes()

    def _fault(observed: AtomicWriteStage) -> None:
        if observed is stage:
            raise OSError(f"fault at {stage.value}")

    ledger._atomic_fault_injector = _fault

    assert ledger.read(SessionId("sess-a"), ref.ref_id) is None

    assert ledger.get_ref_metadata(SessionId("sess-a"), ref.ref_id) is None
    assert ledger._committed_view.refs["sess-a"][ref.ref_id] == ref
    assert ref.ref_id in ledger._refs["sess-a"]
    assert ledger._is_temporarily_unreadable("sess-a", ref.ref_id) is True
    assert ledger.state_degraded is True
    assert ledger.cleanup_allowed is False
    if stage is not AtomicWriteStage.PARENT_FSYNC:
        assert (evidence_root / "refs_index.json").read_bytes() == committed_index


def test_f3_evidence_successful_eviction_clears_marker_before_same_ref_reuse(
    tmp_path: Path,
) -> None:
    ledger = ArtifactLedger(tmp_path / "evidence", salt=b"a" * 32)
    ref = _store(ledger)
    ledger._refs["sess-a"][ref.ref_id] = ref.model_copy(
        update={"created_at": ref.created_at.replace(year=2000)}
    )
    ledger._mark_temporarily_unreadable("sess-a", ref.ref_id, "kms_unavailable")

    assert ledger.evict_expired(SessionId("sess-a"), max_age_seconds=60) == [ref.ref_id]
    recreated = _store(ledger)

    assert recreated.ref_id == ref.ref_id
    assert ledger._is_temporarily_unreadable("sess-a", ref.ref_id) is False
    assert ledger.validate_ref_metadata(SessionId("sess-a"), ref.ref_id) is True


def test_f3_evidence_hash_mismatch_commits_ref_removal_before_blob_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    ledger = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(ledger)
    blob_path = evidence_root / "blobs" / f"{ref.content_hash}.txt"
    blob_path.write_bytes(b"tampered runtime blob")
    events: list[str] = []
    original_persist = ledger._persist_refs_index
    original_delete = ledger._delete_blob_if_unreferenced

    def _persist(refs: dict[str, dict[str, EvidenceRef]]) -> None:
        original_persist(refs)
        assert refs == {}
        events.append("index_committed")

    def _delete(content_hash: str) -> None:
        assert events == ["index_committed"]
        events.append("blob_delete")
        original_delete(content_hash)

    monkeypatch.setattr(ledger, "_persist_refs_index", _persist)
    monkeypatch.setattr(ledger, "_delete_blob_if_unreferenced", _delete)

    assert ledger.read(SessionId("sess-a"), ref.ref_id) is None

    assert events == ["index_committed", "blob_delete"]
    assert blob_path.exists() is False
    assert _index_payload(evidence_root / "refs_index.json") == {}
    restarted = ArtifactLedger(evidence_root, salt=b"a" * 32)
    assert restarted.get_ref_metadata(SessionId("sess-a"), ref.ref_id) is None


def test_f3_evidence_blob_delete_failure_gates_cleanup_after_index_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    ledger = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(ledger)
    ledger._refs["sess-a"][ref.ref_id] = ref.model_copy(
        update={"created_at": ref.created_at.replace(year=2000)}
    )
    blob_path = evidence_root / "blobs" / f"{ref.content_hash}.txt"
    blob_bytes = blob_path.read_bytes()
    original_unlink = Path.unlink

    def _fail_blob_unlink(path: Path, missing_ok: bool = False) -> None:
        if path == blob_path:
            raise OSError("blob delete failed")
        original_unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", _fail_blob_unlink)

    assert ledger.evict_expired(SessionId("sess-a"), max_age_seconds=60) == [ref.ref_id]

    assert _index_payload(evidence_root / "refs_index.json") == {}
    assert ledger.get_ref_metadata(SessionId("sess-a"), ref.ref_id) is None
    assert blob_path.read_bytes() == blob_bytes
    _assert_degraded(ledger, reason="blob_delete_failed")
    assert ledger.collect_garbage() == []
    assert list((evidence_root / "quarantine").iterdir()) == []


@pytest.mark.parametrize("failure_kind", ["unlink", "parent_fsync"])
def test_f3_evidence_batch_removal_stops_after_first_blob_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
) -> None:
    evidence_root = tmp_path / "evidence"
    ledger = ArtifactLedger(evidence_root, salt=b"a" * 32)
    first = _store(ledger, content="first expired blob")
    second = _store(ledger, content="second expired blob")
    for ref in (first, second):
        ledger._refs["sess-a"][ref.ref_id] = ref.model_copy(
            update={"created_at": ref.created_at.replace(year=2000)}
        )
    first_blob = evidence_root / "blobs" / f"{first.content_hash}.txt"
    second_blob = evidence_root / "blobs" / f"{second.content_hash}.txt"
    first_bytes = first_blob.read_bytes()
    second_bytes = second_blob.read_bytes()
    cleanup_attempts: list[str] = []

    if failure_kind == "unlink":
        original_unlink = Path.unlink

        def _fail_first_unlink(path: Path, missing_ok: bool = False) -> None:
            if path in {first_blob, second_blob}:
                cleanup_attempts.append(path.name)
            if path == first_blob:
                raise OSError("first blob unlink failed")
            original_unlink(path, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", _fail_first_unlink)
    else:
        original_fsync = ledger._fsync_directory

        def _fail_first_blob_parent(path: Path) -> None:
            if path == evidence_root / "blobs":
                cleanup_attempts.append(path.name)
                raise OSError("first blob parent fsync failed")
            original_fsync(path)

        monkeypatch.setattr(ledger, "_fsync_directory", _fail_first_blob_parent)

    assert ledger.evict_expired(SessionId("sess-a"), max_age_seconds=60) == [
        first.ref_id,
        second.ref_id,
    ]

    assert _index_payload(evidence_root / "refs_index.json") == {}
    _assert_degraded(ledger, reason="blob_delete_failed")
    assert len(cleanup_attempts) == 1
    if failure_kind == "unlink":
        assert first_blob.read_bytes() == first_bytes
    else:
        assert first_blob.exists() is False
    assert second_blob.read_bytes() == second_bytes
    assert list((evidence_root / "quarantine").iterdir()) == []


def test_f3_evidence_concurrent_evict_then_store_serializes_without_stale_snapshot(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    ledger = ArtifactLedger(evidence_root, salt=b"a" * 32)
    old_ref = _store(ledger, content="old")
    ledger._refs["sess-a"][old_ref.ref_id] = old_ref.model_copy(
        update={"created_at": old_ref.created_at.replace(year=2000)}
    )
    writer_entered = Event()
    writer_release = Event()
    evicted: list[str] = []
    stored: list[EvidenceRef] = []
    errors: list[BaseException] = []

    def _pause_first_write(stage: AtomicWriteStage) -> None:
        if stage is AtomicWriteStage.WRITE and not writer_entered.is_set():
            writer_entered.set()
            assert writer_release.wait(timeout=5.0)

    ledger._atomic_fault_injector = _pause_first_write

    def _evict() -> None:
        try:
            evicted.extend(ledger.evict_expired(SessionId("sess-a"), max_age_seconds=60))
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    def _store_new() -> None:
        try:
            stored.append(_store(ledger, content="new"))
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    evict_thread = Thread(target=_evict)
    store_thread = Thread(target=_store_new)
    evict_thread.start()
    assert writer_entered.wait(timeout=5.0)
    store_thread.start()
    writer_release.set()
    evict_thread.join(timeout=5.0)
    store_thread.join(timeout=5.0)

    assert errors == []
    assert evicted == [old_ref.ref_id]
    assert len(stored) == 1
    assert ledger.get_ref_metadata(SessionId("sess-a"), old_ref.ref_id) is None
    assert ledger.get_ref_metadata(SessionId("sess-a"), stored[0].ref_id) == stored[0]
    restarted = ArtifactLedger(evidence_root, salt=b"a" * 32)
    assert restarted.get_ref_metadata(SessionId("sess-a"), old_ref.ref_id) is None
    assert restarted.get_ref_metadata(SessionId("sess-a"), stored[0].ref_id) == stored[0]


def test_f3_evidence_failed_evict_rollback_cannot_overwrite_waiting_store(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    ledger = ArtifactLedger(evidence_root, salt=b"a" * 32)
    old_ref = _store(ledger, content="old")
    ledger._refs["sess-a"][old_ref.ref_id] = old_ref.model_copy(
        update={"created_at": old_ref.created_at.replace(year=2000)}
    )
    writer_entered = Event()
    writer_release = Event()
    evict_errors: list[BaseException] = []
    store_errors: list[BaseException] = []

    def _fail_first_write(stage: AtomicWriteStage) -> None:
        if stage is AtomicWriteStage.WRITE and not writer_entered.is_set():
            writer_entered.set()
            assert writer_release.wait(timeout=5.0)
            raise OSError("eviction write failed")

    ledger._atomic_fault_injector = _fail_first_write

    def _evict() -> None:
        try:
            ledger.evict_expired(SessionId("sess-a"), max_age_seconds=60)
        except BaseException as exc:  # pragma: no cover - asserted below
            evict_errors.append(exc)

    def _store_new() -> None:
        try:
            _store(ledger, content="new")
        except BaseException as exc:  # pragma: no cover - asserted below
            store_errors.append(exc)

    evict_thread = Thread(target=_evict)
    store_thread = Thread(target=_store_new)
    evict_thread.start()
    assert writer_entered.wait(timeout=5.0)
    store_thread.start()
    writer_release.set()
    evict_thread.join(timeout=5.0)
    store_thread.join(timeout=5.0)

    assert len(evict_errors) == 1
    assert isinstance(evict_errors[0], AtomicWriteError)
    assert len(store_errors) == 1
    assert isinstance(store_errors[0], StatePersistenceDegradedError)
    assert ledger.get_ref_metadata(SessionId("sess-a"), old_ref.ref_id) is None
    assert ledger._committed_view.refs["sess-a"][old_ref.ref_id] == old_ref
    assert ledger.committed_ref_count() == 1
    assert ledger.state_degraded is True
    assert ledger.cleanup_allowed is False


def test_f3_evidence_quarantine_is_collision_safe_and_uses_durable_timestamp(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    ArtifactLedger(evidence_root, salt=b"a" * 32)
    orphan_hash = "d" * 64
    orphan_blob = evidence_root / "blobs" / f"{orphan_hash}.txt"
    orphan_blob.write_bytes(b"first orphan")

    ArtifactLedger(evidence_root)
    first_entries = sorted((evidence_root / "quarantine").iterdir())
    assert len(first_entries) == 1
    assert first_entries[0].name.startswith("v1.")
    assert first_entries[0].read_bytes() == b"first orphan"

    orphan_blob.write_bytes(b"second orphan")
    ArtifactLedger(evidence_root)
    entries = sorted((evidence_root / "quarantine").iterdir())
    assert len(entries) == 2
    assert {path.read_bytes() for path in entries} == {b"first orphan", b"second orphan"}
    assert len({path.name for path in entries}) == 2


def test_f3_evidence_legacy_quarantine_migration_uses_new_time_not_mtime(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    ArtifactLedger(evidence_root, salt=b"a" * 32)
    legacy = evidence_root / "quarantine" / f"{'e' * 64}.txt"
    legacy.write_bytes(b"legacy quarantine")
    os.utime(legacy, (1, 1))

    ArtifactLedger(evidence_root, orphan_retention_seconds=1)

    entries = list((evidence_root / "quarantine").iterdir())
    assert len(entries) == 1
    assert entries[0].name.startswith("v1.")
    assert entries[0].read_bytes() == b"legacy quarantine"


def test_f3_evidence_prune_uses_parseable_quarantine_time_and_fsyncs_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    ArtifactLedger(evidence_root, salt=b"a" * 32)
    quarantine = evidence_root / "quarantine"
    old_entry = quarantine / f"v1.1.{uuid4().hex}.{'f' * 64}.txt"
    old_entry.write_bytes(b"expired quarantine")
    fsynced_paths: list[Path] = []

    original_fsync_directory = ArtifactLedger._fsync_directory

    def _record_fsync(path: Path) -> None:
        fsynced_paths.append(path)
        original_fsync_directory(path)

    monkeypatch.setattr(ArtifactLedger, "_fsync_directory", staticmethod(_record_fsync))

    ArtifactLedger(evidence_root, orphan_retention_seconds=1)

    assert old_entry.exists() is False
    assert quarantine in fsynced_paths


def test_f3_evidence_explicit_reset_is_only_destructive_domain_recovery(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    first = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(first)
    blob_path = evidence_root / "blobs" / f"{ref.content_hash}.txt"
    (evidence_root / "evidence_salt").unlink()
    degraded = ArtifactLedger(evidence_root)
    assert blob_path.exists() is True

    reset = degraded.reset_domain()

    assert reset["status"] == "ok"
    assert reset["destroyed_ref_count"] == 0
    assert degraded.state_degraded is False
    assert degraded.cleanup_allowed is True
    assert degraded.committed_ref_count() == 0
    assert degraded.is_empty_domain() is True
    assert degraded.domain_file_count() == 2
    assert blob_path.exists() is False
    assert degraded.state_load_result().status is StateLoadStatus.OK
    assert degraded.state_load_result().reason == "explicit_reset"
    assert _index_payload(evidence_root / "refs_index.json") == {}


def test_f3_evidence_reset_detach_fsync_failure_restores_old_domain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    ledger = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(ledger)
    original = ArtifactLedger._fsync_directory
    parent_calls = 0

    def _fail_first_parent(path: Path) -> None:
        nonlocal parent_calls
        if path == tmp_path:
            parent_calls += 1
            if parent_calls == 1:
                raise OSError("detach parent fsync failed")
        original(path)

    monkeypatch.setattr(
        ArtifactLedger,
        "_fsync_directory",
        staticmethod(_fail_first_parent),
    )

    with pytest.raises(OSError, match="detach parent fsync failed"):
        ledger.reset_domain()

    assert ledger.state_degraded is False
    assert ledger.read(SessionId("sess-a"), ref.ref_id) == "evidence"
    restarted = ArtifactLedger(evidence_root, salt=b"a" * 32)
    assert restarted.read(SessionId("sess-a"), ref.ref_id) == "evidence"


def test_f3_evidence_reset_create_failure_restores_old_domain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    ledger = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(ledger)

    def _fail_create(_salt: bytes) -> None:
        raise OSError("replacement create failed")

    monkeypatch.setattr(ledger, "_create_domain_files", _fail_create)

    with pytest.raises(OSError, match="replacement create failed"):
        ledger.reset_domain()

    assert ledger.state_degraded is False
    assert ledger.read(SessionId("sess-a"), ref.ref_id) == "evidence"
    restarted = ArtifactLedger(evidence_root, salt=b"a" * 32)
    assert restarted.read(SessionId("sess-a"), ref.ref_id) == "evidence"


@pytest.mark.parametrize("stage", list(AtomicWriteStage))
def test_f3_evidence_reset_atomic_create_fault_restores_old_domain(
    tmp_path: Path,
    stage: AtomicWriteStage,
) -> None:
    evidence_root = tmp_path / "evidence"
    ledger = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(ledger)

    def _fault(observed: AtomicWriteStage) -> None:
        if observed is stage:
            raise OSError(f"reset fault at {stage.value}")

    ledger._atomic_fault_injector = _fault

    with pytest.raises(AtomicWriteError):
        ledger.reset_domain()

    assert ledger.state_degraded is False
    assert ledger.read(SessionId("sess-a"), ref.ref_id) == "evidence"
    restarted = ArtifactLedger(evidence_root, salt=b"a" * 32)
    assert restarted.read(SessionId("sess-a"), ref.ref_id) == "evidence"


def test_f3_evidence_reset_cleanup_failure_is_typed_and_restart_recoverable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    ledger = ArtifactLedger(evidence_root, salt=b"a" * 32)
    ref = _store(ledger)
    original_remove = ledger._remove_path

    def _fail_tombstone_cleanup(path: Path) -> None:
        if ".reset-" in path.name:
            raise OSError("tombstone cleanup failed")
        original_remove(path)

    monkeypatch.setattr(ledger, "_remove_path", _fail_tombstone_cleanup)

    with pytest.raises(OSError, match="tombstone cleanup failed"):
        ledger.reset_domain()

    _assert_degraded(ledger, reason="reset_cleanup_failed")
    assert ledger._committed_view.refs == {}
    assert ledger.get_ref_metadata(SessionId("sess-a"), ref.ref_id) is None
    tombstones = list(tmp_path.glob(".evidence.reset-*"))
    assert len(tombstones) == 1
    assert list(tombstones[0].glob(f"blobs/{ref.content_hash}.txt"))
    restarted = ArtifactLedger(evidence_root)
    _assert_degraded(restarted, reason="reset_cleanup_required")
    recovered = restarted.reset_domain()
    assert recovered["status"] == "ok"
    assert restarted.is_empty_domain() is True
    assert list(tmp_path.glob(".evidence.reset-*")) == []


@pytest.mark.parametrize("invalid_kind", ["file", "symlink"])
def test_f3_evidence_reset_recovers_invalid_root_without_touching_external_target(
    tmp_path: Path,
    invalid_kind: str,
) -> None:
    evidence_root = tmp_path / "evidence"
    external = tmp_path / "external-root"
    external.mkdir()
    external_file = external / "retained.txt"
    external_file.write_bytes(b"external bytes")
    if invalid_kind == "file":
        evidence_root.write_bytes(b"invalid root bytes")
    else:
        evidence_root.symlink_to(external, target_is_directory=True)
    ledger = ArtifactLedger(evidence_root)
    _assert_degraded(ledger, reason="invalid_evidence_root")

    result = ledger.reset_domain()

    assert result["status"] == "ok"
    assert ledger.is_empty_domain() is True
    assert evidence_root.is_dir() is True
    assert evidence_root.is_symlink() is False
    assert external_file.read_bytes() == b"external bytes"


class _RecoverableGateCodec:
    name = "recoverable_gate"

    def __init__(self) -> None:
        self.available = True
        self.decode_calls = 0

    def encode(self, content: str) -> bytes:
        return content.encode("utf-8")

    def decode(self, payload: bytes) -> str:
        self.decode_calls += 1
        if not self.available:
            raise ArtifactBlobCodecError("kms_unavailable")
        return payload.decode("utf-8")


def test_f3_evidence_kms_recovery_is_one_domain_wide_single_flight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence_root = tmp_path / "evidence"
    codec = _RecoverableGateCodec()
    first = ArtifactLedger(evidence_root, salt=b"a" * 32, blob_codec=codec)
    first_ref = _store(first, sid="sess-a", content="first")
    second_ref = _store(first, sid="sess-b", content="second")
    codec.available = False
    restarted = ArtifactLedger(evidence_root, salt=b"a" * 32, blob_codec=codec)
    _assert_degraded(restarted, reason="blob_unreadable")
    baseline_calls = codec.decode_calls
    codec.available = True
    original_probe = restarted._probe_temporarily_unreadable_domain
    probe_entered = Event()
    probe_release = Event()
    probe_calls = 0

    def _blocking_probe() -> None:
        nonlocal probe_calls
        probe_calls += 1
        probe_entered.set()
        assert probe_release.wait(timeout=5.0)
        original_probe()

    monkeypatch.setattr(
        restarted,
        "_probe_temporarily_unreadable_domain",
        _blocking_probe,
    )

    assert restarted.validate_ref_metadata(SessionId("sess-a"), first_ref.ref_id) is False
    assert probe_entered.wait(timeout=5.0)
    assert restarted.validate_ref_metadata(SessionId("sess-b"), second_ref.ref_id) is False
    assert len(restarted._unreadable_probe_in_flight) == 1
    assert probe_calls == 1
    probe_release.set()
    deadline = time.time() + 5.0
    while restarted._unreadable_probe_in_flight and time.time() < deadline:
        time.sleep(0.01)

    assert restarted._unreadable_probe_in_flight == set()
    assert codec.decode_calls - baseline_calls == 2
    assert restarted.state_degraded is False
    assert restarted.get_ref_metadata(SessionId("sess-a"), first_ref.ref_id) == first_ref
    assert restarted.get_ref_metadata(SessionId("sess-b"), second_ref.ref_id) == second_ref


def test_f3_evidence_ref_and_collection_are_deeply_immutable() -> None:
    labels = [TaintLabel.UNTRUSTED]
    ref = EvidenceRef(
        ref_id="ev-immutable",
        content_hash="a" * 64,
        taint_labels=labels,
        source="unit-test",
        summary="immutable",
        byte_size=9,
    )
    labels.append(TaintLabel.USER_REVIEWED)

    assert ref.taint_labels == (TaintLabel.UNTRUSTED,)
    with pytest.raises(ValidationError):
        ref.summary = "mutated"  # type: ignore[misc]

    update_labels = [TaintLabel.UNTRUSTED, TaintLabel.USER_REVIEWED]
    copied = ref.model_copy(update={"taint_labels": update_labels})
    update_labels.clear()

    assert copied.taint_labels == (
        TaintLabel.UNTRUSTED,
        TaintLabel.USER_REVIEWED,
    )
    with pytest.raises(AttributeError):
        copied.taint_labels.append(TaintLabel.SENSITIVE_FILE)  # type: ignore[attr-defined]


def test_f3_evidence_committed_snapshot_is_nested_frozen_and_returned_ref_cannot_mutate(
    tmp_path: Path,
) -> None:
    ledger = ArtifactLedger(tmp_path / "evidence", salt=b"a" * 32)
    ref = _store(ledger)
    view = ledger._committed_view
    returned = ledger.get_ref_metadata(SessionId("sess-a"), ref.ref_id)

    assert returned == ref
    with pytest.raises(TypeError):
        view.refs["new"] = {}  # type: ignore[index]
    with pytest.raises(TypeError):
        view.refs["sess-a"][ref.ref_id] = ref  # type: ignore[index]
    assert returned is not None
    with pytest.raises(ValidationError):
        returned.endorsed_by = "forged"  # type: ignore[misc]


def test_f3_evidence_inflight_writer_leaves_lock_free_prior_committed_snapshot(
    tmp_path: Path,
) -> None:
    ledger = ArtifactLedger(tmp_path / "evidence", salt=b"a" * 32)
    prior = _store(ledger, content="prior")
    writer_entered = Event()
    writer_release = Event()
    stored: list[EvidenceRef] = []

    def _pause_first_write(stage: AtomicWriteStage) -> None:
        if stage is AtomicWriteStage.WRITE and not writer_entered.is_set():
            writer_entered.set()
            assert writer_release.wait(timeout=5.0)

    ledger._atomic_fault_injector = _pause_first_write

    def _store_new() -> None:
        stored.append(_store(ledger, content="pending"))

    writer = Thread(target=_store_new)
    writer.start()
    assert writer_entered.wait(timeout=5.0)
    pending_hash = sha256(b"pending").hexdigest()
    pending_ref_id = ledger._make_ref_id(
        session_id=SessionId("sess-a"),
        content_hash=pending_hash,
    )
    started = time.monotonic()

    assert ledger.get_ref_metadata(SessionId("sess-a"), prior.ref_id) == prior
    assert ledger.validate_ref_metadata(SessionId("sess-a"), prior.ref_id) is True
    assert ledger.get_ref_metadata(SessionId("sess-a"), pending_ref_id) is None
    assert time.monotonic() - started < 0.1

    writer_release.set()
    writer.join(timeout=5.0)
    assert len(stored) == 1
    assert ledger.get_ref_metadata(SessionId("sess-a"), stored[0].ref_id) == stored[0]


def test_f3_evidence_failed_writer_keeps_frozen_refs_but_metadata_rejects_degradation(
    tmp_path: Path,
) -> None:
    ledger = ArtifactLedger(tmp_path / "evidence", salt=b"a" * 32)
    prior = _store(ledger, content="prior")

    def _fail_write(stage: AtomicWriteStage) -> None:
        if stage is AtomicWriteStage.WRITE:
            raise OSError("writer failed")

    ledger._atomic_fault_injector = _fail_write
    with pytest.raises(AtomicWriteError):
        _store(ledger, content="failed")

    assert ledger._committed_view.refs["sess-a"][prior.ref_id] == prior
    assert ledger.get_ref_metadata(SessionId("sess-a"), prior.ref_id) is None
    assert ledger.validate_ref_metadata(SessionId("sess-a"), prior.ref_id) is False


def test_f3_evidence_status_is_actionable_without_claiming_whole_daemon_failure(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    first = ArtifactLedger(evidence_root, salt=b"a" * 32)
    _store(first)
    (evidence_root / "refs_index.json").write_bytes(b"{not-json")

    degraded = ArtifactLedger(evidence_root)
    status = degraded.state_status()

    assert status["status"] == "degraded"
    assert status["scope"] == "evidence_only"
    assert status["fail_closed"] is True
    assert "restore" in status["remediation"].lower()
    assert "explicit" in status["remediation"].lower()
    assert "reset" in status["remediation"].lower()
