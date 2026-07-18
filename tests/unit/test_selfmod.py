"""M1 self-modification manager coverage."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

import shisad.selfmod.manager as selfmod_manager_module
from shisad.core.atomic_state import (
    AtomicWriteError,
    AtomicWriteStage,
    StateLoadStatus,
    StatePersistenceDegradedError,
    encode_versioned_json_snapshot,
)
from shisad.core.tools.registry import ToolRegistry
from shisad.core.types import ToolName
from shisad.security.policy import SkillPolicy
from shisad.selfmod import SelfModificationManager
from shisad.skills.manager import SkillManager


def _write_owner_only_bytes(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def _write_owner_only_text(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o600)


class _PlannerStub:
    def __init__(self) -> None:
        self.defaults: list[tuple[str, str]] = []

    def set_persona_defaults(self, *, tone: str, custom_text: str) -> None:
        self.defaults.append((tone, custom_text))


def _generate_ssh_keypair(tmp_path: Path, *, name: str) -> Path:
    key_path = tmp_path / name
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return key_path


def _write_allowed_signers(path: Path, *, principal: str, public_key: Path) -> None:
    key_type, key_value, *_rest = public_key.read_text(encoding="utf-8").strip().split()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'{principal} namespaces="file" {key_type} {key_value}\n',
        encoding="utf-8",
    )


def _sign_manifest(manifest_path: Path, *, key_path: Path) -> None:
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", "file", str(manifest_path)],
        check=True,
        capture_output=True,
        text=True,
    )


def _skill_manifest_payload(*, tool_name: str = "lookup") -> dict[str, Any]:
    return {
        "manifest_version": "1.0.0",
        "name": "calendar-helper",
        "version": "1.0.0",
        "author": "trusted-dev",
        "signature": "",
        "source_repo": "https://github.com/trusted-dev/calendar-helper",
        "description": "calendar helper",
        "capabilities": {
            "network": [{"domain": "api.good.example", "reason": "calendar api"}],
            "filesystem": [],
            "shell": [],
            "environment": [],
        },
        "dependencies": [],
        "tools": [
            {
                "name": tool_name,
                "description": "Look up calendar entries.",
                "parameters": [{"name": "query", "type": "string", "required": True}],
                "destinations": ["api.good.example"],
            }
        ],
    }


def _write_signed_skill_bundle(root: Path, *, key_path: Path, version: str = "1.0.0") -> Path:
    payload_root = root / "payload"
    payload_root.mkdir(parents=True, exist_ok=True)
    skill_manifest = _skill_manifest_payload()
    skill_manifest["version"] = version
    (payload_root / "skill.manifest.yaml").write_text(
        yaml.safe_dump(skill_manifest, sort_keys=False),
        encoding="utf-8",
    )
    (payload_root / "SKILL.md").write_text("Use the lookup tool for schedule reads.\n")
    files: list[dict[str, Any]] = []
    for path in sorted(payload_root.rglob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        files.append(
            {
                "path": str(path.relative_to(root)),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    manifest = {
        "schema_version": "1",
        "type": "skill_bundle",
        "name": "calendar-helper",
        "version": version,
        "created_at": "2026-03-09T00:00:00+00:00",
        "files": files,
        "declared_capabilities": {
            "network": ["api.good.example"],
            "filesystem": [],
            "shell": [],
            "environment": [],
            "tools": ["skill.calendar-helper.lookup"],
        },
        "provenance": {
            "source_repo": "https://github.com/trusted-dev/calendar-helper",
            "builder_id": "pytest",
        },
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    _sign_manifest(manifest_path, key_path=key_path)
    return root


def _write_signed_behavior_pack(
    root: Path,
    *,
    key_path: Path,
    version: str,
    tone: str,
    custom_text: str,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "instructions.yaml").write_text(
        yaml.safe_dump(
            {
                "tone": tone,
                "custom_persona_text": custom_text,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "manifest.json.sig":
            continue
        if path.name == "manifest.json":
            continue
        data = path.read_bytes()
        files.append(
            {
                "path": str(path.relative_to(root)),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    manifest = {
        "schema_version": "1",
        "type": "behavior_pack",
        "name": "operator-tone",
        "version": version,
        "created_at": "2026-03-09T00:00:00+00:00",
        "files": files,
        "declared_capabilities": {
            "network": [],
            "filesystem": [],
            "shell": [],
            "environment": [],
            "tools": [],
        },
        "provenance": {
            "source_repo": "https://github.com/trusted-dev/behavior-pack",
            "builder_id": "pytest",
        },
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    _sign_manifest(manifest_path, key_path=key_path)
    return root


def _build_manager(
    tmp_path: Path,
    *,
    allowed_signers_path: Path,
) -> tuple[SelfModificationManager, _PlannerStub]:
    planner = _PlannerStub()
    skill_manager = SkillManager(
        storage_dir=tmp_path / "skills-state",
        policy=SkillPolicy(
            require_signature_for_auto_install=False,
            require_review_on_update=False,
        ),
        tool_registry=ToolRegistry(),
    )
    manager = SelfModificationManager(
        root=tmp_path / "selfmod",
        allowed_signers_path=allowed_signers_path,
        skill_manager=skill_manager,
        planner=planner,
        default_persona_tone="neutral",
        default_persona_text="",
    )
    return manager, planner


def _rewrite_manifest(
    artifact_root: Path,
    *,
    key_path: Path,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    manifest_path = artifact_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mutate(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    signature_path = artifact_root / "manifest.json.sig"
    if signature_path.exists():
        signature_path.unlink()
    _sign_manifest(manifest_path, key_path=key_path)


def test_f3_selfmod_missing_inventory_is_healthy_and_applies_defaults(tmp_path: Path) -> None:
    manager, planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "allowed_signers",
    )

    result = manager.inventory_load_result()

    assert result.status == StateLoadStatus.MISSING
    assert manager.state_degraded is False
    assert planner.defaults == [("neutral", "")]
    assert manager.status()["inventory"]["status"] == "ok"


def test_f3_selfmod_legacy_empty_domain_is_initialized_then_guarded(
    tmp_path: Path,
) -> None:
    root = tmp_path / "selfmod"
    for child in ("proposals", "changes", "artifacts"):
        (root / child).mkdir(parents=True, exist_ok=True)

    manager, planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "allowed_signers",
    )

    assert manager.inventory_load_result().status == StateLoadStatus.MISSING
    assert manager.state_degraded is False
    assert planner.defaults == [("neutral", "")]
    assert manager._inventory_path.exists()

    manager._inventory_path.unlink()
    restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "allowed_signers",
    )

    assert restarted.inventory_load_result().status == StateLoadStatus.CORRUPT
    assert restarted.state_degraded is True
    assert restarted_planner.defaults == []


def test_f3_selfmod_existing_domain_missing_inventory_blocks_coupled_skill(
    tmp_path: Path,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    applied = manager.apply(manager.propose(artifact).proposal_id, confirm=True)
    assert applied.applied is True
    tool_name = ToolName("skill.calendar-helper.lookup")
    assert manager._skill_manager._tool_registry.get_tool(tool_name) is not None
    inventory_path = manager._inventory_path
    inventory_path.unlink()

    restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )

    assert restarted.inventory_load_result().status == StateLoadStatus.CORRUPT
    assert restarted.inventory_load_result().reason == "inventory_missing_existing_root"
    assert restarted.state_degraded is True
    assert restarted_planner.defaults == []
    assert restarted._skill_manager._tool_registry.get_tool(tool_name) is None
    assert any(restarted._artifact_root.rglob("manifest.json"))


def test_f3_selfmod_corrupt_inventory_is_retained_and_blocks_runtime(
    tmp_path: Path,
) -> None:
    selfmod_root = tmp_path / "selfmod"
    selfmod_root.mkdir()
    inventory_path = selfmod_root / "inventory.yaml"
    corrupt_bytes = b'{"version":1,"payload":'
    _write_owner_only_bytes(inventory_path, corrupt_bytes)
    registry = ToolRegistry()
    skill_manager = SkillManager(
        storage_dir=tmp_path / "skills-state",
        policy=SkillPolicy(
            require_signature_for_auto_install=False,
            require_review_on_update=False,
        ),
        tool_registry=registry,
    )
    skill_root = tmp_path / "active-skill"
    payload = skill_root / "payload"
    payload.mkdir(parents=True)
    (payload / "skill.manifest.yaml").write_text(
        yaml.safe_dump(_skill_manifest_payload(), sort_keys=False),
        encoding="utf-8",
    )
    (payload / "SKILL.md").write_text("safe helper\n", encoding="utf-8")
    skill_manager.activate_bundle(payload)
    tool_name = ToolName("skill.calendar-helper.lookup")
    assert registry.get_tool(tool_name) is not None
    planner = _PlannerStub()

    manager = SelfModificationManager(
        root=selfmod_root,
        allowed_signers_path=tmp_path / "allowed_signers",
        skill_manager=skill_manager,
        planner=planner,
        default_persona_tone="neutral",
        default_persona_text="",
    )

    result = manager.inventory_load_result()
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "invalid_json"
    assert manager.state_degraded is True
    assert planner.defaults == []
    assert registry.get_tool(tool_name) is None
    assert skill_manager.state_degraded is True
    assert "selfmod" in skill_manager.state_status()["remediation"]
    with pytest.raises(StatePersistenceDegradedError, match="invalid_json"):
        manager.rollback("a" * 32)
    assert inventory_path.read_bytes() == corrupt_bytes
    status_payload = manager.status()["inventory"]
    assert status_payload["status"] == "degraded"
    assert status_payload["load_status"] == "corrupt"
    assert status_payload["fail_closed"] is True


@pytest.mark.parametrize(
    ("recursive_bytes", "expected_reason"),
    [
        pytest.param(
            (b"[" * 10000) + b"0" + (b"]" * 10000),
            "invalid_json",
            id="json",
        ),
        pytest.param((b"- " * 10000) + b"0\n", "invalid_yaml", id="yaml"),
    ],
)
def test_f3_selfmod_recursive_inventory_is_typed_and_retained(
    tmp_path: Path,
    recursive_bytes: bytes,
    expected_reason: str,
) -> None:
    selfmod_root = tmp_path / "selfmod"
    selfmod_root.mkdir()
    inventory_path = selfmod_root / "inventory.yaml"
    _write_owner_only_bytes(inventory_path, recursive_bytes)

    manager, planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "allowed_signers",
    )

    result = manager.inventory_load_result()
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == expected_reason
    assert manager.state_degraded is True
    assert planner.defaults == []
    assert inventory_path.read_bytes() == recursive_bytes


@pytest.mark.parametrize(
    ("snapshot", "status", "reason"),
    [
        (
            encode_versioned_json_snapshot([], version=1),
            StateLoadStatus.CORRUPT,
            "invalid_inventory_payload",
        ),
        (
            encode_versioned_json_snapshot(
                {"skills": {"broken": {"enabled": True}}, "behavior_packs": {}},
                version=1,
            ),
            StateLoadStatus.CORRUPT,
            "invalid_inventory_entry",
        ),
        (
            encode_versioned_json_snapshot(
                {"skills": {}, "behavior_packs": {}},
                version=99,
            ),
            StateLoadStatus.UNSUPPORTED_SCHEMA,
            "unsupported_schema",
        ),
    ],
)
def test_f3_selfmod_inventory_shape_failures_are_typed_and_retained(
    tmp_path: Path,
    snapshot: bytes,
    status: StateLoadStatus,
    reason: str,
) -> None:
    root = tmp_path / "selfmod"
    root.mkdir()
    inventory_path = root / "inventory.yaml"
    _write_owner_only_bytes(inventory_path, snapshot)

    manager, planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "allowed_signers",
    )

    result = manager.inventory_load_result()
    assert result.status == status
    assert result.reason == reason
    assert planner.defaults == []
    assert inventory_path.read_bytes() == snapshot


@pytest.mark.parametrize("snapshot_kind", ["legacy", "versioned"])
@pytest.mark.parametrize("artifact_kind", ["skill", "behavior_pack"])
def test_f3_selfmod_inventory_requires_native_enabled_boolean(
    tmp_path: Path,
    snapshot_kind: str,
    artifact_kind: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_kind == "skill":
        artifact = _write_signed_skill_bundle(tmp_path / "artifact", key_path=key_path)
        bucket = "skills"
        name = "calendar-helper"
    else:
        artifact = _write_signed_behavior_pack(
            tmp_path / "artifact",
            key_path=key_path,
            version="1.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
        bucket = "behavior_packs"
        name = "operator-tone"
    assert manager.apply(manager.propose(artifact).proposal_id, confirm=True).applied is True
    inventory_path = manager._inventory_path
    envelope = json.loads(inventory_path.read_text(encoding="utf-8"))
    payload = envelope["payload"]
    payload[bucket][name]["enabled"] = "yes"
    if snapshot_kind == "legacy":
        retained = yaml.safe_dump(payload, sort_keys=True).encode()
    else:
        retained = encode_versioned_json_snapshot(payload, version=1)
    _write_owner_only_bytes(inventory_path, retained)

    restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )

    assert restarted.inventory_load_result().status == StateLoadStatus.CORRUPT
    assert restarted.inventory_load_result().reason == "invalid_inventory_entry"
    assert restarted_planner.defaults == []
    assert restarted._skill_manager._tool_registry.list_tools() == []
    assert inventory_path.read_bytes() == retained


def test_f3_selfmod_inventory_symlink_is_retained_and_rejected(tmp_path: Path) -> None:
    root = tmp_path / "selfmod"
    root.mkdir()
    target = tmp_path / "outside.yaml"
    target.write_text("skills: {}\nbehavior_packs: {}\n", encoding="utf-8")
    inventory_path = root / "inventory.yaml"
    inventory_path.symlink_to(target)

    manager, planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "allowed_signers",
    )

    result = manager.inventory_load_result()
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "invalid_inventory_target"
    assert planner.defaults == []
    assert inventory_path.is_symlink()


@pytest.mark.parametrize("unsafe_shape", ["mode", "hardlink"])
def test_f3_selfmod_inventory_reopen_rejects_unsafe_file(
    tmp_path: Path,
    unsafe_shape: str,
) -> None:
    manager, _planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "allowed_signers",
    )
    inventory_path = manager._inventory_path
    retained = inventory_path.read_bytes()
    if unsafe_shape == "mode":
        inventory_path.chmod(0o640)
    else:
        os.link(inventory_path, tmp_path / "selfmod-inventory-alias")

    restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "allowed_signers",
    )

    assert restarted.inventory_load_result().status == StateLoadStatus.CORRUPT
    assert restarted.inventory_load_result().reason == "inventory_read_failed"
    assert restarted_planner.defaults == []
    assert inventory_path.read_bytes() == retained


def test_f3_selfmod_symlinked_root_never_loads_or_mutates_external_domain(
    tmp_path: Path,
) -> None:
    outside_root = tmp_path / "outside-selfmod"
    outside_root.mkdir()
    inventory_path = outside_root / "inventory.yaml"
    inventory_bytes = b"skills: {}\nbehavior_packs: {}\n"
    inventory_path.write_bytes(inventory_bytes)
    (tmp_path / "selfmod").symlink_to(outside_root, target_is_directory=True)

    manager, planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "allowed_signers",
    )

    result = manager.inventory_load_result()
    assert result.status == StateLoadStatus.CORRUPT
    assert result.reason == "invalid_selfmod_root"
    assert planner.defaults == []
    assert inventory_path.read_bytes() == inventory_bytes
    assert sorted(path.name for path in outside_root.iterdir()) == ["inventory.yaml"]


def test_f3_selfmod_legacy_inventory_migrates_with_owner_only_modes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "selfmod"
    root.mkdir()
    inventory_path = root / "inventory.yaml"
    _write_owner_only_text(inventory_path, "skills: {}\nbehavior_packs: {}\n")
    previous_umask = os.umask(0)
    try:
        manager, _planner = _build_manager(
            tmp_path,
            allowed_signers_path=tmp_path / "allowed_signers",
        )
        assert manager.inventory_load_result().legacy is True
        manager._persist_inventory()
    finally:
        os.umask(previous_umask)

    envelope = json.loads(inventory_path.read_text(encoding="utf-8"))
    assert envelope["version"] == 1
    assert "checksum" in envelope
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(inventory_path.stat().st_mode) == 0o600


def test_f3_selfmod_proposal_is_checksum_bound_and_owner_only(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    previous_umask = os.umask(0)
    try:
        proposal = manager.propose(artifact)
    finally:
        os.umask(previous_umask)

    proposal_path = manager._proposal_path(proposal.proposal_id)
    envelope = json.loads(proposal_path.read_text(encoding="utf-8"))
    assert envelope["version"] == 1
    assert envelope["payload"]["proposal_id"] == proposal.proposal_id
    assert "checksum" in envelope
    assert stat.S_IMODE(proposal_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(proposal_path.parent.stat().st_mode) == 0o700


def test_f3_selfmod_change_and_incident_records_are_owner_only(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_behavior_pack(
        tmp_path / "behavior-pack",
        key_path=key_path,
        version="1.0.0",
        tone="strict",
        custom_text="Stay strict.",
    )
    previous_umask = os.umask(0)
    try:
        applied = manager.apply(manager.propose(artifact).proposal_id, confirm=True)
        manager._record_incident(
            proposal_id="a" * 32,
            artifact_path=str(artifact),
            reason="test_incident",
        )
    finally:
        os.umask(previous_umask)

    assert applied.applied is True
    change_path = manager._change_path(applied.change_id)
    assert stat.S_IMODE(change_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(change_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(manager._incident_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(manager._incident_path.parent.stat().st_mode) == 0o700


@pytest.mark.parametrize(
    ("record_kind", "expected_reason"),
    [("proposal", "proposal_corrupt"), ("change", "change_corrupt")],
)
def test_f3_selfmod_corrupt_control_record_is_retained_and_not_missing(
    tmp_path: Path,
    record_kind: str,
    expected_reason: str,
) -> None:
    manager, _planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "allowed_signers",
    )
    record_id = "a" * 32
    path = (
        manager._proposal_path(record_id)
        if record_kind == "proposal"
        else manager._change_path(record_id)
    )
    corrupt_bytes = b'{"version":1,"payload":'
    _write_owner_only_bytes(path, corrupt_bytes)

    result = (
        manager.apply(record_id, confirm=True)
        if record_kind == "proposal"
        else manager.rollback(record_id)
    )

    assert result.reason == expected_reason
    assert path.read_bytes() == corrupt_bytes
    record_status = manager.status()["records"][record_kind]
    assert record_status["load_status"] == "corrupt"
    assert record_status["reason"] == "invalid_json"
    doctor = manager.doctor_status()
    assert doctor["status"] == "degraded"
    assert doctor["records"][record_kind]["load_status"] == "corrupt"
    assert f"selfmod_{record_kind}_corrupt" in doctor["problems"]


def test_f3_selfmod_corrupt_incident_is_retained_and_actionable(tmp_path: Path) -> None:
    manager, _planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "allowed_signers",
    )
    corrupt_bytes = b'{"version":1,"payload":'
    _write_owner_only_bytes(manager._incident_path, corrupt_bytes)

    status_payload = manager.status()

    assert status_payload["incident"] == {}
    assert status_payload["records"]["incident"]["load_status"] == "corrupt"
    assert status_payload["records"]["incident"]["reason"] == "invalid_json"
    assert manager._incident_path.read_bytes() == corrupt_bytes


def test_f3_selfmod_future_proposal_is_retained_and_not_missing(tmp_path: Path) -> None:
    manager, _planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "allowed_signers",
    )
    proposal_id = "b" * 32
    path = manager._proposal_path(proposal_id)
    snapshot = encode_versioned_json_snapshot({}, version=99)
    _write_owner_only_bytes(path, snapshot)

    result = manager.apply(proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "proposal_unsupported_schema"
    assert path.read_bytes() == snapshot
    assert manager.status()["records"]["proposal"]["load_status"] == ("unsupported_schema")


def test_f3_selfmod_legacy_raw_proposal_with_artifact_version_remains_readable(
    tmp_path: Path,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    proposal = manager.propose(artifact)
    proposal_path = manager._proposal_path(proposal.proposal_id)
    envelope = json.loads(proposal_path.read_text(encoding="utf-8"))
    _write_owner_only_text(proposal_path, json.dumps(envelope["payload"]))

    preview = manager.apply(proposal.proposal_id, confirm=False)

    assert preview.requires_confirmation is True
    assert manager.status()["records"]["proposal"]["legacy"] is True


def test_f3_selfmod_legacy_proposal_rejects_duplicate_members(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    proposal = manager.propose(artifact)
    proposal_path = manager._proposal_path(proposal.proposal_id)
    payload = json.loads(proposal_path.read_text(encoding="utf-8"))["payload"]
    payload_json = json.dumps(payload, separators=(",", ":"))
    duplicated_payload = payload_json.replace(
        '"artifact_type":"skill_bundle"',
        '"artifact_type":"behavior_pack","artifact_type":"skill_bundle"',
        1,
    )
    assert duplicated_payload != payload_json
    ambiguous_bytes = duplicated_payload.encode()
    _write_owner_only_bytes(proposal_path, ambiguous_bytes)

    result = manager.apply(proposal.proposal_id, confirm=False)

    assert result.applied is False
    assert result.reason == "proposal_corrupt"
    assert manager.status()["records"]["proposal"]["reason"] == "invalid_json"
    assert proposal_path.read_bytes() == ambiguous_bytes


@pytest.mark.parametrize(
    "mutation",
    ["artifact_type", "unsafe_name", "record_id", "manifest_identity", "extra"],
)
def test_f3_selfmod_semantically_invalid_proposal_is_retained_as_corrupt(
    tmp_path: Path,
    mutation: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    proposal = manager.propose(artifact)
    path = manager._proposal_path(proposal.proposal_id)
    payload = json.loads(path.read_text(encoding="utf-8"))["payload"]
    if mutation == "artifact_type":
        payload["artifact_type"] = "unknown"
    elif mutation == "unsafe_name":
        payload["name"] = "../escape"
    elif mutation == "record_id":
        payload["proposal_id"] = "b" * 32
    elif mutation == "manifest_identity":
        payload["version"] = "2.0.0"
    else:
        payload["unexpected"] = True
    snapshot = encode_versioned_json_snapshot(payload, version=1)
    _write_owner_only_bytes(path, snapshot)

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "proposal_corrupt"
    assert path.read_bytes() == snapshot


@pytest.mark.parametrize("mutation", ["artifact_type", "unsafe_name", "record_id", "extra"])
def test_f3_selfmod_semantically_invalid_change_is_retained_as_corrupt(
    tmp_path: Path,
    mutation: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_behavior_pack(
        tmp_path / "behavior-pack",
        key_path=key_path,
        version="1.0.0",
        tone="strict",
        custom_text="Stay strict.",
    )
    applied = manager.apply(manager.propose(artifact).proposal_id, confirm=True)
    path = manager._change_path(applied.change_id)
    payload = json.loads(path.read_text(encoding="utf-8"))["payload"]
    if mutation == "artifact_type":
        payload["artifact_type"] = "unknown"
    elif mutation == "unsafe_name":
        payload["name"] = "../escape"
    elif mutation == "record_id":
        payload["change_id"] = "b" * 32
    else:
        payload["unexpected"] = True
    snapshot = encode_versioned_json_snapshot(payload, version=1)
    _write_owner_only_bytes(path, snapshot)

    result = manager.rollback(applied.change_id)

    assert result.rolled_back is False
    assert result.reason == "change_corrupt"
    assert path.read_bytes() == snapshot


@pytest.mark.parametrize("record_kind", ["legacy", "versioned"])
def test_f3_selfmod_proposal_requires_native_valid_boolean(
    tmp_path: Path,
    record_kind: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "artifact", key_path=key_path)
    proposal = manager.propose(artifact)
    path = manager._proposal_path(proposal.proposal_id)
    payload = json.loads(path.read_text(encoding="utf-8"))["payload"]
    payload["valid"] = "yes"
    retained = (
        json.dumps(payload, sort_keys=True).encode()
        if record_kind == "legacy"
        else encode_versioned_json_snapshot(payload, version=1)
    )
    _write_owner_only_bytes(path, retained)

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "proposal_corrupt"
    assert manager._skill_manager._tool_registry.list_tools() == []
    assert path.read_bytes() == retained


@pytest.mark.parametrize("record_kind", ["legacy", "versioned"])
def test_f3_selfmod_change_requires_native_previous_enabled_boolean(
    tmp_path: Path,
    record_kind: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    stable = _write_signed_behavior_pack(
        tmp_path / "stable",
        key_path=key_path,
        version="1.0.0",
        tone="friendly",
        custom_text="Stay warm.",
    )
    assert manager.apply(manager.propose(stable).proposal_id, confirm=True).applied is True
    candidate = _write_signed_behavior_pack(
        tmp_path / "candidate",
        key_path=key_path,
        version="1.0.1",
        tone="strict",
        custom_text="Stay strict.",
    )
    applied = manager.apply(manager.propose(candidate).proposal_id, confirm=True)
    assert applied.applied is True
    path = manager._change_path(applied.change_id)
    payload = json.loads(path.read_text(encoding="utf-8"))["payload"]
    payload["previous_enabled"] = "yes"
    retained = (
        json.dumps(payload, sort_keys=True).encode()
        if record_kind == "legacy"
        else encode_versioned_json_snapshot(payload, version=1)
    )
    _write_owner_only_bytes(path, retained)

    result = manager.rollback(applied.change_id)

    assert result.rolled_back is False
    assert result.reason == "change_corrupt"
    assert planner.defaults[-1] == ("strict", "Stay strict.")
    assert path.read_bytes() == retained


@pytest.mark.parametrize("artifact_kind", ["skill", "behavior"])
def test_f3_selfmod_startup_artifact_io_failure_degrades_without_aborting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_kind: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_kind == "skill":
        artifact = _write_signed_skill_bundle(tmp_path / "artifact", key_path=key_path)
    else:
        artifact = _write_signed_behavior_pack(
            tmp_path / "artifact",
            key_path=key_path,
            version="1.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
    applied = manager.apply(manager.propose(artifact).proposal_id, confirm=True)
    assert applied.applied is True

    def _inspection_io_failure(**_kwargs: object) -> tuple[bool, str]:
        raise OSError("unreadable active payload")

    monkeypatch.setattr(
        selfmod_manager_module,
        "_validate_manifest_files",
        _inspection_io_failure,
    )

    restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )

    assert restarted.state_degraded is True
    assert restarted.inventory_load_result().reason == "active_artifact_invalid"
    assert restarted_planner.defaults == []
    assert restarted._skill_manager.state_degraded is True
    assert restarted._skill_manager._tool_registry.list_tools() == []


@pytest.mark.parametrize(
    "fault_stage",
    [
        AtomicWriteStage.TEMP_OPEN,
        AtomicWriteStage.WRITE,
        AtomicWriteStage.FILE_FSYNC,
        AtomicWriteStage.REPLACE,
        AtomicWriteStage.PARENT_FSYNC,
    ],
)
def test_f3_selfmod_proposal_record_atomic_fault_is_old_or_new(
    tmp_path: Path,
    fault_stage: AtomicWriteStage,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)

    def _inject(stage: AtomicWriteStage) -> None:
        if stage == fault_stage:
            raise OSError(f"fault:{stage.value}")

    manager._state_fault_injector = _inject
    with pytest.raises(AtomicWriteError) as exc_info:
        manager.propose(artifact)

    assert exc_info.value.publication_may_have_committed is (
        fault_stage == AtomicWriteStage.PARENT_FSYNC
    )
    proposal_files = list(manager._proposal_dir.glob("*.json"))
    assert bool(proposal_files) is (fault_stage == AtomicWriteStage.PARENT_FSYNC)


@pytest.mark.parametrize(
    "fault_stage",
    [
        AtomicWriteStage.TEMP_OPEN,
        AtomicWriteStage.WRITE,
        AtomicWriteStage.FILE_FSYNC,
        AtomicWriteStage.REPLACE,
        AtomicWriteStage.PARENT_FSYNC,
    ],
)
def test_f3_selfmod_apply_inventory_fault_precedes_behavior_runtime(
    tmp_path: Path,
    fault_stage: AtomicWriteStage,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_behavior_pack(
        tmp_path / "behavior-pack",
        key_path=key_path,
        version="1.0.0",
        tone="strict",
        custom_text="Stay strict.",
    )
    proposal = manager.propose(artifact)

    def _inject(stage: AtomicWriteStage) -> None:
        if stage == fault_stage:
            raise OSError(f"fault:{stage.value}")

    manager._state_fault_injector = _inject
    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == (
        "inventory_persistence_uncertain"
        if fault_stage == AtomicWriteStage.PARENT_FSYNC
        else "inventory_persist_failed"
    )
    assert planner.defaults[-1] == ("neutral", "")
    assert manager.state_degraded is (fault_stage == AtomicWriteStage.PARENT_FSYNC)
    restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    if fault_stage == AtomicWriteStage.PARENT_FSYNC:
        assert manager._authority_block_path.exists()
        assert restarted.state_degraded is True
        assert restarted_planner.defaults == []
    else:
        assert restarted.inventory_load_result().status == StateLoadStatus.OK
        assert restarted.status()["behavior_packs"] == {}
        assert restarted_planner.defaults[-1] == ("neutral", "")


def test_f3_selfmod_parent_fsync_restart_guard_blocks_uncertain_skill_activation(
    tmp_path: Path,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    proposal = manager.propose(artifact)

    def _inject(stage: AtomicWriteStage) -> None:
        if stage == AtomicWriteStage.PARENT_FSYNC:
            raise OSError("fault:parent_fsync")

    manager._state_fault_injector = _inject
    result = manager.apply(proposal.proposal_id, confirm=True)

    tool_name = ToolName("skill.calendar-helper.lookup")
    assert result.applied is False
    assert result.reason == "inventory_persistence_uncertain"
    assert manager._skill_manager._tool_registry.get_tool(tool_name) is None

    restarted, _restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )

    assert manager._authority_block_path.exists()
    assert restarted.state_degraded is True
    assert restarted._skill_manager._tool_registry.get_tool(tool_name) is None


@pytest.mark.parametrize(
    "fault_stage",
    [
        AtomicWriteStage.TEMP_OPEN,
        AtomicWriteStage.WRITE,
        AtomicWriteStage.FILE_FSYNC,
        AtomicWriteStage.REPLACE,
        AtomicWriteStage.PARENT_FSYNC,
    ],
)
def test_f3_selfmod_rollback_inventory_fault_precedes_behavior_runtime(
    tmp_path: Path,
    fault_stage: AtomicWriteStage,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_behavior_pack(
        tmp_path / "behavior-pack",
        key_path=key_path,
        version="1.0.0",
        tone="strict",
        custom_text="Stay strict.",
    )
    applied = manager.apply(manager.propose(artifact).proposal_id, confirm=True)
    assert applied.applied is True
    assert planner.defaults[-1] == ("strict", "Stay strict.")

    def _inject(stage: AtomicWriteStage) -> None:
        if stage == fault_stage:
            raise OSError(f"fault:{stage.value}")

    manager._state_fault_injector = _inject
    result = manager.rollback(applied.change_id)

    assert result.rolled_back is False
    assert result.reason == (
        "inventory_persistence_uncertain"
        if fault_stage == AtomicWriteStage.PARENT_FSYNC
        else "inventory_persist_failed"
    )
    assert planner.defaults[-1] == ("strict", "Stay strict.")
    assert manager.state_degraded is (fault_stage == AtomicWriteStage.PARENT_FSYNC)
    _restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    if fault_stage == AtomicWriteStage.PARENT_FSYNC:
        assert restarted_planner.defaults[-1] == ("neutral", "")
    else:
        assert restarted_planner.defaults[-1] == ("strict", "Stay strict.")


@pytest.mark.parametrize(
    "fault_stage",
    [
        AtomicWriteStage.TEMP_OPEN,
        AtomicWriteStage.WRITE,
        AtomicWriteStage.FILE_FSYNC,
        AtomicWriteStage.REPLACE,
        AtomicWriteStage.PARENT_FSYNC,
    ],
)
def test_f3_selfmod_change_record_fault_restores_inventory_and_runtime(
    tmp_path: Path,
    fault_stage: AtomicWriteStage,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_behavior_pack(
        tmp_path / "behavior-pack",
        key_path=key_path,
        version="1.0.0",
        tone="strict",
        custom_text="Stay strict.",
    )
    proposal = manager.propose(artifact)
    occurrences = 0

    def _inject(stage: AtomicWriteStage) -> None:
        nonlocal occurrences
        if stage == fault_stage:
            occurrences += 1
            if occurrences == 2:
                raise OSError(f"fault:{stage.value}")

    manager._state_fault_injector = _inject
    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "change_record_persist_failed"
    assert planner.defaults[-1] == ("neutral", "")
    assert manager.status()["behavior_packs"] == {}
    restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    assert restarted.state_degraded is False
    assert restarted_planner.defaults[-1] == ("neutral", "")


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
@pytest.mark.parametrize("transition", ["failed_apply", "rollback"])
def test_f3_selfmod_runtime_restore_failure_degrades_direct_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
    transition: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        stable = _write_signed_skill_bundle(
            tmp_path / "stable",
            key_path=key_path,
            version="1.0.0",
        )
        candidate = _write_signed_skill_bundle(
            tmp_path / "candidate",
            key_path=key_path,
            version="2.0.0",
        )
        status_key = "skills"
        artifact_name = "calendar-helper"
        transition_reason = "skill_activation_failed"
    else:
        stable = _write_signed_behavior_pack(
            tmp_path / "stable",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        candidate = _write_signed_behavior_pack(
            tmp_path / "candidate",
            key_path=key_path,
            version="2.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
        status_key = "behavior_packs"
        artifact_name = "operator-tone"
        transition_reason = "behavior_overlay_failed"
    assert manager.apply(manager.propose(stable).proposal_id, confirm=True).applied is True

    if transition == "failed_apply":
        proposal = manager.propose(candidate)

        def _fail_change_commit(*_args: object, **_kwargs: object) -> None:
            raise selfmod_manager_module._SelfModificationOperationError(
                "change_record_persist_failed"
            )

        monkeypatch.setattr(manager, "_commit_inventory_and_change", _fail_change_commit)
    else:
        applied = manager.apply(manager.propose(candidate).proposal_id, confirm=True)
        assert applied.applied is True

        def _fail_rollback_runtime(*_args: object, **_kwargs: object) -> list[str]:
            raise selfmod_manager_module._SelfModificationOperationError(transition_reason)

        monkeypatch.setattr(manager, "_apply_runtime_for_inventory", _fail_rollback_runtime)

    monkeypatch.setattr(manager, "_restore_runtime", lambda *_args, **_kwargs: False)

    if transition == "failed_apply":
        result = manager.apply(proposal.proposal_id, confirm=True)
        assert result.applied is False
        assert result.active_version == ""
    else:
        result = manager.rollback(applied.change_id)
        assert result.rolled_back is False
        assert result.active_version == ""

    assert result.reason == "runtime_restore_failed"
    assert manager.state_degraded is True
    assert manager.status()[status_key][artifact_name] == {
        "enabled": False,
        "active_version": "",
    }
    assert manager._authority_block_path.exists() is (transition == "failed_apply")


def test_m1_selfmod_propose_reports_skill_capability_diff(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)

    proposal = manager.propose(artifact)

    assert proposal.valid is True
    assert proposal.artifact_type == "skill_bundle"
    assert proposal.capability_diff["added"]["tools"] == ["skill.calendar-helper.lookup"]
    assert proposal.warnings


def test_m1_selfmod_rejects_invalid_identifiers(tmp_path: Path) -> None:
    manager, _planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "allowed_signers",
    )

    apply_result = manager.apply("../escape", confirm=True)
    rollback_result = manager.rollback("../escape")

    assert apply_result.applied is False
    assert apply_result.reason == "invalid_proposal_id"
    assert rollback_result.rolled_back is False
    assert rollback_result.reason == "invalid_change_id"


def test_m1_selfmod_missing_signature_returns_signature_missing(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    (artifact / "manifest.json.sig").unlink()

    proposal = manager.propose(artifact)

    assert proposal.valid is False
    assert proposal.reason == "signature_missing"


def test_m1_selfmod_invalid_manifest_without_signature_is_fail_closed(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = tmp_path / "invalid-artifact"
    artifact.mkdir(parents=True, exist_ok=True)
    (artifact / "manifest.json").write_text("{not-json", encoding="utf-8")

    proposal = manager.propose(artifact)

    assert proposal.valid is False
    assert proposal.reason == "invalid_manifest_schema"


def test_m1_selfmod_non_utf8_manifest_is_fail_closed(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = tmp_path / "invalid-utf8-artifact"
    artifact.mkdir(parents=True, exist_ok=True)
    (artifact / "manifest.json").write_bytes(b"\xff\xfe\xfd")
    (artifact / "manifest.json.sig").write_text("placeholder", encoding="utf-8")

    proposal = manager.propose(artifact)

    assert proposal.valid is False
    assert proposal.reason == "invalid_manifest_schema"


def test_m1_selfmod_missing_trust_store_fails_closed(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    manager, _planner = _build_manager(
        tmp_path,
        allowed_signers_path=tmp_path / "missing_allowed_signers",
    )
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)

    proposal = manager.propose(artifact)

    assert proposal.valid is False
    assert proposal.reason == "trust_store_missing"


def test_m1_selfmod_rejects_file_set_mismatch(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    (artifact / "payload" / "EXTRA.md").write_text("unexpected file\n", encoding="utf-8")

    proposal = manager.propose(artifact)

    assert proposal.valid is False
    assert proposal.reason == "file_set_mismatch"


def test_m1_selfmod_rejects_declared_capability_mismatch(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    _rewrite_manifest(
        artifact,
        key_path=key_path,
        mutate=lambda manifest: manifest.update({"declared_capabilities": {"tools": []}}),
    )

    proposal = manager.propose(artifact)

    assert proposal.valid is False
    assert proposal.reason == "declared_capabilities_mismatch"


def test_m1_selfmod_rejects_unsafe_artifact_identity_segments(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    _rewrite_manifest(
        artifact,
        key_path=key_path,
        mutate=lambda manifest: manifest.update({"name": "../escape"}),
    )

    proposal = manager.propose(artifact)

    assert proposal.valid is False
    assert proposal.reason == "invalid_manifest_schema"


def test_m1_selfmod_apply_rejects_proposal_artifact_swap(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    proposal = manager.propose(artifact)
    _rewrite_manifest(
        artifact,
        key_path=key_path,
        mutate=lambda manifest: manifest.update({"version": "2.0.0"}),
    )

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "proposal_artifact_changed"
    assert manager.status()["skills"] == {}


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_apply_publishes_only_staged_validated_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
        relative_path = Path("payload/SKILL.md")
        stored_root = tmp_path / "selfmod" / "artifacts" / "skills" / "calendar-helper"
        attacker_bytes = b"attacker skill instructions\n"
    else:
        artifact = _write_signed_behavior_pack(
            tmp_path / "behavior-pack",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        relative_path = Path("instructions.yaml")
        stored_root = tmp_path / "selfmod" / "artifacts" / "behavior_packs" / "operator-tone"
        attacker_bytes = b"tone: hostile\ncustom_persona_text: attacker instructions\n"
    approved_bytes = (artifact / relative_path).read_bytes()
    proposal = manager.propose(artifact)
    original_inspect = manager._inspect_artifact
    source_swapped = False

    def _inspect_then_swap_source(path: Path) -> Any:
        nonlocal source_swapped
        inspected = original_inspect(path)
        if not source_swapped:
            (artifact / relative_path).write_bytes(attacker_bytes)
            source_swapped = True
        return inspected

    monkeypatch.setattr(manager, "_inspect_artifact", _inspect_then_swap_source)

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is True
    assert (stored_root / "1.0.0" / relative_path).read_bytes() == approved_bytes
    assert (artifact / relative_path).read_bytes() == attacker_bytes


def test_f3_selfmod_apply_rejects_symlinked_source_during_staging(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    proposal = manager.propose(artifact)
    external = tmp_path / "external"
    external.mkdir()
    (external / "secret.txt").write_text("operator secret\n", encoding="utf-8")
    (artifact / "escape").symlink_to(external, target_is_directory=True)

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "artifact_store_copy_failed"
    artifact_root = tmp_path / "selfmod" / "artifacts"
    assert not any(path.is_file() for path in artifact_root.rglob("*"))


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_staging_rejects_symlinked_destination_bucket_without_external_mutation(
    tmp_path: Path,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
        bucket = "skills"
        name = "calendar-helper"
    else:
        artifact = _write_signed_behavior_pack(
            tmp_path / "behavior-pack",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        bucket = "behavior_packs"
        name = "operator-tone"
    proposal = manager.propose(artifact)
    external = tmp_path / "external"
    external.mkdir()
    bucket_path = tmp_path / "selfmod" / "artifacts" / bucket
    bucket_path.symlink_to(external, target_is_directory=True)

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "artifact_store_copy_failed"
    assert not (external / name).exists()


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_staging_creates_owner_only_namespace_parents_under_permissive_umask(
    tmp_path: Path,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
        bucket = "skills"
        name = "calendar-helper"
    else:
        artifact = _write_signed_behavior_pack(
            tmp_path / "behavior-pack",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        bucket = "behavior_packs"
        name = "operator-tone"
    proposal = manager.propose(artifact)
    previous_umask = os.umask(0)
    try:
        result = manager.apply(proposal.proposal_id, confirm=True)
    finally:
        os.umask(previous_umask)

    assert result.applied is True
    artifact_root = tmp_path / "selfmod" / "artifacts"
    assert stat.S_IMODE((artifact_root / bucket).stat().st_mode) == 0o700
    assert stat.S_IMODE((artifact_root / bucket / name).stat().st_mode) == 0o700


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_publication_fsync_failure_restores_absent_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
        target = tmp_path / "selfmod" / "artifacts" / "skills" / "calendar-helper" / "1.0.0"
    else:
        artifact = _write_signed_behavior_pack(
            tmp_path / "behavior-pack",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        target = tmp_path / "selfmod" / "artifacts" / "behavior_packs" / "operator-tone" / "1.0.0"
    proposal = manager.propose(artifact)
    calls = 0

    def _fail_first_directory_fsync(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("artifact publication fsync failed")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    monkeypatch.setattr(
        selfmod_manager_module,
        "fsync_directory",
        _fail_first_directory_fsync,
        raising=False,
    )

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "artifact_store_copy_failed"
    assert calls >= 2
    assert not target.exists()
    assert manager.status()["skills"] == {}
    assert manager.status()["behavior_packs"] == {}
    restarted, _planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    assert restarted.status()["skills"] == {}
    assert restarted.status()["behavior_packs"] == {}


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_publication_recovery_fsync_uncertainty_degrades_without_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        stable = _write_signed_skill_bundle(tmp_path / "stable", key_path=key_path)
        candidate = _write_signed_skill_bundle(tmp_path / "candidate", key_path=key_path)
        status_key = "skills"
        artifact_name = "calendar-helper"
    else:
        stable = _write_signed_behavior_pack(
            tmp_path / "stable",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        candidate = _write_signed_behavior_pack(
            tmp_path / "candidate",
            key_path=key_path,
            version="1.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
        status_key = "behavior_packs"
        artifact_name = "operator-tone"
    assert manager.apply(manager.propose(stable).proposal_id, confirm=True).applied is True
    proposal = manager.propose(candidate)

    def _fail_publication_and_recovery_fsync(_path: Path) -> None:
        raise OSError("publication durability uncertain")

    monkeypatch.setattr(
        selfmod_manager_module,
        "fsync_directory",
        _fail_publication_and_recovery_fsync,
    )

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "artifact_store_restore_failed"
    assert result.active_version == ""
    assert manager.state_degraded is True
    assert manager.status()[status_key][artifact_name] == {
        "enabled": False,
        "active_version": "",
    }
    assert planner.defaults[-1] == ("neutral", "")


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_pre_runtime_restore_fsync_uncertainty_degrades_without_candidate_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        stable = _write_signed_skill_bundle(tmp_path / "stable", key_path=key_path)
        candidate = _write_signed_skill_bundle(tmp_path / "candidate", key_path=key_path)
        status_key = "skills"
        artifact_name = "calendar-helper"
    else:
        stable = _write_signed_behavior_pack(
            tmp_path / "stable",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        candidate = _write_signed_behavior_pack(
            tmp_path / "candidate",
            key_path=key_path,
            version="1.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
        status_key = "behavior_packs"
        artifact_name = "operator-tone"
    assert manager.apply(manager.propose(stable).proposal_id, confirm=True).applied is True
    proposal = manager.propose(candidate)

    inventory_write_failed = False

    def _fail_inventory_write(stage: AtomicWriteStage) -> None:
        nonlocal inventory_write_failed
        if not inventory_write_failed and stage == AtomicWriteStage.TEMP_OPEN:
            inventory_write_failed = True
            raise OSError("inventory write failed")

    manager._state_fault_injector = _fail_inventory_write
    fsync_calls = 0

    def _fail_restore_directory_fsync(path: Path) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 2:
            raise OSError("restore durability uncertain")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    monkeypatch.setattr(selfmod_manager_module, "fsync_directory", _fail_restore_directory_fsync)

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "artifact_store_restore_failed"
    assert result.active_version == ""
    assert manager.state_degraded is True
    assert manager.status()[status_key][artifact_name] == {
        "enabled": False,
        "active_version": "",
    }
    assert planner.defaults[-1] == ("neutral", "")
    restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    assert restarted.status()[status_key][artifact_name] == {
        "enabled": False,
        "active_version": "",
    }
    assert restarted._skill_manager._tool_registry.list_tools() == []
    assert restarted_planner.defaults[-1] == ("neutral", "")


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_publish_restore_and_finalize_fsync_the_artifact_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        stable = _write_signed_skill_bundle(tmp_path / "stable", key_path=key_path)
        candidate = _write_signed_skill_bundle(tmp_path / "candidate", key_path=key_path)
    else:
        stable = _write_signed_behavior_pack(
            tmp_path / "stable",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        candidate = _write_signed_behavior_pack(
            tmp_path / "candidate",
            key_path=key_path,
            version="1.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
    assert manager.apply(manager.propose(stable).proposal_id, confirm=True).applied is True
    fsynced: list[Path] = []

    def _record_directory_fsync(path: Path) -> None:
        fsynced.append(path)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    monkeypatch.setattr(
        selfmod_manager_module,
        "fsync_directory",
        _record_directory_fsync,
        raising=False,
    )
    proposal = manager.propose(candidate)
    original_commit = manager._commit_inventory_and_change

    def _fail_change_commit(*_args: object, **_kwargs: object) -> None:
        raise selfmod_manager_module._SelfModificationOperationError("change_record_persist_failed")

    monkeypatch.setattr(manager, "_commit_inventory_and_change", _fail_change_commit)
    failed = manager.apply(proposal.proposal_id, confirm=True)
    assert failed.applied is False
    assert failed.reason == "change_record_persist_failed"
    assert len(fsynced) >= 2

    monkeypatch.setattr(manager, "_commit_inventory_and_change", original_commit)
    fsynced.clear()
    succeeded = manager.apply(proposal.proposal_id, confirm=True)
    assert succeeded.applied is True
    assert len(fsynced) >= 2


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_failed_initial_backup_rename_preserves_active_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        stable = _write_signed_skill_bundle(tmp_path / "stable", key_path=key_path)
        candidate = _write_signed_skill_bundle(tmp_path / "candidate", key_path=key_path)
        target = tmp_path / "selfmod" / "artifacts" / "skills" / "calendar-helper" / "1.0.0"
    else:
        stable = _write_signed_behavior_pack(
            tmp_path / "stable",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        candidate = _write_signed_behavior_pack(
            tmp_path / "candidate",
            key_path=key_path,
            version="1.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
        target = tmp_path / "selfmod" / "artifacts" / "behavior_packs" / "operator-tone" / "1.0.0"
    assert manager.apply(manager.propose(stable).proposal_id, confirm=True).applied is True
    original_replace = Path.replace

    def _fail_initial_backup_rename(path: Path, replacement: Path) -> Path:
        if path == target and replacement.name.startswith(".1.0.0.bak-"):
            raise OSError("initial backup rename failed")
        return original_replace(path, replacement)

    monkeypatch.setattr(Path, "replace", _fail_initial_backup_rename)

    result = manager.apply(manager.propose(candidate).proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "artifact_store_copy_failed"
    assert target.exists()
    restarted, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    status_key = "skills" if artifact_type == "skill_bundle" else "behavior_packs"
    assert restarted.status()[status_key][target.parent.name]["active_version"] == "1.0.0"


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_restore_fsync_failure_still_restores_runtime_and_degrades(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        stable = _write_signed_skill_bundle(tmp_path / "stable", key_path=key_path)
        candidate = _write_signed_skill_bundle(tmp_path / "candidate", key_path=key_path)
    else:
        stable = _write_signed_behavior_pack(
            tmp_path / "stable",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        candidate = _write_signed_behavior_pack(
            tmp_path / "candidate",
            key_path=key_path,
            version="1.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
    assert manager.apply(manager.propose(stable).proposal_id, confirm=True).applied is True
    proposal = manager.propose(candidate)
    original_restore_runtime = manager._restore_runtime
    runtime_restore_attempted = False

    def _record_runtime_restore(*args: object, **kwargs: object) -> None:
        nonlocal runtime_restore_attempted
        runtime_restore_attempted = True
        original_restore_runtime(*args, **kwargs)

    monkeypatch.setattr(manager, "_restore_runtime", _record_runtime_restore)

    def _fail_change_commit(*_args: object, **_kwargs: object) -> None:
        raise selfmod_manager_module._SelfModificationOperationError("change_record_persist_failed")

    monkeypatch.setattr(manager, "_commit_inventory_and_change", _fail_change_commit)
    fsync_calls = 0

    def _fail_restore_directory_fsync(path: Path) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 2:
            raise OSError("artifact restore fsync failed")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    monkeypatch.setattr(selfmod_manager_module, "fsync_directory", _fail_restore_directory_fsync)

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "artifact_store_restore_failed"
    assert result.active_version == ""
    assert runtime_restore_attempted is True
    assert manager.state_degraded is True
    if artifact_type == "skill_bundle":
        assert manager._skill_manager._tool_registry.list_tools() == []
    else:
        assert planner.defaults[-1] == ("neutral", "")
    restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    status_key = "skills" if artifact_type == "skill_bundle" else "behavior_packs"
    artifact_name = "calendar-helper" if artifact_type == "skill_bundle" else "operator-tone"
    assert restarted.status()[status_key][artifact_name] == {
        "enabled": False,
        "active_version": "",
    }
    if artifact_type == "skill_bundle":
        assert restarted._skill_manager._tool_registry.list_tools() == []
    else:
        assert restarted_planner.defaults[-1] == ("neutral", "")


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
@pytest.mark.parametrize("recovery_failure", ["candidate_eviction", "backup_restore"])
def test_f3_selfmod_publication_recovery_failure_quarantines_authority_across_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
    recovery_failure: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        stable = _write_signed_skill_bundle(tmp_path / "stable", key_path=key_path)
        candidate = _write_signed_skill_bundle(tmp_path / "candidate", key_path=key_path)
        target = tmp_path / "selfmod" / "artifacts" / "skills" / "calendar-helper" / "1.0.0"
        status_key = "skills"
        artifact_name = "calendar-helper"
    else:
        stable = _write_signed_behavior_pack(
            tmp_path / "stable",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        candidate = _write_signed_behavior_pack(
            tmp_path / "candidate",
            key_path=key_path,
            version="1.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
        target = tmp_path / "selfmod" / "artifacts" / "behavior_packs" / "operator-tone" / "1.0.0"
        status_key = "behavior_packs"
        artifact_name = "operator-tone"
    assert manager.apply(manager.propose(stable).proposal_id, confirm=True).applied is True
    proposal = manager.propose(candidate)

    with monkeypatch.context() as faults:
        if recovery_failure == "candidate_eviction":
            fsync_calls = 0

            def _fail_publication_fsync(path: Path) -> None:
                nonlocal fsync_calls
                fsync_calls += 1
                if fsync_calls == 1:
                    raise OSError("candidate publication fsync failed")
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)

            original_remove = manager._remove_artifact_tree

            def _fail_candidate_eviction(path: Path) -> None:
                if path == target:
                    raise OSError("candidate eviction failed")
                original_remove(path)

            faults.setattr(selfmod_manager_module, "fsync_directory", _fail_publication_fsync)
            faults.setattr(
                SelfModificationManager,
                "_remove_artifact_tree",
                staticmethod(_fail_candidate_eviction),
            )
        else:
            original_replace = Path.replace

            def _fail_candidate_publish_and_backup_restore(
                path: Path,
                replacement: Path,
            ) -> Path:
                if path.name.startswith(".1.0.0.tmp-") and replacement == target:
                    raise OSError("candidate publish failed")
                if path.name.startswith(".1.0.0.bak-") and replacement == target:
                    raise OSError("backup restore failed")
                return original_replace(path, replacement)

            faults.setattr(Path, "replace", _fail_candidate_publish_and_backup_restore)

        result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "artifact_store_restore_failed"
    assert manager.state_degraded is True
    current_entry = manager.status()[status_key][artifact_name]
    assert current_entry == {"enabled": False, "active_version": ""}
    if artifact_type == "skill_bundle":
        assert manager._skill_manager._tool_registry.list_tools() == []
    else:
        assert planner.defaults[-1] == ("neutral", "")

    restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    restarted_entry = restarted.status()[status_key][artifact_name]
    assert restarted_entry == {"enabled": False, "active_version": ""}
    if artifact_type == "skill_bundle":
        assert restarted._skill_manager._tool_registry.list_tools() == []
    else:
        assert restarted_planner.defaults[-1] == ("neutral", "")


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_quarantine_write_failure_keeps_write_ahead_restart_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        stable = _write_signed_skill_bundle(tmp_path / "stable", key_path=key_path)
        candidate = _write_signed_skill_bundle(tmp_path / "candidate", key_path=key_path)
        target = tmp_path / "selfmod" / "artifacts" / "skills" / "calendar-helper" / "1.0.0"
        status_key = "skills"
        artifact_name = "calendar-helper"
    else:
        stable = _write_signed_behavior_pack(
            tmp_path / "stable",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        candidate = _write_signed_behavior_pack(
            tmp_path / "candidate",
            key_path=key_path,
            version="1.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
        target = tmp_path / "selfmod" / "artifacts" / "behavior_packs" / "operator-tone" / "1.0.0"
        status_key = "behavior_packs"
        artifact_name = "operator-tone"
    assert manager.apply(manager.propose(stable).proposal_id, confirm=True).applied is True
    proposal = manager.propose(candidate)
    quarantine_write_failed = False

    def _fail_quarantine_write(stage: AtomicWriteStage) -> None:
        nonlocal quarantine_write_failed
        if not quarantine_write_failed and stage == AtomicWriteStage.TEMP_OPEN:
            quarantine_write_failed = True
            raise OSError("quarantine inventory write failed")

    manager._state_fault_injector = _fail_quarantine_write
    with monkeypatch.context() as faults:
        fsync_calls = 0

        def _fail_publication_fsync(path: Path) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            if fsync_calls == 1:
                raise OSError("candidate publication fsync failed")
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

        original_remove = manager._remove_artifact_tree

        def _fail_candidate_eviction(path: Path) -> None:
            if path == target:
                raise OSError("candidate eviction failed")
            original_remove(path)

        faults.setattr(selfmod_manager_module, "fsync_directory", _fail_publication_fsync)
        faults.setattr(
            SelfModificationManager,
            "_remove_artifact_tree",
            staticmethod(_fail_candidate_eviction),
        )
        result = manager.apply(proposal.proposal_id, confirm=True)
    manager._state_fault_injector = None

    assert result.applied is False
    assert result.reason == "artifact_store_restore_failed"
    assert quarantine_write_failed is True
    assert manager.state_degraded is True
    assert manager.status()[status_key][artifact_name] == {
        "enabled": False,
        "active_version": "",
    }
    if artifact_type == "skill_bundle":
        assert manager._skill_manager._tool_registry.list_tools() == []
    else:
        assert planner.defaults[-1] == ("neutral", "")
    assert manager._authority_block_path.exists()

    restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    assert restarted.state_degraded is True
    assert restarted.status()[status_key] == {}
    if artifact_type == "skill_bundle":
        assert restarted._skill_manager._tool_registry.list_tools() == []
    else:
        assert restarted_planner.defaults == []


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
@pytest.mark.parametrize("publication_may_have_committed", [False, True])
def test_f3_selfmod_write_ahead_guard_failure_aborts_before_authority_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
    publication_may_have_committed: bool,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        stable = _write_signed_skill_bundle(tmp_path / "stable", key_path=key_path)
        candidate = _write_signed_skill_bundle(tmp_path / "candidate", key_path=key_path)
        target = tmp_path / "selfmod" / "artifacts" / "skills" / "calendar-helper" / "1.0.0"
    else:
        stable = _write_signed_behavior_pack(
            tmp_path / "stable",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
        candidate = _write_signed_behavior_pack(
            tmp_path / "candidate",
            key_path=key_path,
            version="1.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
        target = tmp_path / "selfmod" / "artifacts" / "behavior_packs" / "operator-tone" / "1.0.0"
    assert manager.apply(manager.propose(stable).proposal_id, confirm=True).applied is True
    proposal = manager.propose(candidate)
    target_stat = target.stat()
    original_atomic_write = selfmod_manager_module.atomic_write_bytes

    def _fail_guard_publication(path: Path, payload: bytes, **kwargs: Any) -> int:
        if path == manager._authority_block_path:
            if publication_may_have_committed:
                original_atomic_write(path, payload, **kwargs)
            raise AtomicWriteError(
                path=path,
                stage=(
                    AtomicWriteStage.PARENT_FSYNC
                    if publication_may_have_committed
                    else AtomicWriteStage.TEMP_OPEN
                ),
                publication_may_have_committed=publication_may_have_committed,
            )
        return original_atomic_write(path, payload, **kwargs)

    monkeypatch.setattr(selfmod_manager_module, "atomic_write_bytes", _fail_guard_publication)

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == (
        "authority_guard_persistence_uncertain"
        if publication_may_have_committed
        else "authority_guard_persist_failed"
    )
    assert manager.state_degraded is publication_may_have_committed
    assert manager._authority_block_path.exists() is publication_may_have_committed
    assert (target.stat().st_dev, target.stat().st_ino) == (target_stat.st_dev, target_stat.st_ino)
    assert not any(path.name.startswith(".1.0.0.tmp-") for path in target.parent.iterdir())
    if publication_may_have_committed:
        assert str(manager._authority_block_path) in manager.inventory_state_status()["remediation"]
        restarted, restarted_planner = _build_manager(
            tmp_path,
            allowed_signers_path=allowed_signers,
        )
        assert restarted.state_degraded is True
        if artifact_type == "skill_bundle":
            assert restarted._skill_manager._tool_registry.list_tools() == []
        else:
            assert restarted_planner.defaults == []
    elif artifact_type == "skill_bundle":
        assert manager._skill_manager._tool_registry.list_tools()
    else:
        assert planner.defaults[-1] == ("friendly", "Stay warm.")


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_write_ahead_guard_cleanup_failure_remains_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        artifact = _write_signed_skill_bundle(tmp_path / "skill", key_path=key_path)
        status_key = "skills"
        artifact_name = "calendar-helper"
    else:
        artifact = _write_signed_behavior_pack(
            tmp_path / "behavior",
            key_path=key_path,
            version="1.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
        status_key = "behavior_packs"
        artifact_name = "operator-tone"
    proposal = manager.propose(artifact)
    original_atomic_write = selfmod_manager_module.atomic_write_bytes

    def _fail_guard_completion(path: Path, payload: bytes, **kwargs: Any) -> int:
        if (
            path == manager._authority_block_path
            and payload == selfmod_manager_module._SELFMOD_AUTHORITY_GUARD_COMPLETE_MARKER
        ):
            raise AtomicWriteError(
                path=path,
                stage=AtomicWriteStage.TEMP_OPEN,
                publication_may_have_committed=False,
            )
        return original_atomic_write(path, payload, **kwargs)

    monkeypatch.setattr(selfmod_manager_module, "atomic_write_bytes", _fail_guard_completion)

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "authority_guard_clear_failed"
    assert result.active_version == ""
    assert manager.state_degraded is True
    assert manager._authority_block_path.exists()
    assert manager.status()[status_key][artifact_name] == {
        "enabled": False,
        "active_version": "",
    }
    if artifact_type == "skill_bundle":
        assert manager._skill_manager._tool_registry.list_tools() == []
    else:
        assert planner.defaults[-1] == ("neutral", "")
    restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    assert restarted.state_degraded is True
    assert restarted.status()[status_key] == {}
    if artifact_type == "skill_bundle":
        assert restarted._skill_manager._tool_registry.list_tools() == []
    else:
        assert restarted_planner.defaults == []


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_completed_guard_allows_restart_when_gc_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        artifact = _write_signed_skill_bundle(tmp_path / "skill", key_path=key_path)
    else:
        artifact = _write_signed_behavior_pack(
            tmp_path / "behavior",
            key_path=key_path,
            version="1.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
    proposal = manager.propose(artifact)
    original_remove = selfmod_manager_module.remove_owner_controlled_file_entries

    def _fail_completed_guard_gc(
        directory: Path,
        names: tuple[str, ...],
        **kwargs: Any,
    ) -> int:
        if names == (manager._authority_block_path.name,):
            raise OSError("completed guard garbage collection failed")
        return original_remove(directory, names, **kwargs)

    monkeypatch.setattr(
        selfmod_manager_module,
        "remove_owner_controlled_file_entries",
        _fail_completed_guard_gc,
    )

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is True
    assert manager.state_degraded is False
    assert manager._authority_block_path.read_bytes() == (
        selfmod_manager_module._SELFMOD_AUTHORITY_GUARD_COMPLETE_MARKER
    )
    restarted, restarted_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    assert restarted.state_degraded is False
    if artifact_type == "skill_bundle":
        assert restarted._skill_manager._tool_registry.list_tools()
    else:
        assert planner.defaults[-1] == ("strict", "Stay strict.")
        assert restarted_planner.defaults[-1] == ("strict", "Stay strict.")


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_authority_guard_status_describes_verified_restart_recovery(
    tmp_path: Path,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        artifact = _write_signed_skill_bundle(tmp_path / "skill", key_path=key_path)
    else:
        artifact = _write_signed_behavior_pack(
            tmp_path / "behavior",
            key_path=key_path,
            version="1.0.0",
            tone="strict",
            custom_text="Stay strict.",
        )
    assert manager.apply(manager.propose(artifact).proposal_id, confirm=True).applied is True
    selfmod_manager_module.atomic_write_bytes(
        manager._authority_block_path,
        selfmod_manager_module._SELFMOD_AUTHORITY_BLOCK_MARKER,
        fault_injector=None,
    )

    blocked, blocked_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    status = blocked.inventory_state_status()
    assert blocked.state_degraded is True
    assert str(blocked._authority_block_path) in status["remediation"]
    assert "verify" in status["remediation"].lower()
    assert "inventory and artifact" in status["remediation"].lower()
    if artifact_type == "skill_bundle":
        assert blocked._skill_manager._tool_registry.list_tools() == []
    else:
        assert blocked_planner.defaults == []

    selfmod_manager_module.remove_owner_controlled_file_entries(
        blocked._root,
        (blocked._authority_block_path.name,),
    )
    recovered, recovered_planner = _build_manager(
        tmp_path,
        allowed_signers_path=allowed_signers,
    )
    assert recovered.state_degraded is False
    if artifact_type == "skill_bundle":
        assert recovered._skill_manager._tool_registry.list_tools()
    else:
        assert recovered_planner.defaults[-1] == ("strict", "Stay strict.")


@pytest.mark.parametrize("artifact_type", ["skill_bundle", "behavior_pack"])
def test_f3_selfmod_rejects_signed_unsupported_artifact_manifest_schema(
    tmp_path: Path,
    artifact_type: str,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    if artifact_type == "skill_bundle":
        artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    else:
        artifact = _write_signed_behavior_pack(
            tmp_path / "behavior-pack",
            key_path=key_path,
            version="1.0.0",
            tone="friendly",
            custom_text="Stay warm.",
        )
    _rewrite_manifest(
        artifact,
        key_path=key_path,
        mutate=lambda manifest: manifest.update(
            {"schema_version": "2", "future_policy": {"mode": "future"}}
        ),
    )

    proposal = manager.propose(artifact)

    assert proposal.valid is False
    assert proposal.reason == "invalid_manifest_schema"
    result = manager.apply(proposal.proposal_id, confirm=True)
    assert result.applied is False
    assert result.reason == "invalid_manifest_schema"


def test_m1_selfmod_apply_keeps_inventory_when_skill_activation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    proposal = manager.propose(artifact)
    monkeypatch.setattr(manager._skill_manager, "activate_bundle", lambda *_args, **_kwargs: None)

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "skill_activation_failed"
    assert manager.status()["skills"] == {}
    assert list((tmp_path / "selfmod" / "changes").iterdir()) == []


def test_m1_selfmod_apply_copy_failure_does_not_leave_partial_artifact_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, _planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_skill_bundle(tmp_path / "skill-bundle", key_path=key_path)
    proposal = manager.propose(artifact)

    def _copytree_broken(
        src: Path,
        dst: Path,
        *,
        max_entries: int,
        max_total_bytes: int,
    ) -> object:
        _ = (src, max_entries, max_total_bytes)
        dst.mkdir(parents=True, exist_ok=True)
        (dst / "partial.txt").write_text("partial copy", encoding="utf-8")
        raise OSError("disk full")

    monkeypatch.setattr(
        selfmod_manager_module,
        "copy_bounded_regular_tree",
        _copytree_broken,
    )

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "artifact_store_copy_failed"
    artifact_root = tmp_path / "selfmod" / "artifacts"
    assert not any(path.is_file() for path in artifact_root.rglob("*"))
    assert manager.status()["skills"] == {}


def test_m1_selfmod_same_version_reapply_restores_store_and_runtime_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    stable = _write_signed_behavior_pack(
        tmp_path / "behavior-pack-stable",
        key_path=key_path,
        version="1.0.0",
        tone="friendly",
        custom_text="Stay warm.",
    )
    applied_stable = manager.apply(manager.propose(stable).proposal_id, confirm=True)
    assert applied_stable.applied is True

    candidate = _write_signed_behavior_pack(
        tmp_path / "behavior-pack-candidate",
        key_path=key_path,
        version="1.0.0",
        tone="strict",
        custom_text="Stay strict.",
    )
    proposal = manager.propose(candidate)

    def _commit_broken(*_args: object, **_kwargs: object) -> None:
        raise selfmod_manager_module._SelfModificationOperationError("change_record_persist_failed")

    monkeypatch.setattr(manager, "_commit_inventory_and_change", _commit_broken)

    result = manager.apply(proposal.proposal_id, confirm=True)

    stored_instructions = (
        tmp_path
        / "selfmod"
        / "artifacts"
        / "behavior_packs"
        / "operator-tone"
        / "1.0.0"
        / "instructions.yaml"
    )
    stored_payload = yaml.safe_load(stored_instructions.read_text(encoding="utf-8"))

    assert result.applied is False
    assert result.reason == "change_record_persist_failed"
    assert stored_payload == {
        "tone": "friendly",
        "custom_persona_text": "Stay warm.",
    }
    assert planner.defaults[-1] == ("friendly", "Stay warm.")


def test_m1_behavior_pack_apply_and_rollback_updates_planner_overlay(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    artifact = _write_signed_behavior_pack(
        tmp_path / "behavior-pack",
        key_path=key_path,
        version="1.0.0",
        tone="strict",
        custom_text="Keep responses terse.",
    )

    proposal = manager.propose(artifact)
    preview = manager.apply(proposal.proposal_id, confirm=False)
    applied = manager.apply(proposal.proposal_id, confirm=True)
    rolled_back = manager.rollback(applied.change_id)

    assert preview.applied is False
    assert preview.requires_confirmation is True
    assert applied.applied is True
    assert planner.defaults[-2] == ("strict", "Keep responses terse.")
    assert rolled_back.rolled_back is True
    assert planner.defaults[-1] == ("neutral", "")


def test_m1_selfmod_rollback_rechecks_previous_artifact_integrity(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    stable = _write_signed_behavior_pack(
        tmp_path / "behavior-pack-v1",
        key_path=key_path,
        version="1.0.0",
        tone="friendly",
        custom_text="Stay warm.",
    )
    applied_stable = manager.apply(manager.propose(stable).proposal_id, confirm=True)
    candidate = _write_signed_behavior_pack(
        tmp_path / "behavior-pack-v2",
        key_path=key_path,
        version="1.0.1",
        tone="strict",
        custom_text="Stay strict.",
    )
    applied_candidate = manager.apply(manager.propose(candidate).proposal_id, confirm=True)
    assert applied_stable.applied is True
    assert applied_candidate.applied is True

    previous_store = (
        tmp_path
        / "selfmod"
        / "artifacts"
        / "behavior_packs"
        / "operator-tone"
        / "1.0.0"
        / "instructions.yaml"
    )
    previous_store.write_text(
        yaml.safe_dump(
            {
                "tone": "friendly",
                "custom_persona_text": "tampered payload",
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    rolled_back = manager.rollback(applied_candidate.change_id)

    assert rolled_back.rolled_back is False
    assert rolled_back.reason == "integrity_mismatch"
    assert planner.defaults[-1] == ("strict", "Stay strict.")


def test_m1_selfmod_integrity_mismatch_keeps_last_known_good(tmp_path: Path) -> None:
    key_path = _generate_ssh_keypair(tmp_path, name="dev-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="dev",
        public_key=Path(f"{key_path}.pub"),
    )
    manager, planner = _build_manager(tmp_path, allowed_signers_path=allowed_signers)
    stable = _write_signed_behavior_pack(
        tmp_path / "behavior-pack-v1",
        key_path=key_path,
        version="1.0.0",
        tone="friendly",
        custom_text="Stay warm.",
    )
    applied_stable = manager.apply(manager.propose(stable).proposal_id, confirm=True)
    assert applied_stable.applied is True

    candidate = _write_signed_behavior_pack(
        tmp_path / "behavior-pack-v2",
        key_path=key_path,
        version="1.0.1",
        tone="strict",
        custom_text="Stay strict.",
    )
    proposal = manager.propose(candidate)
    (candidate / "instructions.yaml").write_text(
        yaml.safe_dump(
            {
                "tone": "strict",
                "custom_persona_text": "tampered payload",
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    result = manager.apply(proposal.proposal_id, confirm=True)

    assert result.applied is False
    assert result.reason == "integrity_mismatch"
    assert planner.defaults[-1] == ("friendly", "Stay warm.")
