"""M1 self-modification manager coverage."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import yaml

from shisad.core.tools.registry import ToolRegistry
from shisad.security.policy import SkillPolicy
from shisad.selfmod import SelfModificationManager
from shisad.skills.manager import SkillManager


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
                "sha256": __import__("hashlib").sha256(data).hexdigest(),
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
                "sha256": __import__("hashlib").sha256(data).hexdigest(),
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
