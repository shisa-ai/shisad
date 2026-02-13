"""M4 review coverage for artifact lifecycle, disclosure, and profiling helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from shisad.skills import (
    ArtifactState,
    CapabilityProfile,
    RolloutMetadata,
    SkillArtifact,
    diff_versions,
    generate_manifest_from_profile,
    load_skill_bundle,
    view_content,
)
from shisad.skills.profile import SkillProfiler


def _manifest_payload(
    *,
    name: str = "artifact-skill",
    version: str = "1.0.0",
) -> dict[str, Any]:
    return {
        "manifest_version": "1.0.0",
        "name": name,
        "version": version,
        "author": "trusted-dev",
        "signature": "sha256:placeholder",
        "source_repo": "https://github.com/trusted-dev/skills",
        "description": "safe skill",
        "capabilities": {
            "network": [],
            "filesystem": [],
            "shell": [],
            "environment": [],
        },
        "dependencies": [],
    }


def _write_skill(
    root: Path,
    *,
    manifest: dict[str, Any],
    files: dict[str, str | bytes],
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "skill.manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    return root


def test_m4_rr10_artifact_state_allows_resubmission_from_published() -> None:
    artifact = SkillArtifact(
        artifact_id="art-1",
        name="reviewable",
        version="1.0.0",
        state=ArtifactState.PUBLISHED,
    )
    next_state = artifact.transition(
        action="submit",
        actor="security-reviewer",
        reason="needs re-vetting",
    )
    assert next_state == ArtifactState.REVIEW
    assert artifact.state == ArtifactState.REVIEW


def test_m4_rr11_rollout_metadata_reports_canary_state() -> None:
    assert RolloutMetadata(canary_percent=10).is_canary is True
    assert RolloutMetadata(canary_percent=100).is_canary is False
    assert RolloutMetadata(canary_percent=0).is_canary is False


def test_m4_rr12_disclosure_binary_view_and_diff_include_hash_summary(tmp_path: Path) -> None:
    old_skill = _write_skill(
        tmp_path / "old",
        manifest=_manifest_payload(name="binary-skill", version="1.0.0"),
        files={"blob.bin": b"\x00old-bytes"},
    )
    new_skill = _write_skill(
        tmp_path / "new",
        manifest=_manifest_payload(name="binary-skill", version="1.0.1"),
        files={"blob.bin": b"\x00new-bytes"},
    )
    old_bundle = load_skill_bundle(old_skill)
    new_bundle = load_skill_bundle(new_skill)

    assert view_content(old_bundle, path="blob.bin").startswith("[binary file:")
    diffs = diff_versions(old_bundle, new_bundle)
    changed = next(item for item in diffs if item.path == "blob.bin")
    assert changed.unified_diff.startswith("[binary changed] sha256 ")


def test_m4_rr13_profiler_save_load_roundtrip(tmp_path: Path) -> None:
    profiler = SkillProfiler()
    profiler.record_network("API.GOOD.COM")
    profiler.record_filesystem("/workspace/project")
    profiler.record_shell("curl https://api.good.com/v1")
    profiler.record_environment("aws_token")
    profile_path = tmp_path / "profile" / "skill.json"
    profiler.save(profile_path)

    loaded = SkillProfiler.load(profile_path)
    assert loaded.profile.network_domains == {"api.good.com"}
    assert loaded.profile.filesystem_paths == {"/workspace/project"}
    assert loaded.profile.shell_commands == {"curl https://api.good.com/v1"}
    assert loaded.profile.environment_vars == {"AWS_TOKEN"}


def test_m4_rr14_generate_manifest_from_profile_maps_capabilities() -> None:
    profile = CapabilityProfile(
        network_domains={"api.good.com"},
        filesystem_paths={"/workspace/project"},
        shell_commands={"curl https://api.good.com/v1"},
        environment_vars={"AWS_TOKEN"},
    )
    manifest = generate_manifest_from_profile(
        profile=profile,
        name="profiled-skill",
        author="trusted-dev",
        source_repo="https://github.com/trusted-dev/profiled-skill",
        description="generated from profile",
    )
    assert manifest.name == "profiled-skill"
    assert [item.domain for item in manifest.capabilities.network] == ["api.good.com"]
    assert [item.path for item in manifest.capabilities.filesystem] == ["/workspace/project"]
    assert [item.command for item in manifest.capabilities.shell] == [
        "curl https://api.good.com/v1"
    ]
    assert [item.var for item in manifest.capabilities.environment] == ["AWS_TOKEN"]
