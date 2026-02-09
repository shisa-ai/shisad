"""Security asset provenance and drift verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, Field


class SecurityAsset(BaseModel):
    path: str
    sha256: str


class SecurityAssetManifest(BaseModel):
    version: str
    source_repo: str
    source_commit: str
    license: str = "Apache-2.0"
    assets: list[SecurityAsset] = Field(default_factory=list)

    def digest(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_manifest(manifest_path: Path) -> SecurityAssetManifest:
    return SecurityAssetManifest.model_validate_json(manifest_path.read_text())


def hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_assets(root: Path, manifest: SecurityAssetManifest) -> list[str]:
    drifts: list[str] = []
    expected_paths = {asset.path for asset in manifest.assets}
    for asset in manifest.assets:
        asset_path = root / asset.path
        if not asset_path.exists():
            drifts.append(f"missing:{asset.path}")
            continue
        actual = hash_file(asset_path)
        if actual != asset.sha256:
            drifts.append(f"hash_mismatch:{asset.path}")

    allow_untracked = {"provenance.json"}
    for discovered in root.rglob("*"):
        if not discovered.is_file():
            continue
        relative = discovered.relative_to(root).as_posix()
        if relative in expected_paths or relative in allow_untracked:
            continue
        drifts.append(f"unexpected:{relative}")
    return sorted(drifts)
