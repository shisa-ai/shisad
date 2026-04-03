#!/usr/bin/env python3
"""Manage and verify copied security asset provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from shisad.security.provenance import SecurityAsset, SecurityAssetManifest, verify_assets


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _rules_root() -> Path:
    return _repo_root() / "src" / "shisad" / "security" / "rules"


def _manifest_path() -> Path:
    return _rules_root() / "provenance.json"


def _collect_assets() -> list[SecurityAsset]:
    root = _rules_root()
    assets: list[SecurityAsset] = []
    for path in sorted((root / "yara").glob("*.yara")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assets.append(SecurityAsset(path=str(path.relative_to(root)), sha256=digest))
    return assets


def _update_manifest(source_commit: str) -> None:
    manifest = SecurityAssetManifest(
        version="m2-baseline-2026-02-10",
        source_repo="https://github.com/cisco-ai-defense/skill-scanner",
        source_commit=source_commit,
        assets=_collect_assets(),
    )
    _manifest_path().write_text(manifest.model_dump_json(indent=2))
    print(f"updated {_manifest_path()}")


def _verify_manifest() -> int:
    manifest_path = _manifest_path()
    if not manifest_path.exists():
        print(f"missing manifest: {manifest_path}")
        return 1
    manifest = SecurityAssetManifest.model_validate_json(manifest_path.read_text())
    drifts = verify_assets(_rules_root(), manifest)
    if drifts:
        print("security asset drift detected:")
        for item in drifts:
            print(f"  - {item}")
        return 2
    print(
        json.dumps(
            {
                "status": "ok",
                "version": manifest.version,
                "source_commit": manifest.source_commit,
                "manifest_hash": manifest.digest(),
                "assets": len(manifest.assets),
            },
            indent=2,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    update = sub.add_parser("update", help="regenerate provenance manifest")
    update.add_argument(
        "--source-commit",
        required=True,
        help="Pinned upstream commit hash used for copied assets",
    )
    sub.add_parser("verify", help="verify assets against manifest")

    args = parser.parse_args()
    if args.command == "update":
        _update_manifest(args.source_commit)
        return 0
    if args.command == "verify":
        return _verify_manifest()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
