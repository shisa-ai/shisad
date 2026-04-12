"""Cover missing branches in promptguard_pack for the coverage gate."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from shisad.security.firewall.promptguard_pack import (
    PromptGuardModelPackManifest,
    build_promptguard_model_pack,
    inspect_promptguard_model_pack,
    resign_promptguard_model_pack,
)


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


def _build_signed_pack(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Build a valid signed pack and return (pack_dir, key_path, allowed_signers)."""
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "model.onnx").write_bytes(b"fake-model")
    key_path = _generate_ssh_keypair(tmp_path, name="test-key")
    allowed_signers = tmp_path / "allowed_signers"
    _write_allowed_signers(
        allowed_signers,
        principal="test-signer",
        public_key=Path(f"{key_path}.pub"),
    )
    pack_dir = tmp_path / "pack"
    build_promptguard_model_pack(
        artifact_dir=artifact_dir,
        output_dir=pack_dir,
        name="test-pack",
        version="v1",
        source_model_id="test-model",
        signing_key_path=key_path,
        signer_principal="test-signer",
    )
    return pack_dir, key_path, allowed_signers


# --- Manifest validator coverage ---


class TestManifestValidators:
    def test_invalid_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid model-pack name"):
            PromptGuardModelPackManifest(
                name="../bad",
                version="v1",
                created_at="2026-01-01T00:00:00Z",
            )

    def test_invalid_version_rejected(self) -> None:
        with pytest.raises(ValueError, match="invalid model-pack version"):
            PromptGuardModelPackManifest(
                name="good-name",
                version="../bad",
                created_at="2026-01-01T00:00:00Z",
            )

    def test_digest_is_stable(self) -> None:
        m = PromptGuardModelPackManifest(
            name="test", version="v1", created_at="2026-01-01T00:00:00Z"
        )
        assert m.digest() == m.digest()
        assert len(m.digest()) == 64


# --- build_promptguard_model_pack error branches ---


class TestBuildErrors:
    def test_missing_artifact_dir(self, tmp_path: Path) -> None:
        key_path = _generate_ssh_keypair(tmp_path, name="k")
        with pytest.raises(ValueError, match="artifact_dir_missing"):
            build_promptguard_model_pack(
                artifact_dir=tmp_path / "nope",
                output_dir=tmp_path / "out",
                name="test",
                version="v1",
                source_model_id="m",
                signing_key_path=key_path,
                signer_principal="s",
            )

    def test_missing_source_dir(self, tmp_path: Path) -> None:
        artifact_dir = tmp_path / "art"
        artifact_dir.mkdir()
        key_path = _generate_ssh_keypair(tmp_path, name="k")
        with pytest.raises(ValueError, match="source_dir_missing"):
            build_promptguard_model_pack(
                artifact_dir=artifact_dir,
                output_dir=tmp_path / "out",
                name="test",
                version="v1",
                source_model_id="m",
                signing_key_path=key_path,
                signer_principal="s",
                source_dir=tmp_path / "nope",
            )

    def test_missing_signing_key(self, tmp_path: Path) -> None:
        artifact_dir = tmp_path / "art"
        artifact_dir.mkdir()
        with pytest.raises(ValueError, match="signing_key_missing"):
            build_promptguard_model_pack(
                artifact_dir=artifact_dir,
                output_dir=tmp_path / "out",
                name="test",
                version="v1",
                source_model_id="m",
                signing_key_path=tmp_path / "no-key",
                signer_principal="s",
            )

    def test_empty_signer_principal(self, tmp_path: Path) -> None:
        artifact_dir = tmp_path / "art"
        artifact_dir.mkdir()
        key_path = _generate_ssh_keypair(tmp_path, name="k")
        with pytest.raises(ValueError, match="signer_principal_required"):
            build_promptguard_model_pack(
                artifact_dir=artifact_dir,
                output_dir=tmp_path / "out",
                name="test",
                version="v1",
                source_model_id="m",
                signing_key_path=key_path,
                signer_principal="  ",
            )

    def test_non_empty_output_dir_without_force(self, tmp_path: Path) -> None:
        artifact_dir = tmp_path / "art"
        artifact_dir.mkdir()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        (out_dir / "junk").write_text("x")
        key_path = _generate_ssh_keypair(tmp_path, name="k")
        with pytest.raises(ValueError, match="output_dir_exists"):
            build_promptguard_model_pack(
                artifact_dir=artifact_dir,
                output_dir=out_dir,
                name="test",
                version="v1",
                source_model_id="m",
                signing_key_path=key_path,
                signer_principal="s",
            )

    def test_force_overwrites_output_dir(self, tmp_path: Path) -> None:
        artifact_dir = tmp_path / "art"
        artifact_dir.mkdir()
        (artifact_dir / "model.onnx").write_bytes(b"fake")
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        (out_dir / "junk").write_text("x")
        key_path = _generate_ssh_keypair(tmp_path, name="k")
        manifest = build_promptguard_model_pack(
            artifact_dir=artifact_dir,
            output_dir=out_dir,
            name="test",
            version="v1",
            source_model_id="m",
            signing_key_path=key_path,
            signer_principal="s",
            force=True,
        )
        assert manifest.name == "test"
        assert not (out_dir / "junk").exists()


# --- resign_promptguard_model_pack ---


class TestResign:
    def test_resign_updates_signature(self, tmp_path: Path) -> None:
        pack_dir, key_path, allowed_signers = _build_signed_pack(tmp_path)
        old_sig = (pack_dir / "manifest.json.sig").read_bytes()

        # Add a wrapper file, then resign
        (pack_dir / "README.md").write_text("added", encoding="utf-8")
        manifest = resign_promptguard_model_pack(pack_dir, signing_key_path=key_path)

        new_sig = (pack_dir / "manifest.json.sig").read_bytes()
        assert old_sig != new_sig
        assert manifest.name == "test-pack"

        # Still verifies after resign
        inspection = inspect_promptguard_model_pack(pack_dir, allowed_signers_path=allowed_signers)
        assert inspection.valid is True

    def test_resign_missing_manifest(self, tmp_path: Path) -> None:
        pack_dir = tmp_path / "empty"
        pack_dir.mkdir()
        key_path = _generate_ssh_keypair(tmp_path, name="k")
        with pytest.raises(ValueError, match="pack_manifest_missing"):
            resign_promptguard_model_pack(pack_dir, signing_key_path=key_path)

    def test_resign_missing_key(self, tmp_path: Path) -> None:
        pack_dir, _, _ = _build_signed_pack(tmp_path)
        with pytest.raises(ValueError, match="signing_key_missing"):
            resign_promptguard_model_pack(pack_dir, signing_key_path=tmp_path / "no-key")

    def test_resign_invalid_manifest(self, tmp_path: Path) -> None:
        pack_dir = tmp_path / "bad"
        pack_dir.mkdir()
        (pack_dir / "manifest.json").write_text("not json", encoding="utf-8")
        key_path = _generate_ssh_keypair(tmp_path, name="k")
        with pytest.raises(ValueError, match="pack_invalid_manifest"):
            resign_promptguard_model_pack(pack_dir, signing_key_path=key_path)


# --- inspect branches ---


class TestInspectBranches:
    def test_no_trust_store(self, tmp_path: Path) -> None:
        pack_dir, _, _ = _build_signed_pack(tmp_path)
        inspection = inspect_promptguard_model_pack(pack_dir, allowed_signers_path=None)
        assert not inspection.valid
        assert inspection.reason == "promptguard_pack_trust_store_missing"

    def test_signature_verification_fails_wrong_key(self, tmp_path: Path) -> None:
        pack_dir, _, _ = _build_signed_pack(tmp_path)
        # Create a different keypair for the allowed_signers
        other_key = _generate_ssh_keypair(tmp_path, name="other-key")
        wrong_signers = tmp_path / "wrong_signers"
        _write_allowed_signers(
            wrong_signers,
            principal="other",
            public_key=Path(f"{other_key}.pub"),
        )
        inspection = inspect_promptguard_model_pack(pack_dir, allowed_signers_path=wrong_signers)
        assert not inspection.valid
        assert inspection.reason == "promptguard_pack_signature_verification_failed"

    def test_file_hash_mismatch(self, tmp_path: Path) -> None:
        pack_dir, _, allowed_signers = _build_signed_pack(tmp_path)
        # Corrupt a payload file after signing
        (pack_dir / "payload" / "model.onnx").write_bytes(b"corrupted")
        inspection = inspect_promptguard_model_pack(pack_dir, allowed_signers_path=allowed_signers)
        assert not inspection.valid
        assert inspection.reason == "promptguard_pack_file_hash_mismatch"

    def test_invalid_manifest_json(self, tmp_path: Path) -> None:
        pack_dir = tmp_path / "bad-pack"
        pack_dir.mkdir()
        (pack_dir / "manifest.json").write_text("{invalid", encoding="utf-8")
        inspection = inspect_promptguard_model_pack(pack_dir, allowed_signers_path=None)
        assert not inspection.valid
        assert inspection.reason == "promptguard_pack_invalid_manifest"

    def test_missing_payload_dir(self, tmp_path: Path) -> None:
        pack_dir, _key_path, allowed_signers = _build_signed_pack(tmp_path)
        # Remove payload dir after signing — file set will mismatch
        import shutil

        shutil.rmtree(pack_dir / "payload")
        inspection = inspect_promptguard_model_pack(pack_dir, allowed_signers_path=allowed_signers)
        assert not inspection.valid

    def test_as_dict_includes_all_fields(self, tmp_path: Path) -> None:
        pack_dir, _, allowed_signers = _build_signed_pack(tmp_path)
        inspection = inspect_promptguard_model_pack(pack_dir, allowed_signers_path=allowed_signers)
        d = inspection.as_dict()
        assert d["valid"] is True
        assert d["signer"] == "test-signer"
        assert d["name"] == "test-pack"
        assert len(d["manifest_digest"]) == 64

    def test_as_dict_invalid_inspection(self, tmp_path: Path) -> None:
        pack_dir = tmp_path / "missing"
        pack_dir.mkdir()
        inspection = inspect_promptguard_model_pack(pack_dir, allowed_signers_path=None)
        d = inspection.as_dict()
        assert d["valid"] is False
        assert d["manifest_digest"] == ""
        assert d["payload_dir"] == ""


# --- _resolve_created_at SOURCE_DATE_EPOCH branch ---


class TestResolveCreatedAt:
    def test_source_date_epoch_used(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1704067200")
        artifact_dir = tmp_path / "art"
        artifact_dir.mkdir()
        (artifact_dir / "model.onnx").write_bytes(b"fake")
        key_path = _generate_ssh_keypair(tmp_path, name="k")
        manifest = build_promptguard_model_pack(
            artifact_dir=artifact_dir,
            output_dir=tmp_path / "out",
            name="test",
            version="v1",
            source_model_id="m",
            signing_key_path=key_path,
            signer_principal="s",
        )
        assert "2024-01-01" in manifest.created_at

    def test_invalid_source_date_epoch_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-a-number")
        artifact_dir = tmp_path / "art"
        artifact_dir.mkdir()
        (artifact_dir / "model.onnx").write_bytes(b"fake")
        key_path = _generate_ssh_keypair(tmp_path, name="k")
        manifest = build_promptguard_model_pack(
            artifact_dir=artifact_dir,
            output_dir=tmp_path / "out",
            name="test",
            version="v1",
            source_model_id="m",
            signing_key_path=key_path,
            signer_principal="s",
        )
        # Falls through to datetime.now()
        assert "2026" in manifest.created_at
