#!/usr/bin/env python3
"""Manage local PromptGuard 2 artifacts for export and comparison."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

from shisad.security.firewall.classifier import (
    PromptGuardComparisonCase,
    compare_promptguard_artifacts,
)
from shisad.security.firewall.promptguard_pack import (
    build_promptguard_model_pack,
    inspect_promptguard_model_pack,
    resign_promptguard_model_pack,
)

_HF_TOKEN_ENV_CANDIDATES = (
    "HF_TOKEN",
    "HUGGINGFACE_HUB_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
)


def _artifact_argument(raw: str) -> tuple[str, Path]:
    label, separator, raw_path = raw.partition("=")
    if not separator or not label or not raw_path:
        raise argparse.ArgumentTypeError(
            "Artifacts must be provided as <label>=<local-artifact-dir>"
        )
    return label, Path(raw_path).expanduser().resolve()


def _load_sample_cases(
    raw_samples: list[str],
    sample_file: Path | None,
) -> tuple[PromptGuardComparisonCase, ...]:
    cases: list[PromptGuardComparisonCase] = []
    for index, raw_sample in enumerate(raw_samples, start=1):
        text = raw_sample.strip()
        if text:
            cases.append(PromptGuardComparisonCase(label=f"inline-{index}", text=text))

    if sample_file is not None:
        lines = sample_file.read_text(encoding="utf-8").splitlines()
        for index, raw_line in enumerate(lines, start=1):
            text = raw_line.strip()
            if not text or text.startswith("#"):
                continue
            cases.append(PromptGuardComparisonCase(label=f"{sample_file.stem}-{index}", text=text))

    return tuple(cases)


def _reset_output_dir(output_dir: Path, *, force: bool) -> None:
    if output_dir.exists() and force:
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)


def _copy_if_present(source_dir: Path, output_dir: Path, filenames: Iterable[str]) -> None:
    for filename in filenames:
        source = source_dir / filename
        if source.is_file():
            shutil.copy2(source, output_dir / filename)


def _resolve_hf_token() -> str | None:
    for name in _HF_TOKEN_ENV_CANDIDATES:
        value = os.environ.get(name)
        if value:
            return value
    try:
        from huggingface_hub import get_token  # type: ignore
    except ImportError:
        return None
    return get_token()


def _cmd_compare(args: argparse.Namespace) -> int:
    artifacts = dict(args.artifact)
    cases = _load_sample_cases(args.sample, args.sample_file)
    reports = compare_promptguard_artifacts(
        artifacts,
        cases,
        allowed_signers_path=args.allowed_signers,
    )
    print(json.dumps([report.as_dict() for report in reports], indent=2))
    return 0


def _cmd_download(args: argparse.Namespace) -> int:
    token = _resolve_hf_token()
    if token is None:
        raise SystemExit(
            "PromptGuard download requires Hugging Face authentication. "
            "Use `hf auth login` or set one of: " + ", ".join(_HF_TOKEN_ENV_CANDIDATES)
        )

    _reset_output_dir(args.output_dir, force=args.force)

    from huggingface_hub import snapshot_download  # type: ignore

    snapshot_download(
        repo_id=args.model_id,
        local_dir=str(args.output_dir),
        local_dir_use_symlinks=False,
        token=token,
        resume_download=True,
    )
    return 0


def _cmd_export_onnx(args: argparse.Namespace) -> int:
    _reset_output_dir(args.output_dir, force=args.force)

    from transformers import AutoConfig  # type: ignore

    command = [
        sys.executable,
        "-m",
        "transformers.onnx",
        "-m",
        str(args.source_dir),
        "--feature",
        args.feature,
        "--framework",
        args.framework,
        "--export_with_transformers",
    ]
    command.append(str(args.output_dir))
    subprocess.run(command, check=True)

    AutoConfig.from_pretrained(
        str(args.source_dir),
        local_files_only=True,
        trust_remote_code=False,
    ).save_pretrained(str(args.output_dir))
    _copy_if_present(
        args.source_dir,
        args.output_dir,
        (
            "tokenizer.json",
            "tokenizer_config.json",
            "special_tokens_map.json",
            "added_tokens.json",
            "spm.model",
            "sentencepiece.bpe.model",
            "vocab.json",
            "merges.txt",
        ),
    )
    return 0


def _model_pack_name(model_id: str) -> str:
    tail = model_id.strip().split("/")[-1].strip().lower()
    return re.sub(r"[^a-z0-9._-]+", "-", tail).strip("-") or "promptguard-model-pack"


def _cmd_build_model_pack(args: argparse.Namespace) -> int:
    manifest = build_promptguard_model_pack(
        artifact_dir=args.artifact_dir,
        output_dir=args.output_dir,
        source_dir=args.source_dir,
        name=args.name or _model_pack_name(args.source_model_id),
        version=args.version,
        source_model_id=args.source_model_id,
        signing_key_path=args.signing_key,
        signer_principal=args.signer_principal,
        builder_id=args.builder_id,
        quantization=args.quantization,
        created_at=args.created_at,
        force=args.force,
    )
    print(
        json.dumps(
            {
                "output_dir": str(args.output_dir),
                "manifest_digest": manifest.digest(),
                "name": manifest.name,
                "version": manifest.version,
            },
            indent=2,
        )
    )
    return 0


def _cmd_resign_model_pack(args: argparse.Namespace) -> int:
    manifest = resign_promptguard_model_pack(
        pack_dir=args.pack_dir,
        signing_key_path=args.signing_key,
    )
    print(
        json.dumps(
            {
                "pack_dir": str(args.pack_dir),
                "manifest_digest": manifest.digest(),
                "name": manifest.name,
                "version": manifest.version,
                "file_count": len(manifest.files),
            },
            indent=2,
        )
    )
    return 0


def _cmd_verify_model_pack(args: argparse.Namespace) -> int:
    inspection = inspect_promptguard_model_pack(
        args.pack_dir,
        allowed_signers_path=args.allowed_signers,
    )
    print(json.dumps(inspection.as_dict(), indent=2))
    return 0 if inspection.valid else 1


def _add_compare_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "compare",
        help="Compare local PromptGuard artifact directories against sample prompts.",
    )
    parser.add_argument(
        "--artifact",
        action="append",
        required=True,
        type=_artifact_argument,
        metavar="LABEL=PATH",
        help="Local exported PromptGuard artifact directory.",
    )
    parser.add_argument(
        "--sample",
        action="append",
        default=[],
        help="Inline prompt sample text. May be repeated.",
    )
    parser.add_argument(
        "--sample-file",
        type=Path,
        help="UTF-8 text file with one prompt sample per line.",
    )
    parser.add_argument(
        "--allowed-signers",
        type=Path,
        help="Trusted SSH allowed_signers file for signed model-pack verification.",
    )
    parser.set_defaults(func=_cmd_compare)


def _add_download_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "download",
        help="Download a gated PromptGuard checkpoint into a local directory.",
    )
    parser.add_argument("--model-id", required=True, help="Hugging Face model ID to download.")
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Destination directory for the downloaded local checkpoint.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace the destination directory if it already exists.",
    )
    parser.set_defaults(func=_cmd_download)


def _add_export_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "export-onnx",
        help=(
            "Export a local PromptGuard checkpoint directory into a local ONNX artifact directory."
        ),
    )
    parser.add_argument(
        "--source-dir",
        required=True,
        type=Path,
        help="Local checkpoint directory previously acquired with the download step.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Destination directory for the exported ONNX artifact bundle.",
    )
    parser.add_argument(
        "--feature",
        default="sequence-classification",
        help="Transformers ONNX export feature. Defaults to sequence-classification.",
    )
    parser.add_argument(
        "--framework",
        choices=("pt", "tf"),
        default="pt",
        help="Framework to use for the ONNX export.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace the destination directory if it already exists.",
    )
    parser.set_defaults(func=_cmd_export_onnx)


def _add_build_model_pack_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = subparsers.add_parser(
        "build-model-pack",
        help="Build a signed PromptGuard model pack from a local ONNX artifact directory.",
    )
    parser.add_argument(
        "--artifact-dir",
        required=True,
        type=Path,
        help="Local exported ONNX artifact directory to package under payload/.",
    )
    parser.add_argument(
        "--source-dir",
        type=Path,
        help="Optional source checkpoint directory used to copy license/policy files.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Destination directory for the signed PromptGuard model pack.",
    )
    parser.add_argument(
        "--source-model-id",
        required=True,
        help="Upstream model identifier recorded in the pack manifest.",
    )
    parser.add_argument(
        "--name",
        help="Model-pack name. Defaults to a sanitized name derived from --source-model-id.",
    )
    parser.add_argument(
        "--version",
        default="onnx-fp32",
        help="Model-pack version label recorded in the manifest.",
    )
    parser.add_argument(
        "--quantization",
        default="fp32",
        help="Quantization label recorded in the manifest runtime metadata.",
    )
    parser.add_argument(
        "--builder-id",
        default="promptguard_artifacts.py",
        help="Builder identifier recorded in the manifest provenance.",
    )
    parser.add_argument(
        "--created-at",
        help=(
            "Explicit RFC3339/ISO8601 timestamp for reproducible manifests. "
            "Defaults to SOURCE_DATE_EPOCH when set, otherwise current UTC."
        ),
    )
    parser.add_argument(
        "--signing-key",
        required=True,
        type=Path,
        help="SSH private key used to sign manifest.json.",
    )
    parser.add_argument(
        "--signer-principal",
        required=True,
        help="Principal name expected by the trusted allowed_signers file.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace the destination directory if it already exists.",
    )
    parser.set_defaults(func=_cmd_build_model_pack)


def _add_resign_model_pack_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = subparsers.add_parser(
        "resign-model-pack",
        help="Re-sign an existing model pack after modifying wrapper files (README, NOTICE, etc.).",
    )
    parser.add_argument(
        "--pack-dir",
        required=True,
        type=Path,
        help="Existing model-pack directory to re-sign in place.",
    )
    parser.add_argument(
        "--signing-key",
        required=True,
        type=Path,
        help="SSH private key used to sign manifest.json.",
    )
    parser.set_defaults(func=_cmd_resign_model_pack)


def _add_verify_model_pack_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    parser = subparsers.add_parser(
        "verify-model-pack",
        help="Verify a signed PromptGuard model pack against a trusted allowed_signers file.",
    )
    parser.add_argument(
        "--pack-dir",
        required=True,
        type=Path,
        help="PromptGuard model-pack directory containing manifest.json and payload/.",
    )
    parser.add_argument(
        "--allowed-signers",
        required=True,
        type=Path,
        help="Trusted SSH allowed_signers file used to verify manifest.json.sig.",
    )
    parser.set_defaults(func=_cmd_verify_model_pack)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Manage local PromptGuard artifacts. Runtime inference remains local-only; "
            "download/export are explicit operator build steps."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_compare_parser(subparsers)
    _add_download_parser(subparsers)
    _add_export_parser(subparsers)
    _add_build_model_pack_parser(subparsers)
    _add_resign_model_pack_parser(subparsers)
    _add_verify_model_pack_parser(subparsers)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
