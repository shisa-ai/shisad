"""PromptGuard build CLI dispatch and preflight; real export is a build-group check."""

from pathlib import Path

import pytest

from scripts import promptguard_artifacts as artifacts


def test_tokenizer_save_rejects_chat_template_path_traversal(tmp_path: Path) -> None:
    transformers = pytest.importorskip("transformers", reason="requires security-runtime")
    from tokenizers import Tokenizer
    from tokenizers.models import WordLevel

    tokenizer = transformers.PreTrainedTokenizerFast(
        tokenizer_object=Tokenizer(WordLevel({"[UNK]": 0}, unk_token="[UNK]")),
        unk_token="[UNK]",
        chat_template={"default": "safe", "../../escaped": "untrusted template"},
    )
    with pytest.raises(ValueError, match="Invalid chat template name"):
        tokenizer.save_pretrained(tmp_path / "output")
    assert not (tmp_path / "escaped.jinja").exists()


def test_export_dispatches_local_classifier_and_copies_tokenizer(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "tokenizer.json").write_text("{}")
    output = tmp_path / "output"
    calls = []

    def export(source_dir: Path, output_dir: Path) -> None:
        calls.append((source_dir, output_dir))
        (output_dir / "model.onnx").write_bytes(b"exported")

    monkeypatch.setattr(artifacts, "_export_sequence_classifier", export, raising=False)
    assert (
        artifacts.main(["export-onnx", "--source-dir", str(source), "--output-dir", str(output)])
        == 0
    )
    assert calls == [(source, output)]
    assert (output / "tokenizer.json").read_text() == "{}"
    assert (output / "model.onnx").read_bytes() == b"exported"


@pytest.mark.parametrize("option,value", [("--framework", "tf"), ("--feature", "text-generation")])
def test_unsupported_export_preserves_existing_output(
    tmp_path: Path, option: str, value: str
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    sentinel = output / "keep"
    sentinel.touch()
    with pytest.raises(ValueError, match="PyTorch sequence-classification"):
        artifacts.main(
            [
                "export-onnx",
                "--source-dir",
                str(tmp_path / "source"),
                "--output-dir",
                str(output),
                "--force",
                option,
                value,
            ]
        )
    assert sentinel.exists()


def test_local_deberta_export_matches_onnx_inference(tmp_path: Path) -> None:
    torch = pytest.importorskip("torch", reason="requires the security-build group")
    import numpy as np
    import onnx
    import onnxruntime as ort
    from tokenizers import Tokenizer
    from tokenizers.models import WordLevel
    from tokenizers.pre_tokenizers import Whitespace
    from transformers import (
        DebertaV2Config,
        DebertaV2ForSequenceClassification,
        PreTrainedTokenizerFast,
    )

    source, output = tmp_path / "checkpoint", tmp_path / "onnx"
    backend = Tokenizer(
        WordLevel({"[UNK]": 0, "[PAD]": 1, "This": 2, "is": 3, "local": 4}, unk_token="[UNK]")
    )
    backend.pre_tokenizer = Whitespace()
    tokenizer = PreTrainedTokenizerFast(
        tokenizer_object=backend, unk_token="[UNK]", pad_token="[PAD]"
    )
    tokenizer.save_pretrained(source)
    config = DebertaV2Config(
        vocab_size=5,
        hidden_size=16,
        num_hidden_layers=1,
        num_attention_heads=2,
        intermediate_size=32,
        num_labels=3,
        max_position_embeddings=64,
        relative_attention=True,
        pos_att_type=["p2c", "c2p"],
    )
    torch.manual_seed(1)
    model = DebertaV2ForSequenceClassification(config).eval()
    model.save_pretrained(source)
    assert (
        artifacts.main(["export-onnx", "--source-dir", str(source), "--output-dir", str(output)])
        == 0
    )
    onnx.checker.check_model(str(output / "model.onnx"))
    session = ort.InferenceSession(str(output / "model.onnx"), providers=["CPUExecutionProvider"])
    for texts in [["This is local"], ["This is local", "local"]]:
        encoded = tokenizer(texts, return_tensors="pt", padding=True)
        with torch.no_grad():
            expected = model(**encoded).logits.numpy()
        feed = {i.name: encoded[i.name].numpy() for i in session.get_inputs()}
        actual = session.run(None, feed)[0]
        np.testing.assert_allclose(actual, expected, atol=1e-5, rtol=1e-4)
    assert (output / "tokenizer.json").is_file()
    assert (output / "config.json").is_file()


def test_download_uses_supported_hub_arguments(tmp_path: Path, monkeypatch) -> None:
    import sys
    from types import SimpleNamespace

    calls = []

    def download(*, repo_id: str, local_dir: str, token: str) -> None:
        calls.append((repo_id, local_dir, token))

    monkeypatch.setitem(sys.modules, "huggingface_hub", SimpleNamespace(snapshot_download=download))
    monkeypatch.setattr(artifacts, "_resolve_hf_token", lambda: "test-token")
    assert (
        artifacts.main(["download", "--model-id", "test/model", "--output-dir", str(tmp_path)]) == 0
    )
    assert calls == [("test/model", str(tmp_path), "test-token")]
