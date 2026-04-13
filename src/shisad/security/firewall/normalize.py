"""Egress normalization compatibility shim over textguard."""

from __future__ import annotations

import unicodedata
from typing import cast

from textguard.decode import DecodedText
from textguard.decode import decode_text_layers as _tg_decode_text_layers
from textguard.normalize import normalize_text as _tg_normalize
from textguard.types import Finding as TextGuardFinding

_STRIP_CODEPOINTS = {
    0x200B,
    0x200C,
    0x200D,
    0xFEFF,
}
_BIDI_OVERRIDES = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_INVISIBLE_FORMATTING = set(range(0x2060, 0x2070))
_LEGACY_EGRESS_STRIP_CODEPOINTS = _STRIP_CODEPOINTS | _INVISIBLE_FORMATTING | _BIDI_OVERRIDES


def normalize_text(text: str) -> str:
    """Preserve shisad's outbound normalization behavior via textguard."""
    normalized = cast(
        str,
        _tg_normalize(
            text,
            form="NFC",
            strip_ansi=True,
            strip_invisible=False,
            strip_bidi=False,
            strip_variation_selectors=False,
            strip_tag_chars=False,
            strip_soft_hyphens=False,
            collapse_whitespace=False,
            max_combining_marks=None,
        ),
    )
    return _strip_legacy_egress_codepoints_and_collapse_whitespace(normalized)


def decode_text_layers(
    text: str,
    *,
    max_depth: int = 3,
    max_expansion_ratio: float = 4.0,
    max_total_chars: int = 32768,
    findings: list[TextGuardFinding] | None = None,
) -> DecodedText:
    """Decode encoded forms while preserving the legacy shisad bounds contract."""
    if max_depth <= 0:
        return DecodedText(text=text)
    if max_total_chars <= 0:
        max_total_chars = 32768
    if max_expansion_ratio <= 0:
        max_expansion_ratio = 1.0
    return cast(
        DecodedText,
        _tg_decode_text_layers(
            text,
            max_depth=max_depth,
            max_expansion_ratio=max_expansion_ratio,
            max_total_chars=max_total_chars,
            findings=findings,
        ),
    )


def _strip_legacy_egress_codepoints_and_collapse_whitespace(text: str) -> str:
    filtered_chars: list[str] = []
    previous_was_space = False
    for char in unicodedata.normalize("NFC", text):
        if ord(char) in _LEGACY_EGRESS_STRIP_CODEPOINTS:
            continue
        if char.isspace():
            if not previous_was_space:
                filtered_chars.append(" ")
            previous_was_space = True
            continue
        filtered_chars.append(char)
        previous_was_space = False
    return "".join(filtered_chars).strip()


__all__ = ["DecodedText", "decode_text_layers", "normalize_text"]
