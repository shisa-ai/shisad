"""Egress normalization compatibility shim over textguard."""

from __future__ import annotations

import unicodedata
from typing import cast

from textguard.decode import DecodedText, decode_text_layers
from textguard.normalize import normalize_text as _tg_normalize

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
    return cast(
        str,
        _tg_normalize(
            _strip_legacy_egress_codepoints(unicodedata.normalize("NFC", text)),
            form="NFC",
            strip_ansi=True,
            strip_invisible=False,
            strip_bidi=False,
            strip_variation_selectors=False,
            strip_tag_chars=False,
            strip_soft_hyphens=False,
            collapse_whitespace=True,
            max_combining_marks=None,
        ),
    )


def _strip_legacy_egress_codepoints(text: str) -> str:
    return "".join(
        char
        for char in text
        if ord(char) not in _LEGACY_EGRESS_STRIP_CODEPOINTS
    )


__all__ = ["DecodedText", "decode_text_layers", "normalize_text"]
