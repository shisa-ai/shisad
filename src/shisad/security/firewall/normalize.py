"""Text normalization primitives for Content Firewall."""

from __future__ import annotations

import re
import unicodedata

# Zero-width and invisible formatting chars commonly used for prompt hiding.
_STRIP_CODEPOINTS = {
    0x200B,
    0x200C,
    0x200D,
    0xFEFF,
}

_BIDI_OVERRIDES = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_INVISIBLE_FORMATTING = set(range(0x2060, 0x2070))

_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def normalize_text(text: str) -> str:
    """Normalize untrusted text before classification.

    Steps:
    - Unicode NFC normalization
    - Strip common zero-width/invisible characters
    - Strip bidi override/isolation controls
    - Remove ANSI escape sequences
    - Collapse whitespace classes to plain spaces
    """
    normalized = unicodedata.normalize("NFC", text)
    normalized = _ANSI_RE.sub("", normalized)

    filtered_chars: list[str] = []
    for char in normalized:
        codepoint = ord(char)
        if codepoint in _STRIP_CODEPOINTS:
            continue
        if codepoint in _INVISIBLE_FORMATTING:
            continue
        if codepoint in _BIDI_OVERRIDES:
            continue

        if char.isspace():
            filtered_chars.append(" ")
        else:
            filtered_chars.append(char)

    collapsed = "".join(filtered_chars)
    collapsed = re.sub(r" {2,}", " ", collapsed)
    return collapsed.strip()
