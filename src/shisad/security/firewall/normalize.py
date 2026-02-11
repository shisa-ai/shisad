"""Text normalization primitives for Content Firewall."""

from __future__ import annotations

import codecs
import html
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote

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
_ROT13_SIGNAL_TOKENS = (
    "ignore",
    "disregard",
    "instruction",
    "system prompt",
    "developer message",
    "curl",
    "wget",
    "http://",
    "https://",
    "token",
    "secret",
)


@dataclass(slots=True, frozen=True)
class DecodedText:
    text: str
    reason_codes: tuple[str, ...] = ()
    decode_depth: int = 0


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


def decode_text_layers(
    text: str,
    *,
    max_depth: int = 3,
    max_expansion_ratio: float = 4.0,
    max_total_chars: int = 32768,
) -> DecodedText:
    """Decode common encoded forms with explicit recursion and size bounds."""
    if max_depth <= 0:
        return DecodedText(text=text)
    if max_total_chars <= 0:
        max_total_chars = 32768
    if max_expansion_ratio <= 0:
        max_expansion_ratio = 1.0

    current = text
    reason_codes: set[str] = set()
    depth = 0

    for _ in range(max_depth):
        changed = False
        current, applied = _apply_bounded_decode(
            current=current,
            candidate=unquote(current),
            reason="encoding:url_decoded",
            reason_codes=reason_codes,
            max_expansion_ratio=max_expansion_ratio,
            max_total_chars=max_total_chars,
        )
        changed = changed or applied

        current, applied = _apply_bounded_decode(
            current=current,
            candidate=html.unescape(current),
            reason="encoding:html_entity_decoded",
            reason_codes=reason_codes,
            max_expansion_ratio=max_expansion_ratio,
            max_total_chars=max_total_chars,
        )
        changed = changed or applied

        rot13_candidate = _rot13_decode_candidate(current)
        if rot13_candidate is not None:
            current, applied = _apply_bounded_decode(
                current=current,
                candidate=rot13_candidate,
                reason="encoding:rot13_decoded",
                reason_codes=reason_codes,
                max_expansion_ratio=max_expansion_ratio,
                max_total_chars=max_total_chars,
            )
            changed = changed or applied

        if not changed:
            break
        depth += 1

    if depth >= max_depth and _has_additional_layer(current):
        reason_codes.add("encoding:decode_depth_limited")

    return DecodedText(
        text=current,
        reason_codes=tuple(sorted(reason_codes)),
        decode_depth=depth,
    )


def _apply_bounded_decode(
    *,
    current: str,
    candidate: str,
    reason: str,
    reason_codes: set[str],
    max_expansion_ratio: float,
    max_total_chars: int,
) -> tuple[str, bool]:
    if candidate == current:
        return current, False
    if len(candidate) > max_total_chars:
        reason_codes.add("encoding:decode_bound_hit")
        return current, False
    expansion_limit = max(1, int(len(current) * max_expansion_ratio))
    if len(candidate) > expansion_limit:
        reason_codes.add("encoding:decode_bound_hit")
        return current, False
    reason_codes.add(reason)
    return candidate, True


def _rot13_decode_candidate(text: str) -> str | None:
    decoded = codecs.decode(text, "rot_13")
    if decoded == text:
        return None
    lowered_raw = text.lower()
    lowered_decoded = decoded.lower()
    decoded_hits = {token for token in _ROT13_SIGNAL_TOKENS if token in lowered_decoded}
    if not decoded_hits:
        return None
    raw_hits = {token for token in _ROT13_SIGNAL_TOKENS if token in lowered_raw}
    # Decode when ROT13 reveals at least one signal token that is absent in raw text.
    # This prevents simple raw-token decoys (e.g. appending "http://...") from suppressing decoding.
    if not (decoded_hits - raw_hits):
        return None
    return decoded


def _has_additional_layer(text: str) -> bool:
    if unquote(text) != text:
        return True
    if html.unescape(text) != text:
        return True
    return _rot13_decode_candidate(text) is not None
