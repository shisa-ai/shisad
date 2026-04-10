"""Terminal-friendly rendering helpers for evidence-reference stubs."""

from __future__ import annotations

import re
from dataclasses import dataclass

_SUMMARY_RE = r'(?P<summary>(?:\\.|[^"])*)'
_AVAILABLE_EVIDENCE_STUB_RE = re.compile(
    r"\[EVIDENCE "
    r"ref=(?P<ref_id>\S+) "
    r"source=(?P<source>\S+) "
    r"taint=(?P<taint>\S+) "
    r"size=(?P<size>\d+) "
    rf'summary="{_SUMMARY_RE}" '
    r'Use evidence\.read\("(?P=ref_id)"\) for full content, or '
    r'evidence\.promote\("(?P=ref_id)"\) to add it to the conversation\.\]'
)
_UNAVAILABLE_EVIDENCE_STUB_RE = re.compile(
    r"\[EVIDENCE unavailable "
    r"source=(?P<source>\S+) "
    r"taint=(?P<taint>\S+) "
    r"size=(?P<size>\d+) "
    rf'summary="{_SUMMARY_RE}" '
    r"Evidence storage unavailable; inspect tool_outputs for the full content in this turn\.\]"
)
_ANSI_CSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC_RE = re.compile(r"\x1B\][^\x07\x1B\n]*(?:\x07|\x1B\\)?")
_ANSI_STRING_RE = re.compile(r"\x1B(?:P|X|\^|_)[^\x1B\n]*(?:\x1B\\)?")
_FIELD_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1F\x7F-\x9F]+")
_TEXT_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0B-\x1F\x7F-\x9F]+")


@dataclass(frozen=True, slots=True)
class _ParsedEvidenceStub:
    ref_id: str
    source: str
    taint: str
    size_bytes: int | None
    summary: str
    available: bool


def _unescape_summary(raw: str) -> str:
    chars: list[str] = []
    escaped = False
    for char in raw:
        if escaped:
            chars.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        chars.append(char)
    if escaped:
        chars.append("\\")
    return "".join(chars)


def _strip_terminal_sequences(value: str) -> str:
    cleaned = _ANSI_OSC_RE.sub("", value)
    cleaned = _ANSI_STRING_RE.sub("", cleaned)
    cleaned = _ANSI_CSI_RE.sub("", cleaned)
    return cleaned.replace("\x1b", "")


def _sanitize_terminal_field(value: str) -> str:
    cleaned = _strip_terminal_sequences(value)
    cleaned = _FIELD_CONTROL_CHARS_RE.sub(" ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def _normalize_literal_linebreak_escapes(value: str) -> str:
    chars: list[str] = []
    escaped = False
    index = 0
    while index < len(value):
        char = value[index]
        if not escaped:
            if char == "\\":
                escaped = True
            else:
                chars.append(char)
            index += 1
            continue
        if char == "\\":
            chars.append("\\")
            escaped = False
            index += 1
            continue
        if char == "r":
            if index + 2 < len(value) and value[index + 1] == "\\" and value[index + 2] == "n":
                chars.append("\n")
                escaped = False
                index += 3
                continue
            chars.append("\n")
            escaped = False
            index += 1
            continue
        if char == "n":
            chars.append("\n")
            escaped = False
            index += 1
            continue
        chars.append("\\")
        chars.append(char)
        escaped = False
        index += 1
    if escaped:
        chars.append("\\")
    return "".join(chars)


def _sanitize_terminal_text(value: str) -> str:
    cleaned = _strip_terminal_sequences(value)
    cleaned = cleaned.replace("\r", "\n")
    cleaned = cleaned.replace("\t", " ")
    cleaned = _TEXT_CONTROL_CHARS_RE.sub(" ", cleaned)
    cleaned = re.sub(r"[ ]+\n", "\n", cleaned)
    cleaned = re.sub(r"\n[ ]+", "\n", cleaned)
    cleaned = re.sub(r"[ ]{2,}", " ", cleaned)
    return cleaned


def sanitize_terminal_field(value: str) -> str:
    """Strip terminal control sequences from a one-line operator-facing field."""

    return _sanitize_terminal_field(value)


def sanitize_terminal_text(value: str) -> str:
    """Strip terminal control sequences from multi-line operator-facing text."""

    return _sanitize_terminal_text(value)


def _parsed_stub_from_match(
    match: re.Match[str],
    *,
    available: bool,
) -> _ParsedEvidenceStub:
    summary = _unescape_summary(str(match.group("summary") or ""))
    size_bytes = None
    size_raw = str(match.group("size") or "")
    if size_raw.isdigit():
        size_bytes = int(size_raw)
    ref_id = str(match.groupdict().get("ref_id") or "").strip()
    return _ParsedEvidenceStub(
        ref_id=ref_id,
        source=str(match.group("source") or "").strip(),
        taint=str(match.group("taint") or "").strip(),
        size_bytes=size_bytes,
        summary=summary,
        available=available and bool(ref_id),
    )


def _render_stub(parsed: _ParsedEvidenceStub) -> str:
    ref_id = _sanitize_terminal_field(parsed.ref_id)
    source = _sanitize_terminal_field(parsed.source)
    taint = _sanitize_terminal_field(parsed.taint)
    summary = _sanitize_terminal_field(parsed.summary)
    heading = f"[Evidence {ref_id}]" if parsed.available and ref_id else "[Evidence unavailable]"
    lines = [heading]
    if source:
        lines.append(f"source: {source}")
    if taint:
        lines.append(f"taint: {taint}")
    if parsed.size_bytes is not None:
        lines.append(f"size: {parsed.size_bytes} bytes")
    if summary:
        lines.append(f"summary: {summary}")
    if parsed.available and ref_id:
        lines.append(f'inspect: evidence.read("{ref_id}")')
        lines.append(f'promote: evidence.promote("{ref_id}")')
    return "\n".join(lines)


def _sanitize_terminal_assistant_segment(value: str) -> str:
    trailing_newline = value.endswith("\n")
    normalized_lines: list[str] = []
    in_pending_preview = False
    for line in value.splitlines():
        if in_pending_preview and not line.startswith("     "):
            in_pending_preview = False
        if in_pending_preview:
            normalized_lines.append(line)
        else:
            normalized_lines.append(_normalize_literal_linebreak_escapes(line))
        if line == "   Preview:":
            in_pending_preview = True
    normalized = "\n".join(normalized_lines)
    if trailing_newline:
        normalized += "\n"
    return sanitize_terminal_text(normalized)


def _next_stub_match(text: str, start: int) -> tuple[re.Match[str], bool] | None:
    available = _AVAILABLE_EVIDENCE_STUB_RE.search(text, start)
    unavailable = _UNAVAILABLE_EVIDENCE_STUB_RE.search(text, start)
    if available is None:
        if unavailable is None:
            return None
        return unavailable, False
    if unavailable is None or available.start() <= unavailable.start():
        return available, True
    return unavailable, False


def render_evidence_refs_for_terminal(text: str) -> str:
    """Replace raw evidence stubs with terminal-friendly multi-line blocks."""

    if not text.strip():
        return text.strip()

    chunks: list[str] = []
    cursor = 0
    while match_info := _next_stub_match(text, cursor):
        match, available = match_info
        if match.start() > cursor:
            chunks.append(_sanitize_terminal_assistant_segment(text[cursor : match.start()]))
        chunks.append(_render_stub(_parsed_stub_from_match(match, available=available)))
        cursor = match.end()
    if cursor < len(text):
        chunks.append(_sanitize_terminal_assistant_segment(text[cursor:]))
    return "".join(chunks)
