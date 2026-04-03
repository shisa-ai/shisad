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


def _sanitize_terminal_text(value: str) -> str:
    cleaned = _strip_terminal_sequences(value)
    cleaned = cleaned.replace("\r", "\n")
    cleaned = cleaned.replace("\t", " ")
    cleaned = _TEXT_CONTROL_CHARS_RE.sub(" ", cleaned)
    cleaned = re.sub(r"[ ]+\n", "\n", cleaned)
    cleaned = re.sub(r"\n[ ]+", "\n", cleaned)
    cleaned = re.sub(r"[ ]{2,}", " ", cleaned)
    return cleaned


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
    heading = (
        f"[Evidence {ref_id}]"
        if parsed.available and ref_id
        else "[Evidence unavailable]"
    )
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


def render_evidence_refs_for_terminal(text: str) -> str:
    """Replace raw evidence stubs with terminal-friendly multi-line blocks."""

    if not text.strip():
        return text.strip()

    rendered = _AVAILABLE_EVIDENCE_STUB_RE.sub(
        lambda match: _render_stub(_parsed_stub_from_match(match, available=True)),
        text,
    )
    rendered = _UNAVAILABLE_EVIDENCE_STUB_RE.sub(
        lambda match: _render_stub(_parsed_stub_from_match(match, available=False)),
        rendered,
    )
    return _sanitize_terminal_text(rendered)
