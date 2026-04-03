"""Terminal-friendly rendering helpers for evidence-reference stubs."""

from __future__ import annotations

import re
from dataclasses import dataclass

_EVIDENCE_STUB_RE = re.compile(r"\[EVIDENCE (?P<body>(?:\\.|[^\]])+)\]")
_SUMMARY_RE = re.compile(r'summary="(?P<summary>(?:\\.|[^"])*)"')
_ANSI_CSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC_RE = re.compile(r"\x1B\].*?(?:\x07|\x1B\\)", re.DOTALL)
_ANSI_STRING_RE = re.compile(r"\x1B(?:P|X|\^|_).*?\x1B\\", re.DOTALL)
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1F\x7F-\x9F]+")


@dataclass(frozen=True, slots=True)
class _ParsedEvidenceStub:
    ref_id: str
    source: str
    taint: str
    size_bytes: int | None
    summary: str
    available: bool


def _field(body: str, name: str) -> str:
    match = re.search(rf"{re.escape(name)}=(?P<value>\S+)", body)
    if match is None:
        return ""
    return str(match.group("value") or "").strip()


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


def _sanitize_terminal_field(value: str) -> str:
    cleaned = _ANSI_OSC_RE.sub("", value)
    cleaned = _ANSI_STRING_RE.sub("", cleaned)
    cleaned = _ANSI_CSI_RE.sub("", cleaned)
    cleaned = cleaned.replace("\x1b", "")
    cleaned = _CONTROL_CHARS_RE.sub(" ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def _parse_stub(stub: str) -> _ParsedEvidenceStub | None:
    match = _EVIDENCE_STUB_RE.fullmatch(stub.strip())
    if match is None:
        return None
    body = str(match.group("body") or "")
    ref_id = _field(body, "ref")
    summary_match = _SUMMARY_RE.search(body)
    summary = _unescape_summary(str(summary_match.group("summary") or "")) if summary_match else ""
    size_bytes = None
    size_raw = _field(body, "size")
    if size_raw.isdigit():
        size_bytes = int(size_raw)
    unavailable = body.lstrip().startswith("unavailable ")
    return _ParsedEvidenceStub(
        ref_id=ref_id,
        source=_field(body, "source"),
        taint=_field(body, "taint"),
        size_bytes=size_bytes,
        summary=summary,
        available=not unavailable and bool(ref_id),
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

    def _replace(match: re.Match[str]) -> str:
        parsed = _parse_stub(match.group(0))
        if parsed is None:
            return match.group(0)
        return _render_stub(parsed)

    return _EVIDENCE_STUB_RE.sub(_replace, text)
