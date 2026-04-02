"""Terminal-friendly rendering helpers for evidence-reference stubs."""

from __future__ import annotations

import re
from dataclasses import dataclass

_EVIDENCE_STUB_RE = re.compile(r"\[EVIDENCE (?P<body>(?:\\.|[^\]])+)\]")
_SUMMARY_RE = re.compile(r'summary="(?P<summary>(?:\\.|[^"])*)"')


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


def _parse_stub(stub: str) -> _ParsedEvidenceStub | None:
    match = _EVIDENCE_STUB_RE.fullmatch(stub.strip())
    if match is None:
        return None
    body = str(match.group("body") or "")
    summary_match = _SUMMARY_RE.search(body)
    summary = _unescape_summary(str(summary_match.group("summary") or "")) if summary_match else ""
    size_bytes = None
    size_raw = _field(body, "size")
    if size_raw.isdigit():
        size_bytes = int(size_raw)
    return _ParsedEvidenceStub(
        ref_id=_field(body, "ref"),
        source=_field(body, "source"),
        taint=_field(body, "taint"),
        size_bytes=size_bytes,
        summary=summary,
        available=" unavailable " not in f" {body} ",
    )


def _render_stub(parsed: _ParsedEvidenceStub) -> str:
    heading = (
        f"[Evidence {parsed.ref_id}]"
        if parsed.available and parsed.ref_id
        else "[Evidence unavailable]"
    )
    lines = [heading]
    if parsed.source:
        lines.append(f"source: {parsed.source}")
    if parsed.taint:
        lines.append(f"taint: {parsed.taint}")
    if parsed.size_bytes is not None:
        lines.append(f"size: {parsed.size_bytes} bytes")
    if parsed.summary:
        lines.append(f"summary: {parsed.summary}")
    if parsed.available and parsed.ref_id:
        lines.append(f'inspect: evidence.read("{parsed.ref_id}")')
        lines.append(f'promote: evidence.promote("{parsed.ref_id}")')
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
