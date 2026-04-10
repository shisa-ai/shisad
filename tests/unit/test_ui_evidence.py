"""Terminal rendering coverage for evidence-reference stubs."""

from __future__ import annotations

from shisad.core.evidence import EvidenceRef, format_evidence_stub
from shisad.core.types import TaintLabel
from shisad.ui.evidence import render_evidence_refs_for_terminal


def test_render_evidence_refs_for_terminal_formats_ref_stub_as_block() -> None:
    raw = (
        "Tool results summary:\n"
        "- web.fetch: success=True, ok=True\n"
        "  output: [EVIDENCE ref=ev-61f3d4c48f54ff92 source=web.fetch:example.com "
        'taint=UNTRUSTED size=88 summary="Example Domain" '
        'Use evidence.read("ev-61f3d4c48f54ff92") for full content, or '
        'evidence.promote("ev-61f3d4c48f54ff92") to add it to the conversation.]'
    )

    rendered = render_evidence_refs_for_terminal(raw)

    assert "[EVIDENCE ref=" not in rendered
    assert "[Evidence ev-61f3d4c48f54ff92]" in rendered
    assert "source: web.fetch:example.com" in rendered
    assert "taint: UNTRUSTED" in rendered
    assert "size: 88 bytes" in rendered
    assert "summary: Example Domain" in rendered
    assert 'inspect: evidence.read("ev-61f3d4c48f54ff92")' in rendered
    assert 'promote: evidence.promote("ev-61f3d4c48f54ff92")' in rendered


def test_render_evidence_refs_for_terminal_formats_unavailable_stub() -> None:
    raw = (
        "[EVIDENCE unavailable source=web.fetch:example.com taint=UNTRUSTED size=42 "
        'summary="Content from web.fetch:example.com, 42 bytes" '
        "Evidence storage unavailable; inspect tool_outputs for the full content in this turn.]"
    )

    rendered = render_evidence_refs_for_terminal(raw)

    assert rendered.startswith("[Evidence unavailable]")
    assert "source: web.fetch:example.com" in rendered
    assert "size: 42 bytes" in rendered
    assert "summary: Content from web.fetch:example.com, 42 bytes" in rendered


def test_render_evidence_refs_for_terminal_preserves_surrounding_text() -> None:
    raw = (
        "First line.\n\n"
        "[EVIDENCE ref=ev-aaaaaaaaaaaaaaaa source=web.fetch:example.com taint=UNTRUSTED "
        'size=11 summary="Example" Use evidence.read("ev-aaaaaaaaaaaaaaaa") for full content, '
        'or evidence.promote("ev-aaaaaaaaaaaaaaaa") to add it to the conversation.]\n\n'
        "Last line."
    )

    rendered = render_evidence_refs_for_terminal(raw)

    assert rendered.startswith("First line.")
    assert rendered.endswith("Last line.")
    assert "[Evidence ev-aaaaaaaaaaaaaaaa]" in rendered


def test_render_evidence_refs_keeps_ref_when_summary_mentions_unavailable() -> None:
    raw = (
        "[EVIDENCE ref=ev-61f3d4c48f54ff92 source=web.fetch:example.com taint=UNTRUSTED "
        'size=88 summary="Service unavailable right now" '
        'Use evidence.read("ev-61f3d4c48f54ff92") for full content, or '
        'evidence.promote("ev-61f3d4c48f54ff92") to add it to the conversation.]'
    )

    rendered = render_evidence_refs_for_terminal(raw)

    assert rendered.startswith("[Evidence ev-61f3d4c48f54ff92]")
    assert "summary: Service unavailable right now" in rendered
    assert 'inspect: evidence.read("ev-61f3d4c48f54ff92")' in rendered
    assert 'promote: evidence.promote("ev-61f3d4c48f54ff92")' in rendered


def test_render_evidence_refs_for_terminal_strips_terminal_control_sequences() -> None:
    raw = format_evidence_stub(
        EvidenceRef(
            ref_id="ev-61f3d4c48f54ff92",
            content_hash="hash",
            taint_labels=[TaintLabel.UNTRUSTED],
            source="web.fetch:example.com",
            summary=(
                "click \x1b]8;;https://evil.invalid\x07link\x1b]8;;\x07 "
                "\x1b[31mRED\x1b[0m\r\nnext\x00done"
            ),
            byte_size=88,
        )
    )

    rendered = render_evidence_refs_for_terminal(raw)

    assert "\x1b" not in rendered
    assert "\x00" not in rendered
    assert "\r" not in rendered
    assert "summary: click link RED next done" in rendered


def test_render_evidence_refs_for_terminal_normalizes_literal_linebreaks_before_stripping_escapes(
) -> None:
    raw = "First line\\n\x1b[31mSecond line\x1b[0m"

    rendered = render_evidence_refs_for_terminal(raw)

    assert rendered == "First line\nSecond line"
    assert "\\n" not in rendered
    assert "\x1b" not in rendered


def test_render_evidence_refs_for_terminal_preserves_double_escaped_linebreak_text() -> None:
    raw = r"Regex token \\n should stay literal"

    rendered = render_evidence_refs_for_terminal(raw)

    assert rendered == r"Regex token \n should stay literal"
    assert "\n" not in rendered


def test_render_evidence_refs_for_terminal_keeps_summary_single_line_after_normalization() -> None:
    ref = EvidenceRef(
        ref_id="ev-1234567890abcdef",
        content_hash="hash",
        taint_labels=[TaintLabel.UNTRUSTED],
        source="web.fetch:example.com",
        summary="line one\nsource: spoofed",
        byte_size=42,
    )

    rendered = render_evidence_refs_for_terminal(format_evidence_stub(ref))

    assert "summary: line one source: spoofed" in rendered
    assert rendered.count("\nsource:") == 1


def test_render_evidence_refs_for_terminal_round_trips_escaped_summary_from_stub_formatter() -> (
    None
):
    ref = EvidenceRef(
        ref_id="ev-1234567890abcdef",
        content_hash="hash",
        taint_labels=[TaintLabel.UNTRUSTED],
        source="web.fetch:example.com",
        summary='path \\ share ] "quotes"',
        byte_size=42,
    )

    rendered = render_evidence_refs_for_terminal(format_evidence_stub(ref))

    assert "[Evidence ev-1234567890abcdef]" in rendered
    assert 'summary: path \\ share ] "quotes"' in rendered
    assert "\\]" not in rendered
    assert '\\"' not in rendered


def test_render_evidence_refs_for_terminal_formats_multiple_stubs() -> None:
    first = format_evidence_stub(
        EvidenceRef(
            ref_id="ev-aaaaaaaaaaaaaaaa",
            content_hash="hash-a",
            taint_labels=[TaintLabel.UNTRUSTED],
            source="web.fetch:example.com",
            summary="First summary",
            byte_size=11,
        )
    )
    second = format_evidence_stub(
        EvidenceRef(
            ref_id="ev-bbbbbbbbbbbbbbbb",
            content_hash="hash-b",
            taint_labels=[TaintLabel.UNTRUSTED],
            source="web.fetch:example.org",
            summary="Second summary",
            byte_size=22,
        )
    )
    raw = f"First:\n{first}\n\nSecond:\n{second}"

    rendered = render_evidence_refs_for_terminal(raw)

    assert rendered.count("[Evidence ev-") == 2
    assert "[Evidence ev-aaaaaaaaaaaaaaaa]" in rendered
    assert "[Evidence ev-bbbbbbbbbbbbbbbb]" in rendered
    assert "[EVIDENCE ref=" not in rendered


def test_render_evidence_refs_for_terminal_leaves_malformed_stub_text_unchanged() -> None:
    raw = '[EVIDENCE ref=ev-123 source=web.fetch:example.com summary="missing closing bracket"'

    rendered = render_evidence_refs_for_terminal(raw)

    assert rendered == raw


def test_render_evidence_refs_for_terminal_does_not_partially_rewrite_malformed_fake_stub() -> None:
    raw = (
        "[EVIDENCE ref=ev-61f3d4c48f54ff92 source=web.fetch:example.com taint=UNTRUSTED "
        'size=88 summary="click ] \x1b]8;;https://evil.invalid tail"]'
    )

    rendered = render_evidence_refs_for_terminal(raw)

    assert "\x1b" not in rendered
    assert "[Evidence ev-61f3d4c48f54ff92]" not in rendered
    assert rendered == (
        "[EVIDENCE ref=ev-61f3d4c48f54ff92 source=web.fetch:example.com taint=UNTRUSTED "
        'size=88 summary="click ] '
    )
