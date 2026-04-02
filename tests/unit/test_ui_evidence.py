"""Terminal rendering coverage for evidence-reference stubs."""

from __future__ import annotations

from shisad.ui.evidence import render_evidence_refs_for_terminal


def test_render_evidence_refs_for_terminal_formats_ref_stub_as_block() -> None:
    raw = (
        "Tool results summary:\n"
        "- web.fetch: success=True, ok=True\n"
        '  output: [EVIDENCE ref=ev-61f3d4c48f54ff92 source=web.fetch:example.com '
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
        '[EVIDENCE unavailable source=web.fetch:example.com taint=UNTRUSTED size=42 '
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
        '[EVIDENCE ref=ev-aaaaaaaaaaaaaaaa source=web.fetch:example.com taint=UNTRUSTED '
        'size=11 summary="Example" Use evidence.read("ev-aaaaaaaaaaaaaaaa") for full content, '
        'or evidence.promote("ev-aaaaaaaaaaaaaaaa") to add it to the conversation.]\n\n'
        "Last line."
    )

    rendered = render_evidence_refs_for_terminal(raw)

    assert rendered.startswith("First line.")
    assert rendered.endswith("Last line.")
    assert "[Evidence ev-aaaaaaaaaaaaaaaa]" in rendered
