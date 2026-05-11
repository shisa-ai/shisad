"""Unit coverage for fetched-page actionable evidence extraction."""

from __future__ import annotations

from shisad.assistant.web import _FETCH_TEXT_MAX_CHARS, WebToolkit


def test_fetch_actionable_snippets_select_late_japanese_reservation_markers() -> None:
    text = ("レストラン紹介 " * 1800) + (
        "予約カレンダー 本日夜空席あり。ネット予約で席を確保できます。"
    )

    truncated_text = WebToolkit._extract_text(text, max_chars=_FETCH_TEXT_MAX_CHARS)
    snippets = WebToolkit._extract_actionable_evidence_snippets(text)

    assert "本日夜空席あり" not in truncated_text
    assert snippets
    assert snippets[0]["kind"] == "reservation_evidence_marker"
    assert "本日夜空席あり" in snippets[0]["snippet"]
    assert "ネット予約" in snippets[0]["snippet"]
    assert snippets[0]["taint_labels"] == ["untrusted"]


def test_fetch_actionable_snippets_do_not_label_negated_availability_as_positive() -> None:
    snippets = WebToolkit._extract_actionable_evidence_snippets(
        "予約カレンダー 本日夜空席ありません。ネット予約不可です。"
    )

    assert snippets
    assert all(item["kind"] == "reservation_evidence_marker" for item in snippets)
    assert not any(item["matched_marker"] == "本日夜空席あり" for item in snippets)
    assert not any(item["matched_marker"] == "空席あり" for item in snippets)
    assert "ありません" in snippets[0]["snippet"]


def test_fetch_actionable_snippets_handle_html_split_negated_availability() -> None:
    text = WebToolkit._extract_text(
        "<section>予約カレンダー 空席あり<span>ません</span>。ネット予約不可です。</section>",
        max_chars=None,
    )

    snippets = WebToolkit._extract_actionable_evidence_snippets(text)

    assert "空席あり ません" in text
    assert snippets
    assert not any(item["matched_marker"] == "空席あり" for item in snippets)


def test_fetch_actionable_snippets_keep_offsets_after_casefold_expanding_prefix() -> None:
    snippets = WebToolkit._extract_actionable_evidence_snippets(
        "Straße 予約カレンダー 空席ありません。ネット予約不可です。"
    )

    assert snippets
    assert not any(item["matched_marker"] == "空席あり" for item in snippets)


def test_fetch_actionable_snippets_ignore_page_without_reservation_markers() -> None:
    text = ("店舗紹介のみ。予約状況の表示はありません。 " * 100).strip()

    assert WebToolkit._extract_actionable_evidence_snippets(text) == []
