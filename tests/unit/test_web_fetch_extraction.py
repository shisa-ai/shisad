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
    assert snippets[0]["kind"] == "reservation_availability"
    assert "本日夜空席あり" in snippets[0]["snippet"]
    assert "ネット予約" in snippets[0]["snippet"]
    assert snippets[0]["taint_labels"] == ["untrusted"]


def test_fetch_actionable_snippets_ignore_page_without_reservation_markers() -> None:
    text = ("店舗紹介のみ。予約状況の表示はありません。 " * 100).strip()

    assert WebToolkit._extract_actionable_evidence_snippets(text) == []
