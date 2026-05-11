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

    assert "空席ありません" in text
    assert snippets
    assert not any(item["matched_marker"] == "空席あり" for item in snippets)


def test_fetch_actionable_snippets_handle_html_split_negation_suffix() -> None:
    text = WebToolkit._extract_text(
        "<section>予約カレンダー 空席ありま<span>せん</span>。ネット予約不可です。</section>",
        max_chars=None,
    )

    snippets = WebToolkit._extract_actionable_evidence_snippets(text)

    assert "空席ありません" in text
    assert snippets
    assert not any(item["matched_marker"] == "空席あり" for item in snippets)


def test_fetch_actionable_snippets_handle_html_split_positive_availability() -> None:
    text = WebToolkit._extract_text(
        "<section>予約カレンダー 空席<span>あり</span>。ネット予約できます。</section>",
        max_chars=None,
    )

    snippets = WebToolkit._extract_actionable_evidence_snippets(text)

    assert "空席あり" in text
    assert any(item["matched_marker"] == "空席あり" for item in snippets)


def test_fetch_actionable_snippets_do_not_join_positive_marker_across_punctuation() -> None:
    snippets = WebToolkit._extract_actionable_evidence_snippets(
        "予約カレンダー 空席。ありましたらお電話ください。"
    )

    assert snippets == []


def test_fetch_actionable_snippets_keep_offsets_after_casefold_expanding_prefix() -> None:
    snippets = WebToolkit._extract_actionable_evidence_snippets(
        "Straße 予約カレンダー 空席ありません。ネット予約不可です。"
    )

    assert snippets
    assert not any(item["matched_marker"] == "空席あり" for item in snippets)


def test_fetch_actionable_snippets_prioritize_availability_over_repeated_actions() -> None:
    action_blocks = ("ネット予約 " + ("説明" * 240) + " ") * 6
    snippets = WebToolkit._extract_actionable_evidence_snippets(
        action_blocks + "予約カレンダー 本日夜空席あり。"
    )

    assert len(snippets) <= 5
    assert snippets[0]["matched_marker"] == "本日夜空席あり"
    assert any(item["matched_marker"] == "本日夜空席あり" for item in snippets)


def test_fetch_actionable_snippets_select_late_mixed_case_english_marker() -> None:
    text = ("restaurant profile " * 900) + "Reserve Online from the booking calendar."

    truncated_text = WebToolkit._extract_text(text, max_chars=10_000)
    snippets = WebToolkit._extract_actionable_evidence_snippets(text)

    assert "Reserve Online" not in truncated_text
    assert snippets
    assert snippets[0]["kind"] == "reservation_evidence_marker"
    assert snippets[0]["matched_marker"] == "reserve online"
    assert "Reserve Online" in snippets[0]["snippet"]
    assert snippets[0]["taint_labels"] == ["untrusted"]


def test_fetch_actionable_snippets_handle_html_split_english_marker() -> None:
    text = WebToolkit._extract_text(
        "<section>Booking calendar: Reserve On<span>line</span> today.</section>",
        max_chars=None,
    )

    snippets = WebToolkit._extract_actionable_evidence_snippets(text)

    assert "Reserve Online" in text
    assert snippets
    assert snippets[0]["matched_marker"] == "reserve online"


def test_fetch_actionable_snippets_do_not_match_english_marker_inside_word() -> None:
    snippets = WebToolkit._extract_actionable_evidence_snippets(
        "Preserve Online privacy settings for the venue website."
    )

    assert snippets == []


def test_fetch_actionable_snippets_do_not_match_tag_split_english_prefix() -> None:
    text = WebToolkit._extract_text(
        "<section>Pre<span>serve Online</span> privacy settings.</section>",
        max_chars=None,
    )

    assert "Preserve Online" in text
    assert WebToolkit._extract_actionable_evidence_snippets(text) == []


def test_fetch_actionable_snippets_do_not_match_tag_split_english_suffix() -> None:
    text = WebToolkit._extract_text(
        "<section>Reserve Online<span>s</span> are not relevant text.</section>",
        max_chars=None,
    )

    assert "Reserve Onlines" in text
    assert WebToolkit._extract_actionable_evidence_snippets(text) == []


def test_fetch_actionable_snippets_keep_document_tags_as_boundaries() -> None:
    text = WebToolkit._extract_text(
        "<html><head><title>Venue</title></head><body>Reserve Online today.</body></html>",
        max_chars=None,
    )

    snippets = WebToolkit._extract_actionable_evidence_snippets(text)

    assert "Venue Reserve Online" in text
    assert snippets
    assert snippets[0]["matched_marker"] == "reserve online"


def test_fetch_actionable_snippets_do_not_block_split_custom_tag_names() -> None:
    text = WebToolkit._extract_text(
        "<p-custom>Pre</p-custom><span>serve Online</span> privacy settings.",
        max_chars=None,
    )

    assert "Preserve Online" in text
    assert WebToolkit._extract_actionable_evidence_snippets(text) == []


def test_fetch_actionable_snippets_ignore_page_without_reservation_markers() -> None:
    text = ("店舗紹介のみ。予約状況の表示はありません。 " * 100).strip()

    assert WebToolkit._extract_actionable_evidence_snippets(text) == []
