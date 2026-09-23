"""M6 leak-check and PII detection coverage."""

from __future__ import annotations

import pytest

from shisad.security.firewall.pii import PIIDetector
from shisad.security.leakcheck import CrossThreadLeakDetector


@pytest.mark.parametrize(
    ("outbound", "source"),
    [
        (
            "The garden flowers bloom beside the old stone wall.",
            "Compile the package and upload the release archive.",
        ),
        (
            "Tomorrow we will paint the kitchen blue.",
            "A database index speeds up record retrieval.",
        ),
        ("Please bring fresh oranges for breakfast.", "The lunar rover crossed a rocky crater."),
    ],
)
def test_default_leak_check_does_not_flag_unrelated_text(outbound: str, source: str) -> None:
    result = CrossThreadLeakDetector().evaluate(
        outbound_text=outbound, source_text_by_id={"other": source}
    )
    assert not result.detected
    assert not result.requires_confirmation
    assert result.matched_source_ids == []


def test_default_leak_check_detects_reused_words_and_respects_source_authorization() -> None:
    detector = CrossThreadLeakDetector()
    kwargs = {
        "outbound_text": "alpha bravo charlie delta ledger report",
        "source_text_by_id": {"other": "confidential ledger alpha bravo charlie delta report"},
    }
    result = detector.evaluate(**kwargs)
    assert result.detected and result.requires_confirmation
    assert not detector.evaluate(**kwargs, allowed_source_ids={"other"}).detected


@pytest.mark.parametrize(
    "number",
    [
        "1758342000000",
        "1758342000000000000",
        "1234567890123456",
        "4242424242424243",
        "42424242424242424242424242",
    ],
)
def test_pii_preserves_non_card_numbers(number: str) -> None:
    text = f"Value {number} was recorded."
    detector = PIIDetector()
    assert detector.inspect(text) == []
    assert detector.redact(text) == (text, [])


@pytest.mark.parametrize(
    "number", ["4242 4242 4242 4242", "4242-4242-4242-4242", "4242424242424242"]
)
@pytest.mark.parametrize("suffix", [" was recorded.", "-suffix", ".", "\nnext"])
def test_pii_card_redaction_preserves_following_text(number: str, suffix: str) -> None:
    detector = PIIDetector()
    text = f"Card {number}{suffix}"
    redacted, findings = detector.redact(text)
    assert redacted == f"Card [REDACTED:credit_card]{suffix}"
    assert findings == detector.inspect(text)
    assert [(finding.kind, finding.value) for finding in findings] == [("credit_card", number)]


def test_m6_t12_cross_thread_high_overlap_requires_confirmation() -> None:
    detector = CrossThreadLeakDetector(warning_threshold=0.1, confirmation_threshold=0.2)
    result = detector.evaluate(
        outbound_text="Please send the incident key alpha bravo charlie delta now.",
        source_text_by_id={
            "thread-a": "Incident key alpha bravo charlie delta was recovered from logs.",
            "thread-b": "Unrelated planning notes",
        },
        allowed_source_ids={"thread-b"},
    )
    assert result.detected is True
    assert "thread-a" in result.matched_source_ids
    assert result.requires_confirmation is True
    assert "leakcheck:high_overlap_requires_confirmation" in result.reason_codes


def test_m6_t13_explicit_share_intent_allows_with_warning() -> None:
    detector = CrossThreadLeakDetector(warning_threshold=0.1, confirmation_threshold=0.2)
    result = detector.evaluate(
        outbound_text="Forward the migration plan from finance thread immediately.",
        source_text_by_id={"finance-thread": "Migration plan from finance thread"},
        allowed_source_ids=set(),
        explicit_cross_thread_intent=True,
    )
    assert result.detected is True
    assert result.requires_confirmation is False


def test_m6_pii_detector_redacts_sensitive_tokens() -> None:
    detector = PIIDetector()
    text = "Contact alice@example.com SSN 123-45-6789 card 4242 4242 4242 4242"
    redacted, findings = detector.redact(text)
    assert "[REDACTED:email]" in redacted
    assert "[REDACTED:ssn]" in redacted
    assert "[REDACTED:credit_card]" in redacted
    kinds = {finding.kind for finding in findings}
    assert {"email", "ssn", "credit_card"}.issubset(kinds)


def test_gh34_pii_detector_does_not_prefix_replace_readable_sibling() -> None:
    detector = PIIDetector()
    sibling = "alice@example.com_notes"

    redacted, findings = detector.redact(f"Contact alice@example.com but keep {sibling}")

    assert "[REDACTED:email]" in redacted
    assert sibling in redacted
    assert "[REDACTED:email]_notes" not in redacted
    assert redacted.count("[REDACTED:email]") == 1
    assert {finding.kind for finding in findings} == {"email"}
