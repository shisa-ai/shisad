"""M6 leak-check and PII detection coverage."""

from __future__ import annotations

from shisad.security.firewall.pii import PIIDetector
from shisad.security.leakcheck import CrossThreadLeakDetector


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
