"""M6.T5-T6 reputation and anti-gaming coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from shisad.security.reputation import ReputationScorer, StarSignal


def test_m6_t5_reputation_calculation_matches_expected_scores() -> None:
    scorer = ReputationScorer()
    result = scorer.score(
        positive=["verified_repo", "signed", "established_author"],
        negative=["network_egress"],
    )
    assert result.score == 25
    assert result.tier == "neutral"
    assert result.breakdown["verified_repo"] == 20
    assert result.breakdown["network_egress"] == -10


def test_m6_t6_anti_gaming_detects_coordinated_boosting() -> None:
    scorer = ReputationScorer(submission_window_seconds=120, submission_limit=2)
    now = datetime(2026, 2, 11, 12, 0, tzinfo=UTC)
    stars = [
        StarSignal(
            account_id=f"acct-{index}",
            account_age_days=5,
            timestamp=now - timedelta(minutes=5) + timedelta(seconds=index * 5),
        )
        for index in range(6)
    ]
    detection = scorer.detect_coordinated_boosting(stars, window_minutes=15, min_new_accounts=5)
    assert detection["detected"] is True
    assert detection["reason"] == "new-account-star-burst"

    assert scorer.can_submit(author_id="author-1", now=now) is True
    scorer.record_submission(author_id="author-1", now=now)
    scorer.record_submission(author_id="author-1", now=now + timedelta(seconds=5))
    assert scorer.can_submit(author_id="author-1", now=now + timedelta(seconds=10)) is False
