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


# SEC-L3: negative-path coverage for reputation. The two existing tests only
# exercise the happy paths (known positive/negative signals, obvious boost
# pattern, one submission limit case). These companions pin the boundaries:
# unknown signals are ignored, empty signals clamp at tier `caution`, the
# coordinated-boost detector rejects scattered-old-account patterns and
# out-of-window stars, and per-author submission windows are independent.


def test_reputation_unknown_positive_and_negative_signals_are_ignored() -> None:
    scorer = ReputationScorer()
    result = scorer.score(
        positive=["verified_repo", "not_a_known_signal"],
        negative=["network_egress", "also_unknown"],
    )
    # Only the known signals contribute. Unknown signals must not crash
    # and must not be silently credited with a default weight.
    assert set(result.breakdown) == {"verified_repo", "network_egress"}
    assert result.score == 10  # 20 - 10


def test_reputation_empty_signal_lists_yield_zero_score_and_caution_tier() -> None:
    scorer = ReputationScorer()
    result = scorer.score(positive=[], negative=[])
    assert result.score == 0
    assert result.tier == "caution"
    assert result.breakdown == {}


def test_reputation_tier_boundaries_match_documented_thresholds() -> None:
    scorer = ReputationScorer()
    # At exactly 20: still neutral.
    neutral = scorer.score(positive=["verified_repo"], negative=[])
    assert neutral.score == 20
    assert neutral.tier == "neutral"
    # At 51 (> 50): trusted.
    trusted = scorer.score(
        positive=["audited", "verified_repo", "signed"],  # 25 + 20 + 10 = 55
        negative=[],
    )
    assert trusted.score == 55
    assert trusted.tier == "trusted"
    # Just below neutral threshold: caution.
    caution = scorer.score(positive=["signed"], negative=[])  # 10
    assert caution.score == 10
    assert caution.tier == "caution"


def test_detect_coordinated_boosting_returns_no_signals_on_empty_input() -> None:
    scorer = ReputationScorer()
    detection = scorer.detect_coordinated_boosting([], window_minutes=15, min_new_accounts=5)
    assert detection == {"detected": False, "reason": "no_signals", "window_count": 0}


def test_detect_coordinated_boosting_does_not_flag_only_old_accounts() -> None:
    scorer = ReputationScorer()
    now = datetime(2026, 2, 11, 12, 0, tzinfo=UTC)
    stars = [
        StarSignal(
            account_id=f"vet-{index}",
            account_age_days=365,  # all well above the 30-day threshold
            timestamp=now - timedelta(minutes=index),
        )
        for index in range(10)
    ]
    detection = scorer.detect_coordinated_boosting(stars, window_minutes=30, min_new_accounts=3)
    assert detection["detected"] is False
    # Window still picked up the recent activity, but none of it was young.
    assert detection["new_account_count"] == 0
    assert detection["reason"] == "baseline"


def test_detect_coordinated_boosting_ignores_stars_outside_window() -> None:
    scorer = ReputationScorer()
    now = datetime(2026, 2, 11, 12, 0, tzinfo=UTC)
    # Three young accounts, but the earliest two are outside the 5-minute
    # window from the latest star.
    stars = [
        StarSignal(account_id="young-a", account_age_days=5, timestamp=now - timedelta(hours=6)),
        StarSignal(account_id="young-b", account_age_days=5, timestamp=now - timedelta(hours=5)),
        StarSignal(account_id="young-c", account_age_days=5, timestamp=now),
    ]
    detection = scorer.detect_coordinated_boosting(stars, window_minutes=5, min_new_accounts=3)
    assert detection["detected"] is False
    assert detection["window_count"] == 1
    assert detection["new_account_count"] == 1


def test_can_submit_allows_after_cooldown_window_elapses() -> None:
    scorer = ReputationScorer(submission_window_seconds=60, submission_limit=1)
    now = datetime(2026, 2, 11, 12, 0, tzinfo=UTC)
    scorer.record_submission(author_id="author-1", now=now)
    # Still within the cooldown: blocked.
    assert scorer.can_submit(author_id="author-1", now=now + timedelta(seconds=30)) is False
    # Past the cooldown: allowed again.
    assert scorer.can_submit(author_id="author-1", now=now + timedelta(seconds=61)) is True


def test_submission_limits_are_independent_per_author() -> None:
    scorer = ReputationScorer(submission_window_seconds=60, submission_limit=1)
    now = datetime(2026, 2, 11, 12, 0, tzinfo=UTC)
    scorer.record_submission(author_id="author-a", now=now)
    # author-a is at the limit; author-b must not share the counter.
    assert scorer.can_submit(author_id="author-a", now=now + timedelta(seconds=1)) is False
    assert scorer.can_submit(author_id="author-b", now=now + timedelta(seconds=1)) is True
