"""Skill reputation scoring and anti-gaming controls."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

REPUTATION_SIGNALS: dict[str, int] = {
    "verified_repo": 20,
    "verified_author": 15,
    "signed": 10,
    "popular_repo": 10,
    "established_author": 5,
    "audited": 25,
}

NEGATIVE_SIGNALS: dict[str, int] = {
    "shell_access": -15,
    "network_egress": -10,
    "obfuscated": -30,
    "new_author": -5,
}


@dataclass(slots=True)
class ReputationResult:
    score: int
    tier: str
    breakdown: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class StarSignal:
    account_id: str
    account_age_days: int
    timestamp: datetime


class ReputationScorer:
    """Compute skill reputation and detect suspicious boost patterns."""

    def __init__(self, *, submission_window_seconds: int = 300, submission_limit: int = 5) -> None:
        self._submission_window_seconds = max(60, submission_window_seconds)
        self._submission_limit = max(1, submission_limit)
        self._submission_timestamps: dict[str, deque[datetime]] = defaultdict(deque)

    def score(
        self,
        *,
        positive: list[str],
        negative: list[str],
    ) -> ReputationResult:
        breakdown: dict[str, int] = {}
        for signal in positive:
            weight = REPUTATION_SIGNALS.get(signal)
            if weight is None:
                continue
            breakdown[signal] = weight
        for signal in negative:
            weight = NEGATIVE_SIGNALS.get(signal)
            if weight is None:
                continue
            breakdown[signal] = weight
        total = sum(breakdown.values())
        tier = "caution"
        if total > 50:
            tier = "trusted"
        elif total >= 20:
            tier = "neutral"
        return ReputationResult(score=total, tier=tier, breakdown=breakdown)

    @staticmethod
    def detect_coordinated_boosting(
        stars: list[StarSignal],
        *,
        window_minutes: int = 30,
        min_new_accounts: int = 5,
    ) -> dict[str, Any]:
        if not stars:
            return {"detected": False, "reason": "no_signals", "window_count": 0}
        sorted_stars = sorted(stars, key=lambda item: item.timestamp)
        latest = sorted_stars[-1].timestamp
        cutoff = latest - timedelta(minutes=max(1, window_minutes))
        recent = [item for item in sorted_stars if item.timestamp >= cutoff]
        young = [item for item in recent if item.account_age_days < 30]
        account_ids = {item.account_id for item in young}
        detected = len(account_ids) >= max(1, min_new_accounts)
        return {
            "detected": detected,
            "window_count": len(recent),
            "new_account_count": len(account_ids),
            "reason": "new-account-star-burst" if detected else "baseline",
        }

    def can_submit(self, *, author_id: str, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        entries = self._submission_timestamps[author_id]
        cutoff = current - timedelta(seconds=self._submission_window_seconds)
        while entries and entries[0] < cutoff:
            entries.popleft()
        return len(entries) < self._submission_limit

    def record_submission(self, *, author_id: str, now: datetime | None = None) -> None:
        current = now or datetime.now(UTC)
        entries = self._submission_timestamps[author_id]
        entries.append(current)
