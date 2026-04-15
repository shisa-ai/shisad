"""I4 A2A rate-limit unit coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from shisad.interop.a2a_ratelimit import A2aRateLimiter
from shisad.interop.a2a_registry import A2aRateLimitsConfig

_FINGERPRINT = "sha256:" + ("a" * 64)


def test_a2a_rate_limiter_allows_requests_within_minute_window() -> None:
    limiter = A2aRateLimiter(A2aRateLimitsConfig(max_per_minute=60, max_per_hour=600))
    now = datetime(2026, 4, 15, 12, 0, tzinfo=UTC)

    for offset in range(60):
        result = limiter.check_rate_limit(
            _FINGERPRINT,
            now=now + timedelta(seconds=offset),
        )
        assert result.allowed is True
        assert result.reason == "ok"
        assert result.retry_after_seconds == 0.0


def test_a2a_rate_limiter_rejects_61st_request_with_retry_after() -> None:
    limiter = A2aRateLimiter(A2aRateLimitsConfig(max_per_minute=60, max_per_hour=600))
    now = datetime(2026, 4, 15, 12, 0, tzinfo=UTC)

    for offset in range(60):
        assert limiter.check_rate_limit(
            _FINGERPRINT,
            now=now + timedelta(seconds=offset),
        ).allowed

    blocked = limiter.check_rate_limit(
        _FINGERPRINT,
        now=now + timedelta(seconds=59),
    )

    assert blocked.allowed is False
    assert blocked.reason == "minute_limit_exceeded"
    assert blocked.retry_after_seconds == pytest.approx(1.0, rel=1e-6)


def test_a2a_rate_limiter_rejects_hour_limit_until_oldest_entry_expires() -> None:
    limiter = A2aRateLimiter(A2aRateLimitsConfig(max_per_minute=10, max_per_hour=3))
    now = datetime(2026, 4, 15, 12, 0, tzinfo=UTC)

    for offset_minutes in (0, 10, 20):
        assert limiter.check_rate_limit(
            _FINGERPRINT,
            now=now + timedelta(minutes=offset_minutes),
        ).allowed

    blocked = limiter.check_rate_limit(
        _FINGERPRINT,
        now=now + timedelta(minutes=30),
    )
    reopened = limiter.check_rate_limit(
        _FINGERPRINT,
        now=now + timedelta(hours=1, seconds=1),
    )

    assert blocked.allowed is False
    assert blocked.reason == "hour_limit_exceeded"
    assert blocked.retry_after_seconds == pytest.approx(1800.0, rel=1e-6)
    assert reopened.allowed is True
