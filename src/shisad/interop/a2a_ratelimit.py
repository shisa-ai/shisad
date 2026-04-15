"""Sliding-window rate limiting for authenticated A2A ingress."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime

from shisad.interop.a2a_registry import A2aRateLimitsConfig

_MINUTE_WINDOW_SECONDS = 60.0
_HOUR_WINDOW_SECONDS = 3600.0


@dataclass(frozen=True, slots=True)
class A2aRateLimitResult:
    """Admission result for an authenticated A2A request."""

    allowed: bool
    reason: str = "ok"
    retry_after_seconds: float = 0.0


class A2aRateLimiter:
    """Per-fingerprint sliding-window limiter for A2A ingress."""

    def __init__(self, config: A2aRateLimitsConfig) -> None:
        self._max_per_minute = int(config.max_per_minute)
        self._max_per_hour = int(config.max_per_hour)
        self._entries: dict[str, deque[float]] = {}

    def check_rate_limit(
        self,
        fingerprint: str,
        *,
        now: datetime | None = None,
    ) -> A2aRateLimitResult:
        timestamp = (now or datetime.now(UTC)).timestamp()
        self._prune_expired(timestamp)
        key = str(fingerprint).strip().lower()
        bucket = self._entries.setdefault(key, deque())
        minute_cutoff = timestamp - _MINUTE_WINDOW_SECONDS
        minute_entries = [entry for entry in bucket if entry >= minute_cutoff]
        if len(minute_entries) + 1 > self._max_per_minute:
            retry_after = max(0.0, minute_entries[0] + _MINUTE_WINDOW_SECONDS - timestamp)
            return A2aRateLimitResult(
                allowed=False,
                reason="minute_limit_exceeded",
                retry_after_seconds=retry_after,
            )
        if len(bucket) + 1 > self._max_per_hour:
            retry_after = max(0.0, bucket[0] + _HOUR_WINDOW_SECONDS - timestamp)
            return A2aRateLimitResult(
                allowed=False,
                reason="hour_limit_exceeded",
                retry_after_seconds=retry_after,
            )
        bucket.append(timestamp)
        return A2aRateLimitResult(allowed=True)

    def _prune_expired(self, timestamp: float) -> None:
        cutoff = timestamp - _HOUR_WINDOW_SECONDS
        stale_keys: list[str] = []
        for key, bucket in self._entries.items():
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if not bucket:
                stale_keys.append(key)
        for key in stale_keys:
            self._entries.pop(key, None)
