"""Sliding-window rate limiting and anomaly hooks."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class RateLimitDecision:
    block: bool
    require_confirmation: bool
    anomaly: bool
    reason: str


@dataclass(frozen=True)
class RateLimitConfig:
    window_seconds: int = 60
    per_tool: int = 15
    per_user: int = 40
    per_session: int = 30
    burst_multiplier: float = 2.0


@dataclass(frozen=True)
class RateLimitEvent:
    timestamp: datetime
    session_id: str
    user_id: str
    tool_name: str
    reason: str
    count: int


class RateLimiter:
    """Per-tool/per-user/per-session sliding window limiter."""

    def __init__(
        self,
        config: RateLimitConfig,
        *,
        anomaly_hook: Callable[[RateLimitEvent], None] | None = None,
    ) -> None:
        self._config = config
        self._by_tool: dict[str, deque[float]] = defaultdict(deque)
        self._by_user: dict[str, deque[float]] = defaultdict(deque)
        self._by_session: dict[str, deque[float]] = defaultdict(deque)
        self._anomaly_hook = anomaly_hook

    def evaluate(
        self,
        *,
        session_id: str,
        user_id: str,
        tool_name: str,
        now: datetime | None = None,
    ) -> RateLimitDecision:
        timestamp = (now or datetime.now(UTC)).timestamp()
        counts = {
            "tool": self._record_and_count(self._by_tool[tool_name], timestamp),
            "user": self._record_and_count(self._by_user[user_id], timestamp),
            "session": self._record_and_count(self._by_session[session_id], timestamp),
        }

        if counts["tool"] > self._config.per_tool:
            return self._trigger(
                session_id=session_id,
                user_id=user_id,
                tool_name=tool_name,
                reason="tool_limit_exceeded",
                count=counts["tool"],
                block=True,
            )
        if counts["session"] > self._config.per_session:
            return self._trigger(
                session_id=session_id,
                user_id=user_id,
                tool_name=tool_name,
                reason="session_limit_exceeded",
                count=counts["session"],
                block=True,
            )
        if counts["user"] > self._config.per_user:
            return self._trigger(
                session_id=session_id,
                user_id=user_id,
                tool_name=tool_name,
                reason="user_limit_exceeded",
                count=counts["user"],
                block=True,
            )

        burst_limit = int(self._config.per_tool * self._config.burst_multiplier)
        if counts["tool"] >= burst_limit:
            return self._trigger(
                session_id=session_id,
                user_id=user_id,
                tool_name=tool_name,
                reason="burst_detected",
                count=counts["tool"],
                block=True,
            )

        if counts["tool"] >= max(int(self._config.per_tool * 0.8), 1):
            return RateLimitDecision(
                block=False,
                require_confirmation=True,
                anomaly=False,
                reason="approaching_tool_limit",
            )

        return RateLimitDecision(
            block=False,
            require_confirmation=False,
            anomaly=False,
            reason="ok",
        )

    def _record_and_count(self, bucket: deque[float], timestamp: float) -> int:
        cutoff = timestamp - self._config.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        bucket.append(timestamp)
        return len(bucket)

    def _trigger(
        self,
        *,
        session_id: str,
        user_id: str,
        tool_name: str,
        reason: str,
        count: int,
        block: bool,
    ) -> RateLimitDecision:
        if self._anomaly_hook is not None:
            self._anomaly_hook(
                RateLimitEvent(
                    timestamp=datetime.now(UTC),
                    session_id=session_id,
                    user_id=user_id,
                    tool_name=tool_name,
                    reason=reason,
                    count=count,
                )
            )
        return RateLimitDecision(
            block=block,
            require_confirmation=not block,
            anomaly=True,
            reason=reason,
        )

