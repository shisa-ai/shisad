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
    burst_window_seconds: int | None = None


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
        self._by_tool_burst: dict[str, deque[float]] = defaultdict(deque)
        self._anomaly_hook = anomaly_hook

    def check(
        self,
        *,
        session_id: str,
        user_id: str,
        tool_name: str,
        now: datetime | None = None,
    ) -> RateLimitDecision:
        """Evaluate whether the next action would exceed limits (no mutation)."""
        timestamp = (now or datetime.now(UTC)).timestamp()
        window = self._config.window_seconds
        burst_window = self._burst_window_seconds()

        counts = {
            "tool": self._count(self._by_tool[tool_name], timestamp, window),
            "user": self._count(self._by_user[user_id], timestamp, window),
            "session": self._count(self._by_session[session_id], timestamp, window),
            "burst_tool": self._count(self._by_tool_burst[tool_name], timestamp, burst_window),
        }
        projected = {name: value + 1 for name, value in counts.items()}

        if projected["tool"] > self._config.per_tool:
            return self._trigger(
                session_id=session_id,
                user_id=user_id,
                tool_name=tool_name,
                reason="tool_limit_exceeded",
                count=projected["tool"],
                block=True,
            )
        if projected["session"] > self._config.per_session:
            return self._trigger(
                session_id=session_id,
                user_id=user_id,
                tool_name=tool_name,
                reason="session_limit_exceeded",
                count=projected["session"],
                block=True,
            )
        if projected["user"] > self._config.per_user:
            return self._trigger(
                session_id=session_id,
                user_id=user_id,
                tool_name=tool_name,
                reason="user_limit_exceeded",
                count=projected["user"],
                block=True,
            )

        burst_limit = self._burst_limit()
        if projected["burst_tool"] > burst_limit:
            return self._trigger(
                session_id=session_id,
                user_id=user_id,
                tool_name=tool_name,
                reason="burst_detected",
                count=projected["burst_tool"],
                block=True,
            )

        if projected["tool"] >= max(int(self._config.per_tool * 0.8), 1):
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

    def consume(
        self,
        *,
        session_id: str,
        user_id: str,
        tool_name: str,
        now: datetime | None = None,
    ) -> None:
        """Record an executed action after admission checks pass."""
        timestamp = (now or datetime.now(UTC)).timestamp()
        self._append(self._by_tool[tool_name], timestamp, self._config.window_seconds)
        self._append(self._by_user[user_id], timestamp, self._config.window_seconds)
        self._append(self._by_session[session_id], timestamp, self._config.window_seconds)
        self._append(
            self._by_tool_burst[tool_name],
            timestamp,
            self._burst_window_seconds(),
        )

    def evaluate(
        self,
        *,
        session_id: str,
        user_id: str,
        tool_name: str,
        now: datetime | None = None,
        consume: bool = True,
    ) -> RateLimitDecision:
        decision = self.check(
            session_id=session_id,
            user_id=user_id,
            tool_name=tool_name,
            now=now,
        )
        if consume and not decision.block:
            self.consume(
                session_id=session_id,
                user_id=user_id,
                tool_name=tool_name,
                now=now,
            )
        return decision

    @staticmethod
    def _count(bucket: deque[float], timestamp: float, window_seconds: int) -> int:
        cutoff = timestamp - window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return len(bucket)

    @staticmethod
    def _append(bucket: deque[float], timestamp: float, window_seconds: int) -> None:
        cutoff = timestamp - window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        bucket.append(timestamp)

    def _burst_window_seconds(self) -> int:
        configured = self._config.burst_window_seconds
        if configured is not None and configured > 0:
            return configured
        return max(1, self._config.window_seconds // 6)

    def _burst_limit(self) -> int:
        burst_window = self._burst_window_seconds()
        base = (self._config.per_tool * burst_window) / max(self._config.window_seconds, 1)
        threshold = int(base * self._config.burst_multiplier)
        return max(3, threshold)

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
