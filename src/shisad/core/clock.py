"""Trusted daemon clock helpers."""

from __future__ import annotations

from datetime import UTC, datetime, tzinfo
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def _normalize_utc(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(UTC)


def _format_utc_offset(value: datetime) -> str:
    offset = value.utcoffset()
    if offset is None:
        return "+00:00"
    total_seconds = int(offset.total_seconds())
    sign = "+" if total_seconds >= 0 else "-"
    total_seconds = abs(total_seconds)
    hours, remainder = divmod(total_seconds, 3600)
    minutes = remainder // 60
    return f"{sign}{hours:02d}:{minutes:02d}"


def _runtime_local_timezone() -> tzinfo:
    return datetime.now().astimezone().tzinfo or UTC


def _timezone_label(zone: tzinfo, local_now: datetime, requested: str) -> str:
    if requested:
        return requested
    key = getattr(zone, "key", "")
    if key:
        return str(key)
    return local_now.tzname() or str(zone) or "UTC"


def current_time_payload(
    *,
    now: datetime | None = None,
    timezone: str = "",
) -> dict[str, Any]:
    """Return trusted daemon-clock time metadata for tool output."""
    now_utc = _normalize_utc(now)
    requested_timezone = str(timezone or "").strip()
    timezone_source = "runtime_local"
    zone: tzinfo
    if requested_timezone:
        try:
            zone = ZoneInfo(requested_timezone)
        except (ValueError, ZoneInfoNotFoundError):
            return {
                "ok": False,
                "error": "timezone_unavailable",
                "utc_datetime": now_utc.isoformat(timespec="seconds"),
                "source": "daemon_clock",
                "precision": "seconds",
            }
        timezone_source = "requested"
    else:
        zone = _runtime_local_timezone()
    local_now = now_utc.astimezone(zone)
    timezone_label = _timezone_label(zone, local_now, requested_timezone)
    return {
        "ok": True,
        "utc_datetime": now_utc.isoformat(timespec="seconds"),
        "local_datetime": local_now.isoformat(timespec="seconds"),
        "timezone": timezone_label,
        "timezone_abbreviation": local_now.tzname() or timezone_label,
        "timezone_offset": _format_utc_offset(local_now),
        "timezone_source": timezone_source,
        "source": "daemon_clock",
        "precision": "seconds",
    }


def _sanitize_frontmatter_value(value: object) -> str:
    return " ".join(str(value).replace("\r", " ").replace("\n", " ").split())


def current_time_frontmatter_lines(
    *,
    now: datetime | None = None,
    timezone: str = "",
) -> list[str]:
    """Render current-turn time metadata as trusted frontmatter lines."""
    payload = current_time_payload(now=now, timezone=timezone)
    if not payload.get("ok"):
        payload = current_time_payload(now=now, timezone="UTC")
    return [
        f"current_turn_started_at_utc={_sanitize_frontmatter_value(payload['utc_datetime'])}",
        f"current_turn_local_datetime={_sanitize_frontmatter_value(payload['local_datetime'])}",
        f"current_turn_timezone={_sanitize_frontmatter_value(payload['timezone'])}",
        "current_turn_timezone_abbreviation="
        f"{_sanitize_frontmatter_value(payload['timezone_abbreviation'])}",
        f"current_turn_timezone_offset={_sanitize_frontmatter_value(payload['timezone_offset'])}",
        "current_turn_time_source=daemon_clock",
    ]
