"""Resource-access monitor for metadata-only suspicious access patterns."""

from __future__ import annotations

import fnmatch
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from shisad.security.control_plane.history import ActionHistoryRecord, SessionActionHistoryStore
from shisad.security.control_plane.schema import ActionKind, ControlPlaneAction, RiskTier

SENSITIVE_RESOURCES: dict[str, list[str]] = {
    "credentials": [
        "~/.ssh/*",
        "~/.aws/*",
        "~/.config/gcloud/*",
        "**/credentials*",
        "**/*.pem",
        "**/*.key",
        "**/.env*",
    ],
    "system": ["/etc/passwd", "/etc/shadow", "/etc/hosts"],
    "browser": [
        "~/.config/chromium/**/Cookies",
        "~/.config/google-chrome/**/Login Data",
        "~/.mozilla/**/cookies.sqlite",
    ],
    "crypto": ["~/.bitcoin/*", "~/.ethereum/*", "**/wallet.dat"],
}


class ResourceFinding(BaseModel, frozen=True):
    risk_tier: RiskTier
    reason_code: str
    category: str = ""
    resource_id: str = ""
    evidence: list[str] = Field(default_factory=list)


class ResourceAccessMonitor:
    """Tracks sensitive resource touches and enumeration patterns."""

    def __init__(
        self,
        *,
        enum_resource_threshold: int = 20,
        enum_directory_threshold: int = 10,
        enum_window_seconds: int = 60,
    ) -> None:
        self._enum_resource_threshold = enum_resource_threshold
        self._enum_directory_threshold = enum_directory_threshold
        self._enum_window_seconds = enum_window_seconds

    def analyze(
        self,
        *,
        history: SessionActionHistoryStore,
        candidate_action: ControlPlaneAction,
        now: datetime | None = None,
    ) -> list[ResourceFinding]:
        current = now or datetime.now(UTC)
        session_id = candidate_action.origin.session_id
        if not session_id:
            return []

        candidate_record = ActionHistoryRecord(
            timestamp=candidate_action.timestamp,
            session_id=session_id,
            origin=candidate_action.origin,
            action_kind=candidate_action.action_kind,
            resource_id=candidate_action.resource_id,
            tool_name=candidate_action.tool_name,
        )

        findings: list[ResourceFinding] = []

        for resource in candidate_action.resource_ids or [candidate_action.resource_id]:
            if not resource:
                continue
            category = self._sensitive_category(resource)
            if category:
                findings.append(
                    ResourceFinding(
                        risk_tier=RiskTier.HIGH,
                        reason_code="resource:sensitive_access",
                        category=category,
                        resource_id=resource,
                        evidence=[resource],
                    )
                )

        recent = history.for_analysis(
            session_id,
            window_seconds=self._enum_window_seconds,
            now=current,
            observation_kinds={"action"},
        )
        recent = list(recent)
        recent.append(candidate_record)
        recent = history.dedupe_for_analysis(recent)

        fs_events = [
            item
            for item in recent
            if item.action_kind in {ActionKind.FS_READ, ActionKind.FS_WRITE, ActionKind.FS_LIST}
            and item.resource_id
        ]
        unique_resources = {item.resource_id for item in fs_events}
        if len(unique_resources) > self._enum_resource_threshold:
            findings.append(
                ResourceFinding(
                    risk_tier=RiskTier.MEDIUM,
                    reason_code="resource:enumeration_many_resources",
                    evidence=sorted(unique_resources),
                )
            )

        unique_dirs = {
            str(Path(resource).expanduser().resolve(strict=False).parent)
            for resource in unique_resources
            if resource
        }
        if len(unique_dirs) > self._enum_directory_threshold:
            findings.append(
                ResourceFinding(
                    risk_tier=RiskTier.MEDIUM,
                    reason_code="resource:enumeration_many_directories",
                    evidence=sorted(unique_dirs),
                )
            )

        return findings

    @staticmethod
    def _sensitive_category(resource_id: str) -> str:
        path = resource_id.strip()
        if not path:
            return ""
        expanded = str(Path(path).expanduser())
        for category, patterns in SENSITIVE_RESOURCES.items():
            for pattern in patterns:
                expanded_pattern = (
                    str(Path(pattern).expanduser()) if pattern.startswith("~") else pattern
                )
                if (
                    fnmatch.fnmatch(expanded, expanded_pattern)
                    or fnmatch.fnmatch(expanded, pattern)
                    or fnmatch.fnmatch(path, pattern)
                ):
                    return category
        return ""
