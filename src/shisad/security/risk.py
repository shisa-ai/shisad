"""Risk policy calibration and observation persistence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean
from typing import Any

from pydantic import BaseModel, Field


class RiskThresholds(BaseModel):
    """Thresholds used by the policy engine."""

    auto_approve_threshold: float = Field(default=0.45, ge=0.0, le=1.0)
    block_threshold: float = Field(default=0.85, ge=0.0, le=1.0)


class RiskPolicyVersion(BaseModel):
    """Versioned risk policy snapshot."""

    version: str = "v1"
    thresholds: RiskThresholds = Field(default_factory=RiskThresholds)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RiskObservation(BaseModel):
    """Single risk decision record with outcome for calibration."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    session_id: str = ""
    user_id: str = ""
    tool_name: str = ""
    outcome: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    features: dict[str, Any] = Field(default_factory=dict)


@dataclass(slots=True)
class RiskCalibrator:
    """Persist and calibrate risk thresholds from adjudicated outcomes."""

    policy_path: Path
    observations_path: Path

    def load_policy(self) -> RiskPolicyVersion:
        if not self.policy_path.exists():
            policy = RiskPolicyVersion()
            self.save_policy(policy)
            return policy
        return RiskPolicyVersion.model_validate_json(self.policy_path.read_text())

    def save_policy(self, policy: RiskPolicyVersion) -> None:
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        self.policy_path.write_text(policy.model_dump_json(indent=2))

    def record(self, observation: RiskObservation) -> None:
        self.observations_path.parent.mkdir(parents=True, exist_ok=True)
        with self.observations_path.open("a", encoding="utf-8") as handle:
            handle.write(observation.model_dump_json() + "\n")

    def calibrate(self) -> RiskPolicyVersion:
        observations = self._load_observations()
        current = self.load_policy()
        if not observations:
            return current

        # Deterministic baseline calibration:
        # - auto threshold tracks the running average risk.
        # - block threshold tracks high-risk tail with conservative margin.
        scores = [obs.risk_score for obs in observations]
        avg = mean(scores)
        high = max(scores)
        auto = max(0.2, min(0.7, round(avg, 3)))
        block = max(auto + 0.1, min(0.95, round(high + 0.05, 3)))

        next_policy = RiskPolicyVersion(
            version=self._next_version(current.version),
            thresholds=RiskThresholds(
                auto_approve_threshold=auto,
                block_threshold=block,
            ),
            updated_at=datetime.now(UTC),
        )
        self.save_policy(next_policy)
        return next_policy

    def _load_observations(self) -> list[RiskObservation]:
        if not self.observations_path.exists():
            return []
        rows: list[RiskObservation] = []
        for raw in self.observations_path.read_text().splitlines():
            line = raw.strip()
            if not line:
                continue
            rows.append(RiskObservation.model_validate_json(line))
        return rows

    @staticmethod
    def _next_version(version: str) -> str:
        if version.startswith("v") and version[1:].isdigit():
            return f"v{int(version[1:]) + 1}"
        return "v2"
