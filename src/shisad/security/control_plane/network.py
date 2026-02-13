"""Network intelligence monitor (metadata-only)."""

from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from itertools import pairwise
from statistics import pstdev
from typing import Any, Protocol

from pydantic import BaseModel, Field, ValidationError

from shisad.core.providers.base import Message, ProviderResponse
from shisad.security.control_plane.schema import Origin, RiskTier, risk_rank

logger = logging.getLogger(__name__)


class NetworkMetadata(BaseModel, frozen=True):
    origin: Origin = Field(default_factory=Origin)
    tool_name: str
    destination_host: str
    destination_port: int | None = None
    protocol: str = "https"
    request_size: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    resolved_addresses: list[str] = Field(default_factory=list)


class BaselineEntry(BaseModel):
    first_seen: datetime
    last_seen: datetime
    count: int = 0
    average_request_size: float = 0.0


class NetworkMonitorDecisionKind(StrEnum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"


class NetworkMonitorDecision(BaseModel, frozen=True):
    decision: NetworkMonitorDecisionKind
    risk_tier: RiskTier
    reason_codes: list[str] = Field(default_factory=list)
    enrichment: dict[str, Any] = Field(default_factory=dict)
    timed_out: bool = False
    source: str = "heuristic"


class ThreatIntelProvider(Protocol):
    def lookup(self, host: str) -> dict[str, str]: ...


class MonitorLLMProvider(Protocol):
    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse: ...


class ThreatIntelStub:
    """Threat-intel stub for MVP; returns unknown."""

    def lookup(self, host: str) -> dict[str, str]:
        _ = host
        return {
            "reputation": "unknown",
            "age_days": "unknown",
            "blocklist": "unknown",
        }


class BaselineDatabase:
    """Per-origin/per-host baseline with poisoning-resistant update rules."""

    def __init__(self, storage_path: str | None = None, *, learning_rate: float = 0.1) -> None:
        self._storage_path = storage_path
        self._learning_rate = max(0.01, min(learning_rate, 0.5))
        self._entries: dict[str, BaselineEntry] = {}
        self._load()

    def key_for(self, origin: Origin, host: str) -> str:
        skill = origin.skill_name or "none"
        user = origin.user_id or "anonymous"
        workspace = origin.workspace_id or "none"
        return f"{workspace}:{user}:{skill}:{host.lower()}"

    def get(self, *, origin: Origin, host: str) -> BaselineEntry | None:
        return self._entries.get(self.key_for(origin, host))

    def record(
        self,
        *,
        metadata: NetworkMetadata,
        allow_or_confirmed: bool,
        suspicious: bool,
        lockdown: bool,
    ) -> None:
        if not allow_or_confirmed:
            return
        if suspicious or lockdown:
            return

        key = self.key_for(metadata.origin, metadata.destination_host)
        current = self._entries.get(key)
        if current is None:
            current = BaselineEntry(
                first_seen=metadata.timestamp,
                last_seen=metadata.timestamp,
                count=1,
                average_request_size=float(metadata.request_size),
            )
            self._entries[key] = current
            self._persist()
            return

        current.last_seen = metadata.timestamp
        current.count += 1
        alpha = self._learning_rate
        current.average_request_size = (
            (1.0 - alpha) * current.average_request_size + alpha * float(metadata.request_size)
        )
        self._persist()

    def known_hosts_for_origin(self, origin: Origin) -> set[str]:
        prefix = (
            f"{origin.workspace_id or 'none'}:"
            f"{origin.user_id or 'anonymous'}:"
            f"{origin.skill_name or 'none'}:"
        )
        hosts: set[str] = set()
        for key in self._entries:
            if key.startswith(prefix):
                host = key[len(prefix) :].strip().lower()
                if host:
                    hosts.add(host)
        return hosts

    def _persist(self) -> None:
        if not self._storage_path:
            return
        payload = {
            key: entry.model_dump(mode="json")
            for key, entry in sorted(self._entries.items(), key=lambda item: item[0])
        }
        with open(self._storage_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)

    def _load(self) -> None:
        if not self._storage_path:
            return
        try:
            with open(self._storage_path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(payload, dict):
            return
        for key, value in payload.items():
            if not isinstance(key, str):
                continue
            try:
                self._entries[key] = BaselineEntry.model_validate(value)
            except ValidationError:
                continue


class NetworkIntelligenceMonitor:
    """Metadata-only network monitor with deterministic + optional LLM reasoning."""

    def __init__(
        self,
        *,
        baseline_db: BaselineDatabase,
        threat_intel: ThreatIntelProvider | None = None,
        monitor_provider: MonitorLLMProvider | None = None,
        timeout_seconds: float = 0.5,
        cache_ttl_seconds: int = 300,
        high_critical_timeout_action: str = "BLOCK",
        low_medium_timeout_action: str = "FLAG",
    ) -> None:
        self._baseline_db = baseline_db
        self._threat_intel = threat_intel or ThreatIntelStub()
        self._monitor_provider = monitor_provider
        self._timeout_seconds = timeout_seconds
        self._cache_ttl_seconds = cache_ttl_seconds
        self._high_critical_timeout_action = high_critical_timeout_action.upper()
        self._low_medium_timeout_action = low_medium_timeout_action.upper()
        self._cache: dict[
            tuple[str, str, str, str, tuple[str, ...], str],
            tuple[datetime, NetworkMonitorDecision],
        ] = {}
        self._recent: dict[str, list[NetworkMetadata]] = defaultdict(list)

    async def evaluate(
        self,
        *,
        metadata: NetworkMetadata,
        declared_domains: list[str],
        risk_tier: RiskTier,
    ) -> NetworkMonitorDecision:
        self._observe(metadata)
        canonical_domains = sorted(
            {item.strip().lower() for item in declared_domains if item.strip()}
        )
        enrichment = self.enrich(metadata=metadata, declared_domains=canonical_domains)
        heuristic = self._heuristic_decision(enrichment=enrichment, risk_tier=risk_tier)

        if self._monitor_provider is None:
            return heuristic

        cache_key = self._cache_key(
            metadata=metadata,
            declared_domains=canonical_domains,
            risk_tier=risk_tier,
        )
        cached = self._cache.get(cache_key)
        if cached is not None:
            expires_at, provider_decision = cached
            if expires_at > datetime.now(UTC):
                combined = self._combine_decisions(
                    heuristic=heuristic,
                    llm=provider_decision.model_copy(update={"enrichment": dict(enrichment)}),
                )
                return combined

        try:
            llm_decision = await asyncio.wait_for(
                self._llm_decision(metadata=metadata, enrichment=enrichment, risk_tier=risk_tier),
                timeout=self._timeout_seconds,
            )
        except TimeoutError:
            provider_decision = self._timeout_fallback(risk_tier=risk_tier, enrichment=enrichment)
            self._cache_decision(cache_key, provider_decision)
            return self._combine_decisions(heuristic=heuristic, llm=provider_decision)
        except (OSError, RuntimeError, TypeError, ValueError):
            logger.exception("Network monitor LLM failure; using heuristic fallback")
            return heuristic

        self._cache_decision(cache_key, llm_decision)
        combined = self._combine_decisions(heuristic=heuristic, llm=llm_decision)
        return combined

    def enrich(
        self,
        *,
        metadata: NetworkMetadata,
        declared_domains: list[str],
    ) -> dict[str, Any]:
        baseline = self._baseline_db.get(origin=metadata.origin, host=metadata.destination_host)
        known_hosts = self._baseline_db.known_hosts_for_origin(metadata.origin)
        origin_key = self._origin_recent_key(metadata.origin)
        recent = self._recent.get(origin_key, [])

        one_minute_ago = metadata.timestamp - timedelta(seconds=60)
        recent_minute = [item for item in recent if item.timestamp >= one_minute_ago]

        host_minute = [
            item
            for item in recent_minute
            if item.destination_host == metadata.destination_host
        ]
        small_requests = [item for item in host_minute if item.request_size <= 256]

        intervals: list[float] = []
        host_recent_sorted = sorted(host_minute, key=lambda item: item.timestamp)
        for previous, current in pairwise(host_recent_sorted):
            intervals.append((current.timestamp - previous.timestamp).total_seconds())

        beacon_like = False
        if len(intervals) >= 4:
            deviation = pstdev(intervals)
            beacon_like = deviation <= 0.25 and min(intervals) >= 1.0

        declared = any(
            fnmatch.fnmatch(metadata.destination_host, item) for item in declared_domains
        )
        intel = self._threat_intel.lookup(metadata.destination_host)

        enrichment: dict[str, Any] = {
            "new_domain": metadata.destination_host not in known_hosts,
            "declared_domain": declared,
            "requests_last_minute": len(host_minute),
            "small_requests_last_minute": len(small_requests),
            "fan_out_domains_last_minute": len({item.destination_host for item in recent_minute}),
            "beacon_like": beacon_like,
            "baseline_known": baseline is not None,
            "baseline_avg_size": baseline.average_request_size if baseline is not None else 0.0,
            "threat_intel": intel,
        }
        if baseline is not None and baseline.average_request_size > 0:
            enrichment["size_delta_ratio"] = metadata.request_size / baseline.average_request_size
        else:
            enrichment["size_delta_ratio"] = 1.0
        return enrichment

    def record_learning(
        self,
        *,
        metadata: NetworkMetadata,
        allow_or_confirmed: bool,
        suspicious: bool,
        lockdown: bool,
    ) -> None:
        self._baseline_db.record(
            metadata=metadata,
            allow_or_confirmed=allow_or_confirmed,
            suspicious=suspicious,
            lockdown=lockdown,
        )

    def _observe(self, metadata: NetworkMetadata) -> None:
        key = self._origin_recent_key(metadata.origin)
        rows = self._recent.setdefault(key, [])
        rows.append(metadata)
        cutoff = metadata.timestamp - timedelta(minutes=10)
        self._recent[key] = [item for item in rows if item.timestamp >= cutoff]

    def _origin_recent_key(self, origin: Origin) -> str:
        return f"{origin.workspace_id}:{origin.user_id}:{origin.skill_name}"

    def _heuristic_decision(
        self,
        *,
        enrichment: dict[str, Any],
        risk_tier: RiskTier,
    ) -> NetworkMonitorDecision:
        reason_codes: list[str] = []
        decision = NetworkMonitorDecisionKind.ALLOW
        resulting_risk = risk_tier

        intel = enrichment.get("threat_intel", {})
        reputation = (
            str(intel.get("reputation", "unknown")).lower()
            if isinstance(intel, dict)
            else "unknown"
        )

        if reputation in {"malicious", "phishing", "botnet"}:
            decision = NetworkMonitorDecisionKind.BLOCK
            reason_codes.append("network:threat_intel_malicious")
            resulting_risk = RiskTier.CRITICAL

        if bool(enrichment.get("new_domain")) and not bool(enrichment.get("declared_domain")):
            reason_codes.append("network:undeclared_new_domain")
            if decision != NetworkMonitorDecisionKind.BLOCK:
                decision = NetworkMonitorDecisionKind.FLAG
                resulting_risk = max(resulting_risk, RiskTier.HIGH, key=risk_rank)

        if int(enrichment.get("small_requests_last_minute", 0)) >= 8 and bool(
            enrichment.get("new_domain")
        ):
            decision = NetworkMonitorDecisionKind.BLOCK
            reason_codes.append("network:staged_exfil_small_requests")
            resulting_risk = RiskTier.CRITICAL

        if bool(enrichment.get("beacon_like")):
            reason_codes.append("network:c2_beacon_pattern")
            if decision != NetworkMonitorDecisionKind.BLOCK:
                decision = NetworkMonitorDecisionKind.FLAG
                resulting_risk = max(resulting_risk, RiskTier.HIGH, key=risk_rank)

        if int(enrichment.get("fan_out_domains_last_minute", 0)) >= 6:
            reason_codes.append("network:fanout_anomaly")
            if decision == NetworkMonitorDecisionKind.ALLOW:
                decision = NetworkMonitorDecisionKind.FLAG
                resulting_risk = max(resulting_risk, RiskTier.MEDIUM, key=risk_rank)

        if not reason_codes:
            reason_codes.append("network:baseline_ok")

        return NetworkMonitorDecision(
            decision=decision,
            risk_tier=resulting_risk,
            reason_codes=reason_codes,
            enrichment=enrichment,
            source="heuristic",
        )

    async def _llm_decision(
        self,
        *,
        metadata: NetworkMetadata,
        enrichment: dict[str, Any],
        risk_tier: RiskTier,
    ) -> NetworkMonitorDecision:
        if self._monitor_provider is None:
            raise RuntimeError("monitor provider unavailable")
        payload = {
            "destination_host": metadata.destination_host,
            "destination_port": metadata.destination_port,
            "protocol": metadata.protocol,
            "request_size": metadata.request_size,
            "origin": metadata.origin.model_dump(mode="json"),
            "risk_tier": risk_tier.value,
            "enrichment": enrichment,
        }
        messages = [
            Message(
                role="system",
                content=(
                    "You are a metadata-only network monitor. "
                    "Return JSON with keys decision (ALLOW|FLAG|BLOCK), reason_codes (array). "
                    "Never include prose."
                ),
            ),
            Message(role="user", content=json.dumps(payload, sort_keys=True)),
        ]
        response = await self._monitor_provider.complete(messages)
        parsed = json.loads(response.message.content)
        if not isinstance(parsed, dict):
            raise ValueError("monitor output must be JSON object")
        decision_raw = str(parsed.get("decision", "FLAG")).upper()
        if decision_raw not in {
            NetworkMonitorDecisionKind.ALLOW,
            NetworkMonitorDecisionKind.FLAG,
            NetworkMonitorDecisionKind.BLOCK,
        }:
            decision_raw = NetworkMonitorDecisionKind.FLAG
        reasons = parsed.get("reason_codes", [])
        reason_codes = (
            [str(item) for item in reasons]
            if isinstance(reasons, list)
            else ["network:llm"]
        )
        return NetworkMonitorDecision(
            decision=NetworkMonitorDecisionKind(decision_raw),
            risk_tier=risk_tier,
            reason_codes=reason_codes,
            enrichment=enrichment,
            source="llm",
        )

    def _timeout_fallback(
        self,
        *,
        risk_tier: RiskTier,
        enrichment: dict[str, Any],
    ) -> NetworkMonitorDecision:
        if risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}:
            decision = self._high_critical_timeout_action
            if decision == NetworkMonitorDecisionKind.ALLOW:
                decision = NetworkMonitorDecisionKind.BLOCK
        else:
            decision = self._low_medium_timeout_action
        if decision not in {
            NetworkMonitorDecisionKind.ALLOW,
            NetworkMonitorDecisionKind.FLAG,
            NetworkMonitorDecisionKind.BLOCK,
        }:
            decision = (
                NetworkMonitorDecisionKind.BLOCK
                if risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL}
                else NetworkMonitorDecisionKind.FLAG
            )
        return NetworkMonitorDecision(
            decision=NetworkMonitorDecisionKind(decision),
            risk_tier=risk_tier,
            reason_codes=["network:monitor_timeout"],
            enrichment=enrichment,
            timed_out=True,
            source="timeout_fallback",
        )

    def _combine_decisions(
        self,
        *,
        heuristic: NetworkMonitorDecision,
        llm: NetworkMonitorDecision,
    ) -> NetworkMonitorDecision:
        order = {
            NetworkMonitorDecisionKind.ALLOW: 0,
            NetworkMonitorDecisionKind.FLAG: 1,
            NetworkMonitorDecisionKind.BLOCK: 2,
        }
        left = heuristic.decision
        right = llm.decision
        chosen = heuristic if order[left] >= order[right] else llm
        reason_codes = list(dict.fromkeys([*heuristic.reason_codes, *llm.reason_codes]))
        return chosen.model_copy(update={"reason_codes": reason_codes, "source": "combined"})

    def _cache_decision(
        self,
        cache_key: tuple[str, str, str, str, tuple[str, ...], str],
        decision: NetworkMonitorDecision,
    ) -> None:
        expires = datetime.now(UTC) + timedelta(seconds=self._cache_ttl_seconds)
        self._cache[cache_key] = (expires, decision)

    @staticmethod
    def _cache_key(
        *,
        metadata: NetworkMetadata,
        declared_domains: list[str],
        risk_tier: RiskTier,
    ) -> tuple[str, str, str, str, tuple[str, ...], str]:
        origin = metadata.origin
        return (
            origin.workspace_id or "none",
            origin.user_id or "anonymous",
            origin.skill_name or "none",
            metadata.destination_host.lower(),
            tuple(declared_domains),
            risk_tier.value,
        )


def extract_network_metadata(
    *,
    origin: Origin,
    tool_name: str,
    destination_host: str,
    destination_port: int | None,
    protocol: str,
    request_size: int,
    resolved_addresses: list[str] | None = None,
    timestamp: datetime | None = None,
) -> NetworkMetadata:
    return NetworkMetadata(
        origin=origin,
        tool_name=tool_name,
        destination_host=destination_host,
        destination_port=destination_port,
        protocol=protocol,
        request_size=request_size,
        resolved_addresses=list(resolved_addresses or []),
        timestamp=timestamp or datetime.now(UTC),
    )
