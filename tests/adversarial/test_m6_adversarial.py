"""M6 adversarial evaluation fixtures and exfil-path checks."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shisad.executors.browser import BrowserSandbox, BrowserSandboxPolicy
from shisad.executors.proxy import EgressProxy, NetworkPolicy
from shisad.memory.manager import MemoryManager
from shisad.memory.schema import MemorySource
from shisad.security.control_plane.network import (
    BaselineDatabase,
    NetworkIntelligenceMonitor,
    extract_network_metadata,
)
from shisad.security.control_plane.schema import Origin, RiskTier, sanitize_metadata_payload
from shisad.security.firewall import ContentFirewall
from shisad.security.firewall.output import OutputFirewall


def _json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _origin() -> Origin:
    return Origin(
        session_id="m6-adversarial",
        user_id="user-1",
        workspace_id="ws-1",
        actor="planner",
    )


def test_m6_a1_prompt_injection_direct_fixture_matrix_has_50_plus_variants() -> None:
    fixture = _json(Path(__file__).parent / "injection" / "direct_templates.json")
    assert isinstance(fixture, dict)
    templates = [str(item) for item in fixture["templates"]]
    targets = [str(item) for item in fixture["targets"]]
    tokens = [str(item) for item in fixture["tokens"]]
    variants = [
        template.format(target=target, token=token)
        for template in templates
        for target in targets
        for token in tokens
    ]
    assert len(variants) >= 50
    firewall = ContentFirewall()
    flagged = sum(1 for variant in variants if firewall.inspect(variant).risk_score >= 0.25)
    assert flagged >= 50


def test_m6_a2_memory_poisoning_fixtures_are_blocked_or_confirmation_gated(tmp_path: Path) -> None:
    fixture = _json(Path(__file__).parent / "memory" / "poisoning_cases.json")
    assert isinstance(fixture, list)
    manager = MemoryManager(tmp_path / "memory")
    outcomes: dict[str, str] = {}
    for case in fixture:
        assert isinstance(case, dict)
        source = MemorySource(
            origin=str(case["origin"]),
            source_id=str(case["id"]),
            extraction_method="fixture",
        )
        decision = manager.write(
            entry_type="fact",
            key=str(case["id"]),
            value=str(case["text"]),
            source=source,
            user_confirmed=False,
        )
        outcomes[str(case["id"])] = decision.kind
    assert outcomes["mem-1"] in {"reject", "require_confirmation"}
    assert outcomes["mem-2"] in {"reject", "require_confirmation"}
    assert outcomes["mem-3"] in {"allow", "require_confirmation"}


def test_m6_a3_tool_metadata_poisoning_payloads_are_sanitized() -> None:
    fixture = _json(Path(__file__).parent / "tools" / "metadata_poisoning_cases.json")
    assert isinstance(fixture, list)
    for case in fixture:
        assert isinstance(case, dict)
        payload = sanitize_metadata_payload(dict(case["payload"]))
        lowered = {key.lower() for key in payload}
        assert "request_body" not in lowered
        assert "arguments" not in lowered
        assert "user_goal" not in lowered


@pytest.mark.asyncio
async def test_m6_t9_staged_small_request_exfil_fixture_yields_block_reason_codes() -> None:
    fixture = _json(Path(__file__).parent / "exfil" / "network_exfil_cases.json")
    assert isinstance(fixture, list)
    case = next(item for item in fixture if item["id"] == "exfil-1")
    monitor = NetworkIntelligenceMonitor(
        baseline_db=BaselineDatabase(),
        cache_ttl_seconds=-1,
    )
    origin = _origin()
    now = datetime(2026, 2, 11, 14, 0, tzinfo=UTC)
    decision = None
    for index in range(int(case["count"])):
        metadata = extract_network_metadata(
            origin=origin,
            tool_name="http_request",
            destination_host=str(case["destination_host"]),
            destination_port=443,
            protocol="https",
            request_size=int(case["request_size"]),
            timestamp=now + timedelta(seconds=index),
        )
        decision = await monitor.evaluate(
            metadata=metadata,
            declared_domains=[],
            risk_tier=RiskTier.HIGH,
        )
    assert decision is not None
    assert decision.decision == "BLOCK"
    assert str(case["expected_reason"]) in decision.reason_codes


def test_m6_t10_dns_exfil_simulation_is_flagged_or_blocked_with_deterministic_reason() -> None:
    proxy = EgressProxy()
    long_label = "x" * 64
    host = f"{long_label}.allowed.example"
    decision = proxy.authorize_request(
        tool_name="http_request",
        url=f"https://{host}/collect",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["*.allowed.example"]),
        approved_by_pep=True,
    )
    assert decision.allowed is False
    assert decision.reason == "dns_exfil_suspected"


def test_m6_t11_browser_exfil_attempt_cannot_bypass_policy_gate(tmp_path: Path) -> None:
    policy = BrowserSandboxPolicy(clipboard="enabled")
    sandbox = BrowserSandbox(
        output_firewall=OutputFirewall(safe_domains=["api.good.example"]),
        screenshots_dir=tmp_path / "shots",
        policy=policy,
    )
    prompt = (Path(__file__).parent / "exfil" / "fixtures" / "browser_exfil_prompt.txt").read_text(
        encoding="utf-8"
    )
    result = sandbox.paste(prompt + " https://evil.com/collect")
    assert result.allowed is False
    assert result.blocked is True or result.require_confirmation is True
