"""M6 adversarial evaluation fixtures and exfil-path checks."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, TaintLabel, ToolName
from shisad.executors.browser import BrowserSandbox, BrowserSandboxPolicy
from shisad.executors.proxy import EgressProxy, NetworkPolicy
from shisad.memory.ingestion import IngestionPipeline
from shisad.memory.manager import MemoryManager
from shisad.memory.schema import MemorySource
from shisad.security.control_plane.network import (
    BaselineDatabase,
    NetworkIntelligenceMonitor,
    extract_network_metadata,
)
from shisad.security.control_plane.schema import Origin, RiskTier, sanitize_metadata_payload
from shisad.security.firewall import ContentFirewall
from shisad.security.firewall.classifier import InjectionClassification
from shisad.security.firewall.output import OutputFirewall
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle


def _json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _origin() -> Origin:
    return Origin(
        session_id="m6-adversarial",
        user_id="user-1",
        workspace_id="ws-1",
        actor="planner",
    )


class _CapturingSemanticClassifier:
    """Stub that returns an InjectionClassification with the declared score.

    When ``score_for`` is supplied, the classifier looks up the response per
    call (by substring match) so a single test can drive both the high-risk
    quarantine path and a low-risk baseline through the real firewall
    pipeline, exercising the full ``classify`` → ``InjectionClassification``
    handshake rather than a constant.
    """

    def __init__(
        self,
        score: float = 0.0,
        *,
        score_for: dict[str, float] | None = None,
    ) -> None:
        self._score = score
        self._score_for = dict(score_for or {})
        self.calls: list[str] = []

    def classify(self, text: str) -> InjectionClassification:
        self.calls.append(text)
        resolved = self._score
        for marker, marker_score in self._score_for.items():
            if marker in text:
                resolved = marker_score
                break
        tier = "critical" if resolved >= 0.9 else "high" if resolved >= 0.6 else "none"
        return InjectionClassification(
            risk_score=resolved,
            risk_factors=["promptguard:critical"] if resolved >= 0.9 else [],
            semantic_risk_score=resolved,
            semantic_risk_tier=tier,
            semantic_classifier_id="promptguard-v2",
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


def test_m6_t18_layered_mixed_encoding_fixture_matrix_is_deterministic_and_flagged() -> None:
    fixture = _json(Path(__file__).parent / "injection" / "encoding_layers.json")
    assert isinstance(fixture, list)
    firewall = ContentFirewall()
    seen_ids: set[str] = set()
    for case in fixture:
        assert isinstance(case, dict)
        case_id = str(case["id"])
        assert case_id not in seen_ids
        seen_ids.add(case_id)
        payload = str(case["payload"])
        result = firewall.inspect(payload)
        assert result.risk_score >= float(case.get("min_risk_score", 0.25))
        expected = [str(item) for item in case.get("expected_reasons", [])]
        for reason in expected:
            assert reason in result.risk_factors


def test_h2_tool_content_semantic_classifier_quarantines_high_risk_ingest(tmp_path: Path) -> None:
    semantic = _CapturingSemanticClassifier(score=0.96)
    pipeline = IngestionPipeline(
        tmp_path / "memory",
        firewall=ContentFirewall(semantic_classifier=semantic),
        quarantine_threshold=0.9,
    )

    result = pipeline.ingest(
        source_id="tool-1",
        source_type="tool",
        content="Fetched page content with hidden execution instructions.",
    )

    assert semantic.calls
    assert "Fetched page content" in semantic.calls[0]
    assert result.quarantined is True
    assert result.risk_score == pytest.approx(0.96)
    assert TaintLabel.UNTRUSTED in result.taint_labels


def test_adv_m1_semantic_classifier_low_score_leaves_ingest_unquarantined(
    tmp_path: Path,
) -> None:
    """ADV-M1 companion: the constant-score stub had no negative path, so a
    regression that always quarantined tool content would have been invisible.
    Drive the same classifier through a low-risk path to pin the interface
    (classify(text) -> InjectionClassification -> risk_score) end-to-end.
    """

    semantic = _CapturingSemanticClassifier(
        score_for={
            "benign": 0.05,
            "execution instructions": 0.96,
        }
    )
    pipeline = IngestionPipeline(
        tmp_path / "memory",
        firewall=ContentFirewall(semantic_classifier=semantic),
        quarantine_threshold=0.9,
    )

    low = pipeline.ingest(
        source_id="tool-low",
        source_type="tool",
        content="benign page content with no adversarial markers.",
    )
    high = pipeline.ingest(
        source_id="tool-high",
        source_type="tool",
        content="Another page with hidden execution instructions payload.",
    )

    assert len(semantic.calls) == 2
    assert low.quarantined is False
    assert low.risk_score == pytest.approx(0.05)
    assert high.quarantined is True
    assert high.risk_score == pytest.approx(0.96)


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


def test_m6_t12_browser_navigation_from_untrusted_page_requires_confirmation() -> None:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("browser.navigate"),
            description="Navigate the browser to a URL.",
            parameters=[
                ToolParameter(
                    name="url",
                    type="string",
                    required=True,
                    semantic_type="url",
                )
            ],
            capabilities_required=[Capability.HTTP_REQUEST],
            require_confirmation=False,
        )
    )
    pep = PEP(PolicyBundle(default_require_confirmation=False), registry)

    decision = pep.evaluate(
        ToolName("browser.navigate"),
        {"url": "https://evil.example/phish"},
        PolicyContext(
            capabilities={Capability.HTTP_REQUEST},
            taint_labels={TaintLabel.UNTRUSTED},
            user_goal_host_patterns=set(),
            untrusted_host_patterns={"evil.example"},
        ),
    )

    assert decision.kind.value == "require_confirmation"
