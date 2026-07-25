"""F14A: canonical secret-pattern parity across every runtime consumer."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass

import pytest

from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import (
    Capability,
    CredentialRef,
    PEPDecision,
    PEPDecisionKind,
    TaintLabel,
    ToolName,
)
from shisad.security.firewall import ContentFirewall
from shisad.security.firewall.normalize import normalize_text
from shisad.security.firewall.output import OutputFirewall
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import PolicyBundle
from shisad.security.secret_patterns import SECRET_PATTERNS, SecretPattern


@dataclass(frozen=True, slots=True)
class SecretCase:
    kind: str
    value: str


SECRET_CASES = (
    SecretCase("anthropic_key", "sk-ant-api03-" + "a" * 24),
    SecretCase("openai_key", "sk-proj-" + "b" * 24),
    SecretCase("github_token", "ghp_" + "c" * 24),
    SecretCase("aws_access_key", "AKIA" + "D" * 16),
    SecretCase("oauth_access_token", "ya29." + "e" * 24),
    SecretCase("jwt", "eyJ" + "f" * 12 + "." + "g" * 12 + "." + "h" * 16),
    SecretCase(
        "private_key",
        "-----BEGIN PRIVATE KEY-----\nsynthetic-key-material-only\n-----END PRIVATE KEY-----",
    ),
)
CANONICAL_KINDS = tuple(case.kind for case in SECRET_CASES)


def _matching_kinds(text: str) -> list[str]:
    return [pattern.kind for pattern in SECRET_PATTERNS if pattern.regex.search(text)]


@pytest.fixture(scope="module")
def content_firewall() -> ContentFirewall:
    return ContentFirewall()


@pytest.fixture(scope="module")
def dlp_pep() -> PEP:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("submit_data"),
            description="Submit a structured payload",
            parameters=[ToolParameter(name="payload", type="object", required=True)],
            capabilities_required=[Capability.FILE_READ],
        )
    )
    return PEP(PolicyBundle(default_require_confirmation=False), registry)


def _evaluate_payload(pep: PEP, value: str) -> PEPDecision:
    return _evaluate_structured_payload(pep, {"credential": value})


def _evaluate_structured_payload(pep: PEP, payload: dict[str, object]) -> PEPDecision:
    return pep.evaluate(
        ToolName("submit_data"),
        {"payload": payload},
        PolicyContext(capabilities={Capability.FILE_READ}),
    )


def test_f14a_registry_is_typed_ordered_and_immutable() -> None:
    patterns = SECRET_PATTERNS

    assert isinstance(patterns, tuple)
    assert tuple(pattern.kind for pattern in patterns) == CANONICAL_KINDS
    assert all(isinstance(pattern, SecretPattern) for pattern in patterns)
    assert all(isinstance(pattern.regex, re.Pattern) for pattern in patterns)
    assert len({pattern.kind for pattern in patterns}) == len(patterns)
    assert not hasattr(patterns, "append")
    assert not hasattr(patterns[0], "__dict__")


@pytest.mark.parametrize("case", SECRET_CASES, ids=lambda case: case.kind)
def test_f14a_registry_recognizes_each_family_with_punctuation(case: SecretCase) -> None:
    assert _matching_kinds(f"credential=({case.value}),") == [case.kind]


@pytest.mark.parametrize(
    "case",
    SECRET_CASES[:-1],
    ids=lambda case: case.kind,
)
def test_f14a_ascii_word_adjacency_is_not_a_token_boundary(case: SecretCase) -> None:
    assert _matching_kinds(f"x{case.value}x") == []


def test_f14a_provider_precedence_does_not_double_label_anthropic_key() -> None:
    anthropic = SECRET_CASES[0]
    assert _matching_kinds(anthropic.value) == ["anthropic_key"]


def test_f14a_encoded_and_unicode_variants_do_not_expand_registry_semantics() -> None:
    openai = SECRET_CASES[1].value
    variants = (
        base64.b64encode(openai.encode()).decode(),
        openai.replace("-", "%2D"),
        openai.replace("sk", "\uff53\uff4b", 1),
        openai.replace("sk-", "sk-\u200b", 1),
    )

    assert [_matching_kinds(variant) for variant in variants] == [[], [], [], []]


def test_f14a_consumer_preprocessing_differences_remain_explicit(
    content_firewall: ContentFirewall,
    dlp_pep: PEP,
) -> None:
    openai = SECRET_CASES[1]
    zero_width = openai.value.replace("sk-", "sk-\u200b", 1)
    encoded = base64.b64encode(openai.value.encode()).decode()

    assert _matching_kinds(zero_width) == []
    assert _matching_kinds(normalize_text(zero_width)) == ["openai_key"]

    output = OutputFirewall(safe_domains=[]).inspect(zero_width)
    assert output.secret_findings == ["openai_key"]
    assert "[REDACTED:openai_key]" in output.sanitized_text

    pep_decision = _evaluate_payload(dlp_pep, zero_width)
    assert pep_decision.kind == PEPDecisionKind.ALLOW

    ingress = content_firewall.inspect(encoded)
    assert ingress.sanitized_text == "[REDACTED:openai_key]"
    assert ingress.secret_findings == ["openai_key"]
    assert ingress.decode_depth == 1
    assert "encoding:base64_decoded" in ingress.decode_reason_codes

    assert OutputFirewall(safe_domains=[]).inspect(encoded).secret_findings == []
    assert _evaluate_payload(dlp_pep, encoded).kind == PEPDecisionKind.ALLOW


@pytest.mark.parametrize("case", SECRET_CASES, ids=lambda case: case.kind)
def test_f14a_all_consumers_take_their_distinct_fail_closed_action(
    case: SecretCase,
    content_firewall: ContentFirewall,
    dlp_pep: PEP,
) -> None:
    ingress = content_firewall.inspect(f"credential: {case.value}")
    assert case.value not in ingress.sanitized_text
    assert f"[REDACTED:{case.kind}]" in ingress.sanitized_text
    assert case.kind in ingress.secret_findings
    assert TaintLabel.USER_CREDENTIALS in ingress.taint_labels
    assert case.value not in json.dumps(ingress.model_dump(mode="json"), sort_keys=True)

    alerts: list[dict[str, object]] = []
    output = OutputFirewall(
        safe_domains=[],
        alert_hook=lambda payload: alerts.append(payload),
    ).inspect(f"credential: {case.value}")
    assert case.value not in output.sanitized_text
    assert f"[REDACTED:{case.kind}]" in output.sanitized_text
    assert case.kind in output.secret_findings
    assert "secret_redaction" in output.reason_codes
    assert alerts
    assert case.value not in json.dumps(alerts, sort_keys=True)

    decision = _evaluate_payload(dlp_pep, case.value)
    assert decision.kind == PEPDecisionKind.REJECT
    assert decision.reason_code == "pep:argument_dlp"
    assert "Argument 'payload'" in decision.reason
    assert case.value not in decision.reason


def test_f14a_output_url_diagnostics_redact_canonical_matches() -> None:
    github = SECRET_CASES[2]
    alerts: list[dict[str, object]] = []
    output = OutputFirewall(
        safe_domains=["example.com"],
        alert_hook=lambda payload: alerts.append(payload),
    ).inspect(f"https://example.com/upload?token={github.value}")

    assert output.url_findings
    assert github.value not in json.dumps(output.model_dump(mode="json"), sort_keys=True)
    assert f"[REDACTED:{github.kind}]" in output.url_findings[0].url
    assert alerts
    assert github.value not in json.dumps(alerts, sort_keys=True)

    host_output = OutputFirewall(safe_domains=["example.com"]).inspect(
        f"https://{github.value}.example.com/upload"
    )
    assert github.value not in json.dumps(host_output.model_dump(mode="json"), sort_keys=True)
    assert f"[REDACTED:{github.kind}]" in host_output.url_findings[0].host


@pytest.mark.parametrize("case", SECRET_CASES[-2:], ids=lambda case: case.kind)
def test_f14a_pep_rejects_canonical_matches_in_deep_containers(
    case: SecretCase,
    dlp_pep: PEP,
) -> None:
    decision = _evaluate_structured_payload(
        dlp_pep,
        {"outer": [{"credential": case.value}]},
    )

    assert decision.kind == PEPDecisionKind.REJECT
    assert decision.reason_code == "pep:argument_dlp"
    assert case.value not in decision.reason


def test_f14a_pep_diagnostic_omits_untrusted_nested_keys(dlp_pep: PEP) -> None:
    jwt = SECRET_CASES[-2].value
    decision = _evaluate_structured_payload(dlp_pep, {jwt: jwt})

    assert decision.kind == PEPDecisionKind.REJECT
    assert decision.reason == (
        "Blocked by DLP policy: Argument 'payload' appears to contain a raw secret"
    )
    assert jwt not in decision.reason


def test_f14a_recursive_argument_walker_preserves_credential_ref_scope(
    dlp_pep: PEP,
) -> None:
    baseline_shape = {"payload": {"credential_ref": "synthetic-ref"}}
    deep_shape = {"payload": {"auth": {"credential_ref": "synthetic-ref"}}}
    nested_list_shape = {"payload": {"credential_ref": ["synthetic-ref"]}}

    assert dlp_pep._extract_credential_refs(baseline_shape) == [CredentialRef("synthetic-ref")]
    assert dlp_pep._extract_credential_refs(deep_shape) == []
    assert dlp_pep._extract_credential_refs(nested_list_shape) == []


def test_f14a_recursive_argument_walker_bounds_container_cycles(dlp_pep: PEP) -> None:
    jwt = SECRET_CASES[-2].value
    dictionary_cycle: dict[str, object] = {}
    dictionary_cycle["self"] = dictionary_cycle
    dictionary_cycle["credential"] = jwt
    list_cycle: list[object] = []
    list_cycle.append(list_cycle)
    list_cycle.append(jwt)

    decision = _evaluate_structured_payload(
        dlp_pep,
        {"dictionary": dictionary_cycle, "sequence": list_cycle},
    )

    assert decision.kind == PEPDecisionKind.REJECT
    assert jwt not in decision.reason


def test_f14a_benign_lookalikes_remain_usable(
    content_firewall: ContentFirewall,
    dlp_pep: PEP,
) -> None:
    benign = (
        "sk-short ghp_short AKIA1234 ya29.short eyJ.short.short "
        "-----BEGIN PUBLIC KEY----- synthetic -----END PUBLIC KEY-----"
    )

    assert _matching_kinds(benign) == []
    assert content_firewall.inspect(benign).secret_findings == []
    assert OutputFirewall(safe_domains=[]).inspect(benign).secret_findings == []
    assert _evaluate_payload(dlp_pep, benign).kind == PEPDecisionKind.ALLOW


def test_f14a_ingress_consumer_reexports_the_canonical_registry() -> None:
    from shisad.security.firewall import secrets

    assert secrets.SECRET_PATTERNS is SECRET_PATTERNS
