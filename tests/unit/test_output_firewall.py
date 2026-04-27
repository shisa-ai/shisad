"""M2.T5-T8: outbound output firewall checks."""

from __future__ import annotations

import json
from pathlib import Path

from shisad.security.firewall.output import OutputFirewall


def test_m2_t5_output_firewall_redacts_aws_keys() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    result = firewall.inspect("Token: AKIAABCDEFGHIJKLMNOP")
    assert "[REDACTED:aws_access_key]" in result.sanitized_text
    assert "aws_access_key" in result.secret_findings


def test_m2_t6_output_firewall_redacts_oauth_tokens() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    result = firewall.inspect("Bearer ya29.A0ARrdaMXXXXXXXXXXXXXXXXXXXXXX")
    assert "[REDACTED:oauth_token]" in result.sanitized_text
    assert "oauth_token" in result.secret_findings


def test_m2_t7_output_firewall_blocks_known_malicious_urls() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    result = firewall.inspect("Open https://evil.com/exfil for details")
    assert result.blocked is True
    assert "malicious_url" in result.reason_codes


def test_gh13_output_firewall_treats_redacted_pseudo_url_as_malformed() -> None:
    firewall = OutputFirewall(safe_domains=["hareruyamtg.com", "*.hareruyamtg.com"])

    result = firewall.inspect("Detail: https://www.hareruyamtg.[REDACTED:high_entropy_secret]")

    assert result.blocked is True
    assert "malicious_url" in result.reason_codes
    assert result.url_findings
    assert result.url_findings[0].host == ""
    assert result.url_findings[0].reason == "malformed_url"


def test_m2_t8_markdown_sanitizer_disables_external_images() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    result = firewall.inspect("Screenshot: ![x](https://tracker.evil.com/pixel.png)")
    assert "[IMAGE_REMOVED]" in result.sanitized_text
    assert "markdown_external_image" in result.reason_codes


def test_m2_t8_entropy_detector_redacts_unknown_secrets_and_alerts() -> None:
    alerts: list[dict[str, object]] = []

    firewall = OutputFirewall(
        safe_domains=["api.good.com"],
        alert_hook=lambda payload: alerts.append(payload),
    )
    # High-entropy random-looking token not matched by explicit regex signatures.
    token = "QWxhZGRpbjpPcGVuU2VzYW1lLTIwMjYtWFlaMTIzNDU2Nzg5MA=="
    result = firewall.inspect(f"debug token: {token}", context={"session_id": "s1"})
    assert "[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings
    assert alerts
    assert alerts[0]["context"] == {"session_id": "s1"}


def test_m2_output_firewall_blocks_url_with_embedded_credentials() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    result = firewall.inspect("fetch https://alice:secret@api.good.com/private")
    assert result.blocked is True
    assert any(item.reason == "embedded_url_credentials" for item in result.url_findings)


def test_m2_output_firewall_blocks_unallowlisted_ip_destinations() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    result = firewall.inspect("send to https://203.0.113.10/upload")
    assert result.blocked is True
    assert any(item.reason == "direct_ip_destination" for item in result.url_findings)


def test_m2_output_firewall_toxicity_handles_basic_obfuscation() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    result = firewall.inspect("You should k1ll y0urself right now")
    assert result.require_confirmation is True
    assert "outbound_policy_toxicity" in result.reason_codes


def test_m2_output_firewall_url_adversarial_matrix() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    matrix_path = (
        Path(__file__).resolve().parents[1] / "fixtures" / "m2_url_adversarial_matrix.json"
    )
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    for case in matrix:
        result = firewall.inspect(str(case["text"]))
        assert result.blocked is bool(case["expected_blocked"]), case["id"]
        assert any(item.reason == case["expected_reason"] for item in result.url_findings), case[
            "id"
        ]


def test_m5_output_firewall_host_matching_normalizes_allowlist_rules() -> None:
    firewall = OutputFirewall(safe_domains=["  *.Example.com  "])
    result = firewall.inspect("visit https://docs.example.com/guide")
    assert result.blocked is False
    assert result.require_confirmation is False
    assert result.url_findings[0].allowed is True


def test_m5_dlp1_entropy_detector_keeps_filesystem_paths_unredacted() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    text = "files: /path/to/shisad/CLAUDE.md and /path/to/shisad/pyproject.toml"
    result = firewall.inspect(text)
    assert "/path/to/shisad/CLAUDE.md" in result.sanitized_text
    assert "/path/to/shisad/pyproject.toml" in result.sanitized_text
    assert "high_entropy_secret" not in result.secret_findings


def test_m5_dlp1_entropy_detector_still_redacts_secret_like_tokens() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    secret_blob = "QWxhZGRpbjpPcGVuU2VzYW1lLTIwMjYtWFlaMTIzNDU2Nzg5MA=="
    result = firewall.inspect(f"token={secret_blob} key=AKIAABCDEFGHIJKLMNOP")
    assert "[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert "[REDACTED:aws_access_key]" in result.sanitized_text


def test_m5_rr2_entropy_detector_redacts_slash_separated_high_entropy_tokens() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/a8F2kL9pQ4rT1vN3/b7D4mS8xZ1cV6nH2/u9J3qW5eR7tY2iK4"
    result = firewall.inspect(f"debug={token}")
    assert "[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings
