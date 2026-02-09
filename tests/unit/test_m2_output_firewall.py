"""M2.T5-T8: outbound output firewall checks."""

from __future__ import annotations

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


def test_m2_t8_markdown_sanitizer_disables_external_images() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    result = firewall.inspect("Screenshot: ![x](https://tracker.evil.com/pixel.png)")
    assert "[IMAGE_REMOVED]" in result.sanitized_text
    assert "markdown_external_image" in result.reason_codes

