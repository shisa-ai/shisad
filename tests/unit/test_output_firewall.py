"""M2.T5-T8: outbound output firewall checks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shisad.security.firewall.output import OutputFirewall


def test_m2_t5_output_firewall_redacts_aws_keys() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    result = firewall.inspect("Token: AKIAABCDEFGHIJKLMNOP")
    assert "[REDACTED:aws_access_key]" in result.sanitized_text
    assert "aws_access_key" in result.secret_findings


def test_m2_t6_output_firewall_redacts_oauth_tokens() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    result = firewall.inspect("Bearer ya29.A0ARrdaMXXXXXXXXXXXXXXXXXXXXXX")
    assert "[REDACTED:oauth_access_token]" in result.sanitized_text
    assert "oauth_access_token" in result.secret_findings


def test_gh20_output_firewall_still_labels_openai_keys() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    result = firewall.inspect("OPENAI_API_KEY=sk-abc123def456ghi789jkl012")

    assert "[REDACTED:openai_key]" in result.sanitized_text
    assert "openai_key" in result.secret_findings


def test_gh20_output_firewall_labels_anthropic_keys_distinctly_from_openai() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    result = firewall.inspect("ANTHROPIC_API_KEY=sk-ant-api03-abc123def456ghi789jkl012")

    assert "[REDACTED:anthropic_key]" in result.sanitized_text
    assert "[REDACTED:openai_key]" not in result.sanitized_text
    assert "anthropic_key" in result.secret_findings
    assert "openai_key" not in result.secret_findings
    assert "secret_redaction" in result.reason_codes


def test_m2_t7_output_firewall_blocks_known_malicious_urls() -> None:
    alerts: list[dict[str, object]] = []
    firewall = OutputFirewall(
        safe_domains=["api.good.com"],
        alert_hook=lambda payload: alerts.append(payload),
    )

    result = firewall.inspect("Open https://evil.com/exfil for details")

    assert result.blocked is True
    assert result.reason_codes == ["malicious_url"]
    assert alerts
    assert alerts[0]["reason_codes"] == ["malicious_url"]


def test_gh13_output_firewall_treats_redacted_pseudo_url_as_malformed() -> None:
    firewall = OutputFirewall(safe_domains=["hareruyamtg.com", "*.hareruyamtg.com"])

    result = firewall.inspect("Detail: https://www.hareruyamtg.[REDACTED:high_entropy_secret]")

    assert result.blocked is True
    assert "malicious_url" in result.reason_codes
    assert result.url_findings
    assert result.url_findings[0].host == ""
    assert result.url_findings[0].reason == "malformed_url"


def test_gh22_output_firewall_preserves_malformed_url_aggregate_reason() -> None:
    alerts: list[dict[str, object]] = []
    firewall = OutputFirewall(
        safe_domains=["api.good.com"],
        alert_hook=lambda payload: alerts.append(payload),
    )

    result = firewall.inspect(
        'Echo "http://[2001:db8::1"',
        context={"session_id": "sess-gh22"},
    )

    assert result.blocked is True
    assert "malicious_url" in result.reason_codes
    assert "malformed_url" in result.reason_codes
    assert result.url_findings
    assert result.url_findings[0].reason == "malformed_url"
    assert alerts
    assert "malformed_url" in alerts[0]["reason_codes"]


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


def test_gh34_entropy_detector_does_not_prefix_replace_low_entropy_token_sibling() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "Ab3D4e5F6g7H8i9J0k1L2m3N"
    sibling = f"{token}{'a' * 32}"

    result = firewall.inspect(f"tokens {token} {sibling}")

    assert "[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert sibling in result.sanitized_text
    assert f"[REDACTED:high_entropy_secret]{'a' * 32}" not in result.sanitized_text
    assert result.sanitized_text.count("[REDACTED:high_entropy_secret]") == 1


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


def test_gh34_entropy_detector_keeps_source_fixture_paths_unredacted() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    path = "/home/ubuntu/shisad/tests/fixtures/fake_playwright_cli.py"

    result = firewall.inspect(f"browser.navigate failed: [Errno 13] Permission denied: '{path}'")

    assert path in result.sanitized_text
    assert "high_entropy_secret" not in result.secret_findings
    assert "entropy_secret_redaction" not in result.reason_codes


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


def test_gh34_entropy_detector_still_redacts_secret_like_path_with_source_suffix() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/tmp/a8F2kL9pQ4rT1vN3/b7D4mS8xZ1cV6nH2.py"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret].py" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_redacts_lowercase_secret_like_source_suffix_path() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/tmp/project/b7d4ms8xz1cv6nh2.py"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret].py" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


@pytest.mark.parametrize(
    "stem",
    [
        "abc123def456_ghi789jkl012",
        "abc123def456-ghi789jkl012",
        "a12_b34_c56_d78_e90_f12",
    ],
)
def test_gh34_entropy_detector_redacts_separated_secret_like_source_suffix_path(
    stem: str,
) -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = f"/tmp/project/{stem}.py"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret].py" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


@pytest.mark.parametrize(
    "stem",
    ["abcdefghijkl_mnopqrstuvwx_yzabcdefghi"],
)
def test_gh34_entropy_detector_redacts_separated_alphabetic_secret_like_source_path(
    stem: str,
) -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = f"/tmp/project/{stem}.py"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret].py" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_redacts_short_secret_chunks_with_readable_prefix() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/tmp/a1B2c3D4/e5F6g7H8/i9J0k1L2"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_redacts_lowercase_short_secret_chunks() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/tmp/a1b2c3/d4e5f6/g7h8i9"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_keeps_final_filename_after_short_secret_chunks() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/tmp/a1b2c3/d4e5f6/readme.txt"

    result = firewall.inspect(f"path {token}")

    expected = "/tmp/[REDACTED:high_entropy_secret]/[REDACTED:high_entropy_secret]/readme.txt"
    assert expected in result.sanitized_text
    assert "readme.txt" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_redacts_single_short_secret_like_source_stem() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/home/ubuntu/project/a1B2c3D4.py"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret].py" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_redacts_single_short_secret_like_final_segment() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/home/ubuntu/project/a1B2c3D4"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_redacts_rooted_single_secret_like_source_stem() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/a1B2c3D4.py"

    result = firewall.inspect(f"path {token}")

    assert "/[REDACTED:high_entropy_secret].py" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_redacts_rooted_single_mid_length_secret_segment() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/a1B2c3D4e5F6g7H8i9"

    result = firewall.inspect(f"path {token}")

    assert "/[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_redacts_single_short_final_segment_with_low_entropy_prefix() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/tmp/tmp/tmp/a1B2c3D4"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_redacts_mid_length_final_segment_with_low_entropy_prefix() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/tmp/tmp/tmp/a1B2c3D4e5F6g7H8i9"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_redacts_exact_upper_bound_compact_path_segment() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    secret_segment = "a1B2c3D4e5F6g7H8i9J0k1L"
    assert len(secret_segment) == 23
    token = f"/tmp/tmp/tmp/{secret_segment}"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_redacts_mid_length_source_suffix_stem() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/home/ubuntu/project/a1B2c3D4e5F6g7H8i9.py"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret].py" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_redacts_mid_length_multi_segment_path_secret() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/tmp/a1B2c3D4e5F6g7H8i9/b2C3d4E5f6G7h8I9j0/readme.txt"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert "readme.txt" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_redacts_single_nonfinal_path_secret_segment() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/a/a1B2c3D4e5F6g7H8i9/b"

    result = firewall.inspect(f"path {token}")

    assert "/a/[REDACTED:high_entropy_secret]/b" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


def test_gh34_entropy_detector_does_not_prefix_replace_readable_path_sibling() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    secret_path = "/tmp/a1B2c3D4"
    readable_path = "/tmp/a1B2c3D4readme"

    result = firewall.inspect(f"paths {secret_path} {readable_path}")

    assert "/tmp/[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert readable_path in result.sanitized_text
    assert "[REDACTED:high_entropy_secret]readme" not in result.sanitized_text
    assert result.sanitized_text.count("[REDACTED:high_entropy_secret]") == 1


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://api.good.com/reset/a1B2c3D4",
            "https://api.good.com/reset/[REDACTED:high_entropy_secret]",
        ),
        (
            "https://api.good.com/reset/a1B2c3D4/confirm?next=dashboard",
            "https://api.good.com/reset/[REDACTED:high_entropy_secret]/confirm?next=dashboard",
        ),
    ],
)
def test_gh34_entropy_detector_redacts_compact_secret_url_path_segment(
    url: str,
    expected: str,
) -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])

    result = firewall.inspect(f"url {url}")

    assert expected in result.sanitized_text
    assert url not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings
    assert result.url_findings[0].allowed is True
    assert result.blocked is False
    assert result.require_confirmation is False


def test_gh34_entropy_detector_does_not_prefix_replace_readable_url_sibling() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    secret_url = "https://api.good.com/reset/a1B2c3D4"
    readable_url = "https://api.good.com/reset/a1B2c3D4readme"

    result = firewall.inspect(f"urls {secret_url} {readable_url}")

    assert "https://api.good.com/reset/[REDACTED:high_entropy_secret]" in (result.sanitized_text)
    assert readable_url in result.sanitized_text
    assert "[REDACTED:high_entropy_secret]readme" not in result.sanitized_text
    assert result.sanitized_text.count("[REDACTED:high_entropy_secret]") == 1
    assert all(finding.allowed for finding in result.url_findings)


@pytest.mark.parametrize(
    "url",
    [
        "https://api.good.com/docs/readme",
        "https://api.good.com/docs/v4l2ctl",
    ],
)
def test_gh34_entropy_detector_keeps_readable_url_path_segment(url: str) -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])

    result = firewall.inspect(f"url {url}")

    assert url in result.sanitized_text
    assert "high_entropy_secret" not in result.secret_findings
    assert result.url_findings[0].allowed is True
    assert result.blocked is False
    assert result.require_confirmation is False


def test_gh34_entropy_detector_keeps_readable_technical_final_segment() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/home/ubuntu/project/v4l2ctl"

    result = firewall.inspect(f"path {token}")

    assert token in result.sanitized_text
    assert "high_entropy_secret" not in result.secret_findings


def test_gh34_entropy_detector_keeps_readable_rooted_technical_segment() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/v4l2ctl"

    result = firewall.inspect(f"path {token}")

    assert token in result.sanitized_text
    assert "high_entropy_secret" not in result.secret_findings


@pytest.mark.parametrize(
    "path",
    [
        "src/playwright_runtime_diagnostics.py",
        "/playwright_runtime_diagnostics.py",
        "/src/playwright_runtime_diagnostics.py",
    ],
)
def test_gh34_entropy_detector_keeps_rooted_readable_source_paths(path: str) -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])

    result = firewall.inspect(f"path {path}")

    assert path in result.sanitized_text
    assert "high_entropy_secret" not in result.secret_findings


def test_gh34_entropy_detector_redacts_secret_like_technical_prefix_final_segment() -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])
    token = "/home/ubuntu/project/v4l2a1b2"

    result = firewall.inspect(f"path {token}")

    assert "[REDACTED:high_entropy_secret]" in result.sanitized_text
    assert token not in result.sanitized_text
    assert "high_entropy_secret" in result.secret_findings


@pytest.mark.parametrize(
    "path",
    [
        "/Users/Alice/MyDocs2025/Backup2024/notes.txt",
        "/Users/Alice/Documents2025/Photos2024/img.jpg",
        "/home/me/Project2025/MyApp2024/build/index.html",
    ],
)
def test_gh34_entropy_detector_keeps_camelcase_year_directory_paths(path: str) -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])

    result = firewall.inspect(f"path {path}")

    assert path in result.sanitized_text
    assert "high_entropy_secret" not in result.secret_findings


@pytest.mark.parametrize(
    "path",
    [
        "/home/ubuntu/shisad/tests/adversarial/test_local_fido2_approval.py",
        "/home/ubuntu/shisad/tests/behavioral/test_v04_behavioral_extensions.py",
        "/home/ubuntu/shisad/tests/behavioral/test_no_model_configured_behavioral.py",
        "/home/ubuntu/shisad/tests/unit/test_provider_routing_s0.py",
        "/home/ubuntu/shisad/tests/unit/test_s8_default_posture.py",
        "/tmp/project/test_x509_certificate_validation.py",
        "/tmp/project/test_sha256_digest_validation.py",
        "/tmp/project/test_tls13_handshake.py",
        "/tmp/project/test_utf16_decoder.py",
    ],
)
def test_gh34_entropy_detector_keeps_digit_bearing_readable_source_paths(
    path: str,
) -> None:
    firewall = OutputFirewall(safe_domains=["api.good.com"])

    result = firewall.inspect(f"path {path}")

    assert path in result.sanitized_text
    assert "high_entropy_secret" not in result.secret_findings
