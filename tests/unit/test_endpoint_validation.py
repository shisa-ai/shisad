"""M0.T2-T3: Endpoint allowlist blocks private ranges and non-HTTPS."""

from __future__ import annotations

from shisad.core.providers.base import validate_endpoint


class TestEndpointValidation:
    """M0.T2: endpoint allowlist blocks private ranges."""

    def test_blocks_10_x(self) -> None:
        errors = validate_endpoint("https://10.0.0.1/v1")
        assert any("private range" in e for e in errors)

    def test_blocks_192_168(self) -> None:
        errors = validate_endpoint("https://192.168.1.1/v1")
        assert any("private range" in e for e in errors)

    def test_blocks_172_16(self) -> None:
        errors = validate_endpoint("https://172.16.0.1/v1")
        assert any("private range" in e for e in errors)

    def test_blocks_loopback_ip(self) -> None:
        errors = validate_endpoint("https://127.0.0.1/v1", allow_http_localhost=False)
        assert any("private range" in e for e in errors)

    def test_allows_public_ip(self) -> None:
        errors = validate_endpoint("https://api.openai.com/v1")
        assert errors == []

    def test_allows_localhost_http_when_permitted(self) -> None:
        errors = validate_endpoint(
            "http://localhost:8080/v1",
            allow_http_localhost=True,
            block_private_ranges=False,
        )
        assert errors == []


class TestEndpointHttpsRequired:
    """M0.T3: endpoint allowlist blocks non-HTTPS for remote hosts."""

    def test_blocks_http_remote(self) -> None:
        errors = validate_endpoint("http://api.openai.com/v1")
        assert any("HTTP not allowed" in e for e in errors)

    def test_allows_http_localhost(self) -> None:
        errors = validate_endpoint(
            "http://localhost:8080/v1",
            block_private_ranges=False,
        )
        assert errors == []

    def test_blocks_http_localhost_when_disallowed(self) -> None:
        errors = validate_endpoint(
            "http://localhost:8080/v1",
            allow_http_localhost=False,
        )
        assert any("HTTP not allowed" in e for e in errors)

    def test_blocks_unsupported_scheme(self) -> None:
        errors = validate_endpoint("ftp://example.com/data")
        assert any("Unsupported scheme" in e for e in errors)
