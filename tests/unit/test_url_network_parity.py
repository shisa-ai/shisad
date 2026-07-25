"""Differential contract for canonical URL and network-address facts."""

from __future__ import annotations

import importlib
import io
from pathlib import Path
from typing import Any
from urllib.error import HTTPError

import pytest

from shisad.assistant.web import WebToolkit
from shisad.core import url_parsing
from shisad.core.providers.base import _validate_runtime_endpoint_url, validate_endpoint
from shisad.core.tools.registry import ToolRegistry
from shisad.core.tools.schema import ToolDefinition, ToolParameter
from shisad.core.types import Capability, PEPDecisionKind, ToolName
from shisad.executors.browser import (
    BrowserLocalNetworkMode,
    BrowserSandbox,
    BrowserSandboxPolicy,
    BrowserToolkit,
)
from shisad.executors.proxy import EgressProxy, NetworkPolicy
from shisad.security.firewall.output import OutputFirewall
from shisad.security.pep import PEP, PolicyContext
from shisad.security.policy import EgressRule, PolicyBundle


def _destination(value: str) -> Any:
    return url_parsing.safe_url_destination(value)  # type: ignore[attr-defined]


def _network_address() -> Any:
    return importlib.import_module("shisad.security.network_address")


@pytest.mark.parametrize(
    ("value", "scheme", "host", "port", "has_userinfo"),
    [
        (" HTTPS://User:pass@Example.COM.:8443/a?q=1#f ", "https", "example.com", 8443, True),
        ("http://[::1]:8080/v1", "http", "::1", 8080, False),
        ("ftp://files.example/path", "ftp", "files.example", None, False),
        ("https://api.example/path", "https", "api.example", None, False),
    ],
)
def test_absolute_destination_valid_corpus(
    value: str,
    scheme: str,
    host: str,
    port: int | None,
    has_userinfo: bool,
) -> None:
    destination = _destination(value)

    assert destination is not None
    assert destination.scheme == scheme
    assert destination.host == host
    assert destination.port == port
    assert destination.has_userinfo is has_userinfo


@pytest.mark.parametrize(
    "value",
    [
        "",
        "example.com/path",
        "//example.com/path",
        "https:///missing-host",
        "https://[::1",
        "https://example.com:99999/path",
        "https://example.com:not-a-port/path",
        "https://example.com\\@evil.example/path",
        "https://exa%6dple.com/path",
        "https://example..com/path",
        "https://example.com../path",
        "https://example.com\n.evil.example/path",
        "https://example.com /path",
    ],
)
def test_absolute_destination_malformed_corpus(value: str) -> None:
    assert _destination(value) is None


@pytest.mark.parametrize(
    ("value", "canonical", "is_public", "is_loopback"),
    [
        ("8.8.8.8", "8.8.8.8", True, False),
        ("2606:4700:4700::1111", "2606:4700:4700::1111", True, False),
        ("127.0.0.1", "127.0.0.1", False, True),
        ("127.1", "127.0.0.1", False, True),
        ("2130706433", "127.0.0.1", False, True),
        ("0x7f000001", "127.0.0.1", False, True),
        ("017700000001", "127.0.0.1", False, True),
        ("0300.0250.0001.0001", "192.168.1.1", False, False),
        ("::ffff:127.0.0.1", "::ffff:127.0.0.1", False, True),
        ("100.64.0.1", "100.64.0.1", False, False),
        ("192.0.2.1", "192.0.2.1", False, False),
        ("198.18.0.1", "198.18.0.1", False, False),
        ("224.0.0.1", "224.0.0.1", False, False),
        ("ff02::1", "ff02::1", False, False),
        ("fec0::1", "fec0::1", False, False),
        ("0.0.0.0", "0.0.0.0", False, False),
        ("240.0.0.1", "240.0.0.1", False, False),
    ],
)
def test_network_address_classification_corpus(
    value: str,
    canonical: str,
    is_public: bool,
    is_loopback: bool,
) -> None:
    classified = _network_address().classify_network_address(value)

    assert classified is not None
    assert classified.canonical == canonical
    assert classified.is_public is is_public
    assert classified.is_loopback is is_loopback
    assert _network_address().is_ip_literal(value) is True
    assert _network_address().is_private_or_special_address(value) is (not is_public)


@pytest.mark.parametrize("value", ["", "example.com", "1.2.3.4.5", "0xnot-an-address"])
def test_network_address_invalid_corpus(value: str) -> None:
    network_address = _network_address()

    assert network_address.classify_network_address(value) is None
    assert network_address.is_ip_literal(value) is False
    assert network_address.is_private_or_special_address(value) is False


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "LOCALHOST.",
        "service.localhost",
        "printer.local",
        "api.internal.",
        "router.lan",
    ],
)
def test_local_hostname_corpus(host: str) -> None:
    assert _network_address().is_local_hostname(host) is True


@pytest.mark.parametrize("host", ["local", "notlocalhost", "example.com", "internal.example"])
def test_public_hostname_not_misclassified_as_local(host: str) -> None:
    assert _network_address().is_local_hostname(host) is False


@pytest.mark.parametrize(
    "url",
    [
        "https://100.64.0.1/v1",
        "https://192.0.2.1/v1",
        "https://198.18.0.1/v1",
        "https://224.0.0.1/v1",
        "https://[ff02::1]/v1",
    ],
)
def test_provider_blocks_literal_private_or_special_address(url: str) -> None:
    errors = validate_endpoint(url)

    assert any("private" in error.lower() or "special" in error.lower() for error in errors)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.1:8080/v1",
        "http://2130706433:8080/v1",
        "http://[::ffff:127.0.0.1]:8080/v1",
    ],
)
def test_provider_preserves_enabled_loopback_http_exception(url: str) -> None:
    assert validate_endpoint(url) == []


def test_provider_canonicalizes_root_dot_for_allowlist() -> None:
    errors = validate_endpoint(
        "https://API.EXAMPLE.COM./v1",
        endpoint_allowlist=["api.example.com"],
    )

    assert errors == []


def test_provider_preserves_bare_ipv6_loopback_allowlist() -> None:
    errors = validate_endpoint(
        "http://[::1]:8080/v1",
        endpoint_allowlist=["::1"],
    )

    assert errors == []


@pytest.mark.parametrize("rule", ["ap?.example.com", "[ab]pi.example.com"])
def test_provider_preserves_bare_fnmatch_allowlist_semantics(rule: str) -> None:
    errors = validate_endpoint(
        "https://api.example.com/v1",
        endpoint_allowlist=[rule],
    )

    assert errors == []


@pytest.mark.parametrize(
    "url",
    [
        "example.com/v1",
        "https://[::1",
        "https://example.com:99999/v1",
        "https://exa%6dple.com/v1",
    ],
)
def test_provider_malformed_endpoint_fails_closed_without_exception(url: str) -> None:
    errors = validate_endpoint(url)

    assert any("malformed" in error.lower() for error in errors)


@pytest.mark.parametrize("resolved", ["not-an-address", "100.64.0.1", "224.0.0.1"])
def test_provider_runtime_rejects_invalid_or_special_resolution(
    monkeypatch: pytest.MonkeyPatch,
    resolved: str,
) -> None:
    monkeypatch.setattr(
        "shisad.core.providers.base.socket.getaddrinfo",
        lambda *args, **kwargs: [(0, 0, 0, "", (resolved, 443))],
    )

    errors = _validate_runtime_endpoint_url("https://planner.example.com/v1")

    assert any("private" in error.lower() or "special" in error.lower() for error in errors)


@pytest.mark.parametrize(
    "record",
    [
        None,
        (0, 0, 0, "", ()),
        (0, 0, 0, "", "not-a-sockaddr"),
    ],
)
def test_provider_runtime_rejects_malformed_resolution_record(
    monkeypatch: pytest.MonkeyPatch,
    record: Any,
) -> None:
    monkeypatch.setattr(
        "shisad.core.providers.base.socket.getaddrinfo",
        lambda *args, **kwargs: [record],
    )

    errors = _validate_runtime_endpoint_url("https://planner.example.com/v1")

    assert any("invalid" in error.lower() for error in errors)


@pytest.mark.parametrize("host", ["127.1", "2130706433", "0x7f000001"])
def test_proxy_blocks_legacy_ip_literals(host: str) -> None:
    proxy = EgressProxy(resolver=lambda _host: ["93.184.216.34"])

    decision = proxy.authorize_request(
        tool_name="http_request",
        url=f"https://{host}/v1",
        policy=NetworkPolicy(allow_network=True, allowed_domains=[host]),
    )

    assert decision.allowed is False
    assert decision.reason == "ip_literal_blocked"


def test_proxy_canonicalizes_root_dot_before_allowlist_and_resolution() -> None:
    resolved_hosts: list[str] = []
    proxy = EgressProxy(
        resolver=lambda host: resolved_hosts.append(host) or ["93.184.216.34"],
    )

    decision = proxy.authorize_request(
        tool_name="http_request",
        url="https://API.GOOD.COM./v1",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
    )

    assert decision.allowed is True
    assert decision.destination_host == "api.good.com"
    assert resolved_hosts == ["api.good.com"]


def test_proxy_preserves_bare_ipv6_allowlist() -> None:
    proxy = EgressProxy(resolver=lambda _host: ["::1"])

    decision = proxy.authorize_request(
        tool_name="http_request",
        url="http://[::1]:8080/v1",
        policy=NetworkPolicy(
            allow_network=True,
            allowed_domains=["::1"],
            deny_private_ranges=False,
            deny_ip_literals=False,
        ),
    )

    assert decision.allowed is True


@pytest.mark.parametrize("rule", ["api.good.com:8443", "api.good.com/v1"])
def test_proxy_preserves_baseline_host_projection_for_port_or_path_rule(rule: str) -> None:
    proxy = EgressProxy(resolver=lambda _host: ["93.184.216.34"])

    decision = proxy.authorize_request(
        tool_name="http_request",
        url="https://api.good.com:8443/v1",
        policy=NetworkPolicy(allow_network=True, allowed_domains=[rule]),
    )

    assert decision.allowed is True


@pytest.mark.parametrize(
    "resolved",
    [None, "not-an-address", "100.64.0.1", "224.0.0.1", "ff02::1"],
)
def test_proxy_fails_closed_on_invalid_or_special_resolution(resolved: Any) -> None:
    proxy = EgressProxy(resolver=lambda _host: [resolved])  # type: ignore[list-item]

    decision = proxy.authorize_request(
        tool_name="http_request",
        url="https://api.good.com/v1",
        policy=NetworkPolicy(allow_network=True, allowed_domains=["api.good.com"]),
    )

    assert decision.allowed is False
    assert decision.reason == "private_range_blocked"


def test_proxy_rejects_invalid_resolution_when_private_targets_are_enabled() -> None:
    proxy = EgressProxy(resolver=lambda _host: ["not-an-address"])
    policy = NetworkPolicy(
        allow_network=True,
        allowed_domains=["local.example"],
        deny_private_ranges=False,
        deny_ip_literals=False,
    )

    decision = proxy.authorize_request(
        tool_name="http_request",
        url="http://local.example/",
        policy=policy,
    )

    assert decision.allowed is False
    assert decision.reason == "private_range_blocked"
    assert proxy.resolve_scope_addresses(url="http://local.example/", policy=policy) == []


def test_proxy_rebinding_comparison_uses_canonical_address_forms() -> None:
    calls = 0

    def _resolver(_host: str) -> list[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return ["2606:4700:4700:0:0:0:0:1111"]
        return ["2606:4700:4700::1111"]

    proxy = EgressProxy(resolver=_resolver)
    policy = NetworkPolicy(
        allow_network=True,
        allowed_domains=["api.example"],
    )
    first = proxy.authorize_request(
        tool_name="http_request",
        url="https://api.example/",
        policy=policy,
    )
    second = proxy.authorize_request(
        tool_name="http_request",
        url="https://api.example/",
        policy=policy,
        expected_addresses=first.resolved_addresses,
    )

    assert first.resolved_addresses == ["2606:4700:4700::1111"]
    assert second.allowed is True
    assert second.reason == "allowed"


def _browser_toolkit(
    tmp_path: Path,
    *,
    local_network: BrowserLocalNetworkMode,
    allowed_domains: list[str] | None = None,
) -> BrowserToolkit:
    configured_domains = list(allowed_domains or [])
    sandbox = BrowserSandbox(
        output_firewall=OutputFirewall(safe_domains=configured_domains),
        screenshots_dir=tmp_path / "screenshots",
        policy=BrowserSandboxPolicy(local_network=local_network),
    )
    return BrowserToolkit(
        enabled=True,
        command=["browser"],
        session_root=tmp_path / "browser",
        allowed_domains=configured_domains,
        timeout_seconds=5,
        require_hardened_isolation=False,
        max_read_bytes=4096,
        sandbox_runner=object(),  # type: ignore[arg-type]
        browser_sandbox=sandbox,
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://100.64.0.1/",
        "http://224.0.0.1/",
        "http://[ff02::1]/",
        "http://printer.local./",
        "http://service.localhost/",
    ],
)
def test_browser_explicit_local_network_posture_covers_canonical_special_targets(
    tmp_path: Path,
    url: str,
) -> None:
    toolkit = _browser_toolkit(tmp_path, local_network=BrowserLocalNetworkMode.ALLOWED)

    policy = toolkit._network_policy(target_urls=[url], allow_network=True)

    assert policy.deny_private_ranges is False
    assert policy.deny_ip_literals is False


def test_browser_local_network_posture_does_not_broaden_public_ip(
    tmp_path: Path,
) -> None:
    toolkit = _browser_toolkit(tmp_path, local_network=BrowserLocalNetworkMode.ALLOWED)

    policy = toolkit._network_policy(target_urls=["https://8.8.8.8/"], allow_network=True)

    assert policy.deny_private_ranges is True
    assert policy.deny_ip_literals is True


def test_browser_canonicalizes_root_dot_allowlist_for_local_target(
    tmp_path: Path,
) -> None:
    toolkit = _browser_toolkit(
        tmp_path,
        local_network=BrowserLocalNetworkMode.BLOCKED,
        allowed_domains=["printer.local."],
    )

    policy = toolkit._network_policy(
        target_urls=["http://PRINTER.LOCAL./"],
        allow_network=True,
    )

    assert policy.deny_private_ranges is False
    assert policy.deny_ip_literals is False


@pytest.mark.parametrize("rule", ["api.example/v1", "https://api.example/v1"])
def test_browser_preserves_non_host_rule_for_proxy_owned_projection(
    tmp_path: Path,
    rule: str,
) -> None:
    toolkit = _browser_toolkit(
        tmp_path,
        local_network=BrowserLocalNetworkMode.BLOCKED,
        allowed_domains=[rule],
    )

    assert toolkit._allowed_domains == [rule]


def _web_toolkit(tmp_path: Path, *, allowed_domains: list[str] | None = None) -> WebToolkit:
    return WebToolkit(
        data_dir=tmp_path,
        search_enabled=True,
        search_backend_url="https://search.example",
        fetch_enabled=True,
        allowed_domains=list(allowed_domains or []),
        timeout_seconds=5,
        max_fetch_bytes=65536,
    )


@pytest.mark.parametrize("host", ["127.1", "2130706433", "0x7f000001"])
def test_web_blocks_legacy_ip_literals_without_allowlist(tmp_path: Path, host: str) -> None:
    assert _web_toolkit(tmp_path)._host_block_reason(host) == "ip_literal_not_allowlisted"


@pytest.mark.parametrize("host", ["LOCALHOST.", "service.localhost", "printer.local."])
def test_web_blocks_canonical_local_names_without_allowlist(tmp_path: Path, host: str) -> None:
    assert _web_toolkit(tmp_path)._host_block_reason(host) == "local_destination_not_allowlisted"


def test_web_canonicalizes_root_dot_allowlist(tmp_path: Path) -> None:
    toolkit = _web_toolkit(tmp_path, allowed_domains=["printer.local."])

    assert toolkit._host_block_reason("PRINTER.LOCAL.") == ""


def test_web_malformed_authority_returns_typed_error(tmp_path: Path) -> None:
    result = _web_toolkit(tmp_path).fetch(url="https://[::1")

    assert result["ok"] is False
    assert result["error"] == "malformed_destination"


class _WebResponse:
    def __init__(self, body: bytes, *, final_url: str) -> None:
        self._stream = io.BytesIO(body)
        self.status = 200
        self.headers = {"Content-Type": "text/html"}
        self._final_url = final_url

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def geturl(self) -> str:
        return self._final_url

    def __enter__(self) -> _WebResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return


def test_web_malformed_redirect_authority_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def _redirect(*_args: object, **_kwargs: object) -> Any:
        raise HTTPError(
            url="https://public.example/start",
            code=302,
            msg="Found",
            hdrs={"Location": "https://[::1"},
            fp=None,
        )

    monkeypatch.setattr("shisad.assistant.web._open_no_redirect", _redirect)

    result = _web_toolkit(tmp_path).fetch(url="https://public.example/start")

    assert result["ok"] is False
    assert result["error"] == "malformed_destination"


def test_web_final_url_revalidates_legacy_ip_literal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "shisad.assistant.web._open_no_redirect",
        lambda *_args, **_kwargs: _WebResponse(
            b"<html><title>unexpected</title></html>",
            final_url="http://2130706433/private",
        ),
    )

    result = _web_toolkit(tmp_path).fetch(url="https://public.example/start")

    assert result["ok"] is False
    assert result["error"] == "ip_literal_not_allowlisted"


def test_web_malformed_search_result_url_does_not_abort_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "shisad.assistant.web._open_no_redirect",
        lambda *_args, **_kwargs: _WebResponse(
            b'{"results": [{"title": "bad", "url": "https://[::1"}]}',
            final_url="https://search.example/search",
        ),
    )

    result = _web_toolkit(tmp_path).search(query="test")

    assert result["ok"] is True
    assert result["results"][0]["host"] == ""


def _web_fetch_registry(*, destinations: list[str] | None = None) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("web.fetch"),
            description="Fetch a URL.",
            parameters=[ToolParameter(name="url", type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
            destinations=list(destinations or []),
            require_confirmation=False,
        )
    )
    return registry


def _web_search_registry(destination: str) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            name=ToolName("web.search"),
            description="Search through a configured backend.",
            parameters=[ToolParameter(name="query", type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
            destinations=[destination],
            require_confirmation=False,
        )
    )
    return registry


def _url_field_registry(field: str) -> tuple[ToolRegistry, ToolName]:
    registry = ToolRegistry()
    tool_name = ToolName(f"test.{field}")
    registry.register(
        ToolDefinition(
            name=tool_name,
            description="Exercise a structurally named URL field.",
            parameters=[ToolParameter(name=field, type="string", required=True)],
            capabilities_required=[Capability.HTTP_REQUEST],
            require_confirmation=False,
        )
    )
    return registry, tool_name


def _pep_context(**patterns: set[str]) -> PolicyContext:
    return PolicyContext(
        capabilities={Capability.HTTP_REQUEST},
        trust_level="trusted",
        **patterns,
    )


def test_pep_rejects_present_scheme_less_url_as_malformed() -> None:
    pep = PEP(PolicyBundle(), _web_fetch_registry())

    decision = pep.evaluate(
        ToolName("web.fetch"),
        {"url": "example.com/path"},
        _pep_context(),
    )

    assert decision.kind == PEPDecisionKind.REJECT
    assert decision.reason_code == "pep:egress_malformed_destination"


@pytest.mark.parametrize("field", ["url", "endpoint", "destination", "webhook_url"])
def test_pep_rejects_present_empty_url_field_as_malformed(field: str) -> None:
    registry, tool_name = _url_field_registry(field)
    pep = PEP(PolicyBundle(), registry)

    decision = pep.evaluate(tool_name, {field: ""}, _pep_context())

    assert decision.kind == PEPDecisionKind.REJECT
    assert decision.reason_code == "pep:egress_malformed_destination"


@pytest.mark.parametrize("host", ["127.1", "2130706433", "0x7f000001"])
def test_pep_blocks_legacy_ip_literal_even_when_explicit_user_goal(host: str) -> None:
    pep = PEP(PolicyBundle(), _web_fetch_registry())

    decision = pep.evaluate(
        ToolName("web.fetch"),
        {"url": f"http://{host}/"},
        _pep_context(user_goal_host_patterns={host}),
    )

    assert decision.kind == PEPDecisionKind.REJECT
    assert decision.reason_code == "pep:ip_literal_not_allowlisted"


@pytest.mark.parametrize("host", ["printer.local.", "service.localhost"])
def test_pep_blocks_canonical_local_name_even_when_explicit_user_goal(host: str) -> None:
    pep = PEP(PolicyBundle(), _web_fetch_registry())

    decision = pep.evaluate(
        ToolName("web.fetch"),
        {"url": f"http://{host}/"},
        _pep_context(user_goal_host_patterns={host}),
    )

    assert decision.kind == PEPDecisionKind.REJECT
    assert decision.reason_code == "pep:local_destination_not_allowlisted"


def test_pep_root_dot_public_destination_remains_usable() -> None:
    pep = PEP(PolicyBundle(), _web_fetch_registry())

    decision = pep.evaluate(
        ToolName("web.fetch"),
        {"url": "https://EXAMPLE.COM./"},
        _pep_context(user_goal_host_patterns={"example.com"}),
    )

    assert decision.kind == PEPDecisionKind.ALLOW
    assert pep.egress_attempts[-1].host == "example.com"


def test_pep_canonicalizes_root_dot_operator_allowlist() -> None:
    pep = PEP(
        PolicyBundle(
            egress=[EgressRule(host="example.com.", ports=[443], protocols=["https"])],
        ),
        _web_fetch_registry(),
    )

    decision = pep.evaluate(
        ToolName("web.fetch"),
        {"url": "https://EXAMPLE.COM./"},
        _pep_context(),
    )

    assert decision.kind == PEPDecisionKind.ALLOW


def test_pep_tool_declared_local_root_dot_exception_remains_usable() -> None:
    pep = PEP(PolicyBundle(), _web_fetch_registry(destinations=["localhost"]))

    decision = pep.evaluate(
        ToolName("web.fetch"),
        {"url": "http://LOCALHOST.:8080/"},
        _pep_context(),
    )

    assert decision.kind == PEPDecisionKind.ALLOW


def test_pep_infers_tool_declared_bracketed_ipv6_destination() -> None:
    pep = PEP(PolicyBundle(), _web_search_registry("http://[::1]:8080/search"))

    decision = pep.evaluate(
        ToolName("web.search"),
        {"query": "test"},
        _pep_context(),
    )

    assert decision.kind == PEPDecisionKind.ALLOW
    assert pep.egress_attempts[-1].host == "::1"
    assert pep.egress_attempts[-1].reason == "tool_declared"
