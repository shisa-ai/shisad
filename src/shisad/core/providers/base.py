"""Model provider abstraction.

Defines the ModelProvider protocol and an OpenAI-compatible implementation.
Includes endpoint validation (HTTPS required, SSRF protection) and
configurable prompt logging policy.
"""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import hashlib
import ipaddress
import json
import logging
import socket
from typing import Any, Protocol
from urllib import error, request
from urllib.parse import urljoin, urlparse, urlunparse

from pydantic import BaseModel, Field

from shisad.core.providers.capabilities import RequestParameters

logger = logging.getLogger(__name__)
_PROVIDER_REDIRECT_CODES: set[int] = {301, 302, 303, 307, 308}
_PROVIDER_MAX_REDIRECTS = 5


# --- Provider protocol ---


class Message(BaseModel):
    """A single message in a conversation."""

    role: str  # "system", "user", "assistant", "tool"
    content: str = ""
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    tool_call_id: str | None = None


class ProviderResponse(BaseModel):
    """Response from a model provider."""

    message: Message
    model: str = ""
    finish_reason: str = ""
    usage: dict[str, int] = Field(default_factory=dict)
    trusted_origin: str = Field(default="", exclude=True)


class EmbeddingResponse(BaseModel):
    """Response for embeddings endpoints."""

    vectors: list[list[float]] = Field(default_factory=list)
    model: str = ""
    usage: dict[str, int] = Field(default_factory=dict)


class ModelProvider(Protocol):
    """Protocol for model providers.

    All providers must implement this interface. The actual HTTP call
    goes through the credential broker's egress proxy in production.
    """

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse: ...

    async def embeddings(
        self,
        input_texts: list[str],
        *,
        model_id: str | None = None,
    ) -> EmbeddingResponse: ...


# --- OpenAI-compatible provider ---


class OpenAICompatibleProvider:
    """OpenAI-compatible provider using `/v1/chat/completions` + `/v1/embeddings`."""

    def __init__(
        self,
        *,
        base_url: str,
        model_id: str,
        headers: dict[str, str] | None = None,
        force_json_response: bool = False,
        request_parameters: RequestParameters | None = None,
        timeout_seconds: float = 30.0,
        allow_http_localhost: bool = True,
        block_private_ranges: bool = True,
        endpoint_allowlist: list[str] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model_id = model_id
        self._headers = headers or {}
        self._force_json_response = force_json_response
        self._request_parameters = request_parameters or RequestParameters()
        self._timeout_seconds = timeout_seconds
        self._allow_http_localhost = allow_http_localhost
        self._block_private_ranges = block_private_ranges
        self._endpoint_allowlist = list(endpoint_allowlist or [])

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        payload: dict[str, Any] = {
            "model": self._model_id,
            "messages": [self._serialize_message(msg) for msg in messages],
        }
        payload.update(self._request_parameters.to_payload())
        if self._force_json_response:
            payload["response_format"] = {"type": "json_object"}
        if tools:
            payload["tools"] = tools

        endpoint = self._build_endpoint("chat/completions")
        response_data = await asyncio.to_thread(self._post_json, endpoint, payload)

        choices = response_data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise RuntimeError("Provider response missing choices")
        first_choice = choices[0]
        if not isinstance(first_choice, dict):
            raise RuntimeError("Provider response has invalid choice payload")
        message_data = first_choice.get("message", {})
        if not isinstance(message_data, dict):
            raise RuntimeError("Provider response has invalid message payload")
        message_content = message_data.get("content", "")
        if message_content is None:
            message_content = ""
        elif not isinstance(message_content, str):
            message_content = str(message_content)

        return ProviderResponse(
            message=Message(
                role=str(message_data.get("role", "assistant")),
                content=message_content,
                tool_calls=list(message_data.get("tool_calls", []) or []),
                tool_call_id=(
                    str(message_data["tool_call_id"])
                    if message_data.get("tool_call_id") is not None
                    else None
                ),
            ),
            model=str(response_data.get("model", self._model_id)),
            finish_reason=str(first_choice.get("finish_reason", "")),
            usage=self._coerce_usage(response_data.get("usage")),
        )

    async def embeddings(
        self,
        input_texts: list[str],
        *,
        model_id: str | None = None,
    ) -> EmbeddingResponse:
        payload: dict[str, Any] = {
            "model": model_id or self._model_id,
            "input": input_texts,
        }
        endpoint = self._build_endpoint("embeddings")
        response_data = await asyncio.to_thread(self._post_json, endpoint, payload)

        data = response_data.get("data")
        if not isinstance(data, list):
            raise RuntimeError("Provider embeddings response missing data array")

        vectors: list[list[float]] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            embedding = item.get("embedding")
            if isinstance(embedding, list):
                vectors.append([float(v) for v in embedding])

        return EmbeddingResponse(
            vectors=vectors,
            model=str(response_data.get("model", model_id or self._model_id)),
            usage=self._coerce_usage(response_data.get("usage")),
        )

    @staticmethod
    def _serialize_message(message: Message) -> dict[str, Any]:
        payload: dict[str, Any] = {"role": message.role, "content": message.content}
        if message.tool_calls:
            payload["tool_calls"] = message.tool_calls
        if message.tool_call_id is not None:
            payload["tool_call_id"] = message.tool_call_id
        return payload

    @staticmethod
    def _coerce_usage(value: Any) -> dict[str, int]:
        if not isinstance(value, dict):
            return {}
        usage: dict[str, int] = {}
        for key, item in value.items():
            if isinstance(item, int):
                usage[str(key)] = item
        return usage

    def _build_endpoint(self, suffix: str) -> str:
        parsed = urlparse(self._base_url)
        suffix_path = suffix.lstrip("/")
        current_path = parsed.path.rstrip("/")

        if current_path.endswith(f"/{suffix_path}"):
            endpoint_path = current_path
        elif current_path.endswith("/v1"):
            endpoint_path = f"{current_path}/{suffix_path}"
        elif current_path == "":
            endpoint_path = f"/v1/{suffix_path}"
        else:
            endpoint_path = f"{current_path}/{suffix_path}"

        return urlunparse(parsed._replace(path=endpoint_path, params="", query="", fragment=""))

    def _post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self._headers,
        }
        active_url = url
        redirect_count = 0
        while True:
            validation_errors = _validate_runtime_endpoint_url(
                active_url,
                allow_http_localhost=self._allow_http_localhost,
                block_private_ranges=self._block_private_ranges,
                endpoint_allowlist=self._endpoint_allowlist or None,
            )
            if validation_errors:
                raise RuntimeError(
                    f"Provider endpoint blocked for {active_url}: {validation_errors[0]}"
                )
            req = request.Request(url=active_url, data=body, headers=headers, method="POST")
            try:
                with _open_no_redirect(req, timeout=self._timeout_seconds) as response:
                    raw = response.read().decode("utf-8")
                break
            except error.HTTPError as exc:
                if exc.code in _PROVIDER_REDIRECT_CODES:
                    location = ""
                    if exc.headers is not None:
                        location = str(exc.headers.get("Location", "")).strip()
                    if not location:
                        raise RuntimeError(
                            f"Provider redirect blocked for {active_url}: missing Location header"
                        ) from exc
                    redirect_count += 1
                    if redirect_count > _PROVIDER_MAX_REDIRECTS:
                        raise RuntimeError(
                            f"Provider redirect blocked for {active_url}: too many redirects"
                        ) from exc
                    redirected_url = urljoin(active_url, location)
                    redirect_errors = _validate_runtime_endpoint_url(
                        redirected_url,
                        allow_http_localhost=self._allow_http_localhost,
                        block_private_ranges=self._block_private_ranges,
                        endpoint_allowlist=self._endpoint_allowlist or None,
                    )
                    if redirect_errors:
                        raise RuntimeError(
                            f"Provider redirect blocked for {redirected_url}: {redirect_errors[0]}"
                        ) from exc
                    active_url = redirected_url
                    continue
                details = _read_http_error_details(exc)
                raise RuntimeError(
                    f"Provider HTTP error {exc.code} for {active_url}: {details[:300]}"
                ) from exc
            except error.URLError as exc:
                raise RuntimeError(
                    f"Provider request failed for {active_url}: {exc.reason}"
                ) from exc

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Provider returned non-JSON response for {active_url}") from exc

        if not isinstance(parsed, dict):
            raise RuntimeError(f"Provider response for {active_url} must be a JSON object")
        return parsed


# --- Endpoint validation ---


# RFC 1918 + loopback + link-local ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_endpoint(
    url: str,
    *,
    allow_http_localhost: bool = True,
    block_private_ranges: bool = True,
    endpoint_allowlist: list[str] | None = None,
) -> list[str]:
    """Validate a model endpoint URL for security.

    Returns a list of validation errors (empty = valid).
    """
    errors: list[str] = []

    parsed = urlparse(url)

    # Scheme check
    if parsed.scheme not in ("http", "https"):
        errors.append(f"Unsupported scheme: {parsed.scheme} (must be http or https)")
        return errors

    hostname = parsed.hostname or ""

    # HTTPS required for non-localhost
    if parsed.scheme == "http":
        is_localhost = hostname in ("localhost", "127.0.0.1", "::1")
        if not is_localhost or not allow_http_localhost:
            errors.append(f"HTTP not allowed for non-localhost endpoint: {hostname}")

    # Private range check for IP literals (hostname checks happen at runtime request time).
    # Loopback is only exempt when localhost HTTP is explicitly allowed.
    allow_loopback = allow_http_localhost and hostname in ("localhost", "127.0.0.1", "::1")
    if block_private_ranges and not allow_loopback:
        try:
            addr = ipaddress.ip_address(hostname)
            for network in _PRIVATE_NETWORKS:
                if addr in network:
                    errors.append(f"Endpoint in private range: {hostname} ({network})")
                    break
        except ValueError:
            pass

    # Explicit endpoint allowlist (trusted config)
    if endpoint_allowlist and not _matches_endpoint_allowlist(parsed, endpoint_allowlist):
        errors.append(f"Endpoint not in configured allowlist: {url}")

    return errors


def _matches_endpoint_allowlist(parsed_url: Any, allowlist: list[str]) -> bool:
    hostname = parsed_url.hostname or ""
    normalized_path = parsed_url.path.rstrip("/")

    for raw_rule in allowlist:
        rule = raw_rule.strip()
        if not rule:
            continue

        if "://" in rule:
            parsed_rule = urlparse(rule)
            rule_host = parsed_rule.hostname or ""
            if parsed_rule.scheme and parsed_url.scheme != parsed_rule.scheme:
                continue
            if rule_host and not fnmatch.fnmatch(hostname, rule_host):
                continue
            rule_path = parsed_rule.path.rstrip("/")
            if rule_path and not (
                normalized_path == rule_path or normalized_path.startswith(rule_path + "/")
            ):
                continue
            return True

        if fnmatch.fnmatch(hostname, rule):
            return True

    return False


# --- Prompt logging ---


def log_prompt_metadata(
    messages: list[Message],
    response: ProviderResponse,
    *,
    log_full: bool = False,
) -> dict[str, Any]:
    """Generate prompt metadata for audit logging.

    Default: log only hashes and metadata (no raw prompts).
    Debug mode: log full prompts (opt-in, never log credentials).
    """
    metadata: dict[str, Any] = {
        "message_count": len(messages),
        "roles": [m.role for m in messages],
        "finish_reason": response.finish_reason,
        "usage": response.usage,
    }

    if log_full:
        # Even in debug mode, we log content hashes rather than raw text
        # to avoid accidentally logging credentials
        metadata["message_hashes"] = [
            hashlib.sha256(m.content.encode()).hexdigest()[:16] for m in messages
        ]
        metadata["response_hash"] = hashlib.sha256(response.message.content.encode()).hexdigest()[
            :16
        ]

    return metadata


class _NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


_NO_REDIRECT_OPENER = request.build_opener(_NoRedirectHandler)


def _open_no_redirect(req: request.Request, *, timeout: float) -> Any:
    return _NO_REDIRECT_OPENER.open(req, timeout=timeout)


def _read_http_error_details(exc: error.HTTPError) -> str:
    with contextlib.suppress(OSError, ValueError, TypeError):
        body = exc.read().decode("utf-8", errors="replace")
        if body:
            return body
    return ""


def _validate_runtime_endpoint_url(
    url: str,
    *,
    allow_http_localhost: bool = True,
    block_private_ranges: bool = True,
    endpoint_allowlist: list[str] | None = None,
) -> list[str]:
    errors = validate_endpoint(
        url,
        allow_http_localhost=allow_http_localhost,
        block_private_ranges=block_private_ranges,
        endpoint_allowlist=endpoint_allowlist,
    )
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").strip()
    if not block_private_ranges or not hostname or hostname in {"localhost", "127.0.0.1", "::1"}:
        return errors

    if _is_ip_literal(hostname):
        return errors

    try:
        records = socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except (OSError, socket.gaierror) as exc:
        logger.debug("Endpoint hostname resolution skipped for %s: %s", hostname, exc)
        return errors

    seen_addresses: set[str] = set()
    for record in records:
        sockaddr = record[4]
        if not isinstance(sockaddr, tuple) or not sockaddr:
            continue
        address = str(sockaddr[0])
        if address in seen_addresses:
            continue
        seen_addresses.add(address)
        if _address_in_private_ranges(address):
            errors.append(f"Endpoint resolves to private range: {hostname} ({address})")
            break
    return errors


def _is_ip_literal(hostname: str) -> bool:
    with contextlib.suppress(ValueError):
        ipaddress.ip_address(hostname)
        return True
    return False


def _address_in_private_ranges(address: str) -> bool:
    try:
        ip_addr = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip_addr in network for network in _PRIVATE_NETWORKS)
