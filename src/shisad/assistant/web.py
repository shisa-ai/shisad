"""Web search/fetch helpers with fail-closed controls."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, OpenerDirector, Request, build_opener

_MAX_SEARCH_BYTES = 2 * 1024 * 1024
_MAX_REDIRECT_HOPS = 5
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_BLOCKED_PAGE_HINTS: tuple[str, ...] = (
    "access denied",
    "temporarily blocked",
    "security check",
    "verify you are human",
    "captcha",
    "cloudflare",
    "forbidden",
)


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


_NO_REDIRECT_OPENER: OpenerDirector = build_opener(_NoRedirectHandler())
_REDIRECT_CODES = {301, 302, 303, 307, 308}


@dataclass(slots=True, frozen=True)
class _HttpResponsePayload:
    body: bytes
    status_code: int
    content_type: str
    final_url: str
    truncated: bool


def _open_no_redirect(request: Request, *, timeout: float) -> Any:
    return _NO_REDIRECT_OPENER.open(request, timeout=timeout)


def _host_matches(host: str, rule: str) -> bool:
    candidate = rule.strip().lower()
    if not candidate:
        return False
    value = host.strip().lower()
    if not value:
        return False
    if candidate.startswith("*."):
        return value.endswith(candidate[1:])
    return value == candidate


def _read_limited(payload: Any, *, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    remaining = max(1, limit)
    truncated = False
    while remaining > 0:
        chunk = payload.read(min(16384, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    if payload.read(1):
        truncated = True
    return b"".join(chunks), truncated


@dataclass(slots=True)
class WebToolkit:
    """Reference web/search helper with explicit configuration gating."""

    data_dir: Path
    search_enabled: bool
    search_backend_url: str
    fetch_enabled: bool
    allowed_domains: list[str]
    timeout_seconds: float
    max_fetch_bytes: int

    def search(self, *, query: str, limit: int = 5) -> dict[str, Any]:
        normalized_query = query.strip()
        if not normalized_query:
            return self._error_payload(
                operation="web_search",
                reason="query_required",
                query=normalized_query,
            )
        if not self.search_enabled:
            return self._error_payload(
                operation="web_search",
                reason="web_search_disabled",
                query=normalized_query,
            )

        backend = self.search_backend_url.strip().rstrip("/")
        if not backend:
            return self._error_payload(
                operation="web_search",
                reason="web_search_backend_unconfigured",
                query=normalized_query,
            )
        if not self.allowed_domains:
            return self._error_payload(
                operation="web_search",
                reason="web_allowlist_unconfigured",
                query=normalized_query,
            )
        backend_host = (urlparse(backend).hostname or "").lower()
        if not self._host_allowed(backend_host):
            return self._error_payload(
                operation="web_search",
                reason="web_search_backend_not_allowlisted",
                query=normalized_query,
            )

        request_url = (
            f"{backend}/search?"
            + urlencode(
                {
                    "q": normalized_query,
                    "format": "json",
                    "language": "en",
                    "safesearch": 1,
                }
            )
        )
        request = Request(
            request_url,
            headers={
                "User-Agent": "shisad/0.3 web_search",
                "Accept": "application/json",
            },
        )
        fetched = self._fetch_with_redirect_policy(
            operation="web_search",
            request=request,
            query=normalized_query,
            backend=backend,
            source_url=request_url,
            read_limit=_MAX_SEARCH_BYTES,
            host_disallowed_reason="web_search_backend_not_allowlisted",
            invalid_scheme_reason="unsupported_backend_scheme",
            redirect_limit_reason="search_backend_too_many_redirects",
            missing_redirect_reason="search_backend_redirect_missing_location",
            request_failed_reason="search_backend_request_failed",
        )
        if isinstance(fetched, dict):
            return fetched
        payload_bytes = fetched.body
        truncated = fetched.truncated
        status_code = fetched.status_code

        try:
            payload = json.loads(payload_bytes.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return self._error_payload(
                operation="web_search",
                reason="search_backend_invalid_json",
                query=normalized_query,
                backend=backend,
            )

        rows = payload.get("results", [])
        if not isinstance(rows, list):
            rows = []
        clamped_limit = max(1, min(limit, 20))
        results: list[dict[str, Any]] = []
        for item in rows:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or item.get("link") or "").strip()
            if not url:
                continue
            host = (urlparse(url).hostname or "").lower()
            results.append(
                {
                    "title": str(item.get("title", "")).strip(),
                    "url": url,
                    "snippet": str(item.get("content") or item.get("snippet") or "").strip(),
                    "host": host,
                    "allowlisted_host": self._host_allowed(host),
                    "engine": str(item.get("engine", "")).strip(),
                }
            )
            if len(results) >= clamped_limit:
                break

        return {
            "ok": True,
            "query": normalized_query,
            "backend": backend,
            "results": results,
            "taint_labels": ["untrusted"],
            "evidence": {
                "operation": "web_search",
                "backend_url": backend,
                "query_hash": hashlib.sha256(normalized_query.encode("utf-8")).hexdigest(),
                "response_hash": hashlib.sha256(payload_bytes).hexdigest(),
                "fetched_at": datetime.now(UTC).isoformat(),
                "status_code": status_code,
                "truncated": truncated,
                "result_count": len(results),
                "final_url": fetched.final_url,
            },
            "error": "",
        }

    def fetch(
        self,
        *,
        url: str,
        snapshot: bool = False,
        max_bytes: int | None = None,
    ) -> dict[str, Any]:
        normalized_url = url.strip()
        if not normalized_url:
            return self._error_payload(operation="web_fetch", reason="url_required", url=url)
        if not self.fetch_enabled:
            return self._error_payload(
                operation="web_fetch",
                reason="web_fetch_disabled",
                url=normalized_url,
            )
        if not self.allowed_domains:
            return self._error_payload(
                operation="web_fetch",
                reason="web_allowlist_unconfigured",
                url=normalized_url,
            )
        parsed = urlparse(normalized_url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme.lower() not in {"http", "https"}:
            return self._error_payload(
                operation="web_fetch",
                reason="unsupported_scheme",
                url=normalized_url,
            )
        if not self._host_allowed(host):
            return self._error_payload(
                operation="web_fetch",
                reason="destination_not_allowlisted",
                url=normalized_url,
            )

        fetch_limit = self.max_fetch_bytes if max_bytes is None else int(max_bytes)
        fetch_limit = max(1024, min(fetch_limit, 4 * 1024 * 1024))
        request = Request(
            normalized_url,
            headers={
                "User-Agent": "shisad/0.3 web_fetch",
                "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
            },
        )
        fetched = self._fetch_with_redirect_policy(
            operation="web_fetch",
            request=request,
            query="",
            backend="",
            source_url=normalized_url,
            read_limit=fetch_limit,
            host_disallowed_reason="destination_not_allowlisted",
            invalid_scheme_reason="unsupported_scheme",
            redirect_limit_reason="too_many_redirects",
            missing_redirect_reason="redirect_missing_location",
            request_failed_reason="web_fetch_request_failed",
        )
        if isinstance(fetched, dict):
            return fetched
        payload_bytes = fetched.body
        truncated = fetched.truncated
        status_code = fetched.status_code
        content_type = fetched.content_type

        decoded = payload_bytes.decode("utf-8", errors="replace")
        blocked_reason = self._blocked_page_reason(decoded)
        text = self._extract_text(decoded)
        title_match = _TITLE_RE.search(decoded)
        title = ""
        if title_match:
            title = _WS_RE.sub(" ", title_match.group(1)).strip()[:300]
        evidence = {
            "operation": "web_fetch",
            "url": normalized_url,
            "fetch_profile": "default_html",
            "response_hash": hashlib.sha256(payload_bytes).hexdigest(),
            "fetched_at": datetime.now(UTC).isoformat(),
            "status_code": status_code,
            "content_type": content_type,
            "truncated": truncated,
            "final_url": fetched.final_url,
        }
        if blocked_reason:
            return {
                "ok": False,
                "url": normalized_url,
                "status_code": status_code,
                "title": title,
                "content": "",
                "blocked_reason": blocked_reason,
                "truncated": truncated,
                "taint_labels": ["untrusted"],
                "evidence": evidence,
                "error": "blocked_page_detected",
                "snapshot_path": "",
            }

        snapshot_path = ""
        if snapshot:
            snapshot_dir = self.data_dir / "web_snapshots"
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
            digest = hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()[:12]
            file_name = f"{stamp}-{digest}.txt"
            target = snapshot_dir / file_name
            target.write_text(text, encoding="utf-8")
            snapshot_path = str(target)

        return {
            "ok": True,
            "url": normalized_url,
            "status_code": status_code,
            "title": title,
            "content": text,
            "blocked_reason": "",
            "truncated": truncated,
            "taint_labels": ["untrusted"],
            "evidence": evidence,
            "error": "",
            "snapshot_path": snapshot_path,
        }

    def _host_allowed(self, host: str) -> bool:
        return any(_host_matches(host, rule) for rule in self.allowed_domains)

    def _fetch_with_redirect_policy(
        self,
        *,
        operation: str,
        request: Request,
        query: str,
        backend: str,
        source_url: str,
        read_limit: int,
        host_disallowed_reason: str,
        invalid_scheme_reason: str,
        redirect_limit_reason: str,
        missing_redirect_reason: str,
        request_failed_reason: str,
    ) -> _HttpResponsePayload | dict[str, Any]:
        current_url = source_url
        redirect_count = 0
        headers = dict(request.header_items())
        while True:
            parsed = urlparse(current_url)
            scheme = parsed.scheme.lower()
            host = (parsed.hostname or "").lower()
            if scheme not in {"http", "https"}:
                return self._error_payload(
                    operation=operation,
                    reason=invalid_scheme_reason,
                    query=query,
                    url=source_url,
                    backend=backend,
                )
            if not self._host_allowed(host):
                return self._error_payload(
                    operation=operation,
                    reason=host_disallowed_reason,
                    query=query,
                    url=source_url,
                    backend=backend,
                )

            active_request = Request(current_url, headers=headers)
            try:
                with _open_no_redirect(active_request, timeout=self.timeout_seconds) as response:
                    payload_bytes, truncated = _read_limited(response, limit=read_limit)
                    status_code = int(getattr(response, "status", 200) or 200)
                    content_type = str(response.headers.get("Content-Type", ""))
                    response_geturl = getattr(response, "geturl", None)
                    final_url = (
                        str(response_geturl()) if callable(response_geturl) else current_url
                    )
                    final_parsed = urlparse(final_url)
                    final_scheme = final_parsed.scheme.lower()
                    final_host = (final_parsed.hostname or "").lower()
                    if final_scheme not in {"http", "https"}:
                        return self._error_payload(
                            operation=operation,
                            reason=invalid_scheme_reason,
                            query=query,
                            url=source_url,
                            backend=backend,
                        )
                    if not self._host_allowed(final_host):
                        return self._error_payload(
                            operation=operation,
                            reason=host_disallowed_reason,
                            query=query,
                            url=source_url,
                            backend=backend,
                        )
                    return _HttpResponsePayload(
                        body=payload_bytes,
                        status_code=status_code,
                        content_type=content_type,
                        final_url=final_url,
                        truncated=truncated,
                    )
            except HTTPError as exc:
                if exc.code not in _REDIRECT_CODES:
                    return self._error_payload(
                        operation=operation,
                        reason=f"http_error:{exc.code}",
                        query=query,
                        url=source_url,
                        backend=backend,
                    )
                location = str(exc.headers.get("Location", "")).strip()
                if not location:
                    return self._error_payload(
                        operation=operation,
                        reason=missing_redirect_reason,
                        query=query,
                        url=source_url,
                        backend=backend,
                    )
                redirect_count += 1
                if redirect_count > _MAX_REDIRECT_HOPS:
                    return self._error_payload(
                        operation=operation,
                        reason=redirect_limit_reason,
                        query=query,
                        url=source_url,
                        backend=backend,
                    )
                current_url = urljoin(current_url, location)
            except URLError as exc:
                return self._error_payload(
                    operation=operation,
                    reason=f"network_error:{exc.reason}",
                    query=query,
                    url=source_url,
                    backend=backend,
                )
            except (OSError, TypeError, ValueError):
                return self._error_payload(
                    operation=operation,
                    reason=request_failed_reason,
                    query=query,
                    url=source_url,
                    backend=backend,
                )

    @staticmethod
    def _blocked_page_reason(content: str) -> str:
        lowered = content.lower()
        for token in _BLOCKED_PAGE_HINTS:
            if token in lowered:
                return token.replace(" ", "_")
        return ""

    @staticmethod
    def _extract_text(content: str) -> str:
        stripped = _SCRIPT_STYLE_RE.sub(" ", content)
        stripped = _TAG_RE.sub(" ", stripped)
        return _WS_RE.sub(" ", stripped).strip()[:10000]

    @staticmethod
    def _error_payload(
        *,
        operation: str,
        reason: str,
        query: str = "",
        url: str = "",
        backend: str = "",
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": False,
            "query": query,
            "url": url,
            "backend": backend,
            "results": [],
            "title": "",
            "content": "",
            "status_code": None,
            "blocked_reason": "",
            "truncated": False,
            "taint_labels": ["untrusted"],
            "evidence": {
                "operation": operation,
                "fetched_at": datetime.now(UTC).isoformat(),
            },
            "error": reason,
            "snapshot_path": "",
        }
        return payload
