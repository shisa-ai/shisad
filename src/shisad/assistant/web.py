"""Web search/fetch helpers with bounded resource and redirect controls."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import OpenerDirector, Request, build_opener

from shisad.assistant.boundary_helpers import _host_matches, _NoRedirectHandler, _read_limited

_MAX_SEARCH_BYTES = 2 * 1024 * 1024
_MAX_REDIRECT_HOPS = 5
_FETCH_TEXT_MAX_CHARS = 10000
_FETCH_ACTIONABLE_SNIPPET_CONTEXT_CHARS = 220
_FETCH_ACTIONABLE_SNIPPET_MAX_CHARS = 560
_FETCH_ACTIONABLE_SNIPPET_LIMIT = 5
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_BLOCK_TAG_RE = re.compile(
    r"</?(?:address|article|aside|blockquote|body|br|dd|div|dl|dt|figcaption|"
    r"figure|footer|form|h[1-6]|head|header|hr|html|li|main|nav|ol|p|pre|"
    r"section|table|tbody|td|tfoot|th|thead|title|tr|ul)(?:\s[^>]*)?\s*/?>",
    re.IGNORECASE,
)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_RESERVATION_EVIDENCE_MARKERS: tuple[str, ...] = (
    "\u672c\u65e5\u591c\u7a7a\u5e2d\u3042\u308a",
    "\u30cd\u30c3\u30c8\u4e88\u7d04",
    "\u7a7a\u5e2d\u3042\u308a",
    "\u4e88\u7d04\u53ef",
    "online reservation",
    "reserve online",
)
_FETCH_ACTIONABLE_MARKER_PRIORITY: dict[str, int] = {
    "\u672c\u65e5\u591c\u7a7a\u5e2d\u3042\u308a": 0,
    "\u7a7a\u5e2d\u3042\u308a": 0,
    "\u4e88\u7d04\u53ef": 0,
}
_JAPANESE_AVAILABILITY_MARKERS: frozenset[str] = frozenset(
    (
        "\u672c\u65e5\u591c\u7a7a\u5e2d\u3042\u308a",
        "\u7a7a\u5e2d\u3042\u308a",
    )
)
_JAPANESE_AVAILABILITY_NEGATION_SUFFIXES: tuple[str, ...] = (
    "\u307e\u305b\u3093",
    "\u306a\u3057",
    "\u7121\u3057",
    "\u306a\u3044",
)
_JAPANESE_AVAILABILITY_NEGATION_SEPARATORS = (
    " \t\r\n"
    "\u3000\u3001\u3002\u30fb"
    ",.:;!?()[]{}-"
    "\uff1a\uff1b\uff01\uff1f"
)
_JAPANESE_MARKER_INTERNAL_SEPARATORS = " \t\r\n\u3000"
_BLOCKED_PAGE_HINTS: tuple[str, ...] = (
    "access denied",
    "temporarily blocked",
    "security check",
    "verify you are human",
    "captcha",
    "cloudflare",
    "forbidden",
)


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
        backend_host = (urlparse(backend).hostname or "").lower()
        backend_block_reason = self._host_block_reason(backend_host)
        if backend_block_reason:
            return self._error_payload(
                operation="web_search",
                reason=backend_block_reason,
                query=normalized_query,
            )

        request_url = f"{backend}/search?" + urlencode(
            {
                "q": normalized_query,
                "format": "json",
                "language": "en",
                "safesearch": 1,
            }
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
        parsed = urlparse(normalized_url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme.lower() not in {"http", "https"}:
            return self._error_payload(
                operation="web_fetch",
                reason="unsupported_scheme",
                url=normalized_url,
            )
        destination_block_reason = self._host_block_reason(host)
        if destination_block_reason:
            return self._error_payload(
                operation="web_fetch",
                reason=destination_block_reason,
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
        full_text = self._extract_text(decoded, max_chars=None)
        text = full_text[:_FETCH_TEXT_MAX_CHARS]
        actionable_evidence_snippets = self._extract_actionable_evidence_snippets(full_text)
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
        if actionable_evidence_snippets:
            evidence["actionable_marker_count"] = len(actionable_evidence_snippets)
            evidence["actionable_marker_profile"] = "reservation_evidence_v1"
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
            **(
                {"actionable_evidence_snippets": actionable_evidence_snippets}
                if actionable_evidence_snippets
                else {}
            ),
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

    def _host_block_reason(self, host: str) -> str:
        normalized = host.strip().lower().rstrip(".")
        if not normalized:
            return "missing_host"
        if self._is_ip_literal(normalized) and not self._host_allowed(normalized):
            return "ip_literal_not_allowlisted"
        if self._looks_like_local_destination(normalized) and not self._host_allowed(normalized):
            return "local_destination_not_allowlisted"
        return ""

    @staticmethod
    def _is_ip_literal(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return False
        return True

    @staticmethod
    def _looks_like_local_destination(host: str) -> bool:
        lowered = host.strip().lower()
        if not lowered:
            return False
        if lowered in {"localhost"}:
            return True
        return (
            lowered.endswith(".local") or lowered.endswith(".internal") or lowered.endswith(".lan")
        )

    def _redirect_allowed(self, *, initial_host: str, target_host: str) -> bool:
        source = initial_host.strip().lower().rstrip(".")
        target = target_host.strip().lower().rstrip(".")
        if not source or not target:
            return False
        if target == source:
            return True
        if target.endswith(f".{source}") or source.endswith(f".{target}"):
            return True
        return self._host_allowed(target)

    def _fetch_with_redirect_policy(
        self,
        *,
        operation: str,
        request: Request,
        query: str,
        backend: str,
        source_url: str,
        read_limit: int,
        invalid_scheme_reason: str,
        redirect_limit_reason: str,
        missing_redirect_reason: str,
        request_failed_reason: str,
    ) -> _HttpResponsePayload | dict[str, Any]:
        current_url = source_url
        redirect_count = 0
        initial_host = (urlparse(source_url).hostname or "").lower()
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
            host_block_reason = self._host_block_reason(host)
            if host_block_reason:
                return self._error_payload(
                    operation=operation,
                    reason=host_block_reason,
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
                    final_url = str(response_geturl()) if callable(response_geturl) else current_url
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
                    final_block_reason = self._host_block_reason(final_host)
                    if final_block_reason:
                        return self._error_payload(
                            operation=operation,
                            reason=final_block_reason,
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
                next_url = urljoin(current_url, location)
                next_host = (urlparse(next_url).hostname or "").lower()
                if not self._redirect_allowed(initial_host=initial_host, target_host=next_host):
                    return self._error_payload(
                        operation=operation,
                        reason="redirect_host_not_preapproved",
                        query=query,
                        url=source_url,
                        backend=backend,
                        redirect_url=next_url,
                        redirect_host=next_host,
                    )
                current_url = next_url
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
    def _extract_text(content: str, *, max_chars: int | None = _FETCH_TEXT_MAX_CHARS) -> str:
        stripped = _SCRIPT_STYLE_RE.sub(" ", content)
        stripped = _BLOCK_TAG_RE.sub(" ", stripped)
        stripped = _TAG_RE.sub("", stripped)
        text = _WS_RE.sub(" ", stripped).strip()
        if max_chars is None:
            return text
        return text[:max_chars]

    @staticmethod
    def _extract_actionable_evidence_snippets(text: str) -> list[dict[str, Any]]:
        compacted = _WS_RE.sub(" ", text).strip()
        if not compacted:
            return []

        matches: list[tuple[int, int, int, str]] = []
        for marker in _RESERVATION_EVIDENCE_MARKERS:
            for index, marker_end in WebToolkit._iter_marker_spans(compacted, marker):
                if not WebToolkit._is_negated_japanese_availability_marker(
                    compacted,
                    marker_end=marker_end,
                    marker=marker,
                ):
                    priority = _FETCH_ACTIONABLE_MARKER_PRIORITY.get(marker, 1)
                    matches.append((priority, index, marker_end, marker))

        snippets: list[dict[str, Any]] = []
        seen_ranges: list[tuple[int, int]] = []
        for _priority, index, marker_end, marker in sorted(matches):
            begin = max(0, index - _FETCH_ACTIONABLE_SNIPPET_CONTEXT_CHARS)
            end = min(
                len(compacted),
                marker_end + _FETCH_ACTIONABLE_SNIPPET_CONTEXT_CHARS,
            )
            if any(begin <= seen_end and end >= seen_begin for seen_begin, seen_end in seen_ranges):
                continue
            snippet = compacted[begin:end].strip()
            if begin > 0:
                snippet = f"...{snippet}"
            if end < len(compacted):
                snippet = f"{snippet}..."
            if len(snippet) > _FETCH_ACTIONABLE_SNIPPET_MAX_CHARS:
                snippet = snippet[: _FETCH_ACTIONABLE_SNIPPET_MAX_CHARS - 3].rstrip() + "..."
            snippets.append(
                {
                    "kind": "reservation_evidence_marker",
                    "matched_marker": marker,
                    "snippet": snippet,
                    "taint_labels": ["untrusted"],
                }
            )
            seen_ranges.append((begin, end))
            if len(snippets) >= _FETCH_ACTIONABLE_SNIPPET_LIMIT:
                break
        return snippets

    @staticmethod
    def _iter_marker_spans(text: str, marker: str) -> Iterator[tuple[int, int]]:
        if marker.isascii():
            parts = [re.escape(part) for part in marker.split()]
            pattern = r"(?<![A-Za-z0-9])" + r"\s+".join(parts) + r"(?![A-Za-z0-9])"
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                yield match.start(), match.end()
            return

        search_text, index_map = WebToolkit._collapse_japanese_marker_search_text(text)
        start = 0
        while True:
            index = search_text.find(marker, start)
            if index < 0:
                return
            marker_end_index = index + len(marker) - 1
            yield index_map[index], index_map[marker_end_index] + 1
            start = index + max(1, len(marker))

    @staticmethod
    def _collapse_japanese_marker_search_text(text: str) -> tuple[str, list[int]]:
        search_chars: list[str] = []
        index_map: list[int] = []
        for index, char in enumerate(text):
            if char in _JAPANESE_MARKER_INTERNAL_SEPARATORS:
                continue
            search_chars.append(char)
            index_map.append(index)
        return "".join(search_chars), index_map

    @staticmethod
    def _is_negated_japanese_availability_marker(
        text: str,
        *,
        marker_end: int,
        marker: str,
    ) -> bool:
        if marker not in _JAPANESE_AVAILABILITY_MARKERS:
            return False
        suffix = text[marker_end : marker_end + 8]
        suffix = suffix.lstrip(_JAPANESE_AVAILABILITY_NEGATION_SEPARATORS)
        suffix = "".join(
            char
            for char in suffix
            if char not in _JAPANESE_AVAILABILITY_NEGATION_SEPARATORS
        )
        return any(
            suffix.startswith(negator)
            for negator in _JAPANESE_AVAILABILITY_NEGATION_SUFFIXES
        )

    @staticmethod
    def _error_payload(
        *,
        operation: str,
        reason: str,
        query: str = "",
        url: str = "",
        backend: str = "",
        redirect_url: str = "",
        redirect_host: str = "",
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
        if redirect_url:
            payload["redirect_url"] = redirect_url
        if redirect_host:
            payload["redirect_host"] = redirect_host
        return payload
