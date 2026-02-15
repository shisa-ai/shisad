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
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

_MAX_SEARCH_BYTES = 2 * 1024 * 1024
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)[^>]*>.*?</\\1>", re.IGNORECASE | re.DOTALL)
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
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload_bytes, truncated = _read_limited(response, limit=_MAX_SEARCH_BYTES)
                status_code = int(getattr(response, "status", 200) or 200)
        except HTTPError as exc:
            return self._error_payload(
                operation="web_search",
                reason=f"http_error:{exc.code}",
                query=normalized_query,
                backend=backend,
            )
        except URLError as exc:
            return self._error_payload(
                operation="web_search",
                reason=f"network_error:{exc.reason}",
                query=normalized_query,
                backend=backend,
            )
        except (OSError, TypeError, ValueError):
            return self._error_payload(
                operation="web_search",
                reason="search_backend_request_failed",
                query=normalized_query,
                backend=backend,
            )

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
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload_bytes, truncated = _read_limited(response, limit=fetch_limit)
                status_code = int(getattr(response, "status", 200) or 200)
                content_type = str(response.headers.get("Content-Type", ""))
        except HTTPError as exc:
            return self._error_payload(
                operation="web_fetch",
                reason=f"http_error:{exc.code}",
                url=normalized_url,
            )
        except URLError as exc:
            return self._error_payload(
                operation="web_fetch",
                reason=f"network_error:{exc.reason}",
                url=normalized_url,
            )
        except (OSError, TypeError, ValueError):
            return self._error_payload(
                operation="web_fetch",
                reason="web_fetch_request_failed",
                url=normalized_url,
            )

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
