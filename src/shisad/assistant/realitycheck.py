"""Reality Check integration helpers with strict fail-closed controls."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPRedirectHandler, OpenerDirector, Request, build_opener

_MAX_ENDPOINT_BYTES = 2 * 1024 * 1024
_ALLOWED_TEXT_SUFFIXES = {
    ".md",
    ".markdown",
    ".txt",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
}


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


_NO_REDIRECT_OPENER: OpenerDirector = build_opener(_NoRedirectHandler())


def _host_matches(host: str, rule: str) -> bool:
    candidate = rule.strip().lower()
    if not candidate:
        return False
    normalized_host = host.strip().lower()
    if not normalized_host:
        return False
    if candidate.startswith("*."):
        return normalized_host.endswith(candidate[1:])
    return normalized_host == candidate


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


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


def _snippet(text: str, *, start: int, token_len: int, width: int = 220) -> str:
    left = max(0, start - (width // 2))
    right = min(len(text), start + token_len + (width // 2))
    segment = " ".join(text[left:right].split())
    return segment[:width]


@dataclass(slots=True)
class RealityCheckToolkit:
    """Reality Check integration facade with strict runtime boundaries."""

    enabled: bool
    repo_root: Path
    data_roots: list[Path]
    endpoint_enabled: bool
    endpoint_url: str
    allowed_domains: list[str]
    timeout_seconds: float
    max_read_bytes: int

    def doctor_status(self) -> dict[str, Any]:
        problems: list[str] = []
        resolved_repo: Path | None = None
        try:
            resolved_repo = self.repo_root.expanduser().resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            if self.enabled:
                problems.append("repo_root_invalid")

        configured_roots: list[Path] = []
        for item in self.data_roots:
            if not str(item).strip():
                continue
            try:
                configured_roots.append(item.expanduser().resolve(strict=False))
            except (OSError, RuntimeError, ValueError):
                if self.enabled:
                    problems.append("data_root_invalid")

        existing_roots: list[Path] = []
        for item in configured_roots:
            try:
                if item.exists() and item.is_dir():
                    existing_roots.append(item)
            except (OSError, ValueError):
                continue

        endpoint = self.endpoint_url.strip()
        parsed_endpoint = urlparse(endpoint) if endpoint else None
        endpoint_host = (parsed_endpoint.hostname or "").lower() if parsed_endpoint else ""
        endpoint_scheme = (parsed_endpoint.scheme or "").lower() if parsed_endpoint else ""
        endpoint_port: int | None = None
        endpoint_port_invalid = False
        if parsed_endpoint:
            try:
                endpoint_port = parsed_endpoint.port
            except ValueError:
                endpoint_port_invalid = True
        if (
            endpoint_port is None
            and endpoint_scheme in {"http", "https"}
            and not endpoint_port_invalid
        ):
            endpoint_port = 80 if endpoint_scheme == "http" else 443

        if self.enabled:
            if resolved_repo is None or not resolved_repo.exists() or not resolved_repo.is_dir():
                problems.append("repo_root_missing")
            if not existing_roots:
                problems.append("data_roots_missing")
            if self.endpoint_enabled:
                if not endpoint:
                    problems.append("endpoint_url_missing")
                if endpoint_port_invalid:
                    problems.append("endpoint_port_invalid")
                if endpoint_scheme != "https":
                    problems.append("endpoint_scheme_must_be_https")
                if endpoint_port != 443:
                    problems.append("endpoint_port_must_be_443")
                if not endpoint_host:
                    problems.append("endpoint_host_missing")
                elif not self._host_allowed(endpoint_host):
                    problems.append("endpoint_not_allowlisted")

        status = "disabled"
        if self.enabled:
            status = "ok" if not problems else "misconfigured"

        return {
            "status": status,
            "enabled": self.enabled,
            "surface_enabled": status == "ok",
            "repo_root": str(resolved_repo) if resolved_repo is not None else "",
            "repo_exists": bool(
                resolved_repo is not None and resolved_repo.exists() and resolved_repo.is_dir()
            ),
            "data_roots": [str(item) for item in configured_roots],
            "data_roots_existing": [str(item) for item in existing_roots],
            "endpoint_enabled": self.endpoint_enabled,
            "endpoint_url": endpoint,
            "endpoint_host": endpoint_host,
            "endpoint_allowlisted": (not self.endpoint_enabled)
            or (bool(endpoint_host) and self._host_allowed(endpoint_host)),
            "problems": problems,
        }

    def search(
        self,
        *,
        query: str,
        limit: int = 5,
        mode: str = "auto",
    ) -> dict[str, Any]:
        normalized_query = query.strip()
        if not normalized_query:
            return self._search_error(
                reason="query_required",
                query=normalized_query,
                mode=mode,
            )

        health = self.doctor_status()
        if health["status"] == "disabled":
            return self._search_error(
                reason="realitycheck_disabled",
                query=normalized_query,
                mode=mode,
            )
        if health["status"] != "ok":
            return self._search_error(
                reason="realitycheck_misconfigured",
                query=normalized_query,
                mode=mode,
                details=list(health.get("problems", [])),
            )

        selected_mode = mode.strip().lower() or "auto"
        if selected_mode not in {"auto", "local", "remote"}:
            return self._search_error(
                reason="invalid_mode",
                query=normalized_query,
                mode=selected_mode,
            )
        if selected_mode == "auto":
            selected_mode = "remote" if self.endpoint_enabled else "local"
        if selected_mode == "remote":
            if not self.endpoint_enabled:
                return self._search_error(
                    reason="endpoint_mode_disabled",
                    query=normalized_query,
                    mode=selected_mode,
                )
            return self._search_remote(query=normalized_query, limit=limit)
        return self._search_local(query=normalized_query, limit=limit)

    def read_source(
        self,
        *,
        path: str,
        max_bytes: int | None = None,
    ) -> dict[str, Any]:
        health = self.doctor_status()
        if health["status"] == "disabled":
            return self._read_error(
                reason="realitycheck_disabled",
                path=path,
            )
        if health["status"] != "ok":
            return self._read_error(
                reason="realitycheck_misconfigured",
                path=path,
                details=list(health.get("problems", [])),
            )

        resolved = self._resolve_data_path(path)
        if isinstance(resolved, dict):
            return resolved
        if not resolved.exists():
            return self._read_error(reason="path_not_found", path=str(resolved))
        if not resolved.is_file():
            return self._read_error(reason="not_a_file", path=str(resolved))

        byte_limit = self.max_read_bytes if max_bytes is None else int(max_bytes)
        byte_limit = max(1024, min(byte_limit, 2 * 1024 * 1024))
        try:
            with resolved.open("rb") as handle:
                payload, truncated = _read_limited(handle, limit=byte_limit)
        except OSError:
            return self._read_error(reason="read_failed", path=str(resolved))
        content = payload.decode("utf-8", errors="replace")
        return {
            "ok": True,
            "path": str(resolved),
            "content": content,
            "truncated": truncated,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "taint_labels": ["untrusted"],
            "evidence": {
                "operation": "realitycheck.read",
                "source_path": str(resolved),
                "fetched_at": datetime.now(UTC).isoformat(),
            },
            "error": "",
        }

    def _search_local(self, *, query: str, limit: int) -> dict[str, Any]:
        normalized_query = query.lower()
        max_items = max(1, min(limit, 20))
        roots = self._active_data_roots()
        searched_files = 0
        results: list[dict[str, Any]] = []
        for root in roots:
            for candidate in root.rglob("*"):
                if len(results) >= max_items:
                    break
                if not candidate.is_file():
                    continue
                if candidate.suffix.lower() not in _ALLOWED_TEXT_SUFFIXES:
                    continue
                resolved = candidate.expanduser().resolve(strict=False)
                if not _is_within(resolved, root):
                    continue
                searched_files += 1
                try:
                    with resolved.open("rb") as handle:
                        payload, truncated = _read_limited(handle, limit=self.max_read_bytes)
                except OSError:
                    continue
                text = payload.decode("utf-8", errors="replace")
                haystack = text.lower()
                position = haystack.find(normalized_query)
                if position < 0:
                    continue
                line = text.count("\n", 0, position) + 1
                snippet = _snippet(text, start=position, token_len=len(query))
                results.append(
                    {
                        "title": resolved.name,
                        "snippet": snippet,
                        "citation": {
                            "path": str(resolved),
                            "line": line,
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "truncated": truncated,
                        },
                    }
                )
            if len(results) >= max_items:
                break

        return {
            "ok": True,
            "query": query,
            "mode": "local",
            "results": results,
            "taint_labels": ["untrusted"],
            "evidence": {
                "operation": "realitycheck.search",
                "mode": "local",
                "repo_root": str(self.repo_root.expanduser().resolve(strict=False)),
                "data_roots": [str(item) for item in roots],
                "searched_files": searched_files,
                "result_count": len(results),
                "query_hash": hashlib.sha256(query.encode("utf-8")).hexdigest(),
                "fetched_at": datetime.now(UTC).isoformat(),
            },
            "error": "",
        }

    def _search_remote(self, *, query: str, limit: int) -> dict[str, Any]:
        endpoint = self.endpoint_url.strip().rstrip("/")
        request_url = (
            f"{endpoint}/search?"
            + urlencode(
                {
                    "q": query,
                    "limit": max(1, min(limit, 20)),
                }
            )
        )
        request = Request(
            request_url,
            headers={
                "User-Agent": "shisad/0.3 realitycheck",
                "Accept": "application/json",
            },
        )
        try:
            with _NO_REDIRECT_OPENER.open(request, timeout=self.timeout_seconds) as response:
                payload_bytes, truncated = _read_limited(response, limit=_MAX_ENDPOINT_BYTES)
                status_code = int(getattr(response, "status", 200) or 200)
        except HTTPError as exc:
            if int(exc.code) in {301, 302, 303, 307, 308}:
                return self._search_error(
                    reason="endpoint_redirect_disallowed",
                    query=query,
                    mode="remote",
                )
            return self._search_error(
                reason=f"http_error:{exc.code}",
                query=query,
                mode="remote",
            )
        except URLError as exc:
            return self._search_error(
                reason=f"network_error:{exc.reason}",
                query=query,
                mode="remote",
            )
        except (OSError, TypeError, ValueError):
            return self._search_error(
                reason="endpoint_request_failed",
                query=query,
                mode="remote",
            )

        try:
            payload = json.loads(payload_bytes.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return self._search_error(
                reason="endpoint_invalid_json",
                query=query,
                mode="remote",
            )

        rows = payload.get("results", []) if isinstance(payload, dict) else []
        if not isinstance(rows, list):
            rows = []
        results: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            results.append(
                {
                    "title": str(row.get("title", "")).strip(),
                    "snippet": str(row.get("snippet") or row.get("content") or "").strip(),
                    "citation": row.get("citation", {}),
                }
            )
            if len(results) >= max(1, min(limit, 20)):
                break

        return {
            "ok": True,
            "query": query,
            "mode": "remote",
            "results": results,
            "taint_labels": ["untrusted"],
            "evidence": {
                "operation": "realitycheck.search",
                "mode": "remote",
                "endpoint_url": endpoint,
                "status_code": status_code,
                "truncated": truncated,
                "response_hash": hashlib.sha256(payload_bytes).hexdigest(),
                "query_hash": hashlib.sha256(query.encode("utf-8")).hexdigest(),
                "fetched_at": datetime.now(UTC).isoformat(),
            },
            "error": "",
        }

    def _resolve_data_path(self, path: str) -> Path | dict[str, Any]:
        roots = self._active_data_roots()
        if not roots:
            return self._read_error(reason="data_roots_missing", path=path)
        raw = path.strip()
        if not raw:
            return self._read_error(reason="path_required", path=path)

        try:
            candidate = Path(raw).expanduser()
        except (TypeError, ValueError):
            return self._read_error(reason="invalid_path", path=raw)
        if candidate.is_absolute():
            try:
                resolved = candidate.resolve(strict=False)
            except (OSError, RuntimeError, ValueError):
                return self._read_error(reason="invalid_path", path=raw)
            if not any(_is_within(resolved, root) for root in roots):
                return self._read_error(reason="path_not_allowlisted", path=str(resolved))
            return resolved

        fallback: Path | None = None
        for root in roots:
            try:
                resolved = (root / candidate).resolve(strict=False)
            except (OSError, RuntimeError, ValueError):
                return self._read_error(reason="invalid_path", path=raw)
            if not _is_within(resolved, root):
                return self._read_error(reason="path_not_allowlisted", path=str(resolved))
            try:
                if resolved.exists():
                    return resolved
            except (OSError, ValueError):
                return self._read_error(reason="invalid_path", path=str(resolved))
            if fallback is None:
                fallback = resolved
        if fallback is None:
            return self._read_error(reason="path_not_allowlisted", path=raw)
        return fallback

    def _active_data_roots(self) -> list[Path]:
        roots: list[Path] = []
        for item in self.data_roots:
            if not str(item).strip():
                continue
            try:
                resolved = item.expanduser().resolve(strict=False)
            except (OSError, RuntimeError, ValueError):
                continue
            try:
                if resolved.exists():
                    roots.append(resolved)
            except (OSError, ValueError):
                continue
        return roots

    def _host_allowed(self, host: str) -> bool:
        return any(_host_matches(host, rule) for rule in self.allowed_domains)

    def _search_error(
        self,
        *,
        reason: str,
        query: str,
        mode: str,
        details: list[str] | None = None,
    ) -> dict[str, Any]:
        return {
            "ok": False,
            "query": query,
            "mode": mode,
            "results": [],
            "taint_labels": ["untrusted"],
            "evidence": {
                "operation": "realitycheck.search",
                "fetched_at": datetime.now(UTC).isoformat(),
                "details": details or [],
            },
            "error": reason,
        }

    def _read_error(
        self,
        *,
        reason: str,
        path: str,
        details: list[str] | None = None,
    ) -> dict[str, Any]:
        return {
            "ok": False,
            "path": path,
            "content": "",
            "truncated": False,
            "sha256": "",
            "taint_labels": ["untrusted"],
            "evidence": {
                "operation": "realitycheck.read",
                "fetched_at": datetime.now(UTC).isoformat(),
                "details": details or [],
            },
            "error": reason,
        }
