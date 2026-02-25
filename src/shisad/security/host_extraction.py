"""Host extraction helpers for user-goal provenance checks.

These helpers support the DESIGN-PHILOSOPHY.md "Who asked for it?" principle by
extracting destination hosts mentioned in trusted USER GOAL text and in untrusted
context blobs. Callers can then decide whether a proposed network destination is:
- explicitly requested by the user (auto-approve), or
- suggested by untrusted content (confirmation), or
- unattributed/hallucinated (reject).
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

_URL_FIND_RE: re.Pattern[str] = re.compile(r"https?://[^\s<>()\"']+", re.IGNORECASE)
_DOMAIN_TOKEN_FIND_RE: re.Pattern[str] = re.compile(
    r"\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d{1,5})?\b",
    re.IGNORECASE,
)
_DOMAIN_TOKEN_FULL_RE: re.Pattern[str] = re.compile(
    r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d{1,5})?$",
    re.IGNORECASE,
)

_LOCAL_FILE_EXTENSIONS: set[str] = {
    ".txt",
    ".md",
    ".rst",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".conf",
    ".cfg",
    ".csv",
    ".tsv",
    ".log",
    ".xml",
    ".py",
    ".ts",
    ".js",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".sql",
}

_STRIP_PUNCTUATION = " \t\r\n\"'`.,;:!?)]}>"


def extract_hosts_from_text(
    text: str,
    *,
    max_hosts: int = 64,
    max_chars: int = 50_000,
) -> set[str]:
    """Extract plausible hostnames from free-form text.

    The extraction is intentionally conservative: tokens that look like local paths
    (including common file extensions) are ignored to avoid accidentally treating
    filenames like `README.md` as network destinations.
    """
    snippet = text[: max(0, int(max_chars))]
    hosts: list[str] = []

    def _add(host: str) -> None:
        normalized = host.strip().lower().rstrip(".")
        if not normalized:
            return
        if normalized not in hosts:
            hosts.append(normalized)

    for match in _URL_FIND_RE.finditer(snippet):
        token = match.group(0).strip(_STRIP_PUNCTUATION)
        host = _host_from_token(token)
        if host:
            _add(host)
        if len(hosts) >= max_hosts:
            return set(hosts)

    for match in _DOMAIN_TOKEN_FIND_RE.finditer(snippet):
        token = match.group(0).strip(_STRIP_PUNCTUATION)
        if "@" in token:
            continue
        if _looks_like_local_path_token(token):
            continue
        host = _host_from_token(token)
        if host:
            _add(host)
        if len(hosts) >= max_hosts:
            break

    return set(hosts)


def host_patterns(hosts: set[str]) -> set[str]:
    """Return host + subdomain patterns suitable for matching."""
    patterns: set[str] = set()
    for host in hosts:
        normalized = host.strip().lower().rstrip(".")
        if not normalized:
            continue
        patterns.add(normalized)
        if "." in normalized:
            patterns.add(f"*.{normalized}")
    return patterns


def _host_from_token(token: str) -> str:
    value = token.strip().strip(_STRIP_PUNCTUATION)
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.hostname:
        return parsed.hostname.lower().rstrip(".")
    if _DOMAIN_TOKEN_FULL_RE.match(value):
        host = value.split(":", 1)[0]
        return host.lower().rstrip(".")
    return ""


def _looks_like_local_path_token(token: str) -> bool:
    stripped = token.strip()
    if not stripped:
        return False
    if stripped.startswith(("/", "./", "../", "~/", ".\\", "..\\")):
        return True
    if "\\" in stripped or "/" in stripped:
        return True
    candidate = stripped
    if ":" in candidate:
        head, tail = candidate.rsplit(":", 1)
        if tail.isdigit():
            candidate = head
    suffix = Path(candidate).suffix.lower()
    return suffix in _LOCAL_FILE_EXTENSIONS

