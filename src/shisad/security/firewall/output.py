"""Output firewall for outbound assistant content."""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import unquote, urlparse

from pydantic import BaseModel, Field

from shisad.security.firewall.normalize import normalize_text

_URL_RE = re.compile(r"https?://[^\s)>]+")
_DATA_URI_RE = re.compile(r"\bdata:[^\s)>]+", re.IGNORECASE)
_RAW_HTML_RE = re.compile(r"<[^>]+>")
_IMAGE_MD_RE = re.compile(r"!\[[^\]]*\]\(([^)]+)\)")


class UrlFinding(BaseModel):
    url: str
    host: str
    allowed: bool
    suspicious: bool
    reason: str = ""


class OutputFirewallResult(BaseModel):
    sanitized_text: str
    blocked: bool = False
    require_confirmation: bool = False
    reason_codes: list[str] = Field(default_factory=list)
    secret_findings: list[str] = Field(default_factory=list)
    url_findings: list[UrlFinding] = Field(default_factory=list)
    toxicity_score: float = 0.0


@dataclass(slots=True)
class OutputFirewall:
    """Last-choke-point filter for outbound content."""

    safe_domains: list[str]
    alert_hook: Callable[[dict[str, Any]], None] | None = None

    _SECRET_PATTERNS: ClassVar[list[tuple[str, re.Pattern[str]]]] = [
        ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
        ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("oauth_token", re.compile(r"\bya29\.[A-Za-z0-9._-]{20,}\b")),
    ]
    _MALICIOUS_HOST_HINTS: ClassVar[set[str]] = {
        "evil.com",
        "attacker.com",
        "malware.test",
        "phish.test",
        "stealer.invalid",
        "c2.invalid",
    }
    _SUSPICIOUS_TLDS: ClassVar[tuple[str, ...]] = (".onion", ".zip", ".mov", ".click", ".top")
    _SUSPICIOUS_HOST_TOKENS: ClassVar[tuple[str, ...]] = (
        "pastebin",
        "anon",
        "filedrop",
        "exfil",
        "steal",
        "credential",
        "malware",
    )
    _HIGH_ENTROPY_TOKEN_RE: ClassVar[re.Pattern[str]] = re.compile(r"\b[A-Za-z0-9+/=_-]{24,}\b")
    _QUERY_BLOB_RE: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9+/=_%-]{20,}")
    _TOXIC_PHRASES: ClassVar[dict[str, float]] = {
        "kill yourself": 0.95,
        "end your life": 0.95,
        "go die": 0.9,
        "i will kill you": 1.0,
        "you should die": 0.95,
    }
    _TOXIC_TERMS: ClassVar[dict[str, float]] = {
        "worthless": 0.3,
        "idiot": 0.25,
        "moron": 0.25,
        "stupid": 0.2,
        "hate you": 0.25,
    }

    def inspect(self, text: str, *, context: dict[str, Any] | None = None) -> OutputFirewallResult:
        normalized = normalize_text(text)
        reason_codes: list[str] = []
        findings: list[str] = []
        sanitized = normalized

        for kind, pattern in self._SECRET_PATTERNS:
            if pattern.search(sanitized):
                findings.append(kind)
                sanitized = pattern.sub(f"[REDACTED:{kind}]", sanitized)
        if findings:
            reason_codes.append("secret_redaction")

        sanitized, entropy_findings = self._redact_high_entropy_tokens(sanitized)
        if entropy_findings:
            findings.extend(entropy_findings)
            reason_codes.append("entropy_secret_redaction")

        # Inspect URLs on pre-redaction text so encoded-query risk scoring remains intact.
        url_findings = self._inspect_urls(normalized)
        blocked = any(finding.suspicious for finding in url_findings)
        require_confirmation = any(
            (not finding.allowed) and (not finding.suspicious) for finding in url_findings
        )
        if blocked:
            reason_codes.append("malicious_url")
        elif require_confirmation:
            reason_codes.append("unallowlisted_url")

        image_urls = _IMAGE_MD_RE.findall(sanitized)
        if image_urls:
            sanitized = _IMAGE_MD_RE.sub("[IMAGE_REMOVED]", sanitized)
            reason_codes.append("markdown_external_image")

        if _RAW_HTML_RE.search(sanitized):
            sanitized = _RAW_HTML_RE.sub("", sanitized)
            reason_codes.append("raw_html_removed")

        toxicity_score = self._toxicity_score(sanitized)
        if toxicity_score >= 0.8:
            require_confirmation = True
            reason_codes.append("outbound_policy_toxicity")

        result = OutputFirewallResult(
            sanitized_text=sanitized,
            blocked=blocked,
            require_confirmation=require_confirmation,
            reason_codes=sorted(set(reason_codes)),
            secret_findings=sorted(set(findings)),
            url_findings=url_findings,
            toxicity_score=toxicity_score,
        )
        if self.alert_hook is not None and (result.secret_findings or result.reason_codes):
            self.alert_hook(
                {
                    "blocked": result.blocked,
                    "require_confirmation": result.require_confirmation,
                    "reason_codes": list(result.reason_codes),
                    "secret_findings": list(result.secret_findings),
                    "url_findings": [item.model_dump(mode="json") for item in result.url_findings],
                    "context": context or {},
                }
            )
        return result

    def _inspect_urls(self, text: str) -> list[UrlFinding]:
        findings: list[UrlFinding] = []
        for matched in _URL_RE.findall(text):
            parsed = urlparse(matched)
            host = (parsed.hostname or "").lower()
            allowed = any(self._host_matches(host, domain) for domain in self.safe_domains)
            suspicious_reason = self._suspicious_reason(parsed, host=host, allowed=allowed)
            suspicious = bool(suspicious_reason)
            reason = suspicious_reason or ("not_allowlisted" if not allowed else "")
            findings.append(
                UrlFinding(
                    url=matched,
                    host=host,
                    allowed=allowed,
                    suspicious=suspicious,
                    reason=reason,
                )
            )
        for matched in _DATA_URI_RE.findall(text):
            findings.append(
                UrlFinding(
                    url=matched,
                    host="data",
                    allowed=False,
                    suspicious=True,
                    reason="data_uri",
                )
            )
        return findings

    @staticmethod
    def _host_matches(host: str, domain: str) -> bool:
        value = domain.lower().strip()
        if not value:
            return False
        if value.startswith("*."):
            return host.endswith(value[1:])
        return host == value

    @staticmethod
    def _toxicity_score(text: str) -> float:
        lowered = OutputFirewall._normalize_for_toxicity(text)
        score = 0.0
        for phrase, weight in OutputFirewall._TOXIC_PHRASES.items():
            if phrase in lowered:
                score += weight
        for token, weight in OutputFirewall._TOXIC_TERMS.items():
            if token in lowered:
                score += weight
        return min(score, 1.0)

    @staticmethod
    def _normalize_for_toxicity(text: str) -> str:
        translit = str.maketrans(
            {
                "0": "o",
                "1": "i",
                "3": "e",
                "4": "a",
                "5": "s",
                "7": "t",
                "@": "a",
                "$": "s",
                "!": "i",
            }
        )
        lowered = text.lower().translate(translit)
        return re.sub(r"[^a-z\s]+", " ", lowered)

    @classmethod
    def _suspicious_reason(cls, parsed: Any, *, host: str, allowed: bool) -> str:
        if not host:
            return "malformed_url"
        if host in cls._MALICIOUS_HOST_HINTS:
            return "known_malicious_host"
        if parsed.username or parsed.password:
            return "embedded_url_credentials"
        if host.startswith("xn--"):
            return "punycode_host"
        if any(host.endswith(tld) for tld in cls._SUSPICIOUS_TLDS):
            return "suspicious_tld"
        if any(token in host for token in cls._SUSPICIOUS_HOST_TOKENS):
            return "suspicious_host_pattern"
        if cls._is_ip_literal(host) and not allowed:
            return "direct_ip_destination"
        if cls._looks_encoded_query(parsed.query):
            return "suspicious_encoded_query"
        return ""

    @staticmethod
    def _is_ip_literal(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return False
        return True

    @classmethod
    def _looks_encoded_query(cls, query: str) -> bool:
        if not query:
            return False
        for candidate in {query, unquote(query)}:
            for token in cls._QUERY_BLOB_RE.findall(candidate):
                entropy = cls._shannon_entropy(token)
                if entropy >= 4.0:
                    return True
        return False

    @classmethod
    def _redact_high_entropy_tokens(cls, text: str) -> tuple[str, list[str]]:
        redacted = text
        findings: list[str] = []
        for token in sorted(set(cls._HIGH_ENTROPY_TOKEN_RE.findall(text)), key=len, reverse=True):
            if token.startswith("http"):
                continue
            if "." in token and "/" in token:
                continue
            entropy = cls._shannon_entropy(token)
            if entropy < 4.0:
                continue
            findings.append("high_entropy_secret")
            redacted = redacted.replace(token, "[REDACTED:high_entropy_secret]")
        return redacted, findings

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts: dict[str, int] = {}
        for char in value:
            counts[char] = counts.get(char, 0) + 1
        length = len(value)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy
