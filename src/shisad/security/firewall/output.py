"""Output firewall for outbound assistant content."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from shisad.security.firewall.normalize import normalize_text

_URL_RE = re.compile(r"https?://[^\s)>\]]+")
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

    _SECRET_PATTERNS: ClassVar[list[tuple[str, re.Pattern[str]]]] = [
        ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
        ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("oauth_token", re.compile(r"\bya29\.[A-Za-z0-9._-]{20,}\b")),
    ]
    _MALICIOUS_HOST_HINTS: ClassVar[set[str]] = {"evil.com", "attacker.com", "malware.test"}

    def inspect(self, text: str) -> OutputFirewallResult:
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

        url_findings = self._inspect_urls(sanitized)
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

        return OutputFirewallResult(
            sanitized_text=sanitized,
            blocked=blocked,
            require_confirmation=require_confirmation,
            reason_codes=sorted(set(reason_codes)),
            secret_findings=sorted(set(findings)),
            url_findings=url_findings,
            toxicity_score=toxicity_score,
        )

    def _inspect_urls(self, text: str) -> list[UrlFinding]:
        findings: list[UrlFinding] = []
        for matched in _URL_RE.findall(text):
            parsed = urlparse(matched)
            host = (parsed.hostname or "").lower()
            allowed = any(self._host_matches(host, domain) for domain in self.safe_domains)
            suspicious = host in self._MALICIOUS_HOST_HINTS
            reason = ""
            if suspicious:
                reason = "known_malicious_host"
            elif not allowed:
                reason = "not_allowlisted"
            findings.append(
                UrlFinding(
                    url=matched,
                    host=host,
                    allowed=allowed,
                    suspicious=suspicious,
                    reason=reason,
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
        lowered = text.lower()
        toxic_tokens = ("kill yourself", "hate you", "worthless")
        score = 0.0
        for token in toxic_tokens:
            if token in lowered:
                score += 0.45
        return min(score, 1.0)
