"""Output firewall for outbound assistant content."""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any, ClassVar
from urllib.parse import unquote, urlunparse

from pydantic import BaseModel, Field

from shisad.core.host_matching import host_matches
from shisad.core.url_parsing import safe_parsed_hostname, safe_urlparse
from shisad.security.firewall.normalize import normalize_text
from shisad.security.firewall.pii import PIIDetector

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
    pii_findings: list[str] = Field(default_factory=list)
    url_findings: list[UrlFinding] = Field(default_factory=list)
    toxicity_score: float = 0.0


@dataclass(slots=True)
class OutputFirewall:
    """Last-choke-point filter for outbound content."""

    safe_domains: list[str]
    alert_hook: Callable[[dict[str, Any]], None] | None = None
    pii_detector: PIIDetector = field(default_factory=PIIDetector)

    _SECRET_PATTERNS: ClassVar[list[tuple[str, re.Pattern[str]]]] = [
        ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
        ("openai_key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_-]{16,}\b")),
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
    _PATHISH_TOKEN_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![A-Za-z0-9])(?:/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+|"
        r"(?:[A-Za-z0-9_-]+/)+[A-Za-z0-9_-]+)(?:\.[A-Za-z0-9]{1,8})?"
    )
    _PATH_CONTEXT_CHARS: ClassVar[set[str]] = {
        " ",
        "\t",
        "\n",
        "\r",
        "'",
        '"',
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
        ",",
        ";",
        ":",
    }
    _SOURCE_PATH_SUFFIXES: ClassVar[set[str]] = {
        ".bash",
        ".c",
        ".cfg",
        ".cjs",
        ".conf",
        ".cpp",
        ".cs",
        ".css",
        ".fish",
        ".go",
        ".h",
        ".hpp",
        ".html",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".jsx",
        ".kt",
        ".lock",
        ".md",
        ".mjs",
        ".php",
        ".py",
        ".pyi",
        ".rb",
        ".rs",
        ".rst",
        ".scss",
        ".sh",
        ".sql",
        ".swift",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".yaml",
        ".yml",
        ".zsh",
    }
    _SOURCE_FILE_STEM_ENTROPY_MAX: ClassVar[float] = 4.1
    _SOURCE_FILE_STEM_PART_ENTROPY_MAX: ClassVar[float] = 3.6
    _SOURCE_FILE_STEM_MULTI_DIGIT_PREFIXES: ClassVar[set[str]] = {
        "sha",
        "tls",
        "utf",
        "v",
        "x",
    }
    _READABLE_TECHNICAL_PATH_SEGMENTS: ClassVar[set[str]] = {
        "v4l2ctl",
    }
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

        sanitized, short_path_findings = self._redact_short_secret_path_tokens(sanitized)
        if short_path_findings:
            findings.extend(short_path_findings)
            reason_codes.append("entropy_secret_redaction")

        sanitized, entropy_findings = self._redact_high_entropy_tokens(sanitized)
        if entropy_findings:
            findings.extend(entropy_findings)
            reason_codes.append("entropy_secret_redaction")

        pii_redacted, pii_findings = self.pii_detector.redact(sanitized)
        sanitized = pii_redacted
        pii_kinds = sorted({finding.kind for finding in pii_findings})
        if pii_kinds:
            reason_codes.append("pii_redaction")

        # Inspect URLs on pre-redaction text so encoded-query risk scoring remains intact.
        url_findings = self._inspect_urls(normalized)
        blocked = any(finding.suspicious for finding in url_findings)
        require_confirmation = any(
            (not finding.allowed) and (not finding.suspicious) for finding in url_findings
        )
        if blocked:
            reason_codes.append("malicious_url")
            if any(finding.reason == "malformed_url" for finding in url_findings):
                reason_codes.append("malformed_url")
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
            pii_findings=pii_kinds,
            url_findings=url_findings,
            toxicity_score=toxicity_score,
        )
        if self.alert_hook is not None and (
            result.secret_findings or result.reason_codes or result.pii_findings
        ):
            self.alert_hook(
                {
                    "blocked": result.blocked,
                    "require_confirmation": result.require_confirmation,
                    "reason_codes": list(result.reason_codes),
                    "secret_findings": list(result.secret_findings),
                    "pii_findings": list(result.pii_findings),
                    "url_findings": [item.model_dump(mode="json") for item in result.url_findings],
                    "context": context or {},
                }
            )
        return result

    def _inspect_urls(self, text: str) -> list[UrlFinding]:
        findings: list[UrlFinding] = []
        for matched in _URL_RE.findall(text):
            parsed = safe_urlparse(matched)
            if parsed is None:
                findings.append(
                    UrlFinding(
                        url=matched,
                        host="",
                        allowed=False,
                        suspicious=True,
                        reason="malformed_url",
                    )
                )
                continue
            host = safe_parsed_hostname(parsed)
            allowed = any(host_matches(host, domain) for domain in self.safe_domains)
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
        replacements: list[tuple[int, int, str]] = []
        for match in cls._HIGH_ENTROPY_TOKEN_RE.finditer(text):
            token = match.group(0)
            if token.startswith("http"):
                continue
            if "." in token and "/" in token:
                continue
            path_token = token
            path_start = match.start()
            if path_start > 0 and text[path_start - 1] == "/" and not token.startswith("/"):
                path_token = f"/{token}"
                path_start -= 1
            if cls._looks_like_filesystem_path_token(
                text,
                token=path_token,
                start=path_start,
                end=match.end(),
            ):
                continue
            entropy = cls._shannon_entropy(token)
            if entropy < 4.0:
                continue
            findings.append("high_entropy_secret")
            replacements.append((match.start(), match.end(), "[REDACTED:high_entropy_secret]"))
        if replacements:
            redacted = cls._replace_spans(text, replacements)
        return redacted, findings

    @classmethod
    def _redact_short_secret_path_tokens(cls, text: str) -> tuple[str, list[str]]:
        redacted = text
        url_spans: list[tuple[int, int]] = []
        replacements: list[tuple[int, int, str]] = []
        for match in _URL_RE.finditer(text):
            token = match.group(0)
            url_spans.append((match.start(), match.end()))
            replacement = cls._short_secret_url_replacement(token)
            if replacement is None:
                continue
            replacements.append((match.start(), match.end(), replacement))
        for match in cls._PATHISH_TOKEN_RE.finditer(text):
            token = match.group(0)
            if any(start <= match.start() < end for start, end in url_spans):
                continue
            if token.startswith("http"):
                continue
            replacement = cls._short_secret_path_replacement(token)
            if replacement is None:
                continue
            replacements.append((match.start(), match.end(), replacement))
        if replacements:
            redacted = cls._replace_spans(text, replacements)
        return redacted, ["high_entropy_secret"] if replacements else []

    @staticmethod
    def _replace_spans(text: str, replacements: list[tuple[int, int, str]]) -> str:
        parts: list[str] = []
        last_end = 0
        for start, end, replacement in sorted(replacements, key=lambda item: item[0]):
            parts.append(text[last_end:start])
            parts.append(replacement)
            last_end = end
        parts.append(text[last_end:])
        return "".join(parts)

    @classmethod
    def _short_secret_url_replacement(cls, token: str) -> str | None:
        parsed = safe_urlparse(token)
        if parsed is None or not parsed.path:
            return None
        replacement_path = cls._short_secret_path_replacement(parsed.path)
        if replacement_path is None or replacement_path == parsed.path:
            return None
        return urlunparse(parsed._replace(path=replacement_path))

    @classmethod
    def _short_secret_path_replacement(cls, token: str) -> str | None:
        raw_segments = [segment for segment in token.strip("/").split("/") if segment]
        if not raw_segments:
            return None
        final_index = len(raw_segments) - 1
        short_secret_indexes: list[int] = []
        final_suffix = ""
        for index, raw_segment in enumerate(raw_segments):
            segment = raw_segment
            suffix = ""
            if index == final_index:
                suffix_match = re.search(r"(\.[A-Za-z0-9]{1,8})$", raw_segment)
                if suffix_match is not None:
                    suffix = suffix_match.group(1)
                    segment = raw_segment[: -len(suffix)]
                    final_suffix = suffix
            if cls._looks_like_readable_technical_path_segment(segment):
                continue
            if cls._looks_like_short_secret_path_segment(segment):
                short_secret_indexes.append(index)
        if short_secret_indexes:
            prefix = "/" if token.startswith("/") else ""
            redacted_segments = [
                f"[REDACTED:high_entropy_secret]{final_suffix if index == final_index else ''}"
                if index in short_secret_indexes
                else segment
                for index, segment in enumerate(raw_segments)
            ]
            return prefix + "/".join(redacted_segments)
        return None

    @classmethod
    def _looks_like_filesystem_path_token(
        cls,
        text: str,
        *,
        token: str,
        start: int,
        end: int,
    ) -> bool:
        if "/" not in token:
            return False
        if "+" in token or "=" in token:
            return False
        previous = text[start - 1] if start > 0 else ""
        following = text[end] if end < len(text) else ""
        if previous and previous not in cls._PATH_CONTEXT_CHARS and previous not in {"/", "\\"}:
            return False
        if (
            following
            and following not in cls._PATH_CONTEXT_CHARS
            and following not in {".", "/", "\\"}
        ):
            return False
        segments = [segment for segment in token.strip("/").split("/") if segment]
        if len(segments) < 2 and not token.startswith("/"):
            return False
        if any(len(segment) > 64 for segment in segments):
            return False
        source_suffix = cls._source_path_suffix_after(text, end=end)
        final_index = len(segments) - 1
        has_human_readable_segment = False
        for index, segment in enumerate(segments):
            if not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
                return False
            if cls._looks_like_short_secret_path_segment(
                segment
            ) and not cls._looks_like_readable_technical_path_segment(segment):
                return False
            segment_entropy = cls._shannon_entropy(segment)
            is_readable_source_stem = (
                bool(source_suffix)
                and index == final_index
                and cls._looks_like_source_file_stem(segment)
            )
            if len(segment) >= 10 and segment_entropy >= 3.6 and not is_readable_source_stem:
                return False
            if is_readable_source_stem or (
                re.fullmatch(r"[A-Za-z_-]+", segment) and segment_entropy < 3.4
            ):
                has_human_readable_segment = True
        return has_human_readable_segment

    @classmethod
    def _source_path_suffix_after(cls, text: str, *, end: int) -> str:
        suffix_match = re.match(r"\.[A-Za-z0-9]{1,8}\b", text[end:])
        if suffix_match is None:
            return ""
        suffix = suffix_match.group(0).lower()
        return suffix if suffix in cls._SOURCE_PATH_SUFFIXES else ""

    @classmethod
    def _looks_like_source_file_stem(cls, segment: str) -> bool:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", segment):
            return False
        if "_" in segment or "-" in segment:
            if cls._shannon_entropy(segment) >= cls._SOURCE_FILE_STEM_ENTROPY_MAX:
                return False
            parts = [part for part in re.split(r"[_-]+", segment) if part]
            return len(parts) >= 2 and all(
                cls._looks_like_source_file_stem_part(part) for part in parts
            )
        return (segment.islower() or segment.isupper()) and cls._shannon_entropy(
            segment
        ) < cls._SOURCE_FILE_STEM_PART_ENTROPY_MAX

    @classmethod
    def _looks_like_source_file_stem_part(cls, part: str) -> bool:
        if re.fullmatch(r"[A-Za-z]+", part) is not None:
            return cls._shannon_entropy(part) < cls._SOURCE_FILE_STEM_PART_ENTROPY_MAX
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", part) is None:
            return False
        digit_count = sum(char.isdigit() for char in part)
        if digit_count <= 1:
            return cls._shannon_entropy(part) < cls._SOURCE_FILE_STEM_PART_ENTROPY_MAX
        match = re.fullmatch(r"([A-Za-z]+)([0-9]{2,3})", part)
        if match is None:
            return False
        return match.group(1).lower() in cls._SOURCE_FILE_STEM_MULTI_DIGIT_PREFIXES

    @staticmethod
    def _looks_like_readable_technical_path_segment(segment: str) -> bool:
        lower = segment.lower()
        if lower != segment:
            return False
        return lower in OutputFirewall._READABLE_TECHNICAL_PATH_SEGMENTS

    @staticmethod
    def _looks_like_short_secret_path_segment(segment: str) -> bool:
        if not 6 <= len(segment) <= 23:
            return False
        if re.fullmatch(r"[A-Za-z0-9]+", segment) is None:
            return False
        digit_count = sum(char.isdigit() for char in segment)
        alpha_count = len(segment) - digit_count
        if digit_count < 2 or alpha_count < 2:
            return False
        max_alpha_run = max(
            (len(match.group(0)) for match in re.finditer(r"[A-Za-z]+", segment)),
            default=0,
        )
        if max_alpha_run >= 4:
            return False
        transitions = sum(left.isdigit() != right.isdigit() for left, right in pairwise(segment))
        return transitions >= 3 and len(set(segment.lower())) >= 5

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
