"""Cross-skill correlation scanner for coordinated malicious behavior."""

from __future__ import annotations

import re
from collections import defaultdict
from itertools import combinations

from shisad.core.types import ThreatCategory
from shisad.skills.analyzer import Finding, FindingSeverity, SkillBundle

_SAFE_SHARED_DOMAINS = {
    "github.com",
    "api.github.com",
    "pypi.org",
    "files.pythonhosted.org",
    "gitlab.com",
    "bitbucket.org",
}
_COLLECTION_RE = re.compile(
    r"(aws[_\s-]?credentials|ssh[_\s-]?key|api[_\s-]?key|token|secret|/\.ssh|/\.aws)",
    re.IGNORECASE,
)
_EXFIL_RE = re.compile(
    r"(curl|wget|http[s]?://|webhook|post\s+to|exfil|upload)",
    re.IGNORECASE,
)
_OBFUSCATION_RE = re.compile(r"(base64|xxd|eval\s*\(|\$\(|\\x[0-9a-f]{2})", re.IGNORECASE)
_TRIGGER_COLLECTION_RE = re.compile(r"\b(capture|collect|index|gather|ingest)\b", re.IGNORECASE)
_TRIGGER_TRANSMIT_RE = re.compile(r"\b(send|post|transmit|sync|publish|notify)\b", re.IGNORECASE)
_PROCESS_RE = re.compile(
    r"\b(process|transform|normalize|parse|summari[sz]e|enrich|aggregate|filter)\b",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?")


def scan_cross_skill(skills: list[SkillBundle]) -> list[Finding]:
    findings: list[Finding] = []
    if len(skills) < 2:
        return findings

    skill_domains: dict[str, set[str]] = {}
    skill_collects: dict[str, bool] = {}
    skill_exfils: dict[str, bool] = {}
    skill_obf: dict[str, set[str]] = {}
    skill_desc: dict[str, str] = {}
    skill_processes: dict[str, bool] = {}
    skill_author: dict[str, str] = {}

    for skill in skills:
        name = skill.manifest.name
        skill_author[name] = skill.manifest.author
        skill_desc[name] = skill.manifest.description
        text_corpus = "\n".join(file.content for file in skill.files if not file.binary)
        skill_collects[name] = bool(_COLLECTION_RE.search(text_corpus))
        skill_exfils[name] = bool(_EXFIL_RE.search(text_corpus))
        skill_domains[name] = {match.lower() for match in _URL_RE.findall(text_corpus)}
        skill_obf[name] = {
            token.group(0).lower()
            for token in _OBFUSCATION_RE.finditer(text_corpus)
        }
        skill_processes[name] = bool(
            _PROCESS_RE.search(skill.manifest.description or "")
            or _PROCESS_RE.search(text_corpus)
        )

    findings.extend(_detect_data_relay(skills, skill_collects, skill_exfils))
    findings.extend(
        _detect_transitive_data_relay(
            skills,
            collects=skill_collects,
            exfils=skill_exfils,
            processes=skill_processes,
        )
    )
    findings.extend(_detect_shared_c2(skill_domains))
    findings.extend(_detect_trigger_chain(skill_desc))
    findings.extend(_detect_shared_obfuscation(skill_obf, skill_author))
    return findings


def _detect_data_relay(
    skills: list[SkillBundle],
    collects: dict[str, bool],
    exfils: dict[str, bool],
) -> list[Finding]:
    findings: list[Finding] = []
    names = [skill.manifest.name for skill in skills]
    for src, dst in combinations(names, 2):
        if collects.get(src) and exfils.get(dst):
            findings.append(
                Finding(
                    analyzer="cross-skill",
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=FindingSeverity.CRITICAL,
                    title="Coordinated data relay pattern",
                    detail=(
                        f"{src} collects sensitive data while {dst} "
                        "contains exfiltration patterns"
                    ),
                    tags=["relay", "multi_skill"],
                    metadata={"collector": src, "exfiltrator": dst},
                )
            )
        if collects.get(dst) and exfils.get(src):
            findings.append(
                Finding(
                    analyzer="cross-skill",
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=FindingSeverity.CRITICAL,
                    title="Coordinated data relay pattern",
                    detail=(
                        f"{dst} collects sensitive data while {src} "
                        "contains exfiltration patterns"
                    ),
                    tags=["relay", "multi_skill"],
                    metadata={"collector": dst, "exfiltrator": src},
                )
            )
    return findings


def _detect_transitive_data_relay(
    skills: list[SkillBundle],
    *,
    collects: dict[str, bool],
    exfils: dict[str, bool],
    processes: dict[str, bool],
) -> list[Finding]:
    findings: list[Finding] = []
    names = [skill.manifest.name for skill in skills]
    seen: set[tuple[str, str, str]] = set()
    for collector in names:
        if not collects.get(collector):
            continue
        for exfiltrator in names:
            if exfiltrator == collector or not exfils.get(exfiltrator):
                continue
            for processor in names:
                if processor in {collector, exfiltrator}:
                    continue
                if not processes.get(processor):
                    continue
                key = (collector, processor, exfiltrator)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        analyzer="cross-skill",
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=FindingSeverity.CRITICAL,
                        title="Transitive multi-skill relay chain",
                        detail=(
                            f"{collector} collects sensitive data, {processor} appears to "
                            f"process intermediate payloads, and {exfiltrator} contains "
                            "exfiltration patterns"
                        ),
                        tags=["relay", "transitive_relay", "multi_skill"],
                        metadata={
                            "collector": collector,
                            "processor": processor,
                            "exfiltrator": exfiltrator,
                        },
                    )
                )
    return findings


def _detect_shared_c2(skill_domains: dict[str, set[str]]) -> list[Finding]:
    findings: list[Finding] = []
    by_domain: defaultdict[str, set[str]] = defaultdict(set)
    for skill_name, domains in skill_domains.items():
        for domain in domains:
            if domain in _SAFE_SHARED_DOMAINS:
                continue
            by_domain[domain].add(skill_name)

    for domain, names in sorted(by_domain.items()):
        if len(names) < 2:
            continue
        findings.append(
            Finding(
                analyzer="cross-skill",
                category=ThreatCategory.SUPPLY_CHAIN,
                severity=FindingSeverity.HIGH,
                title="Shared external C2-like domain across skills",
                detail=f"Domain {domain} referenced by {', '.join(sorted(names))}",
                tags=["shared_c2"],
                metadata={"domain": domain, "skills": sorted(names)},
            )
        )
    return findings


def _detect_trigger_chain(descriptions: dict[str, str]) -> list[Finding]:
    collectors = [
        name
        for name, description in descriptions.items()
        if _TRIGGER_COLLECTION_RE.search(description or "")
    ]
    transmitters = [
        name
        for name, description in descriptions.items()
        if _TRIGGER_TRANSMIT_RE.search(description or "")
    ]
    if not collectors or not transmitters:
        return []
    return [
        Finding(
            analyzer="cross-skill",
            category=ThreatCategory.TOOL_SHADOWING,
            severity=FindingSeverity.MEDIUM,
            title="Complementary trigger descriptions detected",
            detail=(
                f"Collectors: {', '.join(sorted(set(collectors)))}; "
                f"Transmitters: {', '.join(sorted(set(transmitters)))}"
            ),
            tags=["trigger_chain"],
            metadata={
                "collectors": sorted(set(collectors)),
                "transmitters": sorted(set(transmitters)),
            },
        )
    ]


def _detect_shared_obfuscation(
    patterns: dict[str, set[str]],
    authors: dict[str, str],
) -> list[Finding]:
    findings: list[Finding] = []
    by_author: defaultdict[str, list[str]] = defaultdict(list)
    for name, author in authors.items():
        by_author[author].append(name)

    for author, names in sorted(by_author.items()):
        if len(names) < 2:
            continue
        overlap = set.intersection(*(patterns.get(name, set()) for name in names))
        if not overlap:
            continue
        findings.append(
            Finding(
                analyzer="cross-skill",
                category=ThreatCategory.SUPPLY_CHAIN,
                severity=FindingSeverity.MEDIUM,
                title="Shared suspicious code motifs across same author",
                detail=(
                    f"Author {author} has overlapping obfuscation markers across "
                    f"{', '.join(sorted(names))}"
                ),
                tags=["shared_obfuscation"],
                metadata={
                    "author": author,
                    "skills": sorted(names),
                    "overlap": sorted(overlap),
                },
            )
        )
    return findings
