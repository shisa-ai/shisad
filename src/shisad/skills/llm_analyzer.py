"""LLM-assisted semantic analyzer for skill bundles."""

from __future__ import annotations

import json
import secrets

from shisad.core.providers.base import Message, ModelProvider
from shisad.core.types import ThreatCategory
from shisad.skills.analyzer import Finding, FindingSeverity, SkillBundle


class LlmSkillAnalyzer:
    """Semantic analyzer that asks a model to assess intent-vs-implementation."""

    def __init__(
        self,
        *,
        provider: ModelProvider,
        enabled: bool = True,
        minimum_static_score: float = 0.0,
    ) -> None:
        self._provider = provider
        self._enabled = enabled
        self._minimum_static_score = minimum_static_score

    async def analyze(
        self,
        skill: SkillBundle,
        *,
        static_risk_score: float = 1.0,
    ) -> list[Finding]:
        if not self._enabled or static_risk_score < self._minimum_static_score:
            return []

        delimiter = f"SHISAD_DELIM_{secrets.token_hex(8)}"
        corpus = self._build_corpus(skill)
        if delimiter in corpus or "SHISAD_DELIM_" in corpus:
            return [
                Finding(
                    analyzer="llm-semantic",
                    category=ThreatCategory.PROMPT_INJECTION_DIRECT,
                    severity=FindingSeverity.HIGH,
                    title="Delimiter injection attempt detected",
                    detail="Skill content attempted to interfere with analyzer prompt delimiters",
                    tags=["delimiter_injection"],
                )
            ]

        prompt = self._build_prompt(skill=skill, corpus=corpus, delimiter=delimiter)
        response = await self._provider.complete(
            [
                Message(role="system", content="You are a strict security analyzer."),
                Message(role="user", content=prompt),
            ]
        )
        return self._parse_response(response.message.content, skill)

    @staticmethod
    def _build_corpus(skill: SkillBundle) -> str:
        parts = [f"manifest:{json.dumps(skill.manifest.model_dump(mode='json'), sort_keys=True)}"]
        for file in skill.files:
            if file.binary:
                continue
            parts.append(f"file:{file.path}\n{file.content[:5000]}")
        return "\n\n".join(parts)

    @staticmethod
    def _build_prompt(*, skill: SkillBundle, corpus: str, delimiter: str) -> str:
        return (
            "Analyze the following skill for semantic threats and output strict JSON with keys "
            "`risk_score`, `mismatch`, `findings`.\n"
            f"Use delimiter {delimiter} exactly.\n"
            f"{delimiter}\n"
            f"Skill name: {skill.manifest.name}\n"
            f"Description: {skill.manifest.description}\n"
            f"{corpus}\n"
            f"{delimiter}\n"
        )

    @staticmethod
    def _parse_response(content: str, skill: SkillBundle) -> list[Finding]:
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            payload = {"risk_score": 0.0, "mismatch": False, "findings": []}

        risk = float(payload.get("risk_score", 0.0) or 0.0)
        mismatch = bool(payload.get("mismatch", False))
        findings_raw = payload.get("findings", [])
        findings: list[Finding] = []
        if mismatch:
            findings.append(
                Finding(
                    analyzer="llm-semantic",
                    category=ThreatCategory.SUPPLY_CHAIN,
                    severity=FindingSeverity.HIGH,
                    title="Description and implementation mismatch",
                    detail=(
                        f"Skill '{skill.manifest.name}' claims benign behavior "
                        "but code appears broader"
                    ),
                    tags=["semantic_mismatch"],
                    metadata={"risk_score": risk},
                )
            )
        if isinstance(findings_raw, list):
            for item in findings_raw:
                if not isinstance(item, dict):
                    continue
                findings.append(
                    Finding(
                        analyzer="llm-semantic",
                        category=ThreatCategory(
                            item.get("category", ThreatCategory.SUPPLY_CHAIN.value)
                        )
                        if item.get("category") in {member.value for member in ThreatCategory}
                        else ThreatCategory.SUPPLY_CHAIN,
                        severity=(
                            FindingSeverity(item.get("severity", FindingSeverity.MEDIUM.value))
                            if item.get("severity")
                            in {member.value for member in FindingSeverity}
                            else FindingSeverity.MEDIUM
                        ),
                        title=str(item.get("title", "Semantic risk finding")),
                        detail=str(item.get("detail", "")),
                        tags=["semantic"],
                        metadata={"risk_score": risk},
                    )
                )
        return findings
