"""Meta-analyzer to reduce static-analysis false positives."""

from __future__ import annotations

import re

from shisad.skills.analyzer import Finding

_PLACEHOLDER_RE = re.compile(
    r"\b(?:YOUR_API_KEY|REPLACE_ME|dummy|placeholder)\b",
    re.IGNORECASE,
)
_EDUCATIONAL_RE = re.compile(
    r"(for example|tutorial|demo|sample only|documentation example)",
    re.IGNORECASE,
)
_TEST_CONTEXT_RE = re.compile(r"(pytest|unittest|test fixture|mock)", re.IGNORECASE)


class MetaAnalyzer:
    """Contextual post-processing for finding quality."""

    def filter(self, findings: list[Finding], *, content_map: dict[str, str]) -> list[Finding]:
        filtered: list[Finding] = []
        for finding in findings:
            context = content_map.get(finding.file_path, "")
            lowered = context.lower()
            if self._is_false_positive(finding, lowered):
                filtered.append(
                    finding.model_copy(
                        update={
                            "false_positive": True,
                            "tags": sorted({*finding.tags, "meta_fp"}),
                            "metadata": {
                                **finding.metadata,
                                "meta_reason": "template_or_test_context",
                            },
                        }
                    )
                )
                continue
            filtered.append(finding)
        return filtered

    @staticmethod
    def _is_false_positive(finding: Finding, context: str) -> bool:
        if not context:
            return False
        if _PLACEHOLDER_RE.search(finding.detail) and _EDUCATIONAL_RE.search(context):
            return True
        if _PLACEHOLDER_RE.search(context) and _EDUCATIONAL_RE.search(context):
            return True
        return bool(
            _TEST_CONTEXT_RE.search(context)
            and "test" in (finding.file_path or "").lower()
        )
