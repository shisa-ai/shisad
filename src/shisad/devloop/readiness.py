"""Doc-backed milestone closure-readiness checks for the v0.4 dev loop."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_MILESTONE_KEY_RE = re.compile(r"^(?:G|M)\d+$", re.IGNORECASE)
_TOP_LEVEL_HEADING_RE = re.compile(r"^## (?P<title>.+)$", re.MULTILINE)
_THIRD_LEVEL_HEADING_RE = re.compile(r"^### (?P<title>.+)$", re.MULTILINE)
_FINDING_ID_RE = re.compile(r"\b(?P<id>(?:G|M)\d+\.(?:R-open\.\d+|RR\d+\.\d+))\b")
_UNCHECKED_CHECKBOX_RE = re.compile(r"^\s*-\s+\[\s\]\s+(?P<item>.+)$", re.MULTILINE)
_FINDING_CLAUSE_SPLIT_RE = re.compile(
    r"\s*(?:;|,|\band\b|\bbut\b|\bwhile\b)\s*"
    r"(?=(?:\[\s*[x ]\s*\]\s*)?(?:G|M)\d+\.(?:R-open\.\d+|RR\d+\.\d+)\b)",
    re.IGNORECASE,
)
_OPEN_CHECKBOX_RE = re.compile(r"\[\s\]")
_RESOLVED_CHECKBOX_RE = re.compile(r"\[\s*x\s*\]", re.IGNORECASE)
_OPEN_FINDING_PATTERNS = (
    re.compile(r"\bopen\b", re.IGNORECASE),
    re.compile(r"\breopened\b", re.IGNORECASE),
    re.compile(r"\bunresolved\b", re.IGNORECASE),
    re.compile(r"\bstill open\b", re.IGNORECASE),
    re.compile(r"\bneeds changes\b", re.IGNORECASE),
    re.compile(r"\bnot closed\b", re.IGNORECASE),
    re.compile(r"\bnot resolved\b", re.IGNORECASE),
)
_RESOLVED_FINDING_PATTERNS = (
    re.compile(r"\bclosed\b", re.IGNORECASE),
    re.compile(r"\bresolved\b", re.IGNORECASE),
    re.compile(r"\bgreen\b", re.IGNORECASE),
    re.compile(r"\baccepted(?:-no-change)?\b", re.IGNORECASE),
    re.compile(r"\bdeferred\b", re.IGNORECASE),
    re.compile(r"\bremediated\b", re.IGNORECASE),
    re.compile(r"\bfixed\b", re.IGNORECASE),
)


@dataclass(frozen=True, slots=True)
class MilestoneReadinessReport:
    """Structured closure-readiness assessment for one milestone section."""

    milestone: str
    implementation_path: Path
    ready: bool
    section_found: bool
    runtime_wiring_recorded: bool
    validation_recorded: bool
    docs_parity_recorded: bool
    worklog_updated: bool
    review_status_recorded: bool
    punchlist_complete: bool
    acceptance_checklist_complete: bool
    missing_evidence: tuple[str, ...]
    unchecked_items: tuple[str, ...]
    open_finding_ids: tuple[str, ...]


def normalize_milestone_key(value: str) -> str:
    """Return a canonical milestone key like ``M4`` or ``G2``."""

    normalized = str(value).strip().upper()
    if not _MILESTONE_KEY_RE.fullmatch(normalized):
        raise ValueError(f"Unsupported milestone key: {value}")
    return normalized


def assess_milestone_readiness(
    *,
    implementation_path: Path,
    milestone: str,
) -> MilestoneReadinessReport:
    """Assess whether a milestone is ready to close based on recorded docs evidence."""

    milestone_key = normalize_milestone_key(milestone)
    try:
        text = implementation_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return MilestoneReadinessReport(
            milestone=milestone_key,
            implementation_path=implementation_path,
            ready=False,
            section_found=False,
            runtime_wiring_recorded=False,
            validation_recorded=False,
            docs_parity_recorded=False,
            worklog_updated=False,
            review_status_recorded=False,
            punchlist_complete=False,
            acceptance_checklist_complete=False,
            missing_evidence=("implementation_doc_missing",),
            unchecked_items=(),
            open_finding_ids=(),
        )

    section = _extract_top_level_section(text, milestone_key)
    if section is None:
        return MilestoneReadinessReport(
            milestone=milestone_key,
            implementation_path=implementation_path,
            ready=False,
            section_found=False,
            runtime_wiring_recorded=False,
            validation_recorded=False,
            docs_parity_recorded=False,
            worklog_updated=_worklog_updated(text=text, milestone_key=milestone_key),
            review_status_recorded=False,
            punchlist_complete=False,
            acceptance_checklist_complete=False,
            missing_evidence=("milestone_section_missing",),
            unchecked_items=(),
            open_finding_ids=(),
        )

    runtime_section = _extract_subsection(
        section,
        prefixes=(f"{milestone_key} Runtime Wiring Evidence",),
    )
    validation_section = _extract_subsection(
        section,
        prefixes=(f"{milestone_key} Validation Evidence",),
    )
    punchlist_section = _extract_subsection(
        section,
        prefixes=(f"{milestone_key} Punchlist",),
    )
    acceptance_section = _extract_subsection(
        section,
        prefixes=(f"{milestone_key} Acceptance Criteria",),
    )
    review_section = _extract_subsection(
        section,
        prefixes=(
            f"{milestone_key} Review Findings Status",
            f"{milestone_key} Re-review Findings Status",
        ),
    )
    worklog_section = _extract_top_level_section(text, "Worklog") or ""

    runtime_wiring_recorded = _section_has_body(runtime_section)
    validation_recorded = _section_has_body(validation_section)
    worklog_updated = _worklog_updated(text=text, milestone_key=milestone_key)
    docs_parity_recorded = (
        worklog_updated
        and acceptance_section is not None
        and "[x] Docs parity evidence recorded." in acceptance_section
    )
    review_status_recorded = _section_has_body(review_section)
    punchlist_unchecked = _unchecked_items(punchlist_section)
    acceptance_unchecked = _unchecked_items(acceptance_section)
    punchlist_complete = punchlist_section is not None and not punchlist_unchecked
    acceptance_checklist_complete = acceptance_section is not None and not acceptance_unchecked
    open_finding_ids = _open_finding_ids(
        text="\n".join(part for part in (review_section, worklog_section) if part),
        milestone_key=milestone_key,
    )

    missing_evidence: list[str] = []
    if not runtime_wiring_recorded:
        missing_evidence.append("runtime_wiring_evidence_missing")
    if not validation_recorded:
        missing_evidence.append("validation_evidence_missing")
    if not worklog_updated:
        missing_evidence.append("worklog_entry_missing")
    if not docs_parity_recorded:
        missing_evidence.append("docs_parity_evidence_missing")
    if not review_status_recorded:
        missing_evidence.append("review_status_missing")
    if not punchlist_complete:
        missing_evidence.append("punchlist_incomplete")
    if not acceptance_checklist_complete:
        missing_evidence.append("acceptance_checklist_incomplete")

    unchecked_items = (*punchlist_unchecked, *acceptance_unchecked)
    ready = len(missing_evidence) == 0 and len(open_finding_ids) == 0
    return MilestoneReadinessReport(
        milestone=milestone_key,
        implementation_path=implementation_path,
        ready=ready,
        section_found=True,
        runtime_wiring_recorded=runtime_wiring_recorded,
        validation_recorded=validation_recorded,
        docs_parity_recorded=docs_parity_recorded,
        worklog_updated=worklog_updated,
        review_status_recorded=review_status_recorded,
        punchlist_complete=punchlist_complete,
        acceptance_checklist_complete=acceptance_checklist_complete,
        missing_evidence=tuple(missing_evidence),
        unchecked_items=unchecked_items,
        open_finding_ids=open_finding_ids,
    )


def _extract_top_level_section(text: str, title_prefix: str) -> str | None:
    matches = list(_TOP_LEVEL_HEADING_RE.finditer(text))
    for index, match in enumerate(matches):
        title = str(match.group("title")).strip()
        if not _title_matches_prefix(title=title, prefix=title_prefix):
            continue
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        return text[start:end].strip()
    return None


def _extract_subsection(section: str | None, *, prefixes: tuple[str, ...]) -> str | None:
    if not section:
        return None
    matches = list(_THIRD_LEVEL_HEADING_RE.finditer(section))
    for index, match in enumerate(matches):
        title = str(match.group("title")).strip()
        if not any(_title_matches_prefix(title=title, prefix=prefix) for prefix in prefixes):
            continue
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(section)
        return section[start:end].strip()
    return None


def _title_matches_prefix(*, title: str, prefix: str) -> bool:
    if not title.startswith(prefix):
        return False
    if len(title) == len(prefix):
        return True
    next_char = title[len(prefix)]
    return not next_char.isalnum()


def _section_has_body(section: str | None) -> bool:
    if not section:
        return False
    lines = section.splitlines()[1:]
    return any(line.strip() for line in lines)


def _unchecked_items(section: str | None) -> tuple[str, ...]:
    if not section:
        return ()
    return tuple(match.group("item").strip() for match in _UNCHECKED_CHECKBOX_RE.finditer(section))


def _worklog_updated(*, text: str, milestone_key: str) -> bool:
    worklog = _extract_top_level_section(text, "Worklog")
    if not worklog:
        return False
    pattern = re.compile(rf"^\s*-\s+.*\b{re.escape(milestone_key)}\b", re.MULTILINE)
    return pattern.search(worklog) is not None


def _finding_resolution_state(line: str) -> bool | None:
    status_text = _FINDING_ID_RE.sub("", line)
    if _OPEN_CHECKBOX_RE.search(status_text) is not None:
        return False
    if any(pattern.search(status_text) is not None for pattern in _OPEN_FINDING_PATTERNS):
        return False
    if _RESOLVED_CHECKBOX_RE.search(status_text) is not None:
        return True
    if any(pattern.search(status_text) is not None for pattern in _RESOLVED_FINDING_PATTERNS):
        return True
    return None


def _finding_clauses(line: str) -> tuple[str, ...]:
    parts = _FINDING_CLAUSE_SPLIT_RE.split(line)
    return tuple(part.strip() for part in parts if part.strip())


def _open_finding_ids(*, text: str, milestone_key: str) -> tuple[str, ...]:
    statuses: dict[str, bool] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        for clause in _finding_clauses(line):
            state = _finding_resolution_state(clause)
            for match in _FINDING_ID_RE.finditer(clause):
                finding_id = str(match.group("id"))
                if not finding_id.startswith(f"{milestone_key}."):
                    continue
                if state is None:
                    statuses.setdefault(finding_id, False)
                    continue
                if finding_id not in statuses:
                    statuses[finding_id] = state
                    continue
                if state is False:
                    statuses[finding_id] = False
                    continue
                statuses[finding_id] = True
    return tuple(sorted(finding_id for finding_id, closed in statuses.items() if not closed))
