"""Unit coverage for doc-backed dev-loop closure readiness."""

from __future__ import annotations

from pathlib import Path

import pytest

from shisad.devloop import assess_milestone_readiness


def test_assess_milestone_readiness_reports_ready_when_evidence_is_complete(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "IMPLEMENTATION.md"
    implementation.write_text(
        """
## M4 — Minimal Dev Loop Orchestration

### M4 Punchlist
- [x] dev.implement works

### M4 Acceptance Criteria
- [x] Runtime wiring evidence recorded.
- [x] Validation evidence recorded.
- [x] Docs parity evidence recorded.
- [x] Review loop complete or deferrals explicitly recorded.

### M4 Review Findings Status (Round 1)
- [x] M4.R-open.1 (Reviewer 1): closed.

### M4 Runtime Wiring Evidence
- Wired on the live daemon path.

### M4 Validation Evidence
- `uv run pytest tests/behavioral/ -q` -> `ok`

## Worklog

- **2026-03-14**: **M4 implementation**
  - Summary: docs updated.
""".strip(),
        encoding="utf-8",
    )

    report = assess_milestone_readiness(
        implementation_path=implementation,
        milestone="m4",
    )

    assert report.ready is True
    assert report.milestone == "M4"
    assert report.missing_evidence == ()
    assert report.open_finding_ids == ()


def test_assess_milestone_readiness_reports_missing_blocks_and_open_findings(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "IMPLEMENTATION.md"
    implementation.write_text(
        """
## M4 — Minimal Dev Loop Orchestration

### M4 Punchlist
- [ ] dev.implement works

### M4 Acceptance Criteria
- [x] Runtime wiring evidence recorded.
- [ ] Validation evidence recorded.
- [ ] Docs parity evidence recorded.
- [ ] Review loop complete or deferrals explicitly recorded.

### M4 Review Findings Status (Round 1)
- [ ] M4.R-open.1 (Reviewer 1): still open.

### M4 Runtime Wiring Evidence
- Wired on the live daemon path.

## Worklog
""".strip(),
        encoding="utf-8",
    )

    report = assess_milestone_readiness(
        implementation_path=implementation,
        milestone="M4",
    )

    assert report.ready is False
    assert "validation_evidence_missing" in report.missing_evidence
    assert "docs_parity_evidence_missing" in report.missing_evidence
    assert "worklog_entry_missing" in report.missing_evidence
    assert "punchlist_incomplete" in report.missing_evidence
    assert "acceptance_checklist_incomplete" in report.missing_evidence
    assert report.open_finding_ids == ("M4.R-open.1",)


def test_assess_milestone_readiness_returns_missing_doc_status(tmp_path: Path) -> None:
    report = assess_milestone_readiness(
        implementation_path=tmp_path / "missing.md",
        milestone="M4",
    )

    assert report.ready is False
    assert report.missing_evidence == ("implementation_doc_missing",)


def test_assess_milestone_readiness_rejects_unknown_milestone(tmp_path: Path) -> None:
    implementation = tmp_path / "IMPLEMENTATION.md"
    implementation.write_text("## Worklog\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported milestone key"):
        assess_milestone_readiness(implementation_path=implementation, milestone="release-close")


def test_assess_milestone_readiness_keeps_reopened_findings_open(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "IMPLEMENTATION.md"
    implementation.write_text(
        """
## M4 — Minimal Dev Loop Orchestration

### M4 Punchlist
- [x] dev.implement works

### M4 Acceptance Criteria
- [x] Runtime wiring evidence recorded.
- [x] Validation evidence recorded.
- [x] Docs parity evidence recorded.
- [x] Review loop complete or deferrals explicitly recorded.

### M4 Review Findings Status (Round 1)
- [x] M4.R-open.1 (Reviewer 1): closed.
- [ ] M4.R-open.1 (Reviewer 3): reopened after regression.

### M4 Runtime Wiring Evidence
- Wired on the live daemon path.

### M4 Validation Evidence
- `uv run pytest tests/behavioral/ -q` -> `ok`

## Worklog

- **2026-03-14**: **M4 remediation**
  - Findings: reopened finding recorded.
""".strip(),
        encoding="utf-8",
    )

    report = assess_milestone_readiness(
        implementation_path=implementation,
        milestone="M4",
    )

    assert report.ready is False
    assert report.open_finding_ids == ("M4.R-open.1",)


def test_assess_milestone_readiness_treats_negative_resolution_phrases_as_open(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "IMPLEMENTATION.md"
    implementation.write_text(
        """
## M4 — Minimal Dev Loop Orchestration

### M4 Punchlist
- [x] dev.implement works

### M4 Acceptance Criteria
- [x] Runtime wiring evidence recorded.
- [x] Validation evidence recorded.
- [x] Docs parity evidence recorded.
- [x] Review loop complete or deferrals explicitly recorded.

### M4 Review Findings Status (Round 1)
- M4.R-open.1 unresolved after re-review.
- M4.R-open.2 not closed pending another pass.

### M4 Runtime Wiring Evidence
- Wired on the live daemon path.

### M4 Validation Evidence
- `uv run pytest tests/behavioral/ -q` -> `ok`

## Worklog

- **2026-03-14**: **M4 remediation**
  - Findings: negative resolution phrases covered.
""".strip(),
        encoding="utf-8",
    )

    report = assess_milestone_readiness(
        implementation_path=implementation,
        milestone="M4",
    )

    assert report.ready is False
    assert report.open_finding_ids == ("M4.R-open.1", "M4.R-open.2")


def test_assess_milestone_readiness_does_not_match_other_milestone_prefixes(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "IMPLEMENTATION.md"
    implementation.write_text(
        """
## M10 — Another Milestone

### M10 Punchlist
- [x] unrelated work

### M10 Acceptance Criteria
- [x] Runtime wiring evidence recorded.
- [x] Validation evidence recorded.
- [x] Docs parity evidence recorded.
- [x] Review loop complete or deferrals explicitly recorded.

### M10 Review Findings Status (Round 1)
- [x] M10.R-open.1: closed.

### M10 Runtime Wiring Evidence
- Wired on the live daemon path.

### M10 Validation Evidence
- `uv run pytest tests/behavioral/ -q` -> `ok`

## Worklog

- **2026-03-14**: **M10 implementation**
  - Summary: unrelated milestone.
""".strip(),
        encoding="utf-8",
    )

    report = assess_milestone_readiness(
        implementation_path=implementation,
        milestone="M1",
    )

    assert report.ready is False
    assert report.section_found is False
    assert report.missing_evidence == ("milestone_section_missing",)


def test_assess_milestone_readiness_does_not_match_other_subsection_prefixes(
    tmp_path: Path,
) -> None:
    implementation = tmp_path / "IMPLEMENTATION.md"
    implementation.write_text(
        """
## M4 — Minimal Dev Loop Orchestration

### M4 Punchlist
- [x] dev.implement works

### M4 Acceptance Criteria
- [x] Runtime wiring evidence recorded.
- [x] Validation evidence recorded.
- [x] Docs parity evidence recorded.
- [x] Review loop complete or deferrals explicitly recorded.

### M40 Review Findings Status (Round 1)
- [x] M40.R-open.1: closed.

### M4 Runtime Wiring Evidence
- Wired on the live daemon path.

### M4 Validation Evidence
- `uv run pytest tests/behavioral/ -q` -> `ok`

## Worklog

- **2026-03-14**: **M4 remediation**
  - Summary: subsection boundary coverage.
""".strip(),
        encoding="utf-8",
    )

    report = assess_milestone_readiness(
        implementation_path=implementation,
        milestone="M4",
    )

    assert report.ready is False
    assert report.review_status_recorded is False
    assert "review_status_missing" in report.missing_evidence
