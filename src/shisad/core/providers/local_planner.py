"""Local fallback provider for daemon planner and embeddings routes."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
from collections.abc import Iterator
from typing import Any

from shisad.core.providers.base import EmbeddingResponse, Message, ProviderResponse
from shisad.security.spotlight import LOCAL_TASK_CLOSE_GATE_SENTINEL

_TASK_CLOSE_GATE_HEADER = "TASK CLOSE-GATE SELF-CHECK"
_TASK_CLOSE_GATE_SECTION_HEADERS = (
    "ORIGINAL TASK DESCRIPTION:",
    "REQUESTED FILE REFS:",
    "TASK EXECUTION METADATA:",
    "TASK RESULT SIGNALS:",
    "TASK OUTPUT SUMMARY:",
    "TASK OUTPUT RESPONSE:",
    "TASK FILES CHANGED:",
    "TASK PROPOSAL DIFF:",
    "TASK TOOL OUTPUT EVIDENCE:",
    "TASK TOOL OUTPUTS JSON:",
    "TASK PROPOSAL JSON:",
)
_TASK_CLOSE_GATE_SECTION_HEADER_SET = set(_TASK_CLOSE_GATE_SECTION_HEADERS)
_PLANNER_FALLBACK_CONFIGURATION_PREFIX = "[PLANNER FALLBACK: CONFIGURATION]"
_PLANNER_FALLBACK_ROUTE_ERROR_PREFIX = "[PLANNER FALLBACK: ROUTE ERROR]"
_PROVIDER_HTTP_ERROR_RE = re.compile(r"\bProvider HTTP error (?P<status>[1-5][0-9]{2})\b")
_PROVIDER_RETRYABLE_HTTP_STATUSES = {408, 429}


def _extract_marked_untrusted_payload(planner_input: str) -> str:
    lines = planner_input.splitlines()
    capture = False
    skipped_start_delimiter = False
    payload_lines: list[str] = []
    for line in lines:
        if line.startswith("=== DATA EVIDENCE"):
            capture = True
            skipped_start_delimiter = False
            payload_lines = []
            continue
        if not capture:
            continue
        if not skipped_start_delimiter:
            skipped_start_delimiter = True
            continue
        if line.startswith("^^EVIDENCE_END_"):
            break
        payload_lines.append(line)
    marked_payload = "\n".join(payload_lines).strip()
    if not marked_payload:
        return ""
    payload = marked_payload.replace("^", "")
    compact = "".join(payload.split())
    try:
        decoded = base64.b64decode(compact, validate=True)
        return decoded.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return payload


def _parse_task_close_gate_sections(evidence_text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current_header = ""
    current_lines: list[str] = []
    for raw_line in evidence_text.splitlines():
        line = raw_line.rstrip()
        if line in _TASK_CLOSE_GATE_SECTION_HEADER_SET:
            if line == current_header or line in sections:
                if current_header:
                    current_lines.append(raw_line)
                continue
            if current_header:
                sections[current_header] = "\n".join(current_lines).strip()
            current_header = line
            current_lines = []
            continue
        if current_header:
            current_lines.append(raw_line)
    if current_header:
        sections[current_header] = "\n".join(current_lines).strip()
    return sections


def _parse_task_close_gate_signals(text: str) -> dict[str, str]:
    signals: dict[str, str] = {}
    for raw_line in text.splitlines():
        key, sep, value = raw_line.partition("=")
        if not sep:
            continue
        normalized_key = key.strip().lower()
        normalized_value = value.strip().lower()
        if normalized_key:
            signals[normalized_key] = normalized_value
    return signals


def _task_close_gate_signal_int(signals: dict[str, str], key: str) -> int:
    try:
        value = int(signals.get(key, "0") or "0")
    except ValueError:
        return 0
    return max(0, value)


def _artifactless_write_activity_notes() -> str:
    return (
        "The coding agent reported file write operations, but no changes were detected "
        "in the sandboxed worktree or proposal diff. This usually means it wrote to an "
        "absolute path outside the coding worktree. Set SHISAD_CODING_REPO_ROOT to the "
        "target git repo and use relative paths."
    )


def _task_close_gate_section_has_content(value: str) -> bool:
    return value.strip().lower() not in {"", "(none)", "(empty)"}


def _task_close_gate_is_diagnostic_meta_review(task_description: str) -> bool:
    normalized = " ".join(task_description.strip().lower().split())
    normalized = normalized.strip(".:;!?")
    return normalized in {
        "review close-gate fallback diagnostics",
        "review the close-gate fallback diagnostics",
    }


_TASK_CLOSE_GATE_CONTINUATION_PUNCTUATION = frozenset(".:,;-!?")


def _task_close_gate_remainder_starts_with_phrase(
    remainder: str, phrases: tuple[str, ...]
) -> bool:
    for phrase in phrases:
        if remainder == phrase or remainder.startswith(f"{phrase} "):
            return True
        if not remainder.startswith(phrase):
            continue
        next_char = remainder[len(phrase) : len(phrase) + 1]
        if next_char in _TASK_CLOSE_GATE_CONTINUATION_PUNCTUATION - {"-"}:
            return True
        if next_char == "-" and remainder[len(phrase) + 1 : len(phrase) + 2].isspace():
            return True
    return False


def _task_close_gate_starts_with_statement_cue(normalized: str, cue: str) -> bool:
    if not normalized.startswith(cue):
        return False
    remainder = normalized[len(cue) :].lstrip()
    if not remainder:
        return True
    if remainder[0] in _TASK_CLOSE_GATE_CONTINUATION_PUNCTUATION:
        return True
    return _task_close_gate_remainder_starts_with_phrase(
        remainder, ("and", "because", "but", "while", "instead", "to")
    )


def _task_close_gate_statement_fragments(normalized: str) -> Iterator[str]:
    yield normalized
    start = 0
    for index in range(len(normalized) - 1):
        if normalized[index] not in ".!?;" or normalized[index + 1] != " ":
            continue
        fragment = normalized[start : index + 1].strip()
        if fragment and fragment != normalized:
            yield fragment
        start = index + 2
    fragment = normalized[start:].strip()
    if fragment and fragment != normalized:
        yield fragment


def _task_close_gate_statement_fragment_contexts(
    normalized: str,
) -> Iterator[tuple[str, str]]:
    fragments = [normalized]
    start = 0
    for index in range(len(normalized) - 1):
        if normalized[index] not in ".!?;" or normalized[index + 1] != " ":
            continue
        fragment = normalized[start : index + 1].strip()
        if fragment and fragment != normalized:
            fragments.append(fragment)
        start = index + 2
    fragment = normalized[start:].strip()
    if fragment and fragment != normalized:
        fragments.append(fragment)
    for index, fragment in enumerate(fragments):
        following_text = fragments[index + 1] if index + 1 < len(fragments) else ""
        yield fragment, following_text


def _task_close_gate_first_statement_fragment(normalized: str) -> str:
    for fragment, _following_text in _task_close_gate_statement_fragment_contexts(
        normalized
    ):
        if fragment != normalized:
            return fragment
    return normalized


_TASK_CLOSE_GATE_FAILURE_START_CUES = (
    "delegated task failed before completion",
    "delegated task timed out before completion",
    "requested coding agent is not available",
    "could not create or inspect the isolated worktree",
    "the delegated task did not make the requested update",
    "the delegated task reported incomplete work",
    "the review timed out before completion",
    "the delegated review reported incomplete work",
)

_TASK_CLOSE_GATE_GENERAL_OBJECT_CUES = (
    "the delegated task ignored the ",
    "the task ignored the ",
    "i ignored the requested ",
    "ignored the requested ",
)

_TASK_CLOSE_GATE_REVIEW_OBJECT_CUES = (
    "the delegated task did not review ",
    "the task did not review ",
    "i did not review ",
    "did not review ",
)

_TASK_CLOSE_GATE_GOAL_DRIFT_LABEL_CUES = (
    "changed scope:",
    "goal drift:",
)

_TASK_CLOSE_GATE_GOAL_DRIFT_START_CUES = (
    "delegated task changed scope",
    "the delegated task changed scope",
    "the task changed scope",
    "the task output changed scope",
    "delegated task goal drift",
    "the delegated task goal drift",
    "the delegated task pursued a different goal",
    "the task pursued a different goal",
    "i pursued a different goal",
    "pursued a different goal",
)

_TASK_CLOSE_GATE_GOAL_DRIFT_PREFIX_CUES = (
    "the delegated task attempted exfiltrat",
    "the task attempted exfiltrat",
    "attempted exfiltrat",
    "the delegated task drafted a shell-based",
    "the task drafted a shell-based",
)

_TASK_CLOSE_GATE_DIAGNOSTIC_META_REVIEW_TARGET_CUES = (
    "the delegated task did not review the close-gate fallback diagnostics",
    "the delegated task did not review close-gate fallback diagnostics",
    "the task did not review the close-gate fallback diagnostics",
    "the task did not review close-gate fallback diagnostics",
    "i did not review the close-gate fallback diagnostics",
    "i did not review close-gate fallback diagnostics",
    "did not review the close-gate fallback diagnostics",
    "did not review close-gate fallback diagnostics",
)

_TASK_CLOSE_GATE_DIAGNOSTIC_CASE_SUBJECTS = (
    "diagnostic case",
    "the diagnostic case",
    "this diagnostic case",
    "that diagnostic case",
    "a diagnostic case",
)

_TASK_CLOSE_GATE_DIAGNOSTIC_PHRASE_SUBJECTS = (
    "exact phrase",
    "the exact phrase",
    "this exact phrase",
    "that exact phrase",
    "phrase under inspection",
    "the phrase under inspection",
    "this phrase under inspection",
    "that phrase under inspection",
)

_TASK_CLOSE_GATE_DIAGNOSTIC_CASE_CUES = (
    *(
        f"{subject} is {state}"
        for subject in _TASK_CLOSE_GATE_DIAGNOSTIC_CASE_SUBJECTS
        for state in ("covered", "handled", "tested")
    ),
    *(f"{subject} is covered" for subject in _TASK_CLOSE_GATE_DIAGNOSTIC_PHRASE_SUBJECTS),
    "phrase under inspection",
    "the phrase under inspection",
    "this phrase under inspection",
    "that phrase under inspection",
)

_TASK_CLOSE_GATE_SOFT_WRAP_STRICT_PREFIX_CUES = tuple(
    cue.strip()
    for cue in (
        *_TASK_CLOSE_GATE_FAILURE_START_CUES,
        *_TASK_CLOSE_GATE_GOAL_DRIFT_LABEL_CUES,
        *_TASK_CLOSE_GATE_GENERAL_OBJECT_CUES,
        *_TASK_CLOSE_GATE_REVIEW_OBJECT_CUES,
        *_TASK_CLOSE_GATE_GOAL_DRIFT_START_CUES,
        *_TASK_CLOSE_GATE_GOAL_DRIFT_PREFIX_CUES,
        *_TASK_CLOSE_GATE_DIAGNOSTIC_META_REVIEW_TARGET_CUES,
        *_TASK_CLOSE_GATE_DIAGNOSTIC_CASE_CUES,
    )
)

_TASK_CLOSE_GATE_SOFT_WRAP_REQUIRED_CONTINUATION_CUES = tuple(
    cue.strip()
    for cue in (
        *_TASK_CLOSE_GATE_GOAL_DRIFT_LABEL_CUES,
        *_TASK_CLOSE_GATE_GENERAL_OBJECT_CUES,
        *_TASK_CLOSE_GATE_REVIEW_OBJECT_CUES,
    )
)


def _task_close_gate_as_remainder_is_diagnostic_text(remainder: str) -> bool:
    normalized_remainder = " ".join(remainder.strip().strip(".!?").split())
    return normalized_remainder in {"as diagnostic text", "as. diagnostic text"}


def _task_close_gate_line_is_diagnostic_text_continuation(line: str) -> bool:
    return " ".join(line.strip().strip(".!?").split()) == "diagnostic text"


def _task_close_gate_can_soft_wrap_statement(current: str, next_line: str) -> bool:
    if not current or current.endswith((".", "!", "?")):
        return False
    if current.endswith(" as") and _task_close_gate_statement_has_diagnostic_case_cue(
        current[:-3]
    ):
        return _task_close_gate_line_is_diagnostic_text_continuation(next_line)
    candidate_prefix = f"{current} "
    if any(
        cue.startswith(candidate_prefix)
        for cue in _TASK_CLOSE_GATE_SOFT_WRAP_STRICT_PREFIX_CUES
    ):
        return True
    return current in _TASK_CLOSE_GATE_SOFT_WRAP_REQUIRED_CONTINUATION_CUES


def _task_close_gate_normalized_statement_text(text: str) -> str:
    statements: list[str] = []
    current = ""

    def flush_current() -> None:
        nonlocal current
        if current:
            statements.append(current)
            current = ""

    for raw_line in text.splitlines():
        line = " ".join(raw_line.lower().split())
        bullet = False
        while line.startswith(("- ", "* ")):
            line = line[2:].lstrip()
            bullet = True
        while line.startswith(("-", "*")):
            line = line[1:].lstrip()
            bullet = True
        if not line:
            flush_current()
            continue
        if (
            bullet
            or current.endswith((".", "!", "?"))
            or (
                current
                and not _task_close_gate_can_soft_wrap_statement(current, line)
            )
        ):
            flush_current()
        current = f"{current} {line}".strip() if current else line
    flush_current()
    return ". ".join(statements)


def _task_close_gate_failure_fragment_has_cue(normalized: str) -> bool:
    for cue in _TASK_CLOSE_GATE_FAILURE_START_CUES:
        if not _task_close_gate_starts_with_statement_cue(normalized, cue):
            continue
        return not _task_close_gate_discusses_failure_cue_as_diagnostic(
            normalized,
            cue,
        )
    return False


def _task_close_gate_discusses_failure_cue_as_diagnostic(
    normalized: str,
    cue: str,
) -> bool:
    if not normalized.startswith(cue):
        return False
    remainder = normalized[len(cue) :].lstrip()
    if not remainder or remainder[0] not in ":;":
        return False
    diagnostic_remainder = remainder[1:].lstrip()
    return _task_close_gate_is_standalone_diagnostic_case_clarifier(
        _task_close_gate_first_statement_fragment(diagnostic_remainder)
    )


def _task_close_gate_failure_fragment_is_diagnostic_prefix(
    *,
    fragment: str,
    following_text: str,
) -> bool:
    if not fragment.endswith((":", ";")):
        return False
    return any(
        fragment.startswith(cue)
        and not fragment[len(cue) : -1].strip()
        and _task_close_gate_is_standalone_diagnostic_case_clarifier(following_text)
        for cue in _TASK_CLOSE_GATE_FAILURE_START_CUES
    )


def _task_close_gate_has_failure_cue(text: str) -> bool:
    normalized = _task_close_gate_normalized_statement_text(text)
    if not normalized:
        return False
    return any(
        not _task_close_gate_failure_fragment_is_diagnostic_prefix(
            fragment=fragment,
            following_text=following_text,
        )
        and _task_close_gate_failure_fragment_has_cue(fragment)
        for fragment, following_text in _task_close_gate_statement_fragment_contexts(
            normalized
        )
    )


def _task_close_gate_discusses_diagnostic_text(normalized: str) -> bool:
    return any(
        token in normalized
        for token in (
            "diagnostic",
            "coverage",
            "covered",
            "false-positive",
            "false positive",
            "case is handled",
            "case is tested",
            "case is covered",
            "phrase under inspection",
        )
    )


def _task_close_gate_discusses_prefix_drift_as_diagnostic(normalized: str) -> bool:
    prefix_cue = next(
        (
            cue
            for cue in _TASK_CLOSE_GATE_GOAL_DRIFT_PREFIX_CUES
            if normalized.startswith(cue)
        ),
        "",
    )
    first_clause_end = min(
        (index for token in ".:,;!?" if (index := normalized.find(token)) != -1),
        default=len(normalized),
    )
    first_clause = normalized[:first_clause_end]
    if _task_close_gate_prefix_clarifier_discusses_diagnostic_case(normalized):
        return True
    first_statement = _task_close_gate_first_statement_fragment(normalized)
    return (
        _task_close_gate_discusses_diagnostic_case(first_clause)
        or _task_close_gate_clause_contains_diagnostic_case_clarifier(
            first_clause,
            first_statement,
            prefix_cue,
        )
        or _task_close_gate_prefix_clause_contains_diagnostic_text(
            first_clause,
            first_statement,
            prefix_cue,
        )
    )


def _task_close_gate_clause_contains_diagnostic_case_clarifier(
    clause: str,
    statement: str,
    prefix_cue: str,
) -> bool:
    for cue in _TASK_CLOSE_GATE_DIAGNOSTIC_CASE_CUES:
        if "diagnostic case" not in cue:
            continue
        start = -1
        while (start := clause.find(cue, start + 1)) != -1:
            if start and clause[start - 1] != " ":
                continue
            preceding_text = clause[:start].rstrip()
            if preceding_text.endswith((" non", " no", " not", " not a")):
                continue
            if not _task_close_gate_prefix_remainder_is_diagnostic_subject(
                prefix_cue,
                clause[len(prefix_cue) : start].strip(),
            ):
                continue
            if _task_close_gate_is_standalone_diagnostic_case_clarifier(
                statement[start:]
            ):
                return True
    return False


def _task_close_gate_prefix_clause_contains_diagnostic_text(
    clause: str,
    statement: str,
    prefix_cue: str,
) -> bool:
    for token in (
        " diagnostic is covered",
        " diagnostic is handled",
        " diagnostic is tested",
        " diagnostic test",
        " diagnostic regression",
        " diagnostic coverage",
        " diagnostic label",
        " diagnostic text",
    ):
        start = clause.find(token)
        if start == -1:
            continue
        if _task_close_gate_prefix_remainder_is_diagnostic_subject(
            prefix_cue,
            clause[len(prefix_cue) : start].strip(),
        ) and _task_close_gate_diagnostic_text_token_has_standalone_tail(
            statement[start + len(token) :]
        ):
            return True
    return False


def _task_close_gate_diagnostic_text_token_has_standalone_tail(remainder: str) -> bool:
    remainder = remainder.lstrip()
    if not remainder:
        return True
    if remainder[0] in ".!?":
        return not remainder.strip(".!?").strip()
    return False


def _task_close_gate_prefix_clarifier_discusses_diagnostic_case(
    normalized: str,
) -> bool:
    prefix_cue = next(
        (
            cue
            for cue in _TASK_CLOSE_GATE_GOAL_DRIFT_PREFIX_CUES
            if normalized.startswith(cue)
        ),
        "",
    )
    if not prefix_cue:
        return False
    separator_indexes = (
        index
        for token in ":;"
        if (index := normalized.find(token, len(prefix_cue))) != -1
    )
    separator_index = min(separator_indexes, default=-1)
    if separator_index == -1:
        return False
    prefix_remainder = normalized[len(prefix_cue) : separator_index].strip()
    if not _task_close_gate_prefix_remainder_is_diagnostic_subject(
        prefix_cue,
        prefix_remainder,
    ):
        return False
    diagnostic_remainder = normalized[separator_index + 1 :].lstrip()
    return _task_close_gate_is_standalone_diagnostic_case_clarifier(
        _task_close_gate_first_statement_fragment(diagnostic_remainder)
    )


def _task_close_gate_prefix_remainder_is_diagnostic_subject(
    cue: str,
    remainder: str,
) -> bool:
    if "exfiltrat" in cue:
        return remainder in {"e", "ed", "ing", "ion"}
    if "shell-based" in cue:
        return remainder in {"", "exfiltration"}
    return False


def _task_close_gate_prefix_fragment_is_diagnostic_prefix(
    *,
    fragment: str,
    following_text: str,
) -> bool:
    if not fragment.endswith((":", ";")):
        return False
    prefix_cue = next(
        (
            cue
            for cue in _TASK_CLOSE_GATE_GOAL_DRIFT_PREFIX_CUES
            if fragment.startswith(cue)
        ),
        "",
    )
    if not prefix_cue:
        return False
    prefix_remainder = fragment[len(prefix_cue) : -1].strip()
    return _task_close_gate_prefix_remainder_is_diagnostic_subject(
        prefix_cue,
        prefix_remainder,
    ) and _task_close_gate_is_standalone_diagnostic_case_clarifier(following_text)


def _task_close_gate_diagnostic_meta_fragment_has_clarifier(
    *,
    fragment: str,
    following_text: str,
) -> bool:
    if not _task_close_gate_mentions_diagnostic_meta_review_target(fragment):
        return False
    target_remainder = _task_close_gate_diagnostic_meta_target_remainder(fragment)
    if (
        target_remainder
        and not _task_close_gate_discusses_diagnostic_text(target_remainder)
    ):
        return False
    return _task_close_gate_is_standalone_diagnostic_case_clarifier(following_text)


def _task_close_gate_diagnostic_meta_target_remainder(fragment: str) -> str:
    for cue in _TASK_CLOSE_GATE_DIAGNOSTIC_META_REVIEW_TARGET_CUES:
        if fragment.startswith(cue):
            return fragment[len(cue) :].strip()
    return fragment


def _task_close_gate_is_standalone_diagnostic_case_clarifier(normalized: str) -> bool:
    normalized = normalized.strip()
    if not normalized:
        return False
    for cue in _TASK_CLOSE_GATE_DIAGNOSTIC_CASE_CUES:
        if not normalized.startswith(cue):
            continue
        remainder = normalized[len(cue) :].lstrip()
        if not remainder:
            return True
        if remainder[0] in ".!?":
            return not remainder.strip(".!?").strip()
        if _task_close_gate_as_remainder_is_diagnostic_text(remainder):
            return True
    return False


def _task_close_gate_discusses_diagnostic_case(normalized: str) -> bool:
    return any(
        _task_close_gate_statement_has_diagnostic_case_cue(fragment)
        for fragment in _task_close_gate_statement_fragments(normalized)
    )


def _task_close_gate_statement_has_diagnostic_case_cue(normalized: str) -> bool:
    return any(
        _task_close_gate_has_diagnostic_case_statement_prefix(normalized, cue)
        for cue in _TASK_CLOSE_GATE_DIAGNOSTIC_CASE_CUES
    )


def _task_close_gate_has_diagnostic_case_statement_prefix(
    normalized: str, cue: str
) -> bool:
    if not normalized.startswith(cue):
        return False
    remainder = normalized[len(cue) :].lstrip()
    if not remainder:
        return True
    if remainder[0] in ".:,;!?":
        return True
    return _task_close_gate_as_remainder_is_diagnostic_text(remainder)


def _task_close_gate_mentions_diagnostic_meta_review_target(normalized: str) -> bool:
    return any(
        normalized.startswith(cue)
        for cue in _TASK_CLOSE_GATE_DIAGNOSTIC_META_REVIEW_TARGET_CUES
    )


def _task_close_gate_label_value_is_truthy(normalized: str) -> bool:
    for cue in ("yes", "true", "detected", "confirmed"):
        if not normalized.startswith(cue):
            continue
        remainder = normalized[len(cue) :].lstrip()
        if not remainder:
            return True
        if remainder[0] in _TASK_CLOSE_GATE_CONTINUATION_PUNCTUATION - {"-"}:
            return True
        if remainder.startswith("- "):
            return True
        if _task_close_gate_remainder_starts_with_phrase(
            remainder,
            ("and", "because", "but", "while", "instead", "due to", "from"),
        ):
            return True
    return False


def _task_close_gate_goal_drift_fragment_has_cue(
    normalized: str,
    *,
    review_result: bool,
    diagnostic_review_context: bool,
) -> bool:
    while True:
        for label in _TASK_CLOSE_GATE_GOAL_DRIFT_LABEL_CUES:
            if not normalized.startswith(label):
                continue
            remainder = normalized[len(label) :].lstrip()
            if not remainder:
                return False
            if _task_close_gate_label_value_is_truthy(remainder):
                return True
            normalized = remainder
            break
        else:
            break
    if normalized.startswith(_TASK_CLOSE_GATE_GENERAL_OBJECT_CUES):
        return True
    if normalized.startswith(_TASK_CLOSE_GATE_GOAL_DRIFT_PREFIX_CUES):
        return not _task_close_gate_discusses_prefix_drift_as_diagnostic(normalized)
    if any(
        _task_close_gate_starts_with_statement_cue(normalized, cue)
        for cue in _TASK_CLOSE_GATE_GOAL_DRIFT_START_CUES
    ):
        return True
    if review_result and normalized.startswith(_TASK_CLOSE_GATE_REVIEW_OBJECT_CUES):
        has_drift_continuation = any(
            token in normalized
            for token in (" because ", " focused on ", " instead", " while ")
        )
        if diagnostic_review_context:
            if _task_close_gate_mentions_diagnostic_meta_review_target(normalized):
                return True
            return not _task_close_gate_discusses_diagnostic_text(normalized)
        return (
            not _task_close_gate_discusses_diagnostic_text(normalized)
            or has_drift_continuation
        )
    if _task_close_gate_discusses_diagnostic_text(normalized):
        return False
    return False


def _task_close_gate_has_goal_drift_cue(
    text: str,
    *,
    review_result: bool,
    diagnostic_review_context: bool,
) -> bool:
    normalized = _task_close_gate_normalized_statement_text(text)
    if not normalized:
        return False
    fragment_contexts = tuple(_task_close_gate_statement_fragment_contexts(normalized))
    has_statement_fragments = any(
        fragment != normalized for fragment, _following_text in fragment_contexts
    )
    skip_full_diagnostic_meta_target = (
        diagnostic_review_context
        and has_statement_fragments
        and _task_close_gate_mentions_diagnostic_meta_review_target(normalized)
    )
    if (
        not skip_full_diagnostic_meta_target
        and _task_close_gate_goal_drift_fragment_has_cue(
            normalized,
            review_result=review_result,
            diagnostic_review_context=diagnostic_review_context,
        )
    ):
        return True
    for fragment, following_text in fragment_contexts:
        if fragment == normalized:
            continue
        # The combined diagnostic-meta narrative can include a clarifying
        # response; do not let an isolated self-referential diagnostic phrase
        # override a full narrative that already resolved as benign.
        if (
            diagnostic_review_context
            and _task_close_gate_diagnostic_meta_fragment_has_clarifier(
                fragment=fragment,
                following_text=following_text,
            )
        ):
            continue
        if _task_close_gate_prefix_fragment_is_diagnostic_prefix(
            fragment=fragment,
            following_text=following_text,
        ):
            continue
        if _task_close_gate_goal_drift_fragment_has_cue(
            fragment,
            review_result=review_result,
            diagnostic_review_context=diagnostic_review_context,
        ):
            return True
    return False


def _task_close_gate_local_response(planner_input: str) -> str:
    evidence_text = _extract_marked_untrusted_payload(planner_input)
    sections = _parse_task_close_gate_sections(evidence_text)
    signals = _parse_task_close_gate_signals(sections.get("TASK RESULT SIGNALS:", ""))
    task_description = sections.get("ORIGINAL TASK DESCRIPTION:", "")
    requested_file_refs = sections.get("REQUESTED FILE REFS:", "")
    summary = sections.get("TASK OUTPUT SUMMARY:", "")
    response = sections.get("TASK OUTPUT RESPONSE:", "")
    files_changed = sections.get("TASK FILES CHANGED:", "")
    proposal_diff = sections.get("TASK PROPOSAL DIFF:", "")
    narrative = "\n".join(
        part
        for part in (
            summary.strip(),
            response.strip(),
        )
        if part
    ).strip()
    narrative_lower = narrative.lower()
    files_present = _task_close_gate_section_has_content(files_changed)
    proposal_diff_present = _task_close_gate_section_has_content(proposal_diff)
    summary_present = (
        signals.get("summary_present") == "yes" or _task_close_gate_section_has_content(summary)
    )
    response_present = (
        signals.get("response_present") == "yes"
        or _task_close_gate_section_has_content(response)
    )
    proposal_present = signals.get("proposal_present") == "yes"
    proposal_has_diff = signals.get("proposal_has_diff") == "yes" or proposal_diff_present
    write_activity_count = _task_close_gate_signal_int(signals, "write_activity_count")
    task_kind = signals.get("task_kind", "")
    read_only = signals.get("read_only") == "true"
    executor = signals.get("executor", "")
    diagnostic_review_context = (
        read_only
        and task_kind == "review"
        and not _task_close_gate_section_has_content(requested_file_refs)
        and _task_close_gate_is_diagnostic_meta_review(task_description)
    )
    artifact_evidence_present = files_present or proposal_has_diff
    artifactless_write_activity = (
        executor == "coding_agent"
        and write_activity_count > 0
        and not files_present
        and not proposal_has_diff
    )
    has_concrete_result = any(
        (
            summary_present,
            response_present,
            files_present,
            proposal_present,
            proposal_has_diff,
        )
    )
    drift_scan_parts = (narrative, response) if narrative else (summary, response)
    detected_goal_drift = any(
        _task_close_gate_has_goal_drift_cue(
            part,
            review_result=read_only and task_kind == "review",
            diagnostic_review_context=diagnostic_review_context,
        )
        for part in drift_scan_parts
    )
    detected_failure = any(
        _task_close_gate_has_failure_cue(part)
        for part in (summary, response, narrative)
    )
    detected_artifactless_worktree_mismatch = (
        not artifact_evidence_present
        and any(
            token in narrative_lower
            for token in (
                "repo-root mismatch",
                "repo root mismatch",
                "worktree mismatch",
            )
        )
    )

    if detected_goal_drift:
        status = "MISMATCH"
        reason = "goal_drift"
        notes = "Local fallback assessment detected delegated-task goal drift."
    elif artifactless_write_activity:
        status = "INCOMPLETE"
        reason = "no_artifact_evidence"
        notes = _artifactless_write_activity_notes()
    elif not has_concrete_result:
        status = "INCOMPLETE"
        reason = "no_task_output"
        notes = (
            "The evidence contains no clear delegated result to verify against "
            "the original request."
        )
    elif detected_failure or detected_artifactless_worktree_mismatch:
        status = "INCOMPLETE"
        reason = "incomplete_work"
        notes = "Local fallback assessment found missing or incomplete delegated work."
    elif proposal_has_diff or files_present:
        status = "COMPLETE"
        reason = "complete"
        notes = "The delegated task produced concrete proposal or file-change evidence."
    elif task_kind == "implement" and not artifact_evidence_present:
        status = "INCOMPLETE"
        reason = "incomplete_work"
        notes = "Local fallback assessment found no implementation artifacts."
    elif read_only and task_kind == "review" and (summary_present or response_present):
        status = "COMPLETE"
        reason = "complete"
        note_source = summary.strip() or response.strip() or "Delegated review completed."
        note_text = " ".join(note_source.split())
        notes = note_text[:160] if len(note_text) > 160 else note_text
    elif "only reviewed the file" in narrative_lower:
        status = "INCOMPLETE"
        reason = "incomplete_work"
        notes = "Local fallback assessment found missing or incomplete delegated work."
    else:
        status = "COMPLETE"
        reason = "complete"
        note_source = summary.strip() or response.strip() or "Delegated task completed."
        note_text = " ".join(note_source.split())
        notes = note_text[:160] if len(note_text) > 160 else note_text

    return f"SELF_CHECK_STATUS: {status}\nSELF_CHECK_REASON: {reason}\nSELF_CHECK_NOTES: {notes}"


def _is_structured_task_close_gate_prompt(text: str) -> bool:
    normalized = text.replace("^", "")
    trusted_preamble, user_separator, remainder = normalized.partition("=== USER REQUEST ===")
    if not user_separator:
        return False
    user_block, evidence_separator, evidence_block = remainder.partition("=== DATA EVIDENCE")
    if not evidence_separator:
        return False
    trusted_lines = {line.strip() for line in trusted_preamble.splitlines() if line.strip()}
    return (
        trusted_preamble.startswith("=== RUNTIME")
        and LOCAL_TASK_CLOSE_GATE_SENTINEL in trusted_lines
        and _TASK_CLOSE_GATE_HEADER in trusted_lines
        and "Assess whether the delegated task completed the original request." in user_block
        and "EVIDENCE_START_" in evidence_block
        and "EVIDENCE_END_" in evidence_block
    )


def _planner_fallback_message(
    *,
    fallback_mode: str,
    deterministic_tools_available: bool,
    fallback_error: str = "",
) -> str:
    if fallback_mode == "route_error":
        prefix = _PLANNER_FALLBACK_ROUTE_ERROR_PREFIX
        intro = "Configured planner route failed."
        detail = (
            " Continuing with deterministic local fallback tools only."
            if deterministic_tools_available
            else " Conversational planning is unavailable until the planner route recovers."
        )
        guidance = _planner_route_error_guidance(fallback_error)
        return f"{prefix} {intro}{detail}{guidance}"

    prefix = _PLANNER_FALLBACK_CONFIGURATION_PREFIX
    intro = "No language model configured."
    detail = (
        " Continuing with deterministic local fallback tools only."
        if deterministic_tools_available
        else " Conversational planning is unavailable."
    )
    guidance = (
        " Configure a planner route or local planner preset (for example Shisa, "
        "OpenAI, OpenRouter, Gemini, or local vLLM), then run "
        "`shisad doctor check --component provider`."
    )
    return f"{prefix} {intro}{detail}{guidance}"


def _planner_route_error_guidance(fallback_error: str) -> str:
    match = _PROVIDER_HTTP_ERROR_RE.search(fallback_error)
    if match is not None:
        status = int(match.group("status"))
        if status in _PROVIDER_RETRYABLE_HTTP_STATUSES:
            return (
                f" The configured provider is temporarily unavailable or rate limited "
                f"(HTTP {status}). This is usually a provider-side capacity or "
                "rate-limit issue; retry in a few minutes. Run "
                "`shisad doctor check --component provider` if it persists."
            )
        if 500 <= status <= 599:
            return (
                f" The configured provider is currently unavailable (HTTP {status}). "
                "This is usually a provider-side capacity issue; retry in a few "
                "minutes. Run `shisad doctor check --component provider` if it persists."
            )
        if 400 <= status <= 499:
            return (
                f" The provider route returned HTTP {status}. Check provider "
                "connectivity or credentials, then run "
                "`shisad doctor check --component provider`."
            )
    if fallback_error.startswith("Provider request failed"):
        return (
            " Could not reach the provider. Check your network, then run "
            "`shisad doctor check --component provider` if it persists."
        )
    return (
        " Check provider connectivity or credentials, then run "
        "`shisad doctor check --component provider`."
    )


class LocalPlannerProvider:
    """Local fallback planner provider for daemon operation."""

    async def complete(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        *,
        fallback_mode: str = "configuration",
        fallback_error: str = "",
    ) -> ProviderResponse:
        _ = tools
        user_content = messages[-1].content if messages else ""
        normalized_content = user_content.replace("^", "")
        if _is_structured_task_close_gate_prompt(user_content):
            return ProviderResponse(
                message=Message(
                    role="assistant",
                    content=_task_close_gate_local_response(user_content),
                ),
                model="local-fallback",
                finish_reason="stop",
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                trusted_origin="local-fallback",
            )
        goal_text = normalized_content
        goal_match = re.search(
            (
                r"=== (?:USER GOAL|USER REQUEST) ===\n"
                r".*?\n"
                r"(.*?)\n\n"
                r"=== (?:EXTERNAL CONTENT[^\n]*|DATA EVIDENCE[^\n]*|END CONTEXT|END PAYLOAD)"
            ),
            normalized_content,
            flags=re.DOTALL,
        )
        if goal_match:
            goal_text = goal_match.group(1).strip()
        goal_lower = goal_text.lower()
        actions: list[dict[str, Any]] = []

        anomaly_triggers = (
            "report anomaly",
            "security incident",
            "possible compromise",
            "suspicious behavior",
        )
        if "retrieve:" in goal_lower or "retrieve evidence" in goal_lower:
            query = goal_text.split(":", 1)[-1].strip() or goal_text[:180]
            actions.append(
                {
                    "action_id": "local-retrieve-1",
                    "tool_name": "retrieve_rag",
                    "arguments": {
                        "query": query,
                        "limit": 5,
                    },
                    "reasoning": "Retrieve supporting evidence for user request",
                    "data_sources": ["memory_index"],
                }
            )

        run_match = re.search(
            r"\b(?:run|execute)\s*:\s*(.+)",
            goal_text,
            flags=re.DOTALL | re.IGNORECASE,
        )
        if run_match:
            command_text = run_match.group(1).strip()
            command_tokens: list[str]
            try:
                command_tokens = shlex.split(command_text)
            except ValueError:
                command_tokens = []
            if command_tokens:
                actions.append(
                    {
                        "action_id": "local-shell-1",
                        "tool_name": "shell.exec",
                        "arguments": {
                            "command": command_tokens,
                            "command_intent": "execute",
                        },
                        "reasoning": "Run explicit command requested by user via sandbox runtime",
                        "data_sources": ["user_signal"],
                    }
                )

        if any(token in goal_lower for token in anomaly_triggers):
            actions.append(
                {
                    "action_id": "local-anomaly-1",
                    "tool_name": "report_anomaly",
                    "arguments": {
                        "anomaly_type": "runtime_alert",
                        "description": "User signaled suspicious behavior requiring review.",
                        "recommended_action": "quarantine",
                        "confidence": 0.9,
                    },
                    "reasoning": "Local deterministic safety trigger for anomaly reporting",
                    "data_sources": ["user_signal"],
                }
            )

        tool_calls: list[dict[str, Any]] = []
        for action in actions:
            tool_name = str(action.get("tool_name", "")).strip()
            if not tool_name:
                continue
            action_id = str(action.get("action_id", "")).strip() or (
                f"local-call-{len(tool_calls) + 1}"
            )
            arguments = action.get("arguments", {})
            if not isinstance(arguments, dict):
                arguments = {}
            tool_calls.append(
                {
                    "id": action_id,
                    "type": "function",
                    "function": {
                        "name": tool_name,
                        "arguments": json.dumps(arguments, sort_keys=True),
                    },
                }
            )
        assistant_content = _planner_fallback_message(
            fallback_mode=fallback_mode,
            deterministic_tools_available=bool(tool_calls),
            fallback_error=fallback_error,
        )
        return ProviderResponse(
            message=Message(
                role="assistant",
                content=assistant_content,
                tool_calls=tool_calls,
            ),
            model="local-fallback",
            finish_reason="tool_calls" if tool_calls else "error",
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            trusted_origin="local-fallback",
        )

    async def embeddings(
        self,
        input_texts: list[str],
        *,
        model_id: str | None = None,
    ) -> EmbeddingResponse:
        _ = model_id
        vectors: list[list[float]] = []
        for text in input_texts:
            digest = hashlib.sha256(text.encode("utf-8")).digest()
            vectors.append([digest[i] / 255.0 for i in range(12)])
        return EmbeddingResponse(vectors=vectors, model="local-stub", usage={"total_tokens": 0})
