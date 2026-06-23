"""Local fallback provider for daemon planner and embeddings routes."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
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
        if line in _TASK_CLOSE_GATE_SECTION_HEADERS:
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


def _task_close_gate_has_failure_cue(text: str) -> bool:
    normalized = " ".join(text.lower().split())
    if not normalized:
        return False
    startswith_cues = (
        "delegated task failed before completion",
        "delegated task timed out before completion",
        "requested coding agent is not available",
        "could not create or inspect the isolated worktree",
        "the delegated task did not make the requested update",
        "the delegated task reported incomplete work",
        "the review timed out before completion",
        "the delegated review reported incomplete work",
    )
    return normalized.startswith(startswith_cues)


def _task_close_gate_local_response(planner_input: str) -> str:
    evidence_text = _extract_marked_untrusted_payload(planner_input)
    sections = _parse_task_close_gate_sections(evidence_text)
    signals = _parse_task_close_gate_signals(sections.get("TASK RESULT SIGNALS:", ""))
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
    detected_goal_drift = any(
        token in narrative_lower
        for token in (
            "changed scope",
            "goal drift",
            "ignored the",
            "did not review",
            "different goal",
            "exfiltrat",
            "shell-based",
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
    elif proposal_has_diff or files_present:
        status = "COMPLETE"
        reason = "complete"
        notes = "The delegated task produced concrete proposal or file-change evidence."
    elif any(
        _task_close_gate_has_failure_cue(part)
        for part in (summary, response, narrative)
    ) or (
        not artifact_evidence_present
        and any(
            token in narrative_lower
            for token in (
                "repo-root mismatch",
                "repo root mismatch",
                "worktree mismatch",
            )
        )
    ):
        status = "INCOMPLETE"
        reason = "incomplete_work"
        notes = "Local fallback assessment found missing or incomplete delegated work."
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
