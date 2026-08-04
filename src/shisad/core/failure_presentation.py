"""Typed semantic failures and user-facing rendering.

This module classifies only finite machine-owned states. Operator diagnostics
remain available to in-process logging and details surfaces but are excluded
from ordinary model serialization and user-facing text.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ApprovalOutcome = Literal["not_applicable", "not_received", "accepted", "rejected"]
ExecutionOutcome = Literal["not_started", "succeeded", "failed", "unknown"]

_PROVIDER_HTTP_ERROR_RE = re.compile(
    r"\bProvider HTTP error (?P<status>[1-5][0-9]{2})\b"
)
_RETRYABLE_PROVIDER_HTTP_STATUSES = frozenset({408, 429})


class UserFacingFailure(BaseModel):
    """Semantic failure state shared by user-surface renderers."""

    model_config = ConfigDict(extra="forbid")

    code: str
    summary: str
    retryable: bool = False
    safe_next_action: str = ""
    approval_outcome: ApprovalOutcome = "not_applicable"
    execution_outcome: ExecutionOutcome = "not_started"
    partial_result: bool = False
    operator_diagnostics: str = Field(default="", exclude=True, repr=False)


def render_user_facing_failure(failure: UserFacingFailure) -> str:
    """Render only the safe user summary and next action."""

    summary = failure.summary.strip()
    next_action = failure.safe_next_action.strip()
    if summary and next_action:
        return f"{summary}\n\n{next_action}"
    return summary or next_action


def planner_route_failure(
    *,
    diagnostic: str,
    partial_result: bool = False,
) -> UserFacingFailure:
    """Map a bounded provider-route diagnostic to safe user semantics."""

    match = _PROVIDER_HTTP_ERROR_RE.search(diagnostic)
    status = int(match.group("status")) if match is not None else None
    setup_required = status is not None and 400 <= status <= 499 and status not in (
        _RETRYABLE_PROVIDER_HTTP_STATUSES
    )
    if setup_required:
        summary = (
            "I could only handle part of this request because the configured model service "
            "needs attention."
            if partial_result
            else (
                "I couldn't complete this request because the configured model service "
                "needs attention."
            )
        )
        return UserFacingFailure(
            code="planner_route_setup_required",
            summary=summary,
            retryable=False,
            safe_next_action="Check the model service setup, then try again.",
            partial_result=partial_result,
            operator_diagnostics=diagnostic,
        )

    summary = (
        "I could only handle part of this request because the model service is temporarily "
        "unavailable."
        if partial_result
        else "The model service is temporarily unavailable, so I couldn't complete this request."
    )
    return UserFacingFailure(
        code="planner_route_temporarily_unavailable",
        summary=summary,
        retryable=True,
        safe_next_action="Please try again in a few minutes.",
        partial_result=partial_result,
        operator_diagnostics=diagnostic,
    )


def planner_output_failure(
    *,
    diagnostic: str = "",
    partial_result: bool = False,
) -> UserFacingFailure:
    """Present invalid planner output without exposing schema mechanics."""

    summary = (
        "I could only handle part of this request because the response couldn't be processed."
        if partial_result
        else "I couldn't complete this request because the response couldn't be processed."
    )
    return UserFacingFailure(
        code="planner_response_invalid",
        summary=summary,
        retryable=True,
        safe_next_action="Please try again.",
        partial_result=partial_result,
        operator_diagnostics=diagnostic,
    )


def execution_failure(
    *,
    code: str,
    approval_outcome: ApprovalOutcome = "not_applicable",
    execution_outcome: Literal["failed", "unknown"] = "failed",
    operator_diagnostics: str = "",
) -> UserFacingFailure:
    """Map a finite execution result code to safe user semantics."""

    approved_prefix = "Your approval was received, but " if approval_outcome == "accepted" else ""
    if execution_outcome == "unknown":
        return UserFacingFailure(
            code=code or "action_outcome_unknown",
            summary=(
                "Your approval was received, but I can't tell whether the action completed."
                if approval_outcome == "accepted"
                else "I can't tell whether the action completed."
            ),
            retryable=False,
            safe_next_action=(
                "Check the result before retrying so the action isn't performed twice."
            ),
            approval_outcome=approval_outcome,
            execution_outcome="unknown",
            operator_diagnostics=operator_diagnostics or code,
        )

    if code == "web_search_backend_unconfigured":
        subject = "web search" if approved_prefix else "Web search"
        return UserFacingFailure(
            code=code,
            summary=f"{approved_prefix}{subject} couldn't run because it isn't set up.",
            retryable=False,
            safe_next_action="Set up web search, then retry your request.",
            approval_outcome=approval_outcome,
            execution_outcome="failed",
            operator_diagnostics=operator_diagnostics or code,
        )

    subject = "the action" if approved_prefix else "The action"
    return UserFacingFailure(
        code=code or "action_execution_failed",
        summary=f"{approved_prefix}{subject} couldn't be completed.",
        retryable=False,
        safe_next_action="Review the action details or setup, then try again.",
        approval_outcome=approval_outcome,
        execution_outcome="failed",
        operator_diagnostics=operator_diagnostics or code,
    )


def confirmed_execution_failure(
    *,
    code: str,
    execution_outcome: Literal["failed", "unknown"] = "failed",
    operator_diagnostics: str = "",
) -> UserFacingFailure:
    """Build a failure after valid user approval was accepted."""

    return execution_failure(
        code=code,
        approval_outcome="accepted",
        execution_outcome=execution_outcome,
        operator_diagnostics=operator_diagnostics,
    )
