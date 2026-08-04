"""I4 contract coverage for typed user-facing failure presentation."""

from __future__ import annotations

from shisad.core.failure_presentation import (
    UserFacingFailure,
    confirmed_execution_failure,
    planner_output_failure,
    planner_route_failure,
    render_user_facing_failure,
)


def test_i4_route_failure_maps_retryable_http_without_serializing_diagnostics() -> None:
    diagnostic = (
        "Provider HTTP error 429 for https://planner.example.test/v1: "
        '{"error":{"message":"rate limited for secret-token"}}; '
        "run `shisad doctor check --component provider`"
    )

    failure = planner_route_failure(diagnostic=diagnostic)

    assert failure.code == "planner_route_temporarily_unavailable"
    assert failure.retryable is True
    assert failure.approval_outcome == "not_applicable"
    assert failure.execution_outcome == "not_started"
    assert failure.partial_result is False
    assert failure.operator_diagnostics == diagnostic
    serialized = failure.model_dump(mode="json")
    assert "operator_diagnostics" not in serialized
    rendered = render_user_facing_failure(failure)
    assert rendered == (
        "The model service is temporarily unavailable, so I couldn't complete this request.\n\n"
        "Please try again in a few minutes."
    )
    assert "HTTP 429" not in rendered
    assert "planner.example" not in rendered
    assert "secret-token" not in rendered
    assert "doctor check" not in rendered


def test_i4_route_failure_maps_nonretryable_setup_and_partial_state() -> None:
    failure = planner_route_failure(
        diagnostic=(
            "Provider HTTP error 400 for https://planner.example.test/v1: invalid credentials"
        ),
        partial_result=True,
    )

    assert failure.code == "planner_route_setup_required"
    assert failure.retryable is False
    assert failure.partial_result is True
    assert render_user_facing_failure(failure) == (
        "I could only handle part of this request because the configured model service "
        "needs attention.\n\nCheck the model service setup, then try again."
    )


def test_i4_planner_output_failure_hides_schema_and_repair_details() -> None:
    failure = planner_output_failure(
        diagnostic=(
            "three repair attempts failed: internal tool-call formatting violated strict schema"
        )
    )

    assert failure.code == "planner_response_invalid"
    assert failure.retryable is True
    assert render_user_facing_failure(failure) == (
        "I couldn't complete this request because the response couldn't be processed.\n\n"
        "Please try again."
    )
    assert "schema" not in render_user_facing_failure(failure).lower()
    assert "tool-call" not in render_user_facing_failure(failure).lower()
    assert "repair" not in render_user_facing_failure(failure).lower()
    assert "operator_diagnostics" not in failure.model_dump(mode="json")


def test_i4_confirmed_missing_backend_separates_approval_from_execution() -> None:
    failure = confirmed_execution_failure(
        code="web_search_backend_unconfigured",
        execution_outcome="failed",
    )

    assert failure.retryable is False
    assert failure.approval_outcome == "accepted"
    assert failure.execution_outcome == "failed"
    assert render_user_facing_failure(failure) == (
        "Your approval was received, but web search couldn't run because it isn't set up.\n\n"
        "Set up web search, then retry your request."
    )


def test_i4_unknown_confirmed_outcome_does_not_invite_unsafe_retry() -> None:
    failure = confirmed_execution_failure(
        code="idempotent_adapter_outcome_unknown",
        execution_outcome="unknown",
    )

    assert failure.retryable is False
    assert failure.code == "action_outcome_unknown"
    assert failure.approval_outcome == "accepted"
    assert failure.execution_outcome == "unknown"
    assert render_user_facing_failure(failure) == (
        "Your approval was received, but I can't tell whether the action completed.\n\n"
        "Check the result before retrying so the action isn't performed twice."
    )


def test_i4_generic_confirmed_failure_remains_safe_and_structural() -> None:
    failure = confirmed_execution_failure(
        code="tool_unavailable",
        execution_outcome="failed",
        operator_diagnostics="private adapter exception",
    )

    assert failure.approval_outcome == "accepted"
    assert failure.execution_outcome == "failed"
    assert failure.code == "action_execution_failed"
    assert render_user_facing_failure(failure) == (
        "Your approval was received, but the action couldn't be completed.\n\n"
        "Review the action details or setup, then try again."
    )
    assert "private adapter exception" not in render_user_facing_failure(failure)
    assert "operator_diagnostics" not in failure.model_dump(mode="json")


def test_i4_post_execution_followup_failure_preserves_successful_execution() -> None:
    failure = confirmed_execution_failure(
        code="artifact_endorse_failed",
        execution_outcome="succeeded",
    )

    assert failure.code == "action_followup_failed"
    assert failure.execution_outcome == "succeeded"
    assert failure.partial_result is True
    assert render_user_facing_failure(failure) == (
        "Your approval was received and the action ran, but follow-up processing "
        "couldn't be completed.\n\nReview the result before retrying the action."
    )


def test_i4_renderer_supports_a_single_safe_summary() -> None:
    failure = UserFacingFailure(code="safe_summary_only", summary="Safe summary.")

    assert render_user_facing_failure(failure) == "Safe summary."
