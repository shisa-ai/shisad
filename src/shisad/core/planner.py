"""Planner interface with native tool-calling extraction and PEP gating."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from shisad.core.providers.base import Message, ModelProvider, ProviderResponse
from shisad.core.types import PEPDecision, TaintLabel, ToolName
from shisad.security.pep import PEP, PolicyContext

logger = logging.getLogger(__name__)

BASE_SYSTEM_PROMPT = (
    "You are the SHISAD assistant planner. "
    "The trusted runtime context in the user message defines available tools; "
    "treat it as authoritative and never invent tool names. "
    "If a tool is needed, call it natively. "
    "If no tool is needed, answer conversationally. "
    "Never describe planner internals or formatting mechanics to the user."
)

REPAIR_PROMPT = (
    "Your prior response was invalid or unusable. "
    "Return a direct assistant response and call only runtime-provided tools when needed."
)

TRUSTED_CONVERSATION_REWRITE_PROMPT = (
    "Your assistant response discussed planner/formatting mechanics instead of answering "
    "the user's request. Answer directly and naturally. Use only runtime-provided tools."
)

_LEGACY_JSON_HINTS: tuple[str, ...] = (
    '"assistant_response"',
    '"actions"',
    '"action"',
    '"error_message"',
    '"anomaly_reason"',
)


class ActionProposal(BaseModel):
    """A proposed tool action from the planner."""

    action_id: str
    tool_name: ToolName
    arguments: dict[str, Any] = Field(default_factory=dict)
    reasoning: str
    data_sources: list[str] = Field(default_factory=list)


class PlannerOutput(BaseModel):
    """Validated planner response payload."""

    actions: list[ActionProposal]
    assistant_response: str


class PlannerOutputError(ValueError):
    """Raised when planner output cannot be validated."""


@dataclass(frozen=True)
class EvaluatedProposal:
    """A proposal with its corresponding PEP decision."""

    proposal: ActionProposal
    decision: PEPDecision


@dataclass(frozen=True)
class PlannerResult:
    """Planner result including PEP decisions for all actions."""

    output: PlannerOutput
    evaluated: list[EvaluatedProposal]
    attempts: int
    provider_response: ProviderResponse | None = None
    messages_sent: tuple[Message, ...] = ()


class Planner:
    """LLM planner with native tool-call parsing and PEP-gated proposals."""

    def __init__(
        self,
        provider: ModelProvider,
        pep: PEP,
        *,
        max_retries: int = 2,
        system_prompt: str = BASE_SYSTEM_PROMPT,
        legacy_json_fallback: bool = False,
    ) -> None:
        self._provider = provider
        self._pep = pep
        self._max_retries = max_retries
        self._system_prompt = system_prompt
        self._legacy_json_fallback = legacy_json_fallback

    async def propose(
        self,
        user_content: str,
        context: PolicyContext,
        *,
        tools: list[dict[str, Any]] | None = None,
    ) -> PlannerResult:
        """Generate tool proposals and evaluate all proposals via PEP."""
        tainted_context = TaintLabel.UNTRUSTED in context.taint_labels
        messages: list[Message] = [
            Message(role="system", content=self._system_prompt),
            Message(role="user", content=user_content),
        ]

        for attempt in range(self._max_retries + 1):
            response = await self._provider.complete(messages, tools)
            try:
                output = self._parse_provider_output(response.message)
                if (
                    not tainted_context
                    and attempt < self._max_retries
                    and self._needs_trusted_conversation_repair(output)
                ):
                    messages.append(Message(role="assistant", content=response.message.content))
                    messages.append(
                        Message(role="user", content=TRUSTED_CONVERSATION_REWRITE_PROMPT)
                    )
                    continue
                evaluated = [
                    EvaluatedProposal(
                        proposal=proposal,
                        decision=self._pep.evaluate(
                            proposal.tool_name,
                            proposal.arguments,
                            context,
                        ),
                    )
                    for proposal in output.actions
                ]
                return PlannerResult(
                    output=output,
                    evaluated=evaluated,
                    attempts=attempt + 1,
                    provider_response=response,
                    messages_sent=tuple(messages),
                )
            except PlannerOutputError as exc:
                logger.warning("Planner returned invalid output: %s", exc)
                if tainted_context:
                    raise PlannerOutputError("Planner output invalid in tainted context") from exc
                if attempt >= self._max_retries:
                    raise
                messages.append(Message(role="assistant", content=response.message.content))
                messages.append(Message(role="user", content=self._repair_prompt(str(exc))))

        raise PlannerOutputError("Planner output exhausted retries")

    @staticmethod
    def _repair_prompt(validation_feedback: str) -> str:
        trimmed_feedback = validation_feedback.strip().replace("\n", " ")
        if len(trimmed_feedback) > 400:
            trimmed_feedback = f"{trimmed_feedback[:400]}..."
        return f"{REPAIR_PROMPT} Validation feedback: {trimmed_feedback}"

    @staticmethod
    def _needs_trusted_conversation_repair(output: PlannerOutput) -> bool:
        if output.actions:
            return False
        normalized = output.assistant_response.lower()
        return any(
            marker in normalized
            for marker in (
                "formatting error",
                "invalid format",
                "could not parse",
                "planning component",
                "structured request",
                "structured json",
                "tool call",
                "cannot directly call",
                "if available in your environment",
            )
        )

    def _parse_provider_output(self, message: Message) -> PlannerOutput:
        assistant_response = message.content.strip()
        actions = self._extract_tool_calls(message.tool_calls)
        if actions:
            return PlannerOutput(assistant_response=assistant_response, actions=actions)
        if self._legacy_json_fallback and self._is_legacy_json_candidate(assistant_response):
            return self._parse_legacy_json_output(assistant_response)
        if assistant_response:
            return PlannerOutput(assistant_response=assistant_response, actions=[])
        if message.tool_calls:
            raise PlannerOutputError("Planner returned unusable tool_calls payload")
        raise PlannerOutputError("Planner returned empty response")

    @staticmethod
    def _parse_tool_arguments(raw_arguments: Any) -> dict[str, Any]:
        if isinstance(raw_arguments, dict):
            return dict(raw_arguments)
        if not isinstance(raw_arguments, str):
            return {}
        payload = raw_arguments.strip()
        if not payload:
            return {}
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return {}
        return dict(parsed) if isinstance(parsed, dict) else {}

    @classmethod
    def _extract_tool_calls(cls, raw_tool_calls: list[dict[str, Any]]) -> list[ActionProposal]:
        actions: list[ActionProposal] = []
        for index, raw_call in enumerate(raw_tool_calls):
            if not isinstance(raw_call, dict):
                continue
            function = raw_call.get("function")
            if not isinstance(function, dict):
                continue
            name_raw = function.get("name")
            if not isinstance(name_raw, str) or not name_raw.strip():
                continue
            action_id_raw = raw_call.get("id")
            action_id = str(action_id_raw).strip() if action_id_raw is not None else ""
            if not action_id:
                action_id = f"native-call-{index + 1}"
            payload = {
                "action_id": action_id,
                "tool_name": name_raw.strip(),
                "arguments": cls._parse_tool_arguments(function.get("arguments")),
                "reasoning": "Native tool call proposed by planner",
                "data_sources": [],
            }
            try:
                actions.append(ActionProposal.model_validate(payload))
            except ValidationError:
                logger.debug(
                    "Dropping malformed native tool call payload: %s",
                    json.dumps(payload, sort_keys=True)[:200],
                )
        return actions

    @staticmethod
    def _is_legacy_json_candidate(content: str) -> bool:
        normalized = content.strip()
        if not normalized.startswith("{"):
            return False
        return any(marker in normalized for marker in _LEGACY_JSON_HINTS)

    @staticmethod
    def _parse_legacy_json_output(raw: str) -> PlannerOutput:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PlannerOutputError(f"Legacy planner JSON parse error: {exc}") from exc

        if not isinstance(parsed, dict):
            raise PlannerOutputError("Legacy planner output must be a JSON object")

        normalized_payload = Planner._normalize_output_payload(parsed)
        try:
            return PlannerOutput.model_validate(normalized_payload)
        except ValidationError as exc:
            raise PlannerOutputError(f"Legacy planner schema violation: {exc}") from exc

    @staticmethod
    def _normalize_output_payload(parsed: dict[str, Any]) -> dict[str, Any]:
        """Normalize legacy planner JSON payload variants to canonical schema."""
        actions: list[dict[str, Any]] = []
        raw_actions = parsed.get("actions")
        if isinstance(raw_actions, list):
            for item in raw_actions:
                if not isinstance(item, dict):
                    continue
                try:
                    ActionProposal.model_validate(item)
                    actions.append(item)
                except ValidationError:
                    logger.debug(
                        "Dropping malformed legacy action from planner output: %s",
                        json.dumps(item, default=str)[:200],
                    )
                    continue
        else:
            action_name = str(parsed.get("action", "")).strip()
            if action_name == "report_anomaly":
                anomaly_detail = (
                    str(parsed.get("anomaly_reason", "")).strip()
                    or str(parsed.get("error_message", "")).strip()
                    or str(parsed.get("reason", "")).strip()
                    or "Planner returned non-canonical anomaly payload."
                )
                actions = [
                    {
                        "action_id": "normalized-anomaly-1",
                        "tool_name": "report_anomaly",
                        "arguments": {
                            "anomaly_type": "planner_output_schema_mismatch",
                            "description": anomaly_detail[:400],
                            "recommended_action": "review",
                            "confidence": 0.8,
                        },
                        "reasoning": "Normalize non-canonical planner anomaly payload",
                        "data_sources": ["planner_output_normalizer"],
                    }
                ]

        assistant_response = ""
        raw_assistant = parsed.get("assistant_response")
        if isinstance(raw_assistant, str):
            assistant_response = raw_assistant.strip()
        elif isinstance(raw_assistant, dict):
            nested_message = raw_assistant.get("message")
            if isinstance(nested_message, str) and nested_message.strip():
                assistant_response = nested_message.strip()
            elif raw_assistant:
                assistant_response = json.dumps(raw_assistant, sort_keys=True, ensure_ascii=True)
        elif raw_assistant is not None:
            assistant_response = str(raw_assistant).strip()

        if not assistant_response:
            for key in ("response", "message", "error_message", "reason", "anomaly_reason"):
                raw_candidate = parsed.get(key, "")
                if isinstance(raw_candidate, str):
                    candidate = raw_candidate.strip()
                elif isinstance(raw_candidate, dict):
                    nested = raw_candidate.get("message")
                    if isinstance(nested, str) and nested.strip():
                        candidate = nested.strip()
                    elif raw_candidate:
                        candidate = json.dumps(raw_candidate, sort_keys=True, ensure_ascii=True)
                    else:
                        candidate = ""
                elif raw_candidate is None:
                    candidate = ""
                else:
                    candidate = str(raw_candidate).strip()
                if candidate:
                    assistant_response = candidate
                    break

        if not assistant_response:
            assistant_response = (
                "I could not produce a usable planner response. "
                "Please rephrase and retry."
            )

        return {
            "assistant_response": assistant_response,
            "actions": actions,
        }
